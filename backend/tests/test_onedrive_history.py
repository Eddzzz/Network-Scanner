import csv
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
test_data = tempfile.TemporaryDirectory()
os.environ["SCANNER_DATA_DIR"] = test_data.name
os.environ["ONEDRIVE_LOCAL_DIR"] = str(Path(test_data.name) / "Nube")
os.environ["ONEDRIVE_AUTO_UPLOAD"] = "false"

from domain.models import Host, NetworkTopology, WirelessIoTScan, WirelessNetwork
from infrastructure import history_api
from infrastructure.onedrive import OneDrive, OneDriveError
from infrastructure.scan_history import ScanHistory, compare_scans, csv_report, json_report

with patch("infrastructure.nmap_adapter.NmapAdapter"):
    from infrastructure import api



def host(ip="127.0.0.1", ports=None, hostname="equipo"):
    return {"ip": ip, "hostname": hostname, "state": "up", "mac_address": None,
            "vendor": None, "os": None, "ports": ports or []}


class HistoryCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.history = ScanHistory(Path(self.temp.name) / "scans.sqlite3")

    def save(self, hosts=None):
        return self.history.save("network", "127.0.0.1", {"hosts": hosts or [host()]})


class HistoryTests(HistoryCase):
    def test_history_survives_reopening_and_paginates(self):
        first = self.save()
        second = self.save()
        reopened = ScanHistory(self.history.path)
        self.assertEqual(reopened.get(first["id"])["data"], first["data"])
        self.assertEqual(reopened.list(1, 0)["total"], 2)
        self.assertEqual(reopened.list(1, 0)["items"][0]["id"], second["id"])
        self.assertEqual(reopened.list(1, 1)["items"][0]["id"], first["id"])

    def test_json_roundtrip_is_idempotent_and_rejects_conflicts(self):
        record = self.save()
        document = json.loads(json_report(record))
        self.assertNotIn("sync", document)
        self.history.restore(document)
        self.assertEqual(self.history.list()["total"], 1)
        document["data"]["hosts"][0]["hostname"] = "otro"
        with self.assertRaises(ValueError):
            self.history.restore(document)
        self.assertEqual(self.history.get(record["id"])["data"], record["data"])

    def test_import_rejects_broken_hosts_and_schema(self):
        document = json.loads(json_report(self.save()))
        document["id"] = str(uuid4())
        document["data"]["hosts"] = [None]
        with self.assertRaises(ValueError):
            self.history.restore(document)
        document["schema_version"] = 2
        with self.assertRaises(ValueError):
            self.history.restore(document)
        self.assertEqual(self.history.list()["total"], 1)

    def test_csv_is_excel_readable_and_escapes_formulas(self):
        port = {"number": 80, "protocol": "tcp", "state": "open", "service": "http"}
        record = self.save([host(ports=[port], hostname=" =HYPERLINK(\"bad\")"), host("127.0.0.2")])
        rows = list(csv.DictReader(io.StringIO(csv_report(record).decode("utf-8-sig"))))
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]["hostname"].startswith("'"))
        self.assertEqual(rows[0]["port"], "80")
        self.assertEqual(rows[1]["port"], "")

    def test_comparison_detects_devices_port_changes_and_services(self):
        port = {"number": 80, "protocol": "tcp", "state": "open", "service": "http"}
        previous = self.save([host(ports=[port]), host("127.0.0.2")])
        changed_port = {**port, "state": "closed"}
        added_port = {**port, "number": 443, "service": "https"}
        current = self.save([host(ports=[changed_port, added_port]), host("127.0.0.3")])
        diff = compare_scans(previous, current)
        self.assertEqual(diff["new_hosts"][0]["ip"], "127.0.0.3")
        self.assertEqual(diff["missing_hosts"][0]["ip"], "127.0.0.2")
        ports = diff["changed_hosts"][0]["ports"]
        self.assertEqual(ports["added"][0]["number"], 443)
        self.assertEqual(ports["changed"][0]["after"]["state"], "closed")
        self.assertEqual(compare_scans(current, previous)["changed_hosts"][0]["ports"]["removed"][0]["number"], 443)
        current["target"] = "otra red"
        with self.assertRaises(ValueError):
            compare_scans(previous, current)


class OneDriveTests(HistoryCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"ONEDRIVE_LOCAL_DIR": str(Path(self.temp.name) / "Nube")}):
            self.cloud = OneDrive()

    def test_status_creates_and_checks_local_folder(self):
        status = self.cloud.status()
        self.assertEqual(status["mode"], "local")
        self.assertTrue(status["connected"])
        self.assertFalse(status["cloud_sync_verified"])
        self.assertEqual(list(self.cloud.folder.iterdir()), [])

    def test_save_and_restore_real_files_without_credentials(self):
        record = self.save()
        paths = self.cloud.upload(record)
        self.assertEqual(set(paths), {"json", "csv"})
        for path in paths.values():
            self.assertEqual(Path(path).parent, self.cloud.folder)
            self.assertTrue(Path(path).is_file())
        self.assertEqual(self.cloud.download(record["id"]), json.loads(json_report(record)))
        self.cloud.upload(record)
        self.assertEqual(len(list(self.cloud.folder.iterdir())), 2)

    def test_listing_ignores_unrelated_files_and_has_scan_ids(self):
        record = self.save()
        self.cloud.upload(record)
        (self.cloud.folder / "notas.txt").write_text("conservar", encoding="utf-8")
        (self.cloud.folder / "scan-invalid.json").write_text("{}", encoding="utf-8")
        items = self.cloud.files()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], record["id"])
        self.assertEqual((self.cloud.folder / "notas.txt").read_text(encoding="utf-8"), "conservar")

    def test_failed_replace_preserves_existing_report_and_cleans_temporary(self):
        record = self.save()
        paths = self.cloud.upload(record)
        original = Path(paths["json"]).read_bytes()
        with patch("infrastructure.onedrive.os.replace", side_effect=PermissionError):
            with self.assertRaises(OneDriveError):
                self.cloud.upload(record)
        self.assertEqual(Path(paths["json"]).read_bytes(), original)
        self.assertEqual(len(list(self.cloud.folder.iterdir())), 2)

    def test_unavailable_folder_is_reported(self):
        self.cloud.folder.write_text("this is a file", encoding="utf-8")
        self.assertFalse(self.cloud.status()["connected"])
        with self.assertRaises(OneDriveError):
            self.cloud.upload(self.save())

    def test_download_rejects_missing_oversized_and_mismatched_reports(self):
        record = self.save()
        with self.assertRaises(OneDriveError) as error:
            self.cloud.download(record["id"])
        self.assertEqual(error.exception.status_code, 404)
        paths = self.cloud.upload(record)
        with patch("infrastructure.onedrive.MAX_REPORT_BYTES", 4):
            with self.assertRaises(OneDriveError) as error:
                self.cloud.download(record["id"])
            self.assertEqual(error.exception.status_code, 413)
        Path(paths["json"]).write_text(json.dumps({"id": str(uuid4())}), encoding="utf-8")
        with self.assertRaises(OneDriveError) as error:
            self.cloud.download(record["id"])
        self.assertEqual(error.exception.status_code, 422)


class ApiTests(HistoryCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(patch.stopall)
        patch.object(history_api, "history", self.history).start()
        self.cloud = Mock(auto_upload=False)
        patch.object(history_api, "onedrive", self.cloud).start()
        patch.dict(os.environ, {"SCANNER_API_KEY": "test-key"}).start()
        self.client = TestClient(api.app, headers={"X-API-Key": "test-key"})
        self.addCleanup(self.client.close)

    def test_new_endpoints_require_key_and_validate_ids(self):
        for path in ("/api/history", "/api/onedrive/status", "/api/onedrive/files"):
            with self.subTest(path=path):
                self.assertEqual(TestClient(api.app).get(path).status_code, 401)
        self.assertEqual(self.client.get("/api/history/invalid").status_code, 422)
        self.assertEqual(self.client.get(f"/api/history/{uuid4()}").status_code, 404)
        self.assertEqual(self.client.get("/api/history?limit=0").status_code, 422)

    def test_all_existing_scans_keep_data_and_archive_results(self):
        now = datetime.now(timezone.utc)
        device = Host(**host(), scan_time=now)
        topology = NetworkTopology("original-id", "127.0.0.1", 1, 1, [device], now, now, 0.0)
        wireless = WirelessIoTScan([WirelessNetwork("wifi", None, 70, 1, "WPA2")], [], None, now)
        cases = [("network", "execute_network_scan", topology, {"network_range": "127.0.0.1"}),
                 ("host", "execute_host_scan", device, {"ip": "127.0.0.1"}),
                 ("discover", "discover_network_hosts", ["127.0.0.1"], {"network_range": "127.0.0.1"}),
                 ("wireless", "execute_wireless_scan", wireless, {})]
        for kind, method, result, body in cases:
            with self.subTest(kind=kind), patch.object(api.scan_service, method, return_value=result):
                reply = self.client.post(f"/api/scan/{kind}", json=body)
                self.assertEqual(reply.status_code, 200, reply.text)
                payload = reply.json()
                self.assertTrue(payload["success"])
                record = self.client.get("/api/history/" + payload["history"]["id"]).json()
                self.assertEqual(record["data"], payload["data"])
                self.assertEqual(record["kind"], kind)
                for format in ("json", "csv"):
                    export = self.client.get(f"/api/history/{record['id']}/export?format={format}")
                    self.assertEqual(export.status_code, 200)
        self.assertEqual(self.history.list()["total"], 4)

    def test_automatic_saving_writes_reports_in_configured_folder(self):
        with patch.dict(os.environ, {"ONEDRIVE_LOCAL_DIR": str(Path(self.temp.name) / "Nube"),
                                     "ONEDRIVE_AUTO_UPLOAD": "true"}):
            storage = OneDrive()
        with patch.object(history_api, "onedrive", storage), patch.object(
            api.scan_service, "discover_network_hosts", return_value=["127.0.0.1"]
        ):
            reply = self.client.post("/api/scan/discover", json={"network_range": "127.0.0.1"})
            self.assertEqual(reply.status_code, 200)
            scan_id = reply.json()["history"]["id"]
            self.assertTrue(reply.json()["history"]["upload_scheduled"])
            self.assertEqual(storage.download(scan_id)["data"], reply.json()["data"])
            self.assertIsNotNone(self.history.get(scan_id)["sync"]["synced_at"])
            self.assertEqual(len(list(storage.folder.iterdir())), 2)

    def test_cloud_failure_preserves_scan_and_manual_retry_clears_error(self):
        self.cloud.auto_upload = True
        self.cloud.upload.side_effect = OneDriveError("Sin conexión", 503)
        with self.assertLogs(history_api.logger, level="WARNING"), patch.object(
            api.scan_service, "discover_network_hosts", return_value=["127.0.0.1"]
        ):
            reply = self.client.post("/api/scan/discover", json={"network_range": "127.0.0.1"})
        self.assertEqual(reply.status_code, 200)
        scan_id = reply.json()["history"]["id"]
        self.assertEqual(self.history.get(scan_id)["sync"]["error"], "Sin conexión")
        self.cloud.upload.side_effect = None
        self.cloud.upload.return_value = {"json": "https://example/json", "csv": "https://example/csv"}
        retry = self.client.post(f"/api/onedrive/scans/{scan_id}/upload")
        self.assertEqual(retry.status_code, 200)
        self.assertIsNone(retry.json()["sync"]["error"])
        self.assertIsNotNone(retry.json()["sync"]["synced_at"])

    def test_compare_and_restore_endpoints(self):
        before = self.save()
        after = self.save([host("127.0.0.2")])
        reply = self.client.get(f"/api/history/compare?before={before['id']}&after={after['id']}")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json()["new_hosts"][0]["ip"], "127.0.0.2")
        document = json.loads(json_report(before))
        document["id"] = str(uuid4())
        self.cloud.download.return_value = document
        restored = self.client.post(f"/api/onedrive/scans/{document['id']}/restore")
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.json()["data"], before["data"])
        self.cloud.download.return_value = {**document, "data": {"hosts": None}}
        self.assertEqual(self.client.post(f"/api/onedrive/scans/{document['id']}/restore").status_code, 422)

    def test_cors_allows_existing_frontend_and_rejects_other_sites(self):
        allowed = self.client.options("/api/history", headers={
            "Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key"})
        self.assertEqual(allowed.status_code, 200)
        denied = self.client.options("/api/history", headers={
            "Origin": "https://unrelated.example", "Access-Control-Request-Method": "GET"})
        self.assertEqual(denied.status_code, 400)


if __name__ == "__main__":
    unittest.main()
