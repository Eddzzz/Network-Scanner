"""Durable scan history and portable JSON/CSV reports."""

import csv
import io
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict


class ScanRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    id: UUID
    kind: Literal["network", "host", "discover", "wireless"]
    target: str
    created_at: datetime
    data: dict


def hosts(record):
    data, kind = record["data"], record["kind"]
    if kind == "host":
        items = [data]
    elif kind == "discover":
        items = [{"ip": ip, "state": "up", "ports": []} for ip in data["hosts"]]
    else:
        items = data["iot_devices" if kind == "wireless" else "hosts"]
    if not isinstance(items, list) or any(
        not isinstance(h, dict) or not isinstance(h.get("ip"), str)
        or not isinstance(h.get("ports", []), list)
        or any(not isinstance(p, dict) or not isinstance(p.get("number"), int)
               or not isinstance(p.get("protocol"), str) for p in h.get("ports", []))
        for h in items
    ):
        raise ValueError("El archivo contiene dispositivos o puertos inválidos")
    return {h["ip"]: h for h in items}


def portable(record):
    return {key: record[key] for key in ScanRecord.model_fields}


def json_report(record):
    return json.dumps(portable(record), ensure_ascii=False, indent=2).encode("utf-8")


def csv_report(record):
    output = io.StringIO(newline="")
    fields = ["scan_id", "created_at", "kind", "target", "ip", "hostname", "state",
              "mac_address", "vendor", "os", "port", "protocol", "port_state",
              "service", "version", "ssid", "bssid", "signal", "channel", "security"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    base = {"scan_id": record["id"], "created_at": record["created_at"],
            "kind": record["kind"], "target": record["target"]}

    def write(values):
        # Excel must treat network-controlled names as text, never as formulas.
        writer.writerow({k: "'" + v if isinstance(v, str) and
                         v.lstrip().startswith(("=", "+", "-", "@")) else v
                         for k, v in values.items()})

    for host in hosts(record).values():
        row = {**base, **{k: host.get(k) for k in
               ("ip", "hostname", "state", "mac_address", "vendor", "os")}}
        for port in host.get("ports", []) or [None]:
            values = {} if port is None else {
                "port": port["number"], "protocol": port["protocol"],
                "port_state": port.get("state"), "service": port.get("service"),
                "version": port.get("version")}
            write({**row, **values})
    for network in record["data"].get("wireless_networks", []):
        write({**base, **{k: network.get(k) for k in
               ("ssid", "bssid", "signal", "channel", "security")}})
    return ("\ufeff" + output.getvalue()).encode("utf-8")


def compare_scans(before, after):
    if before["kind"] != after["kind"] or before["target"] != after["target"]:
        raise ValueError("Compara escaneos del mismo tipo y objetivo")
    old, new = hosts(before), hosts(after)
    changed = []
    for ip in sorted(old.keys() & new.keys()):
        changes = {}
        for field in ("hostname", "state", "mac_address", "vendor", "os"):
            if old[ip].get(field) != new[ip].get(field):
                changes[field] = {"before": old[ip].get(field), "after": new[ip].get(field)}
        old_ports = {(p["protocol"], p["number"]): p for p in old[ip].get("ports", [])}
        new_ports = {(p["protocol"], p["number"]): p for p in new[ip].get("ports", [])}
        ports = {
            "added": [new_ports[p] for p in sorted(new_ports.keys() - old_ports.keys())],
            "removed": [old_ports[p] for p in sorted(old_ports.keys() - new_ports.keys())],
            "changed": [{"before": old_ports[p], "after": new_ports[p]}
                        for p in sorted(old_ports.keys() & new_ports.keys())
                        if old_ports[p] != new_ports[p]],
        }
        if changes or any(ports.values()):
            changed.append({"ip": ip, "fields": changes, "ports": ports})
    return {"before_id": before["id"], "after_id": after["id"],
            "new_hosts": [new[ip] for ip in sorted(new.keys() - old.keys())],
            "missing_hosts": [old[ip] for ip in sorted(old.keys() - new.keys())],
            "changed_hosts": changed}


class ScanHistory:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
                created_at TEXT NOT NULL, payload TEXT NOT NULL,
                synced_at TEXT, sync_error TEXT, remote_urls TEXT NOT NULL DEFAULT '{}'
            )""")

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path, timeout=15)) as db:
            db.row_factory = sqlite3.Row
            with db:
                yield db

    def save(self, kind, target, data):
        record = ScanRecord(id=uuid4(), kind=kind, target=target,
                            created_at=datetime.now(timezone.utc), data=data)
        return self.restore(record.model_dump(mode="json"))

    def restore(self, document):
        record = ScanRecord.model_validate(document).model_dump(mode="json")
        hosts(record)
        networks = record["data"].get("wireless_networks", [])
        if not isinstance(networks, list) or any(not isinstance(n, dict) for n in networks):
            raise ValueError("El archivo contiene redes inalámbricas inválidas")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT payload FROM scans WHERE id = ?", (record["id"],)).fetchone()
            if existing and json.loads(existing["payload"]) != record:
                raise ValueError("El identificador ya existe con otro contenido")
            db.execute("INSERT OR IGNORE INTO scans (id,kind,target,created_at,payload) VALUES (?,?,?,?,?)",
                       (record["id"], record["kind"], record["target"], record["created_at"],
                        json.dumps(record, ensure_ascii=False)))
        return self.get(record["id"])

    def get(self, scan_id):
        scan_id = str(UUID(str(scan_id)))
        with self.connect() as db:
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError(scan_id)
        return {**json.loads(row["payload"]), "sync": {
            "synced_at": row["synced_at"], "error": row["sync_error"],
            "remote_urls": json.loads(row["remote_urls"])}}

    def list(self, limit=50, offset=0):
        with self.connect() as db:
            rows = db.execute("""SELECT id,kind,target,created_at,synced_at,sync_error
                                 FROM scans ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?""",
                              (limit, offset)).fetchall()
            total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        return {"total": total, "items": [dict(row) for row in rows]}

    def mark_sync(self, scan_id, urls=None, error=None):
        with self.connect() as db:
            if error is not None:
                db.execute("UPDATE scans SET sync_error = ? WHERE id = ?", (error, str(scan_id)))
            else:
                db.execute("UPDATE scans SET synced_at = ?, sync_error = NULL, remote_urls = ? WHERE id = ?",
                           (datetime.now(timezone.utc).isoformat(), json.dumps(urls), str(scan_id)))
