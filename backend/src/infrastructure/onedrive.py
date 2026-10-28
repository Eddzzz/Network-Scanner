"""Report storage in the local folder synchronized by OneDrive for Windows."""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv

from infrastructure.scan_history import csv_report, json_report

BACKEND_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_DIR / ".env")
DATA_DIR = Path(os.getenv("SCANNER_DATA_DIR", str(BACKEND_DIR / "data"))).resolve()
MAX_REPORT_BYTES = 10 * 1024 * 1024


class OneDriveError(Exception):
    def __init__(self, message, status_code=503):
        super().__init__(message)
        self.status_code = status_code


class OneDrive:
    def __init__(self):
        default = Path(os.getenv("OneDrive", str(Path.home() / "OneDrive"))) / "Nube"
        self.folder = Path(os.getenv("ONEDRIVE_LOCAL_DIR", str(default))).expanduser().resolve()
        self.auto_upload = os.getenv("ONEDRIVE_AUTO_UPLOAD", "true").lower() == "true"

    def prepare(self):
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OneDriveError("No se puede acceder a la carpeta local de OneDrive") from exc

    def status(self):
        result = {"mode": "local", "folder": str(self.folder), "configured": True,
                  "auto_upload": self.auto_upload, "connected": False,
                  "cloud_sync_verified": False}
        try:
            self.prepare()
            with tempfile.TemporaryFile(dir=self.folder) as probe:
                probe.write(b"Network Scanner")
                probe.flush()
            result["connected"] = True
        except (OneDriveError, OSError):
            result["message"] = "La carpeta local no está disponible para escritura"
        return result

    def upload(self, record):
        reports = {"json": json_report(record), "csv": csv_report(record)}
        if any(len(content) > MAX_REPORT_BYTES for content in reports.values()):
            raise OneDriveError("El reporte supera el límite local de 10 MB", 413)
        scan_id = UUID(str(record["id"]))
        self.prepare()
        paths = {}
        for extension, content in reports.items():
            destination = self.folder / f"scan-{scan_id}.{extension}"
            temporary = None
            try:
                # Replace complete files only, so readers never see partial JSON/CSV.
                with tempfile.NamedTemporaryFile(dir=self.folder, prefix=".scanner-", suffix=".tmp", delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
                paths[extension] = str(destination)
            except OSError as exc:
                raise OneDriveError("No se pudo guardar el reporte en la carpeta local de OneDrive; el historial se conserva") from exc
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        return paths

    def files(self):
        self.prepare()
        items = []
        try:
            for path in sorted(self.folder.glob("scan-*.json")):
                if path.is_symlink() or not path.is_file() or path.resolve().parent != self.folder:
                    continue
                try:
                    scan_id = str(UUID(path.stem.removeprefix("scan-")))
                except ValueError:
                    continue
                stat = path.stat()
                items.append({"id": scan_id, "name": path.name, "path": str(path),
                              "size": stat.st_size,
                              "lastModifiedDateTime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()})
        except OSError as exc:
            raise OneDriveError("No se pudieron listar los reportes de la carpeta local") from exc
        return items

    def download(self, scan_id):
        scan_id = str(UUID(str(scan_id)))
        path = self.folder / f"scan-{scan_id}.json"
        try:
            if path.is_symlink() or path.resolve().parent != self.folder:
                raise OneDriveError("El reporte debe estar dentro de la carpeta configurada", 422)
            with path.open("rb") as stream:
                content = stream.read(MAX_REPORT_BYTES + 1)
            if len(content) > MAX_REPORT_BYTES:
                raise OneDriveError("El reporte supera el límite local de 10 MB", 413)
            document = json.loads(content.decode("utf-8-sig"))
        except FileNotFoundError as exc:
            raise OneDriveError("El reporte no existe en la carpeta local", 404) from exc
        except (ValueError, UnicodeError) as exc:
            raise OneDriveError("El archivo no es un reporte JSON válido", 422) from exc
        except OSError as exc:
            raise OneDriveError("No se pudo leer el reporte de la carpeta local") from exc
        if not isinstance(document, dict) or document.get("id") != scan_id:
            raise OneDriveError("El identificador del reporte no coincide", 422)
        return document
