import logging
import os
import secrets
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Security
from fastapi.responses import Response
from fastapi.security import APIKeyHeader

from infrastructure.onedrive import DATA_DIR, OneDrive, OneDriveError
from infrastructure.scan_history import ScanHistory, compare_scans, csv_report, json_report

logger = logging.getLogger(__name__)
history = ScanHistory(DATA_DIR / "scans.sqlite3")
onedrive = OneDrive()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_key(key: str | None = Security(api_key_header)):
    expected = os.getenv("SCANNER_API_KEY", "")
    if not expected:
        raise HTTPException(503, "Configura SCANNER_API_KEY en backend/.env para acceder al historial")
    if not key or not secrets.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(401, "X-API-Key inválida o ausente")


router = APIRouter(prefix="/api", tags=["Historial y OneDrive"], dependencies=[Depends(require_key)])


def find(scan_id):
    try:
        return history.get(scan_id)
    except KeyError:
        raise HTTPException(404, "Escaneo no encontrado")


def upload_scan(scan_id):
    record = find(scan_id)
    try:
        urls = onedrive.upload(record)
        history.mark_sync(scan_id, urls=urls)
    except OneDriveError as exc:
        history.mark_sync(scan_id, error=str(exc))
        raise HTTPException(exc.status_code, str(exc)) from exc
    return history.get(scan_id)


def auto_upload(scan_id):
    try:
        upload_scan(scan_id)
    except HTTPException as exc:
        logger.warning("No se pudo sincronizar el escaneo %s: %s", scan_id, exc.detail)
    except Exception:
        history.mark_sync(scan_id, error="Error inesperado al sincronizar; revisa el registro del servidor")
        logger.exception("No se pudo sincronizar el escaneo %s con OneDrive", scan_id)


def archive_scan(response, kind, target, tasks: BackgroundTasks):
    record = history.save(kind, target, response["data"])
    response["history"] = {"id": record["id"], "saved_locally": True,
                           "upload_scheduled": onedrive.auto_upload}
    if onedrive.auto_upload:
        tasks.add_task(auto_upload, record["id"])
    return response


@router.get("/history")
def list_history(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return history.list(limit, offset)


@router.get("/history/compare")
def compare(before: UUID, after: UUID):
    try:
        return compare_scans(find(before), find(after))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/history/{scan_id}")
def get_history(scan_id: UUID):
    return find(scan_id)


@router.get("/history/{scan_id}/export")
def export_history(scan_id: UUID, format: Literal["json", "csv"] = "json"):
    record = find(scan_id)
    content = json_report(record) if format == "json" else csv_report(record)
    return Response(content, media_type="application/json" if format == "json" else "text/csv",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.{format}"'})


@router.get("/onedrive/status")
def onedrive_status():
    return onedrive.status()


@router.post("/onedrive/scans/{scan_id}/upload")
def upload_history(scan_id: UUID):
    return upload_scan(scan_id)


@router.get("/onedrive/files")
def list_cloud_history():
    try:
        return {"items": onedrive.files()}
    except OneDriveError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


@router.post("/onedrive/scans/{scan_id}/restore")
def restore_history(scan_id: UUID):
    try:
        return history.restore(onedrive.download(scan_id))
    except OneDriveError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, "Reporte inválido o en conflicto con el historial local") from exc
