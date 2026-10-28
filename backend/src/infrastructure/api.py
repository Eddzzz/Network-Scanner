from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi import BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from dataclasses import asdict
import sys
import os

# Agregar el directorio src al path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from application.services import NetworkScanService
from infrastructure.nmap_adapter import NmapAdapter
from infrastructure.history_api import archive_scan, router as history_router

app = FastAPI(title="Network Scanner API", version="1.0.0")
app.include_router(history_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

nmap_adapter = NmapAdapter()
scan_service = NetworkScanService(nmap_adapter)

class ScanRequest(BaseModel):
    network_range: str
    scan_type: Optional[str] = "quick"

class HostScanRequest(BaseModel):
    ip: str

class WirelessScanRequest(BaseModel):
    network_range: Optional[str] = None

@app.get("/")
def root():
    return {
        "message": "Network Scanner API",
        "version": "1.0.0",
        "endpoints": {
            "scan_network": "/api/scan/network",
            "scan_host": "/api/scan/host",
            "discover": "/api/scan/discover",
            "wireless_scan": "/api/scan/wireless"
        }
    }

@app.post("/api/scan/network")
def scan_network(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        scan_type = request.scan_type or "quick"
        result = scan_service.execute_network_scan(request.network_range, scan_type)
        
        response = {
            "success": True,
            "data": {
                "scan_id": result.scan_id,
                "network_range": result.network_range,
                "total_hosts": result.total_hosts,
                "active_hosts": result.active_hosts,
                "duration": result.duration,
                "scan_start": result.scan_start.isoformat(),
                "scan_end": result.scan_end.isoformat(),
                "hosts": [
                    {
                        "ip": h.ip,
                        "hostname": h.hostname,
                        "state": h.state,
                        "mac_address": h.mac_address,
                        "vendor": h.vendor,
                        "os": h.os,
                        "ports": [
                            {
                                "number": p.number,
                                "protocol": p.protocol,
                                "state": p.state,
                                "service": p.service,
                                "version": p.version
                            }
                            for p in h.ports
                        ]
                    }
                    for h in result.hosts
                ]
            }
        }
        return archive_scan(response, "network", request.network_range, background_tasks)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/host")
def scan_host(request: HostScanRequest, background_tasks: BackgroundTasks):
    try:
        result = scan_service.execute_host_scan(request.ip)
        
        response = {
            "success": True,
            "data": {
                "ip": result.ip,
                "hostname": result.hostname,
                "state": result.state,
                "mac_address": result.mac_address,
                "vendor": result.vendor,
                "os": result.os,
                "ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version
                    }
                    for p in result.ports
                ]
            }
        }
        return archive_scan(response, "host", request.ip, background_tasks)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/discover")
def discover_hosts(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        hosts = scan_service.discover_network_hosts(request.network_range)
        
        response = {
            "success": True,
            "data": {
                "network_range": request.network_range,
                "total_hosts": len(hosts),
                "hosts": hosts
            }
        }
        return archive_scan(response, "discover", request.network_range, background_tasks)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/wireless")
def scan_wireless(request: WirelessScanRequest, background_tasks: BackgroundTasks):
    try:
        result = scan_service.execute_wireless_scan(request.network_range)

        response = {
            "success": True,
            "data": {
                "network_range": result.network_range,
                "scanned_at": result.scanned_at.isoformat(),
                "wireless_networks": [asdict(net) for net in result.wireless_networks],
                "iot_devices": [
                    {
                        "ip": dev.ip,
                        "hostname": dev.hostname,
                        "vendor": dev.vendor,
                        "os": dev.os,
                        "confidence": dev.confidence,
                        "notes": dev.notes,
                        "ports": [
                            {
                                "number": port.number,
                                "protocol": port.protocol,
                                "service": port.service,
                                "version": port.version,
                                "state": port.state
                            }
                            for port in dev.ports
                        ]
                    }
                    for dev in result.iot_devices
                ]
            }
        }
        return archive_scan(response, "wireless", request.network_range or "192.168.1.0/24", background_tasks)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

