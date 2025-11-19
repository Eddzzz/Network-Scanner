from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None

@dataclass
class Host:
    ip: str
    hostname: Optional[str]
    state: str
    mac_address: Optional[str]
    vendor: Optional[str]
    os: Optional[str]
    ports: List[Port]
    scan_time: datetime

@dataclass
class NetworkTopology:
    scan_id: str
    network_range: str
    total_hosts: int
    active_hosts: int
    hosts: List[Host]
    scan_start: datetime
    scan_end: datetime
    duration: float

@dataclass
class WirelessNetwork:
    ssid: str
    bssid: Optional[str]
    signal: Optional[int]
    channel: Optional[int]
    security: Optional[str]

@dataclass
class IoTDevice:
    ip: str
    hostname: Optional[str]
    vendor: Optional[str]
    os: Optional[str]
    ports: List[Port]
    confidence: float
    notes: Optional[str] = None

@dataclass
class WirelessIoTScan:
    wireless_networks: List[WirelessNetwork]
    iot_devices: List[IoTDevice]
    network_range: Optional[str]
    scanned_at: datetime
