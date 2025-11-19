from abc import ABC, abstractmethod
from typing import List, Optional
from .models import Host, NetworkTopology, WirelessIoTScan

class NetworkScannerPort(ABC):
    @abstractmethod
    def scan_network(self, network_range: str, scan_type: str = "quick") -> NetworkTopology:
        pass
    
    @abstractmethod
    def scan_host(self, ip: str) -> Host:
        pass
    
    @abstractmethod
    def discover_hosts(self, network_range: str) -> List[str]:
        pass

    @abstractmethod
    def scan_wireless_iot(self, network_range: Optional[str] = None) -> WirelessIoTScan:
        pass
