from domain.ports import NetworkScannerPort
from domain.models import NetworkTopology, WirelessIoTScan

class NetworkScanService:
    def __init__(self, scanner: NetworkScannerPort):
        self.scanner = scanner
    
    def execute_network_scan(self, network_range: str, scan_type: str = "quick") -> NetworkTopology:
        return self.scanner.scan_network(network_range, scan_type)
    
    def execute_host_scan(self, ip: str):
        return self.scanner.scan_host(ip)
    
    def discover_network_hosts(self, network_range: str):
        return self.scanner.discover_hosts(network_range)

    def execute_wireless_scan(self, network_range: str | None = None) -> WirelessIoTScan:
        return self.scanner.scan_wireless_iot(network_range)
