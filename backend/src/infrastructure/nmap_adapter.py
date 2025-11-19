import nmap
from datetime import datetime
import uuid
from typing import List, Optional
import subprocess
import platform
import re
from domain.ports import NetworkScannerPort
from domain.models import Host, Port, NetworkTopology, WirelessNetwork, IoTDevice, WirelessIoTScan

class NmapAdapter(NetworkScannerPort):
    IOT_VENDOR_KEYWORDS = [
        "hikvision",
        "dahua",
        "tuya",
        "tplink",
        "tp-link",
        "bosch",
        "nest",
        "arlo",
        "yeelight",
        "ring",
        "ubiquiti",
        "meraki",
        "synology",
        "sonos",
    ]
    IOT_SERVICE_KEYWORDS = ["rtsp", "ipp", "mqtt", "upnp", "printer"]
    IOT_PORTS = {23, 80, 81, 82, 37777, 554, 1883, 5683, 8883, 5353}

    def __init__(self):
        self.scanner = nmap.PortScanner()
    
    def scan_network(self, network_range: str, scan_type: str = "quick") -> NetworkTopology:
        scan_start = datetime.now()
        scan_id = str(uuid.uuid4())
        
        scan_args = {
            "quick": "-sn",
            "standard": "-sV -sC",
            "deep": "-sV -sC -O -A",
        }
        
        args = scan_args.get(scan_type, "-sn")
        
        print(f"🔍 Iniciando escaneo con argumentos: {args}")
        
        try:
            self.scanner.scan(hosts=network_range, arguments=args)
            hosts = []
            
            # Obtener todos los hosts detectados
            all_hosts = self.scanner.all_hosts()
            print(f"📊 Hosts detectados por Nmap: {len(all_hosts)}")
            
            for host_ip in all_hosts:
                try:
                    host_data = self._parse_host(host_ip)
                    if host_data:
                        hosts.append(host_data)
                        print(f"  ✓ {host_ip} - Estado: {host_data.state}")
                except Exception as e:
                    print(f"  ✗ Error parseando {host_ip}: {e}")
                    continue
            
            scan_end = datetime.now()
            duration = (scan_end - scan_start).total_seconds()
            
            # CORRECCIÓN: Contar hosts activos correctamente
            active_hosts = len([h for h in hosts if h.state == "up"])
            
            print(f"✅ Escaneo completado:")
            print(f"   - Total hosts: {len(hosts)}")
            print(f"   - Hosts activos: {active_hosts}")
            print(f"   - Duración: {duration:.2f}s")
            
            return NetworkTopology(
                scan_id=scan_id,
                network_range=network_range,
                total_hosts=len(hosts),
                active_hosts=active_hosts,  # Ahora cuenta correctamente
                hosts=hosts,
                scan_start=scan_start,
                scan_end=scan_end,
                duration=duration
            )
        except Exception as e:
            print(f"❌ Error durante el escaneo: {str(e)}")
            raise Exception(f"Error durante el escaneo: {str(e)}")
    
    def scan_host(self, ip: str) -> Host:
        try:
            print(f"🔍 Escaneando host individual: {ip}")
            self.scanner.scan(hosts=ip, arguments="-sV -sC")
            host_data = self._parse_host(ip)
            print(f"✅ Host {ip} escaneado: {len(host_data.ports)} puertos")
            return host_data
        except Exception as e:
            print(f"❌ Error escaneando host {ip}: {str(e)}")
            raise Exception(f"Error escaneando host {ip}: {str(e)}")
    
    def discover_hosts(self, network_range: str) -> List[str]:
        try:
            print(f"🔍 Descubriendo hosts en: {network_range}")
            self.scanner.scan(hosts=network_range, arguments="-sn")
            hosts = self.scanner.all_hosts()
            print(f"✅ Hosts descubiertos: {len(hosts)}")
            return hosts
        except Exception as e:
            print(f"❌ Error descubriendo hosts: {str(e)}")
            raise Exception(f"Error descubriendo hosts: {str(e)}")
    
    def scan_wireless_iot(self, network_range: Optional[str] = None) -> WirelessIoTScan:
        print("?? Iniciando escaneo de redes inalambricas e IoT")
        wireless_networks = self._scan_wireless_networks()
        iot_devices = self._scan_iot_devices(network_range or "192.168.1.0/24")
        return WirelessIoTScan(
            wireless_networks=wireless_networks,
            iot_devices=iot_devices,
            network_range=network_range,
            scanned_at=datetime.now()
        )

    def _parse_host(self, host_ip: str) -> Host:
        """
        Parsea la información de un host desde los resultados de Nmap
        """
        if host_ip not in self.scanner.all_hosts():
            raise Exception(f"Host {host_ip} no encontrado en resultados")
        
        host_info = self.scanner[host_ip]
        
        # IMPORTANTE: Obtener el estado del host
        state = host_info.get('state', {}).get('state', 'unknown')
        
        # Debug: mostrar información del host
        print(f"  Parseando {host_ip}:")
        print(f"    - Estado: {state}")
        print(f"    - Info disponible: {list(host_info.keys())}")
        
        # Obtener información de puertos
        ports = []
        if 'tcp' in host_info:
            print(f"    - Puertos TCP encontrados: {len(host_info['tcp'])}")
            for port_num, port_info in host_info['tcp'].items():
                ports.append(Port(
                    number=port_num,
                    protocol='tcp',
                    state=port_info.get('state', 'unknown'),
                    service=port_info.get('name', 'unknown'),
                    version=port_info.get('version', None)
                ))
        
        if 'udp' in host_info:
            print(f"    - Puertos UDP encontrados: {len(host_info['udp'])}")
            for port_num, port_info in host_info['udp'].items():
                ports.append(Port(
                    number=port_num,
                    protocol='udp',
                    state=port_info.get('state', 'unknown'),
                    service=port_info.get('name', 'unknown'),
                    version=port_info.get('version', None)
                ))
        
        # Obtener información de MAC y vendor
        mac_address = None
        vendor = None
        if 'addresses' in host_info:
            mac_address = host_info['addresses'].get('mac', None)
            if mac_address:
                print(f"    - MAC: {mac_address}")
        
        if 'vendor' in host_info and host_info['vendor']:
            vendor = list(host_info['vendor'].values())[0] if host_info['vendor'] else None
            if vendor:
                print(f"    - Vendor: {vendor}")
        
        # Obtener sistema operativo
        os_info = None
        if 'osmatch' in host_info and host_info['osmatch']:
            os_info = host_info['osmatch'][0].get('name', None)
            if os_info:
                print(f"    - OS: {os_info}")
        
        # Obtener hostname
        hostname = None
        if 'hostnames' in host_info and host_info['hostnames']:
            hostname = host_info['hostnames'][0].get('name', None)
            if hostname:
                print(f"    - Hostname: {hostname}")
        
        return Host(
            ip=host_ip,
            hostname=hostname,
            state=state,  # CRÍTICO: Asegurar que el estado se guarda correctamente
            mac_address=mac_address,
            vendor=vendor,
            os=os_info,
            ports=ports,
            scan_time=datetime.now()
        )
    def _scan_wireless_networks(self) -> List[WirelessNetwork]:
        system = platform.system().lower()
        networks: List[WirelessNetwork] = []
        try:
            if system == "windows":
                result = subprocess.run(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=True
                )
                networks = self._parse_netsh_networks(result.stdout)
            else:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=True
                )
                networks = self._parse_nmcli_networks(result.stdout)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as ex:
            print(f"⚠️ No se pudo ejecutar el escaneo WiFi: {ex}")
        return networks

    def _parse_netsh_networks(self, output: str) -> List[WirelessNetwork]:
        networks: List[WirelessNetwork] = []
        current: Optional[dict] = None
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if line.startswith("SSID"):
                if current:
                    networks.append(WirelessNetwork(**current))
                parts = line.split(":", 1)
                ssid = parts[1].strip() if len(parts) > 1 else "Desconocido"
                if not ssid:
                    ssid = "Oculto"
                current = {
                    "ssid": ssid,
                    "bssid": None,
                    "signal": None,
                    "channel": None,
                    "security": None
                }
            elif current and line.startswith("BSSID"):
                current["bssid"] = line.split(":", 1)[1].strip()
            elif current and line.startswith("Signal"):
                value = line.split(":", 1)[1].strip().replace("%", "")
                current["signal"] = int(value) if value.isdigit() else None
            elif current and line.startswith("Channel"):
                value = line.split(":", 1)[1].strip()
                current["channel"] = int(value) if value.isdigit() else None
            elif current and line.startswith("Authentication"):
                current["security"] = line.split(":", 1)[1].strip()
        if current:
            networks.append(WirelessNetwork(**current))
        return networks

    def _parse_nmcli_networks(self, output: str) -> List[WirelessNetwork]:
        networks: List[WirelessNetwork] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split(":")
            ssid = parts[0] or "Oculto"
            bssid = parts[1] if len(parts) > 1 else None
            signal = parts[2] if len(parts) > 2 else None
            security = parts[3] if len(parts) > 3 else None
            networks.append(
                WirelessNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    signal=int(signal) if signal and signal.isdigit() else None,
                    channel=None,
                    security=security
                )
            )
        return networks

    def _scan_iot_devices(self, network_range: str) -> List[IoTDevice]:
        try:
            print(f"📡 Explorando IoT en {network_range}")
            self.scanner.scan(
                hosts=network_range,
                arguments="-sV -O -Pn --top-ports 50"
            )
        except Exception as exc:
            print(f"⚠️ No se pudo ejecutar nmap para IoT: {exc}")
            return []

        devices: List[IoTDevice] = []
        for host_ip in self.scanner.all_hosts():
            try:
                host = self._parse_host(host_ip)
                confidence, notes = self._is_potential_iot(host)
                if confidence > 0:
                    devices.append(
                        IoTDevice(
                            ip=host.ip,
                            hostname=host.hostname,
                            vendor=host.vendor,
                            os=host.os,
                            ports=host.ports,
                            confidence=confidence,
                            notes=notes
                        )
                    )
            except Exception as exc:
                print(f"⚠️ Error evaluando host {host_ip}: {exc}")
        return devices

    def _is_potential_iot(self, host: Host) -> (float, Optional[str]):
        score = 0.0
        reasons = []
        vendor = (host.vendor or "").lower()
        hostname = (host.hostname or "").lower()

        if vendor:
            for keyword in self.IOT_VENDOR_KEYWORDS:
                if keyword in vendor:
                    score += 0.4
                    reasons.append(f"Vendor coincide con {keyword}")
                    break

        if hostname:
            for keyword in ["cam", "printer", "iot", "smart", "sensor"]:
                if keyword in hostname:
                    score += 0.2
                    reasons.append(f"Hostname contiene '{keyword}'")
                    break

        for port in host.ports:
            if port.number in self.IOT_PORTS:
                score += 0.2
                reasons.append(f"Puerto {port.number} asociado a IoT")
            if (port.service or "").lower() in self.IOT_SERVICE_KEYWORDS:
                score += 0.2
                reasons.append(f"Servicio {port.service} sospechoso")

        if host.os and "linux" in host.os.lower() and "embedded" in host.os.lower():
            score += 0.2
            reasons.append("OS reportado como embedded")

        score = min(score, 1.0)
        notes = "; ".join(reasons) if reasons else None
        return score, notes
