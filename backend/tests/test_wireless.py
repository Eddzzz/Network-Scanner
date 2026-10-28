import unittest
from unittest.mock import patch
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from infrastructure.nmap_adapter import NmapAdapter


class WirelessPermissionTests(unittest.TestCase):
    @patch('infrastructure.nmap_adapter.platform.system', return_value='Windows')
    @patch('infrastructure.nmap_adapter.subprocess.run')
    def test_location_permission_failure_is_reported(self, run, _system):
        run.return_value.stdout = 'Los comandos de shell de red necesitan permiso de ubicación para acceder a la información de WLAN.'
        run.return_value.returncode = 1
        scanner = NmapAdapter.__new__(NmapAdapter)
        with self.assertRaisesRegex(RuntimeError, 'ubicación'):
            scanner._scan_wireless_networks()


if __name__ == '__main__':
    unittest.main()
