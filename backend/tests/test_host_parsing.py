import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from infrastructure.nmap_adapter import NmapAdapter


class HostParsingTests(unittest.TestCase):
    def test_reads_nmap_status_state(self):
        adapter = NmapAdapter.__new__(NmapAdapter)
        adapter.scanner = MagicMock()
        adapter.scanner.all_hosts.return_value = ['127.0.0.1']
        adapter.scanner.__getitem__.return_value = {
            'status': {'state': 'up'},
            'addresses': {'ipv4': '127.0.0.1'},
            'hostnames': [],
        }
        self.assertEqual(adapter._parse_host('127.0.0.1').state, 'up')


if __name__ == '__main__':
    unittest.main()
