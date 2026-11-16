import csv
import errno
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scan_ips import main, scan_ip


class ScanTests(unittest.TestCase):
    def test_classification(self):
        cases = [
            (None, None, "in_use"),
            (ConnectionRefusedError(), None, "in_use"),
            (socket.timeout(), None, "possibly_free"),
            (socket.timeout(), "host.example", "dns_only"),
            (OSError(errno.ENETUNREACH, "unreachable"), None, "unknown"),
        ]
        for error, name, expected in cases:
            with self.subTest(expected=expected, error=error):
                with patch("scan_ips.socket.create_connection", side_effect=error) as connect:
                    with patch("scan_ips.socket.gethostbyaddr") as dns:
                        if name:
                            dns.return_value = (name, [], ["192.0.2.1"])
                        else:
                            dns.side_effect = socket.herror(1, "no PTR")
                        row = scan_ip("192.0.2.1", [22], 1)
                self.assertEqual(row["status"], expected)
                self.assertEqual(row["reverse_dns"], name or "")
                connect.assert_called_once_with(("192.0.2.1", 22), timeout=1)

    def test_mixed_ports_and_dns_failure(self):
        with patch("scan_ips.socket.create_connection", side_effect=[socket.timeout(), ConnectionRefusedError()]):
            with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(2, "temporary failure")):
                row = scan_ip("192.0.2.1", [22, 443], 1)
        self.assertEqual(row["status"], "in_use")
        self.assertEqual(row["tcp_refused"], "443")
        self.assertEqual(row["tcp_timeout"], "22")
        self.assertIn("DNS:", row["errors"])

    def test_csv_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ips.csv"
            with patch("scan_ips.socket.create_connection", side_effect=ConnectionRefusedError()):
                with patch("scan_ips.socket.gethostbyaddr", return_value=("host,example", [], [])):
                    self.assertEqual(main(["192.0.2.0/30", "-o", str(output)]), 0)
            before = output.read_bytes()
            with output.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([r["ip"] for r in rows], ["192.0.2.1", "192.0.2.2"])
            self.assertEqual(rows[0]["reverse_dns"], "host,example")
            self.assertEqual(main(["192.0.2.0/30", "-o", str(output)]), 1)
            self.assertEqual(output.read_bytes(), before)

    def test_real_local_tcp_connection(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                row = scan_ip("127.0.0.1", [listener.getsockname()[1]], 1)
        self.assertEqual(row["status"], "in_use")
        self.assertTrue(row["tcp_open"])


if __name__ == "__main__":
    unittest.main()
