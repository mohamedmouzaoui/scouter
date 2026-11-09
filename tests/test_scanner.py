import time
import unittest

from scouter import scanner
from tests.helpers import fake_service, free_port

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="protocol 2.0"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host></nmaprun>"""


class PortSpecTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(scanner.parse_ports("80,22,8000-8002"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(scanner.parse_ports("top"), scanner.DEFAULT_PORTS)
        self.assertEqual(len(scanner.parse_ports("all")), 65535)

    def test_parse_rejects_bad_input(self):
        for bad in ("", "abc", "0", "70000", "90-80", "22,,x"):
            with self.assertRaises(ValueError):
                scanner.parse_ports(bad)

    def test_compress(self):
        self.assertEqual(scanner.ports_to_spec([22, 80, 81, 82, 443]), "22,80-82,443")


class IdentifyTests(unittest.TestCase):
    def test_ssh(self):
        self.assertEqual(scanner.identify(2222, "SSH-2.0-OpenSSH_9.6"), ("ssh", "OpenSSH", "9.6"))

    def test_http_server_header(self):
        banner = "HTTP/1.1 200 OK\nServer: nginx/1.24.0 (Ubuntu)\nContent-Type: text/html"
        self.assertEqual(scanner.identify(8080, banner), ("http", "nginx", "1.24.0"))

    def test_ftp_smtp_and_fallbacks(self):
        self.assertEqual(scanner.identify(2121, "220 ProFTPD Server (FTP)")[0], "ftp")
        self.assertEqual(scanner.identify(2525, "220 mail ESMTP Postfix")[0], "smtp")
        self.assertEqual(scanner.identify(3306, "")[0], "mysql")
        self.assertEqual(scanner.identify(65000, "")[0], "unknown")

    def test_banner_is_cleaned(self):
        self.assertEqual(scanner.clean_banner(b"SSH-2.0-x\x00\x07\r\n"), "SSH-2.0-x")


class SocketScanTests(unittest.TestCase):
    def test_finds_open_port_and_banner(self):
        with fake_service(b"SSH-2.0-OpenSSH_9.6\r\n") as port:
            found = scanner.scan_socket("127.0.0.1", [port, free_port()], threads=4, timeout=1)
        self.assertEqual([s.port for s in found], [port])
        self.assertEqual(found[0].name, "ssh")
        self.assertEqual(found[0].product, "OpenSSH")

    def test_closed_ports_return_nothing(self):
        self.assertEqual(scanner.scan_socket("127.0.0.1", [free_port()], threads=2, timeout=0.5), [])


class RateLimiterTests(unittest.TestCase):
    def test_limiter_spaces_calls(self):
        limiter = scanner.RateLimiter(50)  # 20 ms apart
        start = time.monotonic()
        for _ in range(6):
            limiter.wait()
        self.assertGreaterEqual(time.monotonic() - start, 0.09)

    def test_unlimited_is_free(self):
        limiter = scanner.RateLimiter(0)
        start = time.monotonic()
        for _ in range(100):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.1)


class NmapParserTests(unittest.TestCase):
    def test_parse_open_ports_only(self):
        services = scanner.parse_nmap_xml(NMAP_XML)
        self.assertEqual([s.port for s in services], [22, 80])
        self.assertEqual(services[0].product, "OpenSSH")
        self.assertEqual(services[0].version, "9.6p1")

    def test_bad_xml(self):
        with self.assertRaises(scanner.ScanError):
            scanner.parse_nmap_xml("not xml")


if __name__ == "__main__":
    unittest.main()
