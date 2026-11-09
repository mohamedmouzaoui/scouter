import unittest

from scouter.recommendations import advise, prioritised
from scouter.scanner import Service


class AdviceTests(unittest.TestCase):
    def test_ssh_rule_formats_port_and_host(self):
        advice = advise(Service(port=2222, name="ssh"), "10.0.0.5")
        self.assertEqual(advice[0].rule.key, "ssh")
        self.assertTrue(any("-p 2222" in c and "10.0.0.5" in c for c in advice[0].checks))

    def test_https_gets_web_and_tls_rules_with_https_scheme(self):
        advice = advise(Service(port=443, name="https"), "example.com")
        keys = [a.rule.key for a in advice]
        self.assertIn("http", keys)
        self.assertIn("tls", keys)
        web = next(a for a in advice if a.rule.key == "http")
        self.assertTrue(any("https://example.com:443/" in c for c in web.checks))

    def test_plain_http_uses_http_scheme_and_mentions_single_js(self):
        web = advise(Service(port=8080, name="http-proxy"), "h")[0]
        self.assertTrue(any("http://h:8080/" in c for c in web.checks))
        self.assertTrue(any("Single_JS" in c for c in web.checks))

    def test_unknown_falls_back(self):
        advice = advise(Service(port=65000, name="unknown"), "h")
        self.assertEqual(advice[0].rule.key, "unknown")

    def test_priority_order(self):
        services = [Service(port=22, name="ssh"), Service(port=21, name="ftp"), Service(port=65000)]
        order = [a.rule.key for a in prioritised(services, "h")]
        self.assertEqual(order[0], "ftp")       # priority 1 first
        self.assertEqual(order[-1], "unknown")  # priority 3 last


if __name__ == "__main__":
    unittest.main()
