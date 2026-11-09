import unittest

from scouter.scope import Scope, ScopeError, parse_rule, validate_target


class ParseTests(unittest.TestCase):
    def test_rule_kinds(self):
        self.assertEqual(parse_rule("10.0.0.5").kind, "ip")
        self.assertEqual(parse_rule("10.0.0.0/24").kind, "cidr")
        self.assertEqual(parse_rule("Lab.Example.com").kind, "host")
        self.assertEqual(parse_rule("*.example.com").kind, "wildcard")

    def test_invalid_rules(self):
        for bad in ("", "-oN", "bad host", "*.", "http://example.com"):
            with self.assertRaises(ScopeError):
                parse_rule(bad)

    def test_target_cannot_look_like_an_option(self):
        with self.assertRaises(ScopeError):
            validate_target("-oN/tmp/x")
        self.assertEqual(validate_target("Example.COM."), "example.com")


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope.from_lines([
            "# comment",
            "10.0.0.0/29   # lab",
            "lab.example.com",
            "*.test.example.com",
            "!10.0.0.3",
        ])

    def test_allows(self):
        self.assertTrue(self.scope.allows("10.0.0.2"))
        self.assertTrue(self.scope.allows("lab.example.com"))
        self.assertTrue(self.scope.allows("api.test.example.com"))
        self.assertFalse(self.scope.allows("test.example.com"))  # wildcard is subdomains only
        self.assertFalse(self.scope.allows("10.0.1.2"))
        self.assertFalse(self.scope.allows("evil.example.com"))

    def test_exclusion_wins(self):
        self.assertFalse(self.scope.allows("10.0.0.3"))
        # a hostname that resolves into an excluded IP is refused too
        self.assertFalse(self.scope.allows("lab.example.com", ip="10.0.0.3"))

    def test_resolved_ip_can_match_cidr(self):
        self.assertTrue(self.scope.allows("other-name.example.net", ip="10.0.0.4"))

    def test_expand(self):
        hosts = self.scope.expand()
        self.assertIn("10.0.0.1", hosts)
        self.assertIn("lab.example.com", hosts)
        self.assertNotIn("10.0.0.3", hosts)
        self.assertEqual(self.scope.wildcards, ["*.test.example.com"])

    def test_expand_limit(self):
        big = Scope.from_lines(["10.0.0.0/16"])
        with self.assertRaises(ScopeError):
            big.expand(max_hosts=256)

    def test_empty_scope_rejected(self):
        with self.assertRaises(ScopeError):
            Scope.from_lines(["# nothing", "!10.0.0.1"])

    def test_error_mentions_line_number(self):
        with self.assertRaises(ScopeError) as ctx:
            Scope.from_lines(["10.0.0.1", "not valid!"])
        self.assertIn("line 2", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
