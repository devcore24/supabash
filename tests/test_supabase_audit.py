import base64
import json
import unittest

from supabash.tools.supabase_audit import SupabaseAuditScanner


def make_jwt(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        enc = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
        return enc
    return f"{b64(header)}.{b64(payload)}.signature"


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code
        self.encoding = "utf-8"
        self.closed = False

    def iter_content(self, chunk_size=1, decode_unicode=False):
        payload = self.text.encode(self.encoding)
        for offset in range(0, len(payload), chunk_size):
            yield payload[offset : offset + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.get_options = []

    def get(self, url, timeout=10, allow_redirects=True, stream=False):
        self.calls.append(("GET", url, allow_redirects))
        self.get_options.append({"url": url, "stream": stream})
        return self.responses.get(("GET", url), FakeResponse(status_code=404))

    def post(self, url, json=None, timeout=10, allow_redirects=True):
        self.calls.append(("POST", url, allow_redirects))
        return self.responses.get(("POST", url), FakeResponse(status_code=404))


class TestSupabaseAudit(unittest.TestCase):
    def test_discovered_cross_origin_backend_is_reported_but_not_probed(self):
        anon = make_jwt({"role": "anon"})
        service = make_jwt({"role": "service_role"})
        html = (
            "const supabaseUrl = 'https://abcd1234.supabase.co';"
            f"const supabaseKey = '{anon}';"
            f"const serviceRoleKey = '{service}';"
            "supabase.rpc('list_users');"
        )
        responses = {
            ("GET", "https://app.example.com"): FakeResponse(text=html, status_code=200),
            ("GET", "https://abcd1234.supabase.co/rest/v1/"): FakeResponse(text="{}", status_code=200),
            ("GET", "https://abcd1234.supabase.co/rest/v1/rpc/"): FakeResponse(text="{}", status_code=200),
            ("POST", "https://abcd1234.supabase.co/rest/v1/rpc/list_users"): FakeResponse(text="{}", status_code=200),
        }
        session = FakeSession(responses)
        scanner = SupabaseAuditScanner(session=session)
        result = scanner.scan(["https://app.example.com"], max_pages=2)
        self.assertTrue(result["success"])
        self.assertIn("https://abcd1234.supabase.co", result.get("supabase_urls", []))
        key_types = {k.get("type") for k in result.get("keys", [])}
        self.assertIn("anon", key_types)
        self.assertIn("service_role", key_types)
        exposure_types = {e.get("type") for e in result.get("exposures", [])}
        self.assertNotIn("rest_root_reachable", exposure_types)
        self.assertNotIn("rpc_root_reachable", exposure_types)
        self.assertNotIn("rls_misconfig", exposure_types)
        self.assertNotIn("rpc_public", exposure_types)
        self.assertEqual(result.get("rpc_probe_mode"), "read_only")
        self.assertEqual(result.get("probed_supabase_urls"), [])
        self.assertFalse(any(method == "POST" for method, _url, _redirects in session.calls))
        self.assertTrue(all(not redirects for _method, _url, redirects in session.calls))
        self.assertTrue(all(item["stream"] for item in session.get_options))
        self.assertFalse(
            any("abcd1234.supabase.co/rest/" in url for _method, url, _redirects in session.calls)
        )

    def test_explicit_backend_override_gets_read_only_root_probes(self):
        html = "supabase.rpc('list_users'); const supabaseUrl = 'https://abcd1234.supabase.co';"
        responses = {
            ("GET", "https://app.example.com"): FakeResponse(text=html, status_code=200),
            ("GET", "https://abcd1234.supabase.co/rest/v1/"): FakeResponse(text="{}", status_code=200),
            ("GET", "https://abcd1234.supabase.co/rest/v1/rpc/"): FakeResponse(text="{}", status_code=200),
        }
        session = FakeSession(responses)
        scanner = SupabaseAuditScanner(session=session)

        result = scanner.scan(
            ["https://app.example.com"],
            supabase_urls_override=["https://abcd1234.supabase.co"],
        )

        exposure_types = {e.get("type") for e in result.get("exposures", [])}
        self.assertEqual(result.get("rpc_probe_mode"), "read_only")
        self.assertEqual(
            result.get("probed_supabase_urls"), ["https://abcd1234.supabase.co"]
        )
        self.assertIn("rest_root_reachable", exposure_types)
        self.assertIn("rpc_root_reachable", exposure_types)
        self.assertNotIn("rpc_public", exposure_types)
        self.assertFalse(any(method == "POST" for method, _url, _redirects in session.calls))
        self.assertTrue(all(not redirects for _method, _url, redirects in session.calls))

    def test_embedded_or_lookalike_supabase_url_is_never_authorized_for_probing(self):
        targets = [
            "https://app.example.com/?next=https://victim1.supabase.co",
            "https://victim2.supabase.co.evil.example/path",
        ]
        session = FakeSession(
            {
                ("GET", targets[0]): FakeResponse(text="ok", status_code=200),
                ("GET", targets[1]): FakeResponse(text="ok", status_code=200),
            }
        )
        scanner = SupabaseAuditScanner(session=session)

        result = scanner.scan(targets, max_pages=2)

        self.assertEqual(result.get("probed_supabase_urls"), [])
        self.assertEqual(result.get("exposures"), [])
        self.assertFalse(any("/rest/v1/" in url for _method, url, _redirects in session.calls))

    def test_direct_supabase_target_uses_only_its_canonical_origin(self):
        target = "https://abcd1234.supabase.co/some/path?next=https://other123.supabase.co"
        session = FakeSession(
            {
                ("GET", target): FakeResponse(text="ok", status_code=200),
                ("GET", "https://abcd1234.supabase.co/rest/v1/"): FakeResponse(
                    text="{}", status_code=200
                ),
                ("GET", "https://abcd1234.supabase.co/rest/v1/rpc/"): FakeResponse(
                    text="{}", status_code=200
                ),
            }
        )
        scanner = SupabaseAuditScanner(session=session)

        result = scanner.scan([target])

        self.assertEqual(
            result.get("probed_supabase_urls"), ["https://abcd1234.supabase.co"]
        )
        self.assertNotIn("https://other123.supabase.co", result.get("probed_supabase_urls", []))

    def test_max_pages_caps_network_requests(self):
        responses = {
            ("GET", "https://one.example.com"): FakeResponse(text="hello", status_code=200),
            ("GET", "https://two.example.com"): FakeResponse(text="world", status_code=200),
        }
        scanner = SupabaseAuditScanner(session=FakeSession(responses))
        result = scanner.scan(["https://one.example.com", "https://two.example.com"], max_pages=1)
        self.assertTrue(result["success"])
        self.assertEqual(
            result.get("scanned"),
            ["https://one.example.com"],
        )

    def test_max_pages_has_a_hard_upper_bound(self):
        targets = [f"https://site-{index}.example.com" for index in range(100)]
        scanner = SupabaseAuditScanner(session=FakeSession({}))

        result = scanner.scan(targets, max_pages=10_000)

        self.assertEqual(result["requests_made"], scanner.MAX_PAGE_REQUESTS)
        self.assertEqual(len(result["page_hits"]), scanner.MAX_PAGE_REQUESTS)
        self.assertEqual(result["request_limits"]["total_requests"], scanner.MAX_TOTAL_REQUESTS)

    def test_page_response_body_is_streamed_and_bounded(self):
        class GuardedLargeResponse(FakeResponse):
            def __init__(self):
                super().__init__(status_code=200)
                self.chunks_yielded = 0

            def iter_content(self, chunk_size=1, decode_unicode=False):
                while True:
                    self.chunks_yielded += 1
                    if self.chunks_yielded > 40:
                        raise AssertionError("response body was not bounded")
                    yield b"x" * chunk_size

        response = GuardedLargeResponse()
        session = FakeSession({("GET", "https://app.example.com"): response})
        scanner = SupabaseAuditScanner(session=session)

        result = scanner.scan(["https://app.example.com"])

        self.assertTrue(result["success"])
        self.assertLessEqual(response.chunks_yielded, 32)
        self.assertTrue(response.closed)
        self.assertTrue(session.get_options[0]["stream"])


if __name__ == "__main__":
    unittest.main()
