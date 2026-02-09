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


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, timeout=10):
        return self.responses.get(("GET", url), FakeResponse(status_code=404))

    def post(self, url, json=None, timeout=10):
        return self.responses.get(("POST", url), FakeResponse(status_code=404))


class TestSupabaseAudit(unittest.TestCase):
    def test_detects_supabase_urls_keys_and_rpc_exposure(self):
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
        scanner = SupabaseAuditScanner(session=FakeSession(responses))
        result = scanner.scan(["https://app.example.com"], max_pages=2)
        self.assertTrue(result["success"])
        self.assertIn("https://abcd1234.supabase.co", result.get("supabase_urls", []))
        key_types = {k.get("type") for k in result.get("keys", [])}
        self.assertIn("anon", key_types)
        self.assertIn("service_role", key_types)
        exposure_types = {e.get("type") for e in result.get("exposures", [])}
        self.assertIn("rest_api_public", exposure_types)
        self.assertIn("rpc_root_public", exposure_types)
        self.assertIn("rpc_public", exposure_types)

    def test_scans_all_targets_even_when_content_parse_is_capped(self):
        responses = {
            ("GET", "https://one.example.com"): FakeResponse(text="hello", status_code=200),
            ("GET", "https://two.example.com"): FakeResponse(text="world", status_code=200),
        }
        scanner = SupabaseAuditScanner(session=FakeSession(responses))
        result = scanner.scan(["https://one.example.com", "https://two.example.com"], max_pages=1)
        self.assertTrue(result["success"])
        self.assertEqual(
            result.get("scanned"),
            ["https://one.example.com", "https://two.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
