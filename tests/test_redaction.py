import unittest
import json

from supabash.redaction import (
    REDACTED,
    command_contains_unredacted_secret,
    redact_argv,
    redact_command_text,
    redact_sensitive_data,
    redact_sensitive_text,
)


class TestCommandRedaction(unittest.TestCase):
    def test_hydra_and_cme_short_secret_flags_are_redacted(self):
        hydra, changed = redact_argv(["hydra", "-l", "admin", "-p", "secret", "ssh://host"])
        self.assertTrue(changed)
        self.assertEqual(hydra[4], REDACTED)
        cme, changed = redact_argv(["netexec", "smb", "host", "-u", "admin", "-H", "deadbeef"])
        self.assertTrue(changed)
        self.assertEqual(cme[-1], REDACTED)

    def test_generic_long_inline_and_url_secrets_are_redacted(self):
        safe = redact_command_text(
            "wpscan --api-token=abc123 --url https://user:password@example.test/path"
        )
        self.assertNotIn("abc123", safe)
        self.assertNotIn("password", safe)
        self.assertGreaterEqual(safe.count(REDACTED), 2)

    def test_non_secret_port_flag_is_preserved(self):
        safe, changed = redact_argv(["nmap", "-p", "443", "localhost"])
        self.assertFalse(changed)
        self.assertEqual(safe[2], "443")

    def test_detection_ignores_already_redacted_values(self):
        self.assertTrue(command_contains_unredacted_secret("hydra -p secret ssh://host"))
        self.assertFalse(command_contains_unredacted_secret("hydra -p '<redacted>' ssh://host"))


    def test_recursive_result_redaction_removes_discovered_credentials(self):
        jwt = "eyJabcdefghijk.eyJabcdefghijk.signature"
        payload = {
            "raw_output": (
                "[22][ssh] host: 127.0.0.1 login: root password: hunter2\n"
                "[+] DOMAIN\\admin:S3cret!\n"
                f"Authorization: Bearer browser-token\nkey={jwt}"
            ),
            "found_credentials": [
                {"login": "root", "password": "hunter2"},
            ],
            "task": "Cookie: session=browser-cookie",
            "command": (
                "sqlmap -u "
                "https://example.test/items?id=1&access_token=query-secret"
            ),
        }

        safe = redact_sensitive_data(payload)
        serialized = json.dumps(safe)

        for secret in (
            "hunter2",
            "S3cret!",
            "browser-token",
            "browser-cookie",
            "query-secret",
            jwt,
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(safe["found_credentials"][0]["password"], REDACTED)
        self.assertGreaterEqual(serialized.count(REDACTED), 6)

    def test_secret_query_and_supabase_secret_text_are_redacted(self):
        safe = redact_sensitive_text(
            "https://example.test/?apikey=value&ok=1 sb_secret_abcdefghijklmnopqrstuvwxyz"
        )
        self.assertNotIn("value", safe)
        self.assertNotIn("sb_secret_", safe)
        self.assertIn("ok=1", safe)

    def test_basic_auth_and_database_url_credentials_are_redacted(self):
        safe = redact_sensitive_text(
            "Authorization: Basic dXNlcjpwYXNz "
            "postgresql://dbuser:dbpass@db.example.test/app "
            "redis://cache:cachepass@cache.example.test/0"
        )
        self.assertNotIn("dXNlcjpwYXNz", safe)
        self.assertNotIn("dbpass", safe)
        self.assertNotIn("cachepass", safe)
        self.assertGreaterEqual(safe.count(REDACTED), 3)

    def test_aws_secret_assignment_is_redacted_in_command(self):
        safe = redact_command_text(
            "tool --env AWS_SECRET_ACCESS_KEY=hunter2 --region eu-central-1"
        )
        self.assertNotIn("hunter2", safe)
        self.assertIn("AWS_SECRET_ACCESS_KEY=<redacted>", safe)

    def test_nested_command_context_is_preserved(self):
        safe = redact_sensitive_data(
            {
                "commands": [
                    {"argv": "hydra -l root -p nested-secret ssh://localhost"},
                    {"details": {"value": "redis://u:redis-secret@localhost/0"}},
                ]
            }
        )
        serialized = json.dumps(safe)
        self.assertNotIn("nested-secret", serialized)
        self.assertNotIn("redis-secret", serialized)
        self.assertGreaterEqual(serialized.count(REDACTED), 2)

    def test_unquoted_multisegment_secret_is_fully_redacted(self):
        safe = redact_sensitive_text(
            "password: correct horse, battery staple\nstatus: ok"
        )
        self.assertNotIn("correct", safe)
        self.assertNotIn("horse", safe)
        self.assertNotIn("battery", safe)
        self.assertNotIn("staple", safe)

if __name__ == "__main__":
    unittest.main()
