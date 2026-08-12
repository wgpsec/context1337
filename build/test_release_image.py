"""Behavioral contract tests for a published Context1337 image."""

import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid


class ReleaseImageContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = os.environ.get("CONTEXT1337_RELEASE_IMAGE")
        if not cls.image:
            raise unittest.SkipTest("CONTEXT1337_RELEASE_IMAGE is not set")

        cls.container = f"context1337-release-test-{uuid.uuid4().hex[:12]}"
        cls.api_key = "release-contract-test"
        subprocess.run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                cls.container,
                "--publish",
                "127.0.0.1::1337",
                "--env",
                f"ABOUTSECURITY_API_KEY={cls.api_key}",
                cls.image,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        try:
            port_result = subprocess.run(
                ["docker", "port", cls.container, "1337/tcp"],
                check=True,
                capture_output=True,
                text=True,
            )
            cls.port = int(port_result.stdout.strip().rsplit(":", 1)[1])
            cls.base_url = f"http://127.0.0.1:{cls.port}"
            cls._wait_until_ready()
        except Exception:
            cls._dump_logs()
            cls._remove_container()
            raise

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "container", None):
            cls._remove_container()

    @classmethod
    def _remove_container(cls):
        subprocess.run(
            ["docker", "rm", "--force", cls.container],
            check=False,
            capture_output=True,
            text=True,
        )

    @classmethod
    def _dump_logs(cls):
        result = subprocess.run(
            ["docker", "logs", cls.container],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.stdout or result.stderr:
            print(result.stdout + result.stderr)

    @classmethod
    def _wait_until_ready(cls):
        deadline = time.monotonic() + 90
        last_error = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"{cls.base_url}/health", timeout=2) as response:
                    if response.read() == b"OK":
                        return
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
            time.sleep(0.25)
        raise AssertionError(f"release image did not become ready: {last_error}")

    @classmethod
    def _get_json(cls, path):
        request = urllib.request.Request(
            f"{cls.base_url}{path}",
            headers={"Authorization": f"Bearer {cls.api_key}"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    @classmethod
    def _post_mcp(cls, payload, session_id=None):
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {cls.api_key}",
            "Content-Type": "application/json",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        request = urllib.request.Request(
            f"{cls.base_url}/mcp",
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode()
            response_headers = response.headers

        data_lines = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
        if not data_lines:
            raise AssertionError(f"MCP response did not contain an SSE data event: {body[:500]}")
        return json.loads(data_lines[-1]), response_headers

    def test_default_image_exposes_nuclei_as_a_secondary_vulnerability_source(self):
        payload = self._get_json("/api/stats")
        nuclei_rows = [
            row
            for row in payload.get("stats", [])
            if row.get("type") == "vuln" and row.get("source") == "nuclei"
        ]

        self.assertEqual(len(nuclei_rows), 1, payload)
        self.assertGreaterEqual(nuclei_rows[0].get("count", 0), 3_000, payload)

    def test_default_image_exposes_the_supported_http_categories(self):
        for category in (
            "nuclei-cve",
            "nuclei-cnvd",
            "nuclei-vulnerability",
            "nuclei-misconfiguration",
            "nuclei-default-login",
        ):
            payload = self._get_json(
                "/api/resources?type=vuln&source=nuclei&category="
                f"{urllib.parse.quote(category)}&limit=1"
            )
            self.assertGreater(payload.get("total", 0), 0, (category, payload))

    def test_builtin_database_uses_current_fts_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "builtin.db")
            subprocess.run(
                [
                    "docker",
                    "cp",
                    f"{self.container}:/app/data/builtin.db",
                    database_path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with sqlite3.connect(database_path) as database:
                row = database.execute(
                    "SELECT value FROM meta WHERE key='fts_contract_version'"
                ).fetchone()

        self.assertEqual(row, ("go-security-tokenizer-v3",))

    def test_image_records_the_resolved_nuclei_revision(self):
        result = subprocess.run(
            ["docker", "image", "inspect", self.image],
            check=True,
            capture_output=True,
            text=True,
        )
        image_config = json.loads(result.stdout)[0]["Config"]
        revision = image_config.get("Labels", {}).get(
            "org.opencontainers.image.nuclei-templates.revision"
        )
        environment = dict(
            item.split("=", 1)
            for item in image_config.get("Env", [])
            if "=" in item
        )

        self.assertRegex(revision or "", re.compile(r"^[0-9a-f]{40}$"))
        self.assertEqual(environment.get("NUCLEI_MIN_SEVERITY"), "high")
        self.assertEqual(
            environment.get("NUCLEI_TEMPLATES_DIR"),
            f"/app/data/nuclei-templates-{revision}",
        )

    def test_nuclei_detail_includes_the_original_template_yaml(self):
        resources = self._get_json("/api/resources?type=vuln&source=nuclei&limit=1")
        self.assertGreater(resources.get("total", 0), 0, resources)
        name = resources["items"][0]["name"]
        stable_id = f"absec://nuclei/vuln/{urllib.parse.quote(name, safe='')}"

        _, headers = self._post_mcp(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "release-contract-test", "version": "1"},
                },
            }
        )
        session_id = headers.get("Mcp-Session-Id")
        self.assertTrue(session_id, headers)
        detail, _ = self._post_mcp(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "get_security_detail",
                    "arguments": {"id": stable_id, "type": "vuln", "depth": "full"},
                },
            },
            session_id,
        )

        self.assertIn("# Nuclei Template", json.dumps(detail))
        self.assertIn("```yaml", json.dumps(detail))


if __name__ == "__main__":
    unittest.main()
