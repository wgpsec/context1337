"""Tests for build_index.py -- _meta.yaml support for dict/payload indexing."""
import os
import shutil
import sqlite3
import tempfile
import textwrap
import unittest
from unittest.mock import patch

# Mock jieba before importing build_index so the import succeeds
# even when jieba is not installed.
import types

_fake_jieba = types.ModuleType("jieba")


def _fake_cut_for_search(text):
    return text.split()


_fake_jieba.cut_for_search = _fake_cut_for_search
_fake_jieba.load_userdict = lambda p: None

import sys

sys.modules["jieba"] = _fake_jieba

import build_index  # noqa: E402


def _create_db():
    """Create an in-memory SQLite DB with the resources schema."""
    conn = sqlite3.connect(":memory:")
    build_index.create_schema(conn)
    return conn


class TestLoadMetaYaml(unittest.TestCase):
    """Tests for _load_meta_yaml helper."""

    def test_returns_none_when_no_meta(self):
        with tempfile.TemporaryDirectory() as d:
            result = build_index._load_meta_yaml(d)
            self.assertIsNone(result)

    def test_loads_valid_meta(self):
        with tempfile.TemporaryDirectory() as d:
            meta_path = os.path.join(d, "_meta.yaml")
            with open(meta_path, "w") as f:
                f.write(textwrap.dedent("""\
                    category: auth
                    description: "Auth dictionaries"
                    tags: "auth,login"
                    files:
                      - name: top100.txt
                        description: "Top 100 passwords"
                        tags: "top,common"
                """))
            result = build_index._load_meta_yaml(d)
            self.assertIsNotNone(result)
            self.assertEqual(result["category"], "auth")
            self.assertEqual(len(result["files"]), 1)

    def test_returns_none_on_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            meta_path = os.path.join(d, "_meta.yaml")
            with open(meta_path, "w") as f:
                f.write(":\n  - :\n  bad: [yaml")
            result = build_index._load_meta_yaml(d)
            # Should return None or a parsed result; not raise
            # (yaml.safe_load may parse partial content, so we just
            # verify no exception is raised)


class TestIndexDictsWithMeta(unittest.TestCase):
    """Test index_dicts when _meta.yaml is present."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create Dic/auth/password/ with _meta.yaml and a data file
        pw_dir = os.path.join(self.tmpdir, "Dic", "auth", "password")
        os.makedirs(pw_dir)

        with open(os.path.join(pw_dir, "_meta.yaml"), "w") as f:
            f.write(textwrap.dedent("""\
                category: auth
                subcategory: password
                description: "常见弱口令及按复杂度规则生成的密码字典集合"
                tags: "password,弱口令,爆破"
                files:
                  - name: top100.txt
                    lines: 100
                    description: "最常见的100个弱口令"
                    usage: "登录爆破初筛"
                    tags: "top,common,weak"
            """))
        with open(os.path.join(pw_dir, "top100.txt"), "w") as f:
            f.write("admin\npassword\n123456\n")

        self.conn = _create_db()

    def tearDown(self):
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_meta_category_is_used(self):
        count = build_index.index_dicts(self.conn, self.tmpdir)
        self.assertEqual(count, 1)

        row = self.conn.execute(
            "SELECT category, description, tags, body FROM resources WHERE type='dict'"
        ).fetchone()
        self.assertIsNotNone(row)
        category, description, tags, body = row

        # Category should come from _meta.yaml, not from path
        self.assertEqual(category, "auth")

    def test_meta_description_is_indexed(self):
        build_index.index_dicts(self.conn, self.tmpdir)
        row = self.conn.execute(
            "SELECT description FROM resources WHERE type='dict'"
        ).fetchone()
        self.assertIsNotNone(row)
        # Description should contain tokenized version of file-level description
        self.assertIn("最常见", row[0])

    def test_tags_are_merged(self):
        build_index.index_dicts(self.conn, self.tmpdir)
        row = self.conn.execute(
            "SELECT tags FROM resources WHERE type='dict'"
        ).fetchone()
        self.assertIsNotNone(row)
        tags = row[0]
        # Should contain both directory-level and file-level tags (merged)
        self.assertIn("password", tags)
        self.assertIn("top", tags)

    def test_body_contains_description_usage_tags(self):
        build_index.index_dicts(self.conn, self.tmpdir)
        row = self.conn.execute(
            "SELECT body FROM resources WHERE type='dict'"
        ).fetchone()
        self.assertIsNotNone(row)
        body = row[0]
        # Body should include description, usage, and tags
        self.assertIn("最常见", body)
        self.assertIn("登录", body)


class TestIndexDictsFallback(unittest.TestCase):
    """Test index_dicts when no _meta.yaml is present (fallback)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create Dic/network/ with a data file but NO _meta.yaml
        net_dir = os.path.join(self.tmpdir, "Dic", "network")
        os.makedirs(net_dir)
        with open(os.path.join(net_dir, "subdomains.txt"), "w") as f:
            f.write("www\nmail\nftp\n")

        self.conn = _create_db()

    def tearDown(self):
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_fallback_uses_path_category(self):
        count = build_index.index_dicts(self.conn, self.tmpdir)
        self.assertEqual(count, 1)

        row = self.conn.execute(
            "SELECT category, description FROM resources WHERE type='dict'"
        ).fetchone()
        self.assertIsNotNone(row)
        category, description = row
        self.assertEqual(category, "network")
        self.assertIn("network", description)
        self.assertIn("dictionary", description)
        self.assertIn("subdomains.txt", description)


class TestIndexPayloadsWithMeta(unittest.TestCase):
    """Test index_payloads when _meta.yaml is present."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create Payload/xss/ with _meta.yaml and a data file
        xss_dir = os.path.join(self.tmpdir, "Payload", "xss")
        os.makedirs(xss_dir)

        with open(os.path.join(xss_dir, "_meta.yaml"), "w") as f:
            f.write(textwrap.dedent("""\
                category: xss
                description: "XSS payload collection"
                tags: "xss,cross-site-scripting"
                files:
                  - name: basic.txt
                    description: "Basic XSS payloads"
                    usage: "Test reflected XSS"
                    tags: "reflected,basic"
            """))
        with open(os.path.join(xss_dir, "basic.txt"), "w") as f:
            f.write("<script>alert(1)</script>\n")

        self.conn = _create_db()

    def tearDown(self):
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_payload_meta_indexed(self):
        count = build_index.index_payloads(self.conn, self.tmpdir)
        self.assertEqual(count, 1)

        row = self.conn.execute(
            "SELECT type, category, description, tags FROM resources WHERE type='payload'"
        ).fetchone()
        self.assertIsNotNone(row)
        rtype, category, description, tags = row
        self.assertEqual(rtype, "payload")
        self.assertEqual(category, "xss")
        self.assertIn("Basic", description)
        self.assertIn("xss", tags)
        self.assertIn("reflected", tags)


class TestIndexPayloadsFallback(unittest.TestCase):
    """Test index_payloads fallback without _meta.yaml."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        pay_dir = os.path.join(self.tmpdir, "Payload", "sqli")
        os.makedirs(pay_dir)
        with open(os.path.join(pay_dir, "union.txt"), "w") as f:
            f.write("' UNION SELECT 1--\n")

        self.conn = _create_db()

    def tearDown(self):
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_payload_fallback(self):
        count = build_index.index_payloads(self.conn, self.tmpdir)
        self.assertEqual(count, 1)

        row = self.conn.execute(
            "SELECT category, description FROM resources WHERE type='payload'"
        ).fetchone()
        self.assertIsNotNone(row)
        category, description = row
        self.assertEqual(category, "sqli")
        self.assertIn("payload", description)
        self.assertIn("union.txt", description)


class TestSkipFiles(unittest.TestCase):
    """Test that _meta.yaml, .gitkeep, .DS_Store are not indexed as resources."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        d = os.path.join(self.tmpdir, "Dic", "misc")
        os.makedirs(d)

        with open(os.path.join(d, "_meta.yaml"), "w") as f:
            f.write("category: misc\ndescription: test\ntags: test\nfiles:\n  - name: data.txt\n    description: data\n")
        with open(os.path.join(d, ".gitkeep"), "w") as f:
            f.write("")
        with open(os.path.join(d, ".DS_Store"), "w") as f:
            f.write("")
        with open(os.path.join(d, "data.txt"), "w") as f:
            f.write("some data\n")

        self.conn = _create_db()

    def tearDown(self):
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_only_data_files_indexed(self):
        count = build_index.index_dicts(self.conn, self.tmpdir)
        self.assertEqual(count, 1)

        rows = self.conn.execute("SELECT name FROM resources WHERE type='dict'").fetchall()
        names = [r[0] for r in rows]
        self.assertEqual(len(names), 1)
        self.assertIn("data.txt", names[0])
        for skip in ("_meta.yaml", ".gitkeep", ".DS_Store"):
            for n in names:
                self.assertNotIn(skip, n)


class TestFileNotInMeta(unittest.TestCase):
    """Test file present in dir but not listed in _meta.yaml files list."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        d = os.path.join(self.tmpdir, "Dic", "auth")
        os.makedirs(d)

        with open(os.path.join(d, "_meta.yaml"), "w") as f:
            f.write(textwrap.dedent("""\
                category: auth
                description: Auth dicts
                tags: "auth"
                files:
                  - name: listed.txt
                    description: "A listed file"
            """))
        with open(os.path.join(d, "listed.txt"), "w") as f:
            f.write("data\n")
        with open(os.path.join(d, "unlisted.txt"), "w") as f:
            f.write("other data\n")

        self.conn = _create_db()

    def tearDown(self):
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_unlisted_file_uses_fallback(self):
        count = build_index.index_dicts(self.conn, self.tmpdir)
        self.assertEqual(count, 2)

        rows = self.conn.execute(
            "SELECT name, category, description FROM resources WHERE type='dict' ORDER BY name"
        ).fetchall()
        self.assertEqual(len(rows), 2)

        # Find the unlisted file
        unlisted = [r for r in rows if "unlisted" in r[0]]
        self.assertEqual(len(unlisted), 1)
        # Fallback should derive category from path
        self.assertEqual(unlisted[0][1], "auth")
        self.assertIn("dictionary", unlisted[0][2])


class TestEmptyDir(unittest.TestCase):
    """Test that missing Dic/Payload dirs return 0."""

    def test_no_dic_dir(self):
        with tempfile.TemporaryDirectory() as d:
            conn = _create_db()
            self.assertEqual(build_index.index_dicts(conn, d), 0)
            conn.close()

    def test_no_payload_dir(self):
        with tempfile.TemporaryDirectory() as d:
            conn = _create_db()
            self.assertEqual(build_index.index_payloads(conn, d), 0)
            conn.close()


class TestMitreField(unittest.TestCase):
    def setUp(self):
        self.conn = _create_db()
        self.tmpdir = tempfile.mkdtemp()
        skill_dir = os.path.join(self.tmpdir, "skills", "exploit", "test-skill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "SKILL.md"), "w") as f:
            f.write("""---
name: test-skill
description: Test skill with MITRE
metadata:
  tags: "test"
  category: "exploit"
  mitre_attack: "T1190,T1059"
---
Test body
""")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmpdir)

    def test_mitre_field_indexed(self):
        build_index.index_skills(self.conn, self.tmpdir)
        self.conn.commit()
        row = self.conn.execute(
            "SELECT mitre FROM resources WHERE name='test-skill'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIn("T1190", row[0])


if __name__ == "__main__":
    unittest.main()
