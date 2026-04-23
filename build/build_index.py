#!/usr/bin/env python3
"""Build the FTS5 index (builtin.db) from AboutSecurity data.

Usage:
    python build_index.py --input ./AboutSecurity/ --dict ./security_dict.txt --output ./builtin.db
"""
import argparse
import json
import os
import sqlite3
import sys

import jieba
import yaml


def init_jieba(dict_path: str):
    """Load custom security dictionary into jieba."""
    if dict_path and os.path.exists(dict_path):
        jieba.load_userdict(dict_path)
        print(f"Loaded custom dict: {dict_path}")


def tokenize(text: str) -> str:
    """Tokenize text using jieba cut_for_search mode."""
    tokens = jieba.cut_for_search(text)
    return " ".join(t.strip() for t in tokens if t.strip())


def create_schema(conn: sqlite3.Connection):
    """Create the database schema."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS resources (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,
            name        TEXT NOT NULL,
            source      TEXT NOT NULL,
            file_path   TEXT NOT NULL,
            category    TEXT,
            tags        TEXT,
            mitre       TEXT,
            difficulty  TEXT,
            description TEXT,
            body        TEXT,
            metadata    TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now')),
            UNIQUE(type, name, source)
        );

        CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(type);
        CREATE INDEX IF NOT EXISTS idx_resources_source ON resources(source);
        CREATE INDEX IF NOT EXISTS idx_resources_category ON resources(type, category);

        CREATE VIRTUAL TABLE IF NOT EXISTS resources_fts USING fts5(
            name, description, tags, category, mitre, body,
            content='resources', content_rowid='id',
            tokenize='unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS resources_ai AFTER INSERT ON resources BEGIN
            INSERT INTO resources_fts(rowid, name, description, tags, category, mitre, body)
            VALUES (new.id, new.name, new.description, new.tags, new.category, new.mitre, new.body);
        END;

        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
    """)


def parse_skill_md(path: str) -> dict:
    """Parse a SKILL.md file, extracting frontmatter and body."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.startswith("---"):
        return None

    end = content.find("\n---", 3)
    if end < 0:
        return None

    fm = yaml.safe_load(content[3:end])
    body = content[end + 4:].strip()

    meta = fm.get("metadata", {})
    tags = meta.get("tags", "")
    if isinstance(tags, list):
        tags = ",".join(str(t) for t in tags)
    return {
        "name": fm.get("name", ""),
        "description": fm.get("description", ""),
        "tags": tags,
        "category": meta.get("category", ""),
        "difficulty": meta.get("difficulty", ""),
        "mitre": meta.get("mitre_attack", ""),
        "body": body,
        "file_path": path,
    }


def index_skills(conn: sqlite3.Connection, base_dir: str):
    """Index all SKILL.md files."""
    skills_dir = os.path.join(base_dir, "skills")
    if not os.path.isdir(skills_dir):
        print(f"Warning: {skills_dir} not found")
        return 0

    count = 0
    for root, dirs, files in os.walk(skills_dir):
        for f in files:
            if f != "SKILL.md":
                continue
            path = os.path.join(root, f)
            skill = parse_skill_md(path)
            if not skill or not skill["name"]:
                continue

            # Append references content to body for FTS5
            body = skill["body"]
            ref_dir = os.path.join(root, "references")
            if os.path.isdir(ref_dir):
                for ref_name in sorted(os.listdir(ref_dir)):
                    if not ref_name.endswith(".md"):
                        continue
                    ref_path = os.path.join(ref_dir, ref_name)
                    try:
                        with open(ref_path, "r", encoding="utf-8") as rf:
                            body += f"\n\n---\n## [ref] {ref_name}\n" + rf.read()
                    except Exception:
                        pass

            tok_body = tokenize(f"{skill['description']} {body}")
            tok_tags = tokenize(skill["tags"])

            conn.execute(
                "INSERT OR REPLACE INTO resources (type,name,source,file_path,category,tags,mitre,difficulty,description,body) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("skill", skill["name"], "builtin", skill["file_path"],
                 skill["category"], tok_tags, skill["mitre"], skill["difficulty"],
                 tokenize(skill["description"]), tok_body),
            )
            count += 1

    return count


def _load_meta_yaml(directory):
    """Load _meta.yaml from a directory if it exists."""
    meta_path = os.path.join(directory, "_meta.yaml")
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _index_data_dir(conn, base_dir, subdir, resource_type):
    """Index dict or payload files, using _meta.yaml when available."""
    data_dir = os.path.join(base_dir, subdir)
    if not os.path.isdir(data_dir):
        return 0

    skip_files = {'_meta.yaml', '.gitkeep', '.DS_Store'}
    count = 0

    for root, dirs, files in os.walk(data_dir):
        data_files = [f for f in files if f not in skip_files]
        if not data_files:
            continue

        meta = _load_meta_yaml(root)

        if meta and "files" in meta:
            file_lookup = {entry["name"]: entry for entry in meta["files"]}
            dir_tags = meta.get("tags", "")
            dir_cat = meta.get("category", "")

            for f in data_files:
                path = os.path.join(root, f)
                rel = os.path.relpath(path, data_dir)
                entry = file_lookup.get(f)

                if entry:
                    file_tags = entry.get("tags", "")
                    merged_tags = ",".join(filter(None, [dir_tags, file_tags]))
                    desc = entry.get("description", "")
                    usage = entry.get("usage", "")
                    body_text = f"{desc} {usage} {merged_tags}"

                    conn.execute(
                        "INSERT OR REPLACE INTO resources "
                        "(type,name,source,file_path,category,tags,description,body) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (resource_type, rel, "builtin", path, dir_cat,
                         tokenize(merged_tags), tokenize(desc),
                         tokenize(body_text)),
                    )
                else:
                    _index_file_fallback(conn, resource_type, data_dir, root, f)
                count += 1
        else:
            for f in data_files:
                _index_file_fallback(conn, resource_type, data_dir, root, f)
                count += 1

    return count


def _index_file_fallback(conn, resource_type, data_dir, root, filename):
    """Fallback: index a file using only its path for metadata."""
    path = os.path.join(root, filename)
    rel = os.path.relpath(path, data_dir)
    parts = rel.split(os.sep)
    cat = parts[0] if len(parts) > 1 else ""
    label = "dictionary" if resource_type == "dict" else "payload"
    conn.execute(
        "INSERT OR REPLACE INTO resources "
        "(type,name,source,file_path,category,description,body) "
        "VALUES (?,?,?,?,?,?,?)",
        (resource_type, rel, "builtin", path, cat,
         f"{cat} {label}: {filename}", tokenize(f"{cat} {filename}")),
    )


def index_dicts(conn, base_dir):
    """Index dictionary files, using _meta.yaml when available."""
    return _index_data_dir(conn, base_dir, "Dic", "dict")


def index_payloads(conn, base_dir):
    """Index payload files, using _meta.yaml when available."""
    return _index_data_dir(conn, base_dir, "Payload", "payload")


def _extract_vuln_desc(body: str, title: str) -> str:
    """Extract description from vuln body. Looks for ## 漏洞描述 section, fallback to title."""
    import re
    for marker in ["## 漏洞描述", "## 漏洞概述", "## 简介", "## 概述"]:
        idx = body.find(marker)
        if idx < 0:
            continue
        after = body[idx + len(marker):].lstrip()
        # Take first paragraph (up to double newline or next heading)
        m = re.search(r'\n\n|\n#', after)
        para = after[:m.start()].strip() if m else after.strip()
        if para:
            return para[:200] + "..." if len(para) > 200 else para
    return title


def parse_vuln_md(path: str) -> dict:
    """Parse a vulnerability Markdown file with YAML frontmatter."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.startswith("---"):
        return None

    end = content.find("\n---", 3)
    if end < 0:
        return None

    fm = yaml.safe_load(content[3:end])
    if not fm or not fm.get("id"):
        return None

    body = content[end + 4:].strip()

    tags = fm.get("tags", "")
    if isinstance(tags, list):
        tags = ",".join(tags)

    desc = fm.get("description", "")
    if not desc:
        desc = _extract_vuln_desc(body, fm.get("title", ""))

    return {
        "id": fm.get("id", ""),
        "title": fm.get("title", ""),
        "description": desc,
        "product": fm.get("product", ""),
        "vendor": fm.get("vendor", ""),
        "version_affected": fm.get("version_affected", ""),
        "severity": fm.get("severity", "").upper(),
        "tags": tags,
        "fingerprint": fm.get("fingerprint", ""),
        "body": body,
        "file_path": path,
    }


def index_vulns(conn: sqlite3.Connection, base_dir: str):
    """Index vulnerability Markdown files."""
    vulns_dir = os.path.join(base_dir, "Vuln")
    if not os.path.isdir(vulns_dir):
        return 0

    count = 0
    for root, dirs, files in os.walk(vulns_dir):
        for f in files:
            if not f.endswith(".md"):
                continue
            path = os.path.join(root, f)
            vuln = parse_vuln_md(path)
            if not vuln:
                continue

            # Extract category from directory path: Vuln/{category}/...
            rel = os.path.relpath(root, vulns_dir)
            parts = rel.split(os.sep)
            cat = parts[0] if parts[0] != "." else ""

            meta = json.dumps({
                "severity": vuln["severity"],
                "product": vuln["product"],
                "vendor": vuln["vendor"],
                "version_affected": vuln["version_affected"],
                "fingerprint": vuln["fingerprint"],
            })

            tok_tags = tokenize(vuln["tags"])
            tok_desc = tokenize(vuln["description"])
            tok_body = tokenize(f"{vuln['description']} {vuln['title']} {vuln['body']}")

            conn.execute(
                "INSERT OR REPLACE INTO resources "
                "(type,name,source,file_path,category,tags,description,body,metadata) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ("vuln", vuln["id"], "builtin", vuln["file_path"],
                 cat, tok_tags, tok_desc, tok_body, meta),
            )
            count += 1

    return count


def index_tools(conn: sqlite3.Connection, base_dir: str):
    """Index tool YAML files."""
    tools_dir = os.path.join(base_dir, "Tools")
    if not os.path.isdir(tools_dir):
        return 0

    count = 0
    for root, dirs, files in os.walk(tools_dir):
        for f in files:
            if not f.endswith(".yaml"):
                continue
            path = os.path.join(root, f)
            with open(path, "r") as fh:
                tool = yaml.safe_load(fh)
            if not tool:
                continue

            desc = tool.get("description", "")
            cat = tool.get("category", "")
            if not cat:
                # Derive category from subdirectory name
                rel = os.path.relpath(root, tools_dir)
                if rel != ".":
                    cat = rel.split(os.sep)[0]
            meta = json.dumps({"binary": tool.get("binary", ""), "homepage": tool.get("homepage", "")})

            conn.execute(
                "INSERT OR REPLACE INTO resources (type,name,source,file_path,category,description,body,metadata) VALUES (?,?,?,?,?,?,?,?)",
                ("tool", tool.get("id", f), "builtin", path, cat,
                 tokenize(desc), tokenize(f"{desc} {tool.get('name', '')}"), meta),
            )
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Build AboutSecurity FTS5 index")
    parser.add_argument("--input", required=True, help="AboutSecurity data directory")
    parser.add_argument("--dict", default="", help="Custom jieba dictionary file")
    parser.add_argument("--output", required=True, help="Output SQLite database path")
    args = parser.parse_args()

    init_jieba(args.dict)

    if os.path.exists(args.output):
        os.remove(args.output)

    conn = sqlite3.connect(args.output)
    create_schema(conn)

    skills = index_skills(conn, args.input)
    dicts = index_dicts(conn, args.input)
    payloads = index_payloads(conn, args.input)
    tools = index_tools(conn, args.input)
    vulns = index_vulns(conn, args.input)

    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('builtin_version', ?)",
                 (f"v1-{skills}s-{dicts}d-{payloads}p-{tools}t-{vulns}v",))

    conn.execute("INSERT INTO resources_fts(resources_fts) VALUES('optimize')")
    conn.execute("PRAGMA journal_mode=DELETE")

    conn.commit()
    conn.close()

    print(f"Built {args.output}: {skills} skills, {dicts} dicts, {payloads} payloads, {tools} tools, {vulns} vulns")


if __name__ == "__main__":
    main()
