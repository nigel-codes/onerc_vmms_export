"""Private immutable SQLite snapshots and content-addressed attachment bytes.

No source business records are changed. Snapshots contain only the migration
field allowlist, never database credentials, password hashes or API secrets.
"""
import html
import hashlib
import json
import os
import re
import sqlite3
import uuid
from pathlib import Path
from urllib.parse import unquote, urlsplit

PROTOCOL = 2
DATASETS = ("source", "users", "employees", "applicants", "members", "memberships",
            "membership_types", "invoices", "files", "missing_columns", "custom_fields", "history", "schemas")
MAP_DATASETS = {"users", "employees", "applicants", "members", "memberships", "membership_types", "invoices", "files", "history", "schemas"}
MAX_PAGE = 500
MAX_CHUNK = 4 * 1024 * 1024


class ExportError(Exception):
    pass


def valid_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ExportError("Invalid snapshot or file identifier.")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with temp.open("x", encoding="utf-8") as handle:
        os.chmod(temp, 0o600)
        handle.write(canonical(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_file(site_path, url, public_root=None, private_root=None):
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    prefix = "/private/files/" if parsed.path.startswith("/private/files/") else "/files/"
    if not parsed.path.startswith(prefix):
        return None
    root = Path(private_root or Path(site_path) / "private/files") if prefix.startswith("/private") else Path(public_root or Path(site_path) / "public/files")
    root = root.resolve()
    # Prefer the exact stored path. Percent-decoding is only a fallback.
    tail = parsed.path[len(prefix):]
    for relative in dict.fromkeys((tail, unquote(tail))):
        if not relative or "\\" in relative or ".." in Path(relative).parts:
            continue
        candidate = root / relative
        if candidate.is_symlink():
            continue
        resolved = candidate.resolve()
        if root in resolved.parents and resolved.is_file():
            return resolved
    return None


def find_urls(value, found=None):
    found = found if found is not None else set()
    if hasattr(value, "iter_values"):
        for item in value.iter_values():
            find_urls(item, found)
    elif isinstance(value, dict):
        for item in value.values():
            find_urls(item, found)
    elif isinstance(value, list):
        for item in value:
            find_urls(item, found)
    elif isinstance(value, str) and value.startswith(("/files/", "/private/files/")):
        found.add(value)
    elif isinstance(value, str):
        for match in re.finditer(r"""\b(?:src|href)\s*=\s*(["'])(/(?:private/)?files/[^"']+)\1""",value,re.I):
            found.add(html.unescape(match[2]))
    return found


def initialise_db(path):
    db = sqlite3.connect(path)
    os.chmod(path, 0o600)
    db.executescript("""
        CREATE TABLE records (dataset TEXT NOT NULL, record_key TEXT NOT NULL,
          payload TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(dataset,record_key));
        CREATE TABLE attachments (id TEXT PRIMARY KEY, source_url TEXT UNIQUE,
          sha256 TEXT, size INTEGER, payload TEXT NOT NULL);
    """)
    return db


def build(root, snapshot_id, source_id, owner, data, source_site, file_records=None,
          public_root=None, private_root=None, progress=None, login_envelope=None, login_metadata=None):
    """Build in a reserved directory. Only a complete database becomes visible."""
    root = Path(root)
    folder = root / "snapshots" / valid_id(snapshot_id)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = folder / "snapshot.sqlite"
    if final.exists():
        raise ExportError("Snapshot already exists.")
    temp = folder / ("building-" + uuid.uuid4().hex + ".sqlite")
    db = initialise_db(temp)
    counts = {}
    blobs = root / "blobs"
    blobs.mkdir(exist_ok=True, mode=0o700)
    missing = 0
    try:
        # Export metadata does not contain the source server's local paths/DB name.
        data = dict(data)
        data["source"] = {"source_id": source_id, "db_name": source_id,
                          "site_path": source_id, "apps": data["source"].get("apps"),
                          "snapshot_id": snapshot_id, "protocol": PROTOCOL,
                          "authentication_policy": {field:value for field,value in
                              (data["source"].get("authentication_policy") or {}).items()
                              if field in ('login_with_email_link','login_with_email_link_expiry',
                                  'rate_limit_email_link_login','allow_login_using_user_name',
                                  'allow_login_using_mobile_number','enable_two_factor_auth')}}
        data.pop("password_hashes", None)
        for dataset in DATASETS:
            value = data.get(dataset, {} if dataset in MAP_DATASETS else [])
            rows = value.iter_items() if hasattr(value, "iter_items") else sorted(value.items()) if dataset in MAP_DATASETS else [("value", value)]
            counts[dataset] = len(value) if dataset in MAP_DATASETS else len(rows)
            for key, row in rows:
                payload = canonical(row)
                db.execute("INSERT INTO records VALUES (?,?,?,?)", (dataset, key, payload, hashlib.sha256(payload.encode()).hexdigest()))
        owners = {}
        urls = set(data.get("files", {}))
        for key in ("users", "employees", "applicants", "members", "memberships", "history"):
            find_urls(data.get(key, {}), urls)
        for row in file_records or list(data.get("files", {}).values()):
            url = row.get("file_url")
            if url in urls:
                owners.setdefault(url, []).append(row)
        for index, url in enumerate(sorted(urls), 1):
            item = {"id": hashlib.sha256(url.encode()).hexdigest()[:32], "source_url": url,
                    "is_private": int(url.startswith("/private/") or any(r.get("is_private") for r in owners.get(url, []))),
                    "references": owners.get(url, [])}
            path = resolve_file(source_site, url, public_root, private_root)
            if path is None:
                item.update(status="missing", size=None, sha256=None)
                missing += 1
            else:
                # Pin original bytes; later source edits cannot change this snapshot.
                tmp_blob = blobs / ("part-" + uuid.uuid4().hex)
                digest = hashlib.sha256()
                legacy_md5 = hashlib.md5(usedforsecurity=False)
                size = 0
                try:
                    before = path.stat()
                    with path.open("rb") as src, tmp_blob.open("xb") as out:
                        os.chmod(tmp_blob, 0o600)
                        while chunk := src.read(1024 * 1024):
                            out.write(chunk)
                            digest.update(chunk)
                            legacy_md5.update(chunk)
                            size += len(chunk)
                    after = path.stat()
                    sha = digest.hexdigest()
                    dest = blobs / sha
                    if dest.exists() and digest_file(dest) == sha:
                        tmp_blob.unlink()
                    else:
                        os.replace(tmp_blob, dest)
                    mismatches = []
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        mismatches.append("source_file_changed_during_capture")
                    # The supported v15 File implementation stores a whole-file
                    # MD5. SHA-256 remains the transfer integrity authority.
                    for reference in owners.get(url, []):
                        expected_size = reference.get("file_size")
                        expected_hash = reference.get("content_hash")
                        if expected_size and int(expected_size) != size:
                            mismatches.append("source_file_size_mismatch")
                        if expected_hash and re.fullmatch(r"[a-fA-F0-9]{32}", expected_hash) and expected_hash.lower() != legacy_md5.hexdigest():
                            mismatches.append("source_file_hash_mismatch")
                    item.update(status="corrupt" if mismatches else "ready", size=size, sha256=sha)
                    if mismatches:
                        item["errors"] = sorted(set(mismatches))
                        missing += 1
                finally:
                    if tmp_blob.exists():
                        tmp_blob.unlink()
            db.execute("INSERT INTO attachments VALUES (?,?,?,?,?)", (item["id"], url, item["sha256"], item["size"], canonical(item)))
            if progress and index % 100 == 0:
                progress({"files_processed": index, "files_total": len(urls)})
        db.commit()
        db.close()
        if login_envelope is not None:
            atomic_json(folder / "login-envelope.json", login_envelope)
        os.replace(temp, final)
        result = {"snapshot_id": snapshot_id, "source_id": source_id, "protocol": PROTOCOL,
                  "owner": owner, "status": "ready", "counts": counts, "files": len(urls),
                  "missing_files": missing, "database_sha256": digest_file(final),
                  "logins": login_metadata or {"included": False},
                  "include_logins": bool(login_metadata and login_metadata.get("included")),
                  "recipient_fingerprint": (login_metadata or {}).get("recipient_fingerprint", "")}
        atomic_json(folder / "status.json", result)
        return result
    except Exception:
        db.close()
        raise


def read_db(root, snapshot_id):
    path = Path(root) / "snapshots" / valid_id(snapshot_id) / "snapshot.sqlite"
    if not path.is_file():
        raise ExportError("Snapshot is not ready.")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def page(root, snapshot_id, dataset, after="", limit=200):
    if dataset not in DATASETS and dataset != "file_manifest":
        raise ExportError("Unknown dataset.")
    limit = int(limit)
    if not 1 <= limit <= MAX_PAGE:
        raise ExportError("Page size must be between 1 and 500.")
    db = read_db(root, snapshot_id)
    try:
        if dataset == "file_manifest":
            rows = db.execute("SELECT id AS record_key,payload FROM attachments WHERE id>? ORDER BY id LIMIT ?", (after, limit + 1)).fetchall()
            result = [json.loads(r["payload"]) for r in rows[:limit]]
        else:
            rows = db.execute("SELECT record_key,payload,sha256 FROM records WHERE dataset=? AND record_key>? ORDER BY record_key LIMIT ?", (dataset, after, limit + 1)).fetchall()
            result = [{"key": r["record_key"], "data": json.loads(r["payload"]), "sha256": r["sha256"]} for r in rows[:limit]]
        return {"rows": result, "next_after": rows[limit - 1]["record_key"] if len(rows) > limit else None}
    finally:
        db.close()


def attachment(root, snapshot_id, file_id):
    db = read_db(root, snapshot_id)
    try:
        row = db.execute("SELECT payload FROM attachments WHERE id=?", (valid_id(file_id),)).fetchone()
        if not row:
            raise ExportError("File is not in this snapshot.")
        item = json.loads(row[0])
        if item["status"] != "ready":
            raise ExportError("Source file is missing.")
        path = Path(root) / "blobs" / item["sha256"]
        if not path.is_file() or path.stat().st_size != item["size"]:
            raise ExportError("Snapshot file is unavailable.")
        return path, item
    finally:
        db.close()
