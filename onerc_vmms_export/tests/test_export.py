import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import frappe
from onerc_vmms_export import api, snapshot

SID = "a" * 32
SOURCE = "b" * 32


class TestSnapshots(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.site = self.root / "site"
        self.files = self.site / "public/files"
        self.files.mkdir(parents=True)
        (self.site / "private/files").mkdir(parents=True)

    def build(self, data, file_records=None):
        data.setdefault("source", {"apps": "frappe 15", "db_name": "SECRET-DB", "site_path": "/SECRET/PATH"})
        return snapshot.build(self.root / "exports", SID, SOURCE, "manager", data, self.site, file_records)

    def test_snapshot_pins_bytes_and_preserves_case_and_shared_blobs(self):
        (self.files / "ID.pdf").write_bytes(b"first")
        (self.files / "id.pdf").write_bytes(b"second")
        (self.files / "same.pdf").write_bytes(b"first")
        data = {"users": {"one": {"image": "/files/ID.pdf"}, "two": {"image": "/files/id.pdf"}, "three": {"image": "/files/same.pdf"}}}
        result = self.build(data)
        self.assertEqual(result["files"], 3)
        rows = snapshot.page(self.root / "exports", SID, "file_manifest")["rows"]
        self.assertEqual(len({r["sha256"] for r in rows}), 2)
        (self.files / "ID.pdf").write_bytes(b"changed after capture")
        item = next(r for r in rows if r["source_url"] == "/files/ID.pdf")
        path, _ = snapshot.attachment(self.root / "exports", SID, item["id"])
        self.assertEqual(path.read_bytes(), b"first")
        source = snapshot.page(self.root / "exports", SID, "source")["rows"][0]["data"]
        self.assertNotIn("SECRET", json.dumps(source))

    def test_safe_login_policy_survives_metadata_redaction(self):
        self.build({'source':{'db_name':'SECRET-DB','authentication_policy':{
            'login_with_email_link':1,'api_secret':'SECRET-TOKEN'}}})
        row=snapshot.page(self.root/'exports',SID,'source')['rows'][0]['data']
        self.assertEqual(row['authentication_policy'],{'login_with_email_link':1})
        self.assertNotIn('SECRET',json.dumps(row))

    def test_private_files_and_duplicate_ownership_are_preserved(self):
        (self.site / "private/files/scan.pdf").write_bytes(b"private")
        url = "/private/files/scan.pdf"
        rows = [{"file_url": url, "is_private": 1, "attached_to_name": person} for person in ("one", "two")]
        self.build({"files": {url: rows[0]}}, rows)
        item = snapshot.page(self.root / "exports", SID, "file_manifest")["rows"][0]
        self.assertEqual(item["is_private"], 1)
        self.assertEqual(len(item["references"]), 2)

    def test_missing_files_are_explicit_and_cannot_download(self):
        result = self.build({"users": {"u": {"image": "/private/files/missing.pdf"}}})
        self.assertEqual(result["missing_files"], 1)
        item = snapshot.page(self.root / "exports", SID, "file_manifest")["rows"][0]
        with self.assertRaises(snapshot.ExportError):
            snapshot.attachment(self.root / "exports", SID, item["id"])

    def test_bytes_are_compared_with_legacy_file_metadata(self):
        (self.files / "scan.pdf").write_bytes(b"changed")
        row = {"file_url": "/files/scan.pdf", "content_hash": hashlib.md5(b"original").hexdigest(), "file_size": 8}
        result = self.build({"files": {row["file_url"]: row}})
        self.assertEqual(result["missing_files"], 1)
        item = snapshot.page(self.root / "exports", SID, "file_manifest")["rows"][0]
        self.assertEqual(item["status"], "corrupt")
        self.assertIn("source_file_hash_mismatch", item["errors"])

    def test_pagination_is_repeatable_and_bounded(self):
        self.build({"users": {str(n): {"name": str(n)} for n in range(5)}})
        first = snapshot.page(self.root / "exports", SID, "users", limit=2)
        self.assertEqual(first, snapshot.page(self.root / "exports", SID, "users", limit=2))
        second = snapshot.page(self.root / "exports", SID, "users", first["next_after"], limit=2)
        self.assertEqual([r["key"] for r in first["rows"] + second["rows"]], ["0", "1", "2", "3"])
        for limit in (0, 501, -1):
            with self.assertRaises(snapshot.ExportError):
                snapshot.page(self.root / "exports", SID, "users", limit=limit)

    def test_embedded_html_local_attachments_are_captured(self):
        value='<img src="/files/photo.png"><a href="/private/files/A &amp; B.pdf">proof</a><img src="https://other.test/files/x">'
        self.assertEqual(snapshot.find_urls(value), {'/files/photo.png','/private/files/A & B.pdf'})

    def test_files_cannot_escape_source_roots(self):
        secret = self.site / "secret"
        secret.write_bytes(b"secret")
        (self.files / "link").symlink_to(secret)
        for url in ("/files/../secret", "/files/%2e%2e/secret", "/files/link", "https://example.org/files/a", "/files/a?token=x"):
            self.assertIsNone(snapshot.resolve_file(self.site, url), url)


class TestAuthorization(TestCase):
    def setUp(self):
        def throw(message, exc=frappe.ValidationError, **kwargs):
            raise exc(message)
        self.addCleanup(patch.stopall)
        patch.object(frappe.local, "flags", frappe._dict(in_test=False), create=True).start()
        patch.object(frappe, "throw", side_effect=throw).start()
        patch.object(frappe, "conf", frappe._dict(onerc_vmms_export_enabled=1,
            onerc_vmms_export_users=["manager"], onerc_vmms_export_source_id=SOURCE, encryption_key="secret")).start()
        patch.object(frappe, "session", SimpleNamespace(user="manager")).start()
        self.roles = patch.object(frappe, "get_roles", return_value=["System Manager"]).start()

    def test_every_endpoint_denies_unlisted_account(self):
        frappe.session.user = "intruder"
        for method, args in ((api.capabilities, ()), (api.authentication_audit, ()), (api.create_snapshot, (SID,)),
            (api.snapshot_status, (SID,)), (api.records, (SID, "users")),
            (api.file_manifest, (SID,)), (api.file_chunk, (SID, "c" * 32)),
            (api.login_bundle, (SID, "fingerprint"))):
            with self.subTest(method=method.__name__), self.assertRaises(frappe.PermissionError):
                method(*args)

    def test_disabled_export_and_revoked_manager_role_deny_access(self):
        frappe.conf.onerc_vmms_export_enabled = 0
        with self.assertRaises(frappe.PermissionError):
            api.capabilities()
        frappe.conf.onerc_vmms_export_enabled = 1
        self.roles.return_value = ["Website User"]
        with self.assertRaises(frappe.PermissionError):
            api.capabilities()

    def test_string_zero_is_disabled(self):
        frappe.conf.onerc_vmms_export_enabled="0"
        with self.assertRaises(frappe.PermissionError):api.capabilities()
        frappe.conf.onerc_vmms_export_enabled="1"
        frappe.conf.onerc_vmms_export_logins_enabled="0"
        with self.assertRaises(frappe.PermissionError):api.assert_login_export("not-registered")

    def test_login_export_requires_separate_host_opt_in(self):
        with self.assertRaises(frappe.PermissionError):
            api.assert_login_export("not-registered")

    def test_cursor_is_bound_to_snapshot_and_dataset(self):
        cursor = api.cursor_for(SID, "users", "last-user")
        self.assertEqual(api.read_cursor(cursor, SID, "users"), "last-user")
        for token, sid, dataset in ((cursor, "c" * 32, "users"), (cursor, SID, "employees"), (cursor + "x", SID, "users")):
            with self.assertRaises(frappe.ValidationError):
                api.read_cursor(token, sid, dataset)
