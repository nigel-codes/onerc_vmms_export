"""Version 2 export API. Every endpoint requires an enabled, allowlisted manager."""
import base64
import hashlib
import hmac
import json
from pathlib import Path

import frappe
from werkzeug.wrappers import Response

from onerc_vmms_export import snapshot


def enabled(value):
    return value is True or value in (1,"1","true","True")


def authorize():
    allowed = frappe.conf.get("onerc_vmms_export_users") or []
    if (not enabled(frappe.conf.get("onerc_vmms_export_enabled"))
        or not isinstance(allowed, list)
        or frappe.session.user == "Guest"
        or frappe.session.user not in allowed
        or "System Manager" not in frappe.get_roles()):
        frappe.throw("VMMS export is not enabled for this account.", frappe.PermissionError)
    if not frappe.conf.get("onerc_vmms_export_source_id"):
        frappe.throw("The export source identity has not been configured.")


def root():
    path = Path(frappe.get_site_path("private", "onerc_vmms_export"))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path.resolve()


def status_for(snapshot_id):
    try:
        path = root() / "snapshots" / snapshot.valid_id(snapshot_id) / "status.json"
        value = json.loads(path.read_text())
    except (snapshot.ExportError, FileNotFoundError):
        frappe.throw("Unknown export snapshot.")
    if value.get("owner") != frappe.session.user:
        frappe.throw("This snapshot belongs to another export account.", frappe.PermissionError)
    return value


def public_status(value):
    return {k: v for k, v in value.items() if k not in ("owner",)}


@frappe.whitelist(methods=["GET"])
def capabilities():
    authorize()
    login_info = {"enabled": enabled(frappe.conf.get("onerc_vmms_export_logins_enabled"))}
    if login_info["enabled"]:
        from onerc_vmms_export.login_crypto import fingerprint
        login_info["recipient_fingerprint"] = fingerprint(frappe.conf.get("onerc_vmms_export_login_public_key"))
    return {"protocol": snapshot.PROTOCOL, "source_id": frappe.conf.onerc_vmms_export_source_id,
            "datasets": list(snapshot.DATASETS), "max_page_size": snapshot.MAX_PAGE,
            "max_chunk_bytes": snapshot.MAX_CHUNK, "password_hashes": False,
            "web_frozen": enabled(frappe.conf.get("onerc_vmms_export_freeze")),
            "sealed_logins": login_info,
            "snapshot_files": "immutable", "refresh_mode": "full metadata; reuse unchanged file bytes"}


@frappe.whitelist(methods=["GET"])
def authentication_audit():
    authorize()
    from onerc_vmms_export.reader import DatabaseSource
    from onerc_vmms_export.logins import audit
    source_path = frappe.conf.get("onerc_vmms_export_restored_source") or str(Path(frappe.get_site_path()).resolve())
    with DatabaseSource({"source_site_path":source_path}) as source:
        return audit(source)


@frappe.whitelist(methods=["POST"])
def create_snapshot(request_id: str, include_logins: bool = False, recipient_fingerprint: str = ""):
    authorize()
    include_logins = include_logins in (True, 1, "1", "true", "True")
    if include_logins:
        assert_login_export(recipient_fingerprint)
    try:
        snapshot_id = snapshot.valid_id(request_id)
    except snapshot.ExportError as exc:
        frappe.throw(str(exc))
    directory = root() / "snapshots" / snapshot_id
    directory.parent.mkdir(exist_ok=True, mode=0o700)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        old = status_for(snapshot_id)
        if bool(old.get("include_logins")) != include_logins or old.get("recipient_fingerprint", "") != recipient_fingerprint:
            frappe.throw("The snapshot login-transfer options changed. Start a fresh capture.")
        return public_status(old)
    value = {"snapshot_id": snapshot_id, "owner": frappe.session.user, "status": "queued",
             "source_id": frappe.conf.onerc_vmms_export_source_id, "protocol": snapshot.PROTOCOL,
             "include_logins": include_logins, "recipient_fingerprint": recipient_fingerprint}
    snapshot.atomic_json(directory / "status.json", value)
    try:
        frappe.enqueue("onerc_vmms_export.api.build_snapshot", queue=frappe.conf.get("onerc_vmms_export_queue") or "long", timeout=21600,
                       job_id="vmms-export-" + snapshot_id, snapshot_id=snapshot_id,
                       owner=frappe.session.user, enqueue_after_commit=True)
    except Exception:
        value.update(status="failed", error="Could not enqueue export. Check the long worker.")
        snapshot.atomic_json(directory / "status.json", value)
        raise
    return public_status(value)


def build_snapshot(snapshot_id, owner):
    frappe.set_user(owner)
    authorize()
    state = status_for(snapshot_id)
    if state["status"] not in ("queued",):
        return
    folder = root() / "snapshots" / snapshot_id
    state.update(status="building")
    snapshot.atomic_json(folder / "status.json", state)
    try:
        from onerc_vmms_export.reader import DatabaseSource
        from onerc_vmms_export.extract import extract
        from onerc_vmms_export.history import extract as history_extract
        source_path = frappe.conf.get("onerc_vmms_export_restored_source") or str(Path(frappe.get_site_path()).resolve())
        with DatabaseSource({"source_site_path": source_path}) as source:
            if not all(source.has(dt) for dt in ("User", "Employee", "Job Applicant", "VM Member", "VM Membership")):
                raise snapshot.ExportError("The selected source does not contain the legacy VMMS schema.")
            data = extract(source)
            from onerc_vmms_export.logins import authentication_policy
            data["source"]["authentication_policy"]=authentication_policy(source)
            data["custom_fields"] = source.custom_fields()
            data["history"], data["schemas"] = history_extract(source, folder / "history-spool.sqlite")
            login_envelope, login_metadata = None, None
            if state.get("include_logins"):
                assert_login_export(state["recipient_fingerprint"])
                from onerc_vmms_export.logins import collect
                from onerc_vmms_export.login_crypto import seal
                credentials = collect(source, data["users"])
                login_envelope = seal(credentials, frappe.conf.onerc_vmms_export_login_public_key,
                    frappe.conf.onerc_vmms_export_source_id, snapshot_id)
                login_metadata = {"included": True, "users_with_password": len(credentials),
                    "recipient_fingerprint": state["recipient_fingerprint"]}
                del credentials
            file_records = source.select("File", ["file_url", "file_name", "is_private", "attached_to_doctype",
                "attached_to_name", "attached_to_field", "content_hash", "file_size"])
            # Include every File URL, preserving every owner in the manifest.
            for row in file_records:
                if row.get("file_url"):
                    data["files"].setdefault(row["file_url"], row)
        def progress(value):
            state.update(value)
            snapshot.atomic_json(folder / "status.json", state)
        return snapshot.build(root(), snapshot_id, frappe.conf.onerc_vmms_export_source_id,
            owner, data, source.site_path, file_records=file_records,
            public_root=frappe.conf.get("onerc_vmms_export_public_root"),
            private_root=frappe.conf.get("onerc_vmms_export_private_root"), progress=progress,
            login_envelope=login_envelope, login_metadata=login_metadata)
    except Exception:
        # Detailed traceback is kept in protected host logs, not returned to the client.
        state.update(status="failed", error="Export failed. Ask hosting support to inspect the source worker log.")
        snapshot.atomic_json(folder / "status.json", state)
        raise


@frappe.whitelist(methods=["GET"])
def snapshot_status(snapshot_id: str):
    authorize()
    return public_status(status_for(snapshot_id))


def assert_login_export(recipient_fingerprint):
    from onerc_vmms_export.login_crypto import fingerprint
    if not enabled(frappe.conf.get("onerc_vmms_export_logins_enabled")):
        frappe.throw("Login transfer must be explicitly enabled by the source host.", frappe.PermissionError)
    if fingerprint(frappe.conf.get("onerc_vmms_export_login_public_key")) != recipient_fingerprint:
        frappe.throw("The source host has not registered this recipient key.", frappe.PermissionError)


@frappe.whitelist(methods=["POST"])
def login_bundle(snapshot_id: str, recipient_fingerprint: str):
    authorize()
    assert_login_export(recipient_fingerprint)
    state = status_for(snapshot_id)
    if (state["status"] != "ready" or not state.get("logins", {}).get("included")
        or state["logins"].get("recipient_fingerprint") != recipient_fingerprint):
        frappe.throw("This snapshot does not contain a login bundle for this recipient.")
    return json.loads((root() / "snapshots" / snapshot_id / "login-envelope.json").read_text())


def cursor_key():
    key = frappe.conf.get("encryption_key")
    if not key:
        frappe.throw("Source encryption key is missing.")
    return key.encode()


def cursor_for(snapshot_id, dataset, after):
    payload = snapshot.canonical([snapshot_id, dataset, after]).encode()
    token = base64.urlsafe_b64encode(payload).decode()
    return token + "." + hmac.new(cursor_key(), payload, hashlib.sha256).hexdigest()


def read_cursor(cursor, snapshot_id, dataset):
    if not cursor:
        return ""
    try:
        if len(cursor) > 4096:
            raise ValueError()
        encoded, sig = cursor.split(".")
        payload = base64.b64decode(encoded.encode(), altchars=b"-_", validate=True)
        expected = hmac.new(cursor_key(), payload, hashlib.sha256).hexdigest()
        sid, kind, after = json.loads(payload)
        if not hmac.compare_digest(expected, sig) or sid != snapshot_id or kind != dataset or not isinstance(after, str):
            raise ValueError()
        return after
    except (ValueError, TypeError):
        frappe.throw("Invalid or mismatched export cursor.")


def get_page(snapshot_id, dataset, cursor, limit):
    state = status_for(snapshot_id)
    if state["status"] != "ready":
        frappe.throw("Wait for the export snapshot to finish.")
    after = read_cursor(cursor, snapshot_id, dataset)
    try:
        result = snapshot.page(root(), snapshot_id, dataset, after, limit)
    except (snapshot.ExportError, ValueError) as exc:
        frappe.throw(str(exc))
    after = result.pop("next_after")
    result["next_cursor"] = cursor_for(snapshot_id, dataset, after) if after is not None else None
    return result


@frappe.whitelist(methods=["GET"])
def records(snapshot_id: str, dataset: str, cursor: str = "", limit: int = 200):
    authorize()
    if dataset not in snapshot.DATASETS:
        frappe.throw("Unknown export dataset.")
    return get_page(snapshot_id, dataset, cursor, limit)


@frappe.whitelist(methods=["GET"])
def file_manifest(snapshot_id: str, cursor: str = "", limit: int = 200):
    authorize()
    return get_page(snapshot_id, "file_manifest", cursor, limit)


@frappe.whitelist(methods=["GET"])
def file_chunk(snapshot_id: str, file_id: str, offset: int = 0, length: int = snapshot.MAX_CHUNK):
    authorize()
    if status_for(snapshot_id)["status"] != "ready":
        frappe.throw("Wait for the export snapshot to finish.")
    try:
        offset, length = int(offset), int(length)
        path, item = snapshot.attachment(root(), snapshot_id, file_id)
        if offset < 0 or offset > item["size"] or not 1 <= length <= snapshot.MAX_CHUNK:
            raise snapshot.ExportError("Invalid byte range.")
        with path.open("rb") as handle:
            handle.seek(offset)
            content = handle.read(length)
    except (snapshot.ExportError, ValueError) as exc:
        frappe.throw(str(exc))
    # Bounded chunks avoid HTTP worker memory growth and support exact resume.
    return Response(content, status=200, mimetype="application/octet-stream", headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "X-VMMS-Offset": str(offset), "X-VMMS-Size": str(item["size"]),
        "X-VMMS-SHA256": item["sha256"],
        "X-VMMS-Chunk-SHA256": hashlib.sha256(content).hexdigest(),
    })
