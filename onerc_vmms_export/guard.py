"""Optional host-controlled web freeze that keeps the protected export API open."""
import frappe
from onerc_vmms_export.api import enabled


class SourceFrozen(frappe.ValidationError):
    http_status_code=503


def allowed(path,freeze):
    return not enabled(freeze) or str(path or '').startswith('/api/method/onerc_vmms_export.api.')


def before_request():
    if not allowed(frappe.local.request.path,frappe.conf.get('onerc_vmms_export_freeze')):
        raise SourceFrozen('This VMMS site is temporarily frozen for migration cutover. Please try again after the cutover.')
