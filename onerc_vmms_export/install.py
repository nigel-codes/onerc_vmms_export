import uuid
import frappe


def after_install():
    if not frappe.conf.get("onerc_vmms_export_source_id"):
        from frappe.installer import update_site_config
        update_site_config("onerc_vmms_export_source_id", uuid.uuid4().hex)
