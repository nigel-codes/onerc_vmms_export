app_name = "onerc_vmms_export"
app_title = "VMMS Export"
app_publisher = "Nigel"
app_description = "Read-only VMMS business-data export for Redhive migration"
app_email = "nigelnathan2@gmail.com"
app_license = "mit"
# Reads legacy tables through a separate read-only SQL session. No legacy app
# code is imported, so restored-backup test sites need only Frappe and this app.
after_install = "onerc_vmms_export.install.after_install"
before_request = ["onerc_vmms_export.guard.before_request"]
