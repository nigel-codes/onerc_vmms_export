"""Everything the migration needs from the old site, as plain dictionaries.

`extract(source)` is the only function that touches the old database. What it
returns — a `snapshot` — is JSON-able and is what `transform` reads, so the
transform is pure and can be tested against a hand-written snapshot.

Field lists name what the mapping uses. A field this particular prod site does
not have comes back as None (see `Source.select`), and `profile` reports which
ones were missing so that a gap is seen before it is loaded.
"""

from onerc_vmms_export.reader import DatabaseSource as Source

# Person facts that exist on both User and Job Applicant as Custom Fields.
PERSON_FIELDS = [
	"gender",
	"marital_status",
	"citizenship",
	"country_of_citizenship",
	"identification_type",
	"id_number",
	"passport_number",
	"county",
	"sub_county",
	"ward",
	"administrative_location",
	"sub_location",
	"profession",
	"blood_group",
	"number_of_dependants",
	"access_to_internet",
	"consent_to_use_of_bio_data",
]

# Table fields that exist on both User and Job Applicant. Resolved to their
# child doctype from the old site's own metadata, not from a hard-coded name.
PERSON_TABLES = [
	"languages",
	"disabilities",
	"allergies",
	"supporting_documents",
	"education",
	"work_experience",
	"work_references",
	"courses",
	"additional_skills",
	"driving_licence",
	"licences",
	"certification",
]

USER_FIELDS = [
	"language",
	"time_zone",
	"username",
	"login_after",
	"login_before",
	"restrict_ip",
	"email",
	"first_name",
	"middle_name",
	"last_name",
	"enabled",
	"user_type",
	"role_profile_name",
	"mobile_no",
	"phone",
	"user_image",
	"birth_date",
	"creation",
	"last_login",
	*PERSON_FIELDS,
]
USER_TABLES = [*PERSON_TABLES, "skill", "internship", "social_logins", "roles"]

APPLICANT_FIELDS = [
	"email_id",
	"applicant_name",
	"first_name",
	"surname",
	"other_names",
	"phone_number",
	"mpesa_mobile_phone",
	"profile_photo",
	"company",
	"status",
	"docstatus",
	"is_volunteer",
	"job_title",
	"creation",
	"has_insurance",
	"place_of_work",
	"reason_to_join_krcs",
	"date_of_birth",
	*PERSON_FIELDS,
]
APPLICANT_TABLES = PERSON_TABLES

EMPLOYEE_FIELDS = [
	"employee_name",
	"first_name",
	"middle_name",
	"last_name",
	"gender",
	"date_of_birth",
	"marital_status",
	"blood_group",
	"cell_number",
	"personal_email",
	"prefered_email",
	"company_email",
	"user_id",
	"company",
	"branch",
	"status",
	"date_of_joining",
	"relieving_date",
	"is_volunteer",
	"job_applicant",
	"image",
	"person_to_be_contacted",
	"emergency_phone_number",
	"relation",
	"creation",
]
EMPLOYEE_TABLES = ["education", "external_work_history"]

MEMBER_FIELDS = ["member_name", "email_id", "volunteer", "customer", "image", "creation"]
MEMBERSHIP_FIELDS = [
	"member",
	"membership_type",
	"company",
	"status",
	"from_date",
	"to_date",
	"member_since_date",
	"paid",
	"amount",
	"currency",
	"member_name",
	"docstatus",
	"creation",
]
MEMBERSHIP_TYPE_FIELDS = ["membership_type", "amount", "billing_cycle", "currency"]

ATTACHED_TO = ("User", "Job Applicant", "Employee", "VM Member", "VM Membership")


def extract(source: Source) -> dict:
	if hasattr(source, "data"):
		return source.data
	users = _index(source.select("User", USER_FIELDS, "where name not in ('Administrator', 'Guest')"))
	_attach_tables(source, "User", users, USER_TABLES)

	employees = _index(source.select("Employee", EMPLOYEE_FIELDS))
	_attach_tables(source, "Employee", employees, EMPLOYEE_TABLES)

	applicants = _index(source.select("Job Applicant", APPLICANT_FIELDS))
	_attach_tables(source, "Job Applicant", applicants, APPLICANT_TABLES)

	members = _index(source.select("VM Member", MEMBER_FIELDS))
	memberships = _index(source.select("VM Membership", MEMBERSHIP_FIELDS))
	membership_types = _index(source.select("VM Membership Type", MEMBERSHIP_TYPE_FIELDS))

	return {
		"source": {
			"db_name": source.db_name,
			"site_path": source.site_path,
			"apps": source.frappe_version(),
		},
		"users": users,
		"password_hashes": {},
		"employees": employees,
		"applicants": applicants,
		"members": members,
		"memberships": memberships,
		"membership_types": membership_types,
		"invoices": _membership_invoices(source),
		"files": _files(source),
		"missing_columns": _missing_columns(source),
	}


def _index(rows: list[dict]) -> dict[str, dict]:
	return {row["name"]: row for row in rows}


def _attach_tables(source: Source, doctype: str, records: dict, tables: list[str]) -> None:
	for fieldname in tables:
		grouped = source.children(doctype, fieldname)
		for name, record in records.items():
			record[fieldname] = grouped.get(name, [])


def _membership_invoices(source: Source) -> dict[str, dict]:
	"""The paid invoice behind each membership, if the old site recorded one."""
	if "membership" not in source.columns("Sales Invoice"):
		return {}
	rows = source.sql(
		"select name, membership, posting_date, status, outstanding_amount, grand_total"
		" from `tabSales Invoice` where docstatus = 1 and ifnull(membership, '') != ''"
		" order by posting_date"
	)
	invoices: dict[str, dict] = {}
	for row in rows:
		# The latest paid invoice wins; an unpaid one only when nothing was paid.
		current = invoices.get(row["membership"])
		if current is None or row["status"] == "Paid" or current["status"] != "Paid":
			invoices[row["membership"]] = row
	return invoices


def _files(source: Source) -> dict[str, dict]:
	"""File records by URL, for the doctypes a person's attachments hang off."""
	rows = source.select(
		"File",
		[
			"file_url",
			"file_name",
			"is_private",
			"attached_to_doctype",
			"attached_to_name",
			"attached_to_field",
			"content_hash",
			"file_size",
		],
		"where attached_to_doctype in %s",
		(ATTACHED_TO,),
	)
	by_url: dict[str, dict] = {}
	for row in rows:
		if row["file_url"]:
			by_url.setdefault(row["file_url"], row)
	return by_url


def _missing_columns(source: Source) -> dict[str, list[str]]:
	wanted = {
		"User": USER_FIELDS,
		"Job Applicant": APPLICANT_FIELDS,
		"Employee": EMPLOYEE_FIELDS,
		"VM Member": MEMBER_FIELDS,
		"VM Membership": MEMBERSHIP_FIELDS,
	}
	missing = {}
	for doctype, fields in wanted.items():
		if not source.has(doctype):
			missing[doctype] = ["<table missing>"]
			continue
		absent = sorted(set(fields) - source.columns(doctype))
		if absent:
			missing[doctype] = absent
	return missing
