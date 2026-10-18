"""A read-only connection to the old onerc_vmms database.

Plain SQL through PyMySQL, never the old app's code. The old site runs a
different Frappe major, and its data model is partly site-level Custom Fields
that exist only in its database, so the only honest description of it is the
database itself. Every read goes through `select()`, which asks
`information_schema` which columns exist and returns NULL for a column the
mapping names but this site does not have. A field one prod site has and
another lacks becomes a gap in the report, not a crash halfway through.

**Read-only twice over.** The session is opened `READ ONLY` and every read
happens inside one `START TRANSACTION WITH CONSISTENT SNAPSHOT`, so a run sees
the database as it was at a single instant even if someone is still using the
old site. Point it at a restored backup anyway: that is the plan's rule.
"""

import json
import os
from collections import defaultdict

import frappe
import pymysql
import pymysql.cursors



# Frappe's standard bookkeeping columns. `select()` always fetches `name`; these
# are left out of child-row payloads so a hash of a person does not change
# because somebody re-saved a record without changing it.
BOOKKEEPING = {
	"creation",
	"modified",
	"modified_by",
	"owner",
	"docstatus",
	"idx",
	"parent",
	"parentfield",
	"parenttype",
	"_user_tags",
	"_comments",
	"_assign",
	"_liked_by",
	"_seen",
}


class SourceError(Exception):
	pass


class DatabaseSource:
	def __init__(self, conf: frappe._dict | None = None):
		conf = conf or {}
		site_path = conf.get("source_site_path")

		if not site_path or not os.path.isdir(site_path):
			raise SourceError(
				f"source_site_path is not a directory: {site_path!r}. Set it in the target's "
				"export configuration."
			)

		self.site_path = site_path
		site_conf = _read_json(os.path.join(site_path, "site_config.json"))
		common_conf = _read_json(os.path.join(os.path.dirname(site_path), "common_site_config.json"))

		self.db_name = site_conf.get("db_name")
		host = conf.get("source_db_host") or site_conf.get("db_host") or common_conf.get("db_host")
		port = conf.get("source_db_port") or site_conf.get("db_port") or common_conf.get("db_port")

		if not self.db_name:
			raise SourceError(f"No db_name in {site_path}/site_config.json")

		self.connection = pymysql.connect(
			host=host or "127.0.0.1",
			port=int(port or 3306),
			user=site_conf.get("db_user") or self.db_name,
			password=site_conf.get("db_password"),
			database=self.db_name,
			charset="utf8mb4",
			cursorclass=pymysql.cursors.DictCursor,
			autocommit=False,
		)
		self._columns: dict[str, set[str]] = {}
		self._tables: set[str] | None = None

		with self.connection.cursor() as cursor:
			cursor.execute("SET SESSION TRANSACTION READ ONLY")
			cursor.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")

	def close(self):
		try:
			self.connection.rollback()
		finally:
			self.connection.close()

	def __enter__(self):
		return self

	def __exit__(self, *exc):
		self.close()

	# --- schema ---------------------------------------------------------------

	def sql(self, query: str, params=None) -> list[dict]:
		with self.connection.cursor() as cursor:
			cursor.execute(query, params)
			return list(cursor.fetchall())

	def tables(self) -> set[str]:
		if self._tables is None:
			rows = self.sql(
				"select table_name as t from information_schema.tables where table_schema = %s",
				(self.db_name,),
			)
			self._tables = {row["t"] for row in rows}
		return self._tables

	def has(self, doctype: str) -> bool:
		return f"tab{doctype}" in self.tables()

	def columns(self, doctype: str) -> set[str]:
		if doctype not in self._columns:
			rows = self.sql(
				"select column_name as c from information_schema.columns"
				" where table_schema = %s and table_name = %s",
				(self.db_name, f"tab{doctype}"),
			)
			self._columns[doctype] = {row["c"] for row in rows}
		return self._columns[doctype]

	def select(self, doctype: str, fields: list[str], where: str = "", params=None) -> list[dict]:
		"""Rows of `doctype` with exactly `fields` as keys; absent columns are None."""
		if not self.has(doctype):
			return []

		present = self.columns(doctype)
		wanted = ["name", *[f for f in fields if f != "name"]]
		chosen = [f for f in wanted if f in present]
		cols = ", ".join(f"`{f}`" for f in chosen)
		rows = self.sql(f"select {cols} from `tab{doctype}` {where} order by `name`", params)

		for row in rows:
			for field in wanted:
				row.setdefault(field, None)

		return rows

	def child_doctype(self, parent: str, fieldname: str) -> str | None:
		"""Which child doctype a table field points at, standard or custom."""
		for source in ("DocField", "Custom Field"):
			parent_col = "parent" if source == "DocField" else "dt"
			rows = self.sql(
				f"select options from `tab{source}` where {parent_col} = %s and fieldname = %s"
				" and fieldtype in ('Table', 'Table MultiSelect') limit 1",
				(parent, fieldname),
			)
			if rows and rows[0]["options"]:
				return rows[0]["options"]
		return None

	def children(self, parent: str, fieldname: str) -> dict[str, list[dict]]:
		"""Child rows of one table field, grouped by parent name, in idx order."""
		child = self.child_doctype(parent, fieldname)

		if not child or not self.has(child):
			return {}

		rows = self.sql(
			f"select * from `tab{child}` where parenttype = %s and parentfield = %s order by parent, idx",
			(parent, fieldname),
		)
		grouped: dict[str, list[dict]] = defaultdict(list)

		for row in rows:
			parent_name = row["parent"]
			grouped[parent_name].append({k: v for k, v in row.items() if k not in BOOKKEEPING})

		return dict(grouped)

	def custom_fields(self) -> list[dict]:
		if not self.has("Custom Field"):
			return []
		return self.sql(
			"select dt, fieldname, fieldtype, options, label from `tabCustom Field`"
			" where fieldtype not in ('Section Break', 'Column Break', 'Tab Break', 'HTML')"
			" order by dt, idx"
		)

	def frappe_version(self) -> str | None:
		if not self.has("Installed Application"):
			return None
		rows = self.sql("select app_name, app_version from `tabInstalled Application` order by app_name")
		return ", ".join(f"{r['app_name']} {r['app_version']}" for r in rows)

	# --- files ----------------------------------------------------------------

	def file_path(self, file_url: str) -> str | None:
		"""Where a `/files/..` or `/private/files/..` URL lives on the old disk."""
		if not file_url:
			return None

		url = file_url.split("?", 1)[0]

		if url.startswith("/private/files/"):
			candidate = os.path.join(self.site_path, "private", "files", url[len("/private/files/") :])
		elif url.startswith("/files/"):
			candidate = os.path.join(self.site_path, "public", "files", url[len("/files/") :])
		else:
			return None

		return candidate if os.path.isfile(candidate) else None


def _read_json(path: str) -> dict:
	if not os.path.isfile(path):
		return {}
	with open(path) as handle:
		return json.load(handle)
