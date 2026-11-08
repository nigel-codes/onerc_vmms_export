# VMMS Export (source app)

Version **0.4.0**. Install on the **old VMMS v15 site**. The target uses `onerc_vmms_migrate`.
This app exports reviewed business scope, source column evidence and pinned attachment bytes through
an authenticated API. It does not change people, approvals or memberships.
Known structured password, credential and API-secret fields are protected. Existing local password hashes use the separately enabled sealed-login path below. Preserve a complete sealed source backup for protected and uncaptured evidence.

Requires a source **long worker** and enough private storage for the export's
metadata and content-addressed file cache. Source files are read and copied to
private snapshot storage; operators do not download/upload archives.

```sh
bench --site OLD install-app onerc_vmms_export
bench --site OLD set-config -p onerc_vmms_export_enabled 1
bench --site OLD set-config -p onerc_vmms_export_users '["migration@example.org"]'
```

Create a dedicated enabled System Manager account, generate its API key/secret,
and enter them in the new site's VMMS Migration Settings. Every endpoint checks
the allowlist and current manager access. Snapshots belong to their creating
account. Disable export and revoke the key after cutover.

API prefix: `/api/method/onerc_vmms_export.api.`

- GET `capabilities`
- GET `authentication_audit` (counts only; no account names or hashes)
- POST `create_snapshot` (`request_id`: client-generated 32-character UUID hex)
- GET `snapshot_status` (`snapshot_id`)
- GET `records` (`snapshot_id`, `dataset`, optional signed `cursor`, `limit`)
- GET `file_manifest` (`snapshot_id`, optional signed `cursor`, `limit`)
- GET `file_chunk` (`snapshot_id`, `file_id`, `offset`, `length` up to 4 MiB)

All requests use standard Frappe token authentication. Use HTTPS in production.
Record batches include canonical SHA-256 hashes. File chunks include range and
digest headers; receivers verify each chunk and the complete file.

Missing files and bytes that differ from v15 File metadata are explicit manifest
exceptions. A snapshot can finish with exceptions for inspection, and remain visible on the receiver. A successful rehearsal/import requires
complete bytes or an explicitly reviewed missing-file exception. A hash mismatch may mean the
database and files are from different backup dates; it does not establish that
the file itself is damaged. Private files stay in private snapshot storage.

Exports read records within one read-only database transaction, then pin file
bytes. Freeze the source for final cutover: a database transaction does not freeze
filesystem writes. Snapshot caches have no automatic deletion; hosting must apply
the agreed private-data retention policy. No scheduler is required for export.

For local backup testing, host-only `onerc_vmms_export_public_root` and
`onerc_vmms_export_private_root` settings may point to extracted original files.
Neither these paths nor the source database name is exposed in API responses.

For an isolated local exporter test site, host-only
`onerc_vmms_export_restored_source` may point at an existing restored v15 site.
It reads that site's database using its local configuration, while all export
API state and pinned bytes live on the isolated exporter site. Leave this unset
on the real old production site.


## Optional protected login transfer

Normal record endpoints never return password hashes. To preserve existing
passwords, hosting must explicitly set `onerc_vmms_export_logins_enabled=1` and
register the receiving site's PEM public key in
`onerc_vmms_export_login_public_key`. Obtain the public key from the new site's
Migration Settings. The source migration account must remain allowlisted.

The receiver requests a new snapshot with `include_logins=1` and its registered
`recipient_fingerprint`. Only hashes for captured non-built-in users are read,
within the same read-only transaction as the records. They are encrypted to the
pinned recipient before writing snapshot storage. POST `login_bundle` returns
only that encrypted envelope, after account, ownership and recipient checks.

The envelope uses AES-256-GCM with a data key wrapped by RSA-OAEP/SHA-256; source,
snapshot and recipient identity are authenticated. Neither ordinary snapshot
SQLite nor reports contain plaintext hashes. Disable login export with the main
export service after cutover. A supported source hash must exist to preserve a
local password; do not invent a replacement for an account without one.

The full protocol also captures allowlisted VMMS and Buzz business history and dependent ERP records. Source User secrets, authentication/configuration tables and Password fields are excluded from ordinary history. Source records are read in a separate read-only consistent transaction; only migration snapshot/cache state is written on the source site. Exporting still consumes worker, CPU, database-read and disk resources, so rehearse timing on the live infrastructure before scheduling the final freeze.

Disable with `bench --site OLD set-config -p onerc_vmms_export_enabled 0` and `bench --site OLD set-config -p onerc_vmms_export_logins_enabled 0`, then revoke the dedicated account token.


## Final cutover freeze

Normal capture leaves the old website online. For final cutover, hosting can set
`onerc_vmms_export_freeze=1` (integer or boolean) to reject non-export Frappe web
requests with HTTP 503 while keeping the protected export API reachable. This
flag is off by default and never turns itself on. It does not modify business
records. Pause the source scheduler and drain/stop business-writing background
jobs before the final capture; keep an export worker running. Direct database
writers and already-running jobs are outside the web guard.

```sh
bench --site OLD set-config -p onerc_vmms_export_freeze 1
bench --site OLD disable-scheduler
bench --site OLD clear-cache
```

Do not use generic maintenance mode if it blocks the export API. To reopen the
source after an abandoned cutover, set the freeze flag to `0`, clear the cache,
and restore its original scheduler/worker state. Keep it frozen after a successful
move so users cannot create records on the retired site.

The snapshot records non-secret System Settings login-method flags, including email-link login and its expiry/rate limits, inside the same read-only transaction. The login audit returns these flags alongside credential coverage counts; SMTP/provider secrets and two-factor enrollment seeds are excluded.

## Continuity export preparation — 0.3.0

This version expands historical capture to include Navari M-Pesa, full noncredential User records, change/security/workflow/deletion logs and additional finance/permission dependencies. Physical source-only columns are retained, and a source.continuity manifest records every SQL table/column/type, uncaptured/protected obligations and source naming rules/counters/conditions.

Known structured credentials are excluded or protected, including nested Version/deletion payloads. Unparsed historical JSON is marked for protected backup rather than exposed as unchecked text. A complete sealed source backup is still required; the manifest does not certify full source retention or a completed migration.

Use with receiver 0.5.0 and a fresh reviewed capture. Updating code does not add missing records to an old capture. Preparation did not run an export or change source data. Site deployment/runtime rehearsal remains pending.


## Effective person metadata — 0.4.0

Pair with receiver 0.6.0 and create a fresh reviewed capture. Operational child extraction and historical schema discovery now honor effective DocField/Custom Field/Property Setter definitions. This fixes User.education overrides to Employee Education and preserves the site's actual education-level options.

The operational payload includes User/Applicant LinkedIn and GitHub, User biography and Employee.custom_profession. Source metadata carries profile_mapping_version=2 through transport; old captures do not gain these fields by updating code. The receiver preserves insurance and old consent only as evidence, without creating current answers. No business records are rewritten by extraction.
