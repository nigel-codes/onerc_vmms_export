"""Complete VMMS/Buzz business records, with schema and child-row identity.

This is a host-controlled scope, never a client-supplied doctype or SQL query.
Authentication secrets are handled exclusively by the sealed login endpoint.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

MODULES = {'Volunteer and Member Management', 'Buzz', 'Events', 'Ticketing', 'Proposals', 'Buzz Marketing'}
EXTRA = {
    'Employee', 'Job Applicant', 'Project', 'Task', 'Event', 'Training Event',
    'Certification', 'Timesheet', 'Attendance', 'LMS Course', 'LMS Enrollment',
    'LMS Certificate', 'LMS Batch', 'LMS Batch Enrollment', 'Comment', 'Communication',
    'File', 'Company', 'Shift Type', 'Profession', 'Gender', 'Language', 'Disability',
    'Identification Document Type', 'Education Level', 'Designation', 'Location',
    'Project Type', 'Task Type', 'Training Program', 'Sales Invoice', 'Payment Entry',
    'Payment Request', 'Customer', 'Mode of Payment',
}
FORBIDDEN = {'User', 'Email Account', 'Payment Gateway Account', 'Social Login Key',
             'OAuth Client', 'OAuth Bearer Token', 'Sessions', 'Access Log'}
SECRET_FIELDS = {'api_key', 'api_secret', 'password', 'new_password', 'reset_password_key',
                 'last_reset_password_key_generated_on', 'access_token', 'refresh_token',
                 'secret', 'client_secret', 'encryption_key', 'secret_key', 'signature',
                 'authorization_code', 'oauth_token', 'oauth_token_secret'}
LAYOUT = {'Section Break', 'Column Break', 'Tab Break', 'HTML', 'Button', 'Fold', 'Heading'}
SYSTEM = {'name', 'creation', 'modified', 'modified_by', 'owner', 'docstatus', 'idx',
          'parent', 'parenttype', 'parentfield', '_user_tags', '_comments', '_assign', '_liked_by'}


def record_key(doctype, name):
    return hashlib.sha256((str(doctype) + '\0' + str(name)).encode()).hexdigest()


class DiskRecords:
    def __init__(self,path,count):
        self.path,self.count=Path(path),count
    def __len__(self):return self.count
    def iter_items(self):
        with sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True) as db:
            for key,payload in db.execute('SELECT record_key,payload FROM history ORDER BY record_key'):
                yield key,json.loads(payload)
    def iter_values(self):
        for _,value in self.iter_items():yield value


def extract(source, spool_path=None):
    types = {r['name']: r for r in source.select('DocType', ['module', 'istable', 'issingle'])}
    fields = {}
    for table, parent in (('DocField', 'parent'), ('Custom Field', 'dt')):
        for row in source.sql(f'SELECT `{parent}` AS dt,fieldname,fieldtype,options,reqd FROM `tab{table}` ORDER BY idx'):
            fields.setdefault(row['dt'], {})[row['fieldname']] = row
    selected = {n for n, r in types.items() if r.get('module') in MODULES} | (EXTRA & set(types))
    # Include all child doctypes of selected business documents, recursively.
    pending = list(selected)
    while pending:
        name = pending.pop()
        for f in fields.get(name, {}).values():
            if f['fieldtype'] in ('Table', 'Table MultiSelect') and f.get('options') in types:
                child = f['options']
                if child not in selected:
                    selected.add(child)
                    pending.append(child)
    selected -= FORBIDDEN
    records, schemas = {}, {}
    spool=None
    count=0
    if spool_path:
        import os
        spool=sqlite3.connect(spool_path)
        os.chmod(spool_path,0o600)
        spool.execute('CREATE TABLE history (record_key TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    for name in sorted(selected):
        meta = types.get(name)
        if not meta or meta.get('issingle') or not source.has(name):
            continue
        allowed, omitted = [], []
        for f in fields.get(name, {}).values():
            if f['fieldtype'] == 'Password' or f['fieldname'].casefold() in SECRET_FIELDS:
                omitted.append(f['fieldname'])
            elif f['fieldtype'] not in LAYOUT:
                allowed.append({k: v for k, v in f.items() if k != 'dt'})
        columns = (SYSTEM | {f['fieldname'] for f in allowed}) & source.columns(name)
        if name == 'File':
            columns.discard('content')  # Attachment bytes use the verified blob transport.
        rows = source.select(name, sorted(columns))
        schemas[name] = {'doctype': name, 'module': meta.get('module'), 'istable': bool(meta.get('istable')),
                         'fields': allowed, 'omitted_secret_fields': sorted(omitted), 'count': len(rows)}
        link_fields={field['fieldname'] for field in allowed if field['fieldtype'] in ('Link','Dynamic Link')}
        for row in rows:
            row['name']=str(row['name'])
            for field in link_fields:
                if row.get(field) is not None:row[field]=str(row[field])
            item={'doctype': name, 'record': row}
            key=record_key(name,row['name'])
            if spool is not None:
                spool.execute('INSERT INTO history VALUES (?,?)',(key,json.dumps(item,ensure_ascii=False,default=str)))
            else:records[key]=item
            count+=1
    if spool is not None:
        spool.commit();spool.close()
        return DiskRecords(spool_path,count),schemas
    return records, schemas
