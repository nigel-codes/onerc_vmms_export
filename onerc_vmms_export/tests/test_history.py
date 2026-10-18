from unittest import TestCase
import tempfile
from pathlib import Path
from onerc_vmms_export import history


class Source:
    def __init__(self):
        self.rows={'DocType':[
            {'name':'Buzz Event','module':'Events'},
            {'name':'Event Child','module':'Something Else','istable':1},
            {'name':'User','module':'Volunteer and Member Management'},
            {'name':'Unrelated','module':'Something Else'}],
            'Buzz Event':[{'name':'old-event','title':'Mission','private_secret':'sensitive',
                'api_key':'sensitive','unknown_column':'not exported','docstatus':1}],
            'Event Child':[{'name':'child','parent':'old-event','parenttype':'Buzz Event','parentfield':'schedule','idx':2,'title':'Briefing'}],
            'User':[{'name':'user','reset_password_key':'sensitive'}],
            'Unrelated':[{'name':'other'}]}
    def select(self,doctype,fields):
        return [{k:r.get(k) for k in ['name',*fields] if k in r} for r in self.rows.get(doctype,[])]
    def columns(self,doctype):
        return set().union(*(r.keys() for r in self.rows.get(doctype,[])))
    def has(self,doctype):
        return doctype in self.rows
    def sql(self,query):
        if 'Custom Field' in query:return []
        return [{'dt':'Buzz Event','fieldname':'title','fieldtype':'Data'},
            {'dt':'Buzz Event','fieldname':'schedule','fieldtype':'Table','options':'Event Child'},
            {'dt':'Buzz Event','fieldname':'private_secret','fieldtype':'Password'},
            {'dt':'Buzz Event','fieldname':'api_key','fieldtype':'Data'},
            {'dt':'Event Child','fieldname':'title','fieldtype':'Data'}]


class TestHistoryScope(TestCase):
    def test_business_scope_includes_children_without_authentication_or_unknown_columns(self):
        records,schemas=history.extract(Source())
        self.assertEqual(set(schemas),{'Buzz Event','Event Child'})
        self.assertEqual(len(records),2)
        event=records[history.record_key('Buzz Event','old-event')]['record']
        self.assertEqual(event,{'name':'old-event','title':'Mission','docstatus':1})
        self.assertEqual(schemas['Buzz Event']['omitted_secret_fields'],['api_key','private_secret'])
        child=records[history.record_key('Event Child','child')]['record']
        self.assertEqual(child['parent'],'old-event')
        self.assertEqual(child['idx'],2)

    def test_record_identity_includes_doctype_and_preserves_unicode_and_case(self):
        keys={history.record_key(dt,name) for dt,name in [('One','id'),('Two','id'),('One','ID'),('One','íd')]}
        self.assertEqual(len(keys),4)

    def test_spooled_export_matches_in_memory_rows_and_snapshot_protocol(self):
        from onerc_vmms_export import snapshot
        expected,schemas=history.extract(Source())
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            stored,stored_schemas=history.extract(Source(),path/'spool.sqlite')
            self.assertEqual(stored_schemas,schemas)
            self.assertEqual(len(stored),len(expected))
            self.assertEqual(dict(stored.iter_items()),expected)
            result=snapshot.build(path/'exports','a'*32,'b'*32,'manager',
                {'source':{},'history':stored,'schemas':stored_schemas},path)
            self.assertEqual(result['counts']['history'],len(expected))
            self.assertEqual(len(snapshot.page(path/'exports','a'*32,'history')['rows']),2)
