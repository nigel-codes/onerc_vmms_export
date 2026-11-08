"""An effective table override must govern both child rows and history schema."""
import sqlite3
from unittest import TestCase

from onerc_vmms_export.reader import DatabaseSource
from onerc_vmms_export import extract, history


class Source(DatabaseSource):
    def __init__(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        for table,parent in [('DocField','parent'),('Custom Field','dt')]:
            self.db.execute('CREATE TABLE `tab'+table+'` ('+parent+' TEXT,fieldname TEXT,label TEXT,fieldtype TEXT,options TEXT,reqd INTEGER,hidden INTEGER,read_only INTEGER,idx INTEGER)')
        self.db.execute('CREATE TABLE `tabProperty Setter` (doc_type TEXT,field_name TEXT,property TEXT,value TEXT,property_type TEXT,modified TEXT,name TEXT)')
        self.db.execute("INSERT INTO `tabCustom Field` VALUES ('User','education','Education','Table','Education Detail',0,0,0,1)")
        self.db.execute("INSERT INTO `tabProperty Setter` VALUES ('User','education','options','Employee Education','Data','2026-01-01','setter')")
        self.db.execute('CREATE TABLE `tabEmployee Education` (name TEXT,parent TEXT,parenttype TEXT,parentfield TEXT,idx INTEGER,school_univ TEXT)')
        self.db.execute("INSERT INTO `tabEmployee Education` VALUES ('ED','user','User','education',1,'Original school')")
    def sql(self,query,params=None):return [dict(row) for row in self.db.execute(query.replace('%s','?'),params or ())]
    def has(self,doctype):return bool(self.db.execute("SELECT name FROM sqlite_master WHERE name=?",('tab'+doctype,)).fetchone())


class TestEffectiveMetadata(TestCase):
    def setUp(self):
        self.source=Source();self.addCleanup(self.source.db.close)

    def test_property_setter_selects_actual_child_type_and_keeps_original_row(self):
        self.assertEqual(self.source.child_doctype('User','education'),'Employee Education')
        self.assertEqual(self.source.children('User','education'),{'user':[{'name':'ED','school_univ':'Original school'}]})

    def test_new_extraction_contract_names_social_links_and_employee_profession(self):
        for field in ('linkedin','github'):
            self.assertIn(field,extract.USER_FIELDS);self.assertIn(field,extract.APPLICANT_FIELDS)
        self.assertIn('custom_profession',extract.EMPLOYEE_FIELDS)

    def test_history_uses_effective_table_options_too(self):
        from onerc_vmms_export.tests.test_history import Source as HistorySource
        source=HistorySource();source.rows['Property Setter']=[]
        original=source.sql
        def sql(query,params=None):
            if 'Property Setter' in query:return [{'doc_type':'Buzz Event','field_name':'schedule','property':'options','value':'Override Child','property_type':'Data'}]
            return original(query)
        source.sql=sql
        source.rows['DocType'].append({'name':'Override Child','module':'Other','istable':1})
        source.rows['Override Child']=[{'name':'row','parent':'old-event','parenttype':'Buzz Event','parentfield':'schedule'}]
        _,schemas=history.extract(source)
        self.assertIn('Override Child',schemas)
        field=next(f for f in schemas['Buzz Event']['fields'] if f['fieldname']=='schedule')
        self.assertEqual(field['options'],'Override Child')

    def test_transport_keeps_the_person_mapping_capture_version(self):
        import tempfile
        from pathlib import Path
        from onerc_vmms_export import snapshot
        with tempfile.TemporaryDirectory() as folder:
            snapshot.build(Path(folder),'a'*32,'b'*32,'manager',{'source':{'profile_mapping_version':2}},Path(folder))
            result=snapshot.page(Path(folder),'a'*32,'source')['rows'][0]['data']
            self.assertEqual(result.get('profile_mapping_version'),2)
