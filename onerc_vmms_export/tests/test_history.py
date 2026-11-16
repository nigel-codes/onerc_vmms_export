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
    def test_business_scope_preserves_users_and_physical_columns_without_credentials(self):
        records,schemas=history.extract(Source())
        self.assertEqual(set(schemas),{'Buzz Event','Event Child','User'})
        self.assertEqual(len(records),3)
        event=records[history.record_key('Buzz Event','old-event')]['record']
        self.assertEqual(event,{'name':'old-event','title':'Mission','docstatus':1,'unknown_column':'not exported'})
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
            self.assertEqual(len(snapshot.page(path/'exports','a'*32,'history')['rows']),len(expected))


class HelpdeskSource(Source):
    """An old site with helpdesk: tickets, their comments and settings."""
    def __init__(self):
        super().__init__()
        self.rows['DocType'] += [
            {'name':'HD Ticket','module':'Helpdesk'},
            {'name':'HD Ticket Comment','module':'Helpdesk'},
            {'name':'HD Team','module':'Helpdesk'},
            {'name':'HD Team Member','module':'Helpdesk','istable':1},
            {'name':'HD Settings','module':'Helpdesk','issingle':1},
            {'name':'Communication','module':'Core'},
            {'name':'Comment','module':'Core'}]
        self.rows.update({
            'HD Ticket':[{'name':16856,'subject':'Login','raised_by':'a@x.org','key':'portal-key','_assign':'["agent@x.org"]'}],
            'HD Ticket Comment':[{'name':'k1','reference_ticket':'16856','content':'note'}],
            'HD Team':[{'name':'NAVARI','team_name':'NAVARI'}],
            'HD Team Member':[{'name':1,'parent':'NAVARI','parenttype':'HD Team','parentfield':'users','user':'agent@x.org'}],
            'HD Settings':[{'name':'HD Settings'}],
            'Communication':[{'name':'c1','reference_doctype':'HD Ticket','reference_name':'16856'},
                             {'name':'c2','reference_doctype':'Job Applicant','reference_name':'a'}],
            'Comment':[{'name':'k1','reference_doctype':'HD Ticket','reference_name':'16856','comment_type':'Comment'}]})
    def sql(self,query):
        if 'Custom Field' in query:return []
        return super().sql(query)+[
            {'dt':'HD Ticket','fieldname':'subject','fieldtype':'Data'},
            {'dt':'HD Ticket','fieldname':'key','fieldtype':'Data'},
            {'dt':'HD Team','fieldname':'users','fieldtype':'Table MultiSelect','options':'HD Team Member'}]


class TestHelpdeskScope(TestCase):
    def test_helpdesk_records_are_captured_with_their_threads(self):
        records,schemas=history.extract(HelpdeskSource())
        for doctype in ('HD Ticket','HD Ticket Comment','HD Team','HD Team Member','Communication','Comment'):
            self.assertIn(doctype,schemas)
        self.assertNotIn('HD Settings',schemas)  # singles stay out
        ticket=records[history.record_key('HD Ticket','16856')]['record']
        self.assertEqual(ticket['name'],'16856')  # names travel as text
        self.assertEqual(ticket['key'],'portal-key')
        self.assertEqual(ticket['_assign'],'["agent@x.org"]')
        member=records[history.record_key('HD Team Member','1')]['record']
        self.assertEqual((member['parent'],member['user']),('NAVARI','agent@x.org'))
        # Whole tables, as before: the receiver keeps the ticket rows.
        self.assertIn(history.record_key('Communication','c2'),records)
