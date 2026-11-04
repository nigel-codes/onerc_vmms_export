import json
from unittest import TestCase

from onerc_vmms_export import history, snapshot
from onerc_vmms_export.tests.test_history import Source


class ContinuitySource(Source):
    def __init__(self):
        super().__init__()
        for name, module in [('Version', 'Core'), ('Access Log', 'Core'),
                             ('Mpesa Express Request', 'Frappe Mpsa Payments')]:
            self.rows['DocType'].append({'name': name, 'module': module})
        self.rows['Version'] = [{'name': 'version', 'ref_doctype': 'User', 'docname': 'user',
            'data': json.dumps({'changed': [['private_secret', 'before', 'after'],
                                           ['title', 'Old', 'New']]})}]
        self.rows['Access Log'] = [{'name': 'access', 'reference_doctype': 'Employee'}]
        self.rows['Mpesa Express Request'] = [{'name': 'MEXP-old', 'status': 'Completed',
            'transaction_id': 'RECEIPT', 'amount': '100.00'}]

    def sql(self, query):
        rows = super().sql(query)
        if 'Custom Field' in query:
            return rows
        return rows + [
            {'dt': 'Version', 'fieldname': f, 'fieldtype': 'Code' if f == 'data' else 'Data'}
            for f in ['ref_doctype', 'docname', 'data']
        ] + [{'dt': 'Access Log', 'fieldname': 'reference_doctype', 'fieldtype': 'Data'}]


class TestContinuityCapture(TestCase):
    def test_navari_audit_and_full_user_evidence_are_included(self):
        records, schemas = history.extract(ContinuitySource())
        self.assertTrue({'Version', 'Access Log', 'User', 'Mpesa Express Request'} <= schemas.keys())
        payment = records[history.record_key('Mpesa Express Request', 'MEXP-old')]['record']
        self.assertEqual(payment['transaction_id'], 'RECEIPT')
        self.assertEqual(payment['amount'], '100.00')
        self.assertNotIn('reset_password_key', records[history.record_key('User', 'user')]['record'])

    def test_physical_source_only_column_survives_with_explicit_schema_evidence(self):
        records, schemas = history.extract(ContinuitySource())
        record = records[history.record_key('Buzz Event', 'old-event')]['record']
        self.assertEqual(record['unknown_column'], 'not exported')
        self.assertIn('unknown_column', schemas['Buzz Event']['physical_only_fields'])

    def test_nested_history_secret_changes_are_protected_and_public_changes_survive(self):
        records, _ = history.extract(ContinuitySource())
        raw = records[history.record_key('Version', 'version')]['record']['data']
        self.assertNotIn('before', raw)
        self.assertNotIn('after', raw)
        self.assertIn('Old', raw)
        self.assertIn('New', raw)

    def test_source_continuity_manifest_survives_transport_metadata_filter(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            snapshot.build(Path(folder), 'a' * 32, 'b' * 32, 'manager',
                {'source': {'continuity': {'version': 1, 'naming': {'counter': 31709}}}}, Path(folder))
            data = snapshot.page(Path(folder), 'a' * 32, 'source')['rows'][0]['data']
            self.assertEqual(data['continuity']['naming']['counter'], 31709)

    def test_retired_credential_columns_are_not_exposed_when_their_metadata_is_gone(self):
        source = ContinuitySource()
        source.rows['Buzz Event'][0]['retired_api_secret'] = 'must stay protected'
        records, schemas = history.extract(source)
        row = records[history.record_key('Buzz Event', 'old-event')]['record']
        self.assertNotIn('retired_api_secret', row)
        self.assertIn('retired_api_secret', schemas['Buzz Event']['omitted_secret_fields'])

    def test_unparsed_history_is_explicitly_held_for_protected_backup(self):
        source = ContinuitySource()
        source.rows['Version'][0]['data'] = 'unparsed sensitive original'
        records, schemas = history.extract(source)
        row = records[history.record_key('Version', 'version')]['record']
        self.assertNotIn('sensitive original', row['data'])
        self.assertEqual(schemas['Version']['protected_payload_errors'], 1)

    def test_serialized_json_inside_a_deletion_payload_is_also_protected(self):
        value = {'data': json.dumps({'changed': [['api_secret', 'sensitive-old', 'sensitive-new']]})}
        protected = history.protect_nested(value, history.SECRET_FIELDS)
        self.assertNotIn('sensitive-old', protected['data'])
        self.assertNotIn('sensitive-new', protected['data'])

    def test_original_field_labels_remain_available_for_future_history_display(self):
        source = ContinuitySource()
        original = source.sql
        def labelled(query):
            rows = original(query)
            for row in rows:
                if row.get('dt') == 'Buzz Event' and row.get('fieldname') == 'title':
                    row['label'] = 'Original mission label'
            return rows
        source.sql = labelled
        _, schemas = history.extract(source)
        field = next(f for f in schemas['Buzz Event']['fields'] if f['fieldname'] == 'title')
        self.assertEqual(field['label'], 'Original mission label')
