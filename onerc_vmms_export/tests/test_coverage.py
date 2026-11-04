from unittest import TestCase
from onerc_vmms_export.coverage import inventory


class TestCoverage(TestCase):
    def test_uncaptured_tables_and_credentials_cannot_disappear_from_inventory(self):
        result = inventory(['tabUser', 'tabVersion', 'tabOther', '__Auth', 'tabSingles'],
            {'tabUser': ['name', 'api_key'], '__Auth': ['password']},
            {'User': {'count': 3, 'omitted_secret_fields': ['api_key']}, 'Version': {'count': 7}})
        self.assertEqual(result['tables']['tabOther']['disposition'], 'source_backup_required')
        self.assertEqual(result['tables']['__Auth']['disposition'], 'protected_backup_or_transfer')
        self.assertEqual(result['tables']['tabUser']['columns'], ['api_key', 'name'])
        self.assertEqual(result['tables']['tabVersion']['captured_rows'], 7)
        self.assertFalse(result['complete_source_preservation_proven'])

    def test_column_types_and_conditional_rule_evidence_are_captured(self):
        from onerc_vmms_export.coverage import capture
        class Source:
            db_name = 'restored'
            def tables(self): return ['tabUser']
            def sql(self, query, params=None):
                if 'property_type' in query:
                    return [{'field_name':'pin','property':'default','property_type':'Data','value':'private-default'}]
                return [{'t':'tabUser','c':'name','kind':'varchar(140)'}] if 'information_schema' in query else []
            def select(self, doctype, fields):
                return [{'name':'rule','document_type':'Employee','counter':42}] if doctype == 'Document Naming Rule' else []
            def children(self, doctype, field): return {'rule':[{'field':'company','value':'branch'}]}
        result = capture(Source(), {'User':{'count':1}})
        self.assertEqual(result['tables']['tabUser']['column_types']['name'], 'varchar(140)')
        self.assertEqual(result['naming']['rules'][0]['conditions'][0]['value'], 'branch')
        self.assertNotIn('private-default', result['property_setters'][0]['value'])
