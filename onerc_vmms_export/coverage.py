"""Complete schema obligations, independent of the business export allowlist."""
from collections import defaultdict


def inventory(tables, columns, schemas):
    result = {}
    for table in sorted(tables):
        doctype = table[3:] if table.startswith('tab') else None
        captured = schemas.get(doctype)
        disposition = 'captured_history' if captured is not None else 'source_backup_required'
        if table == '__Auth' or table in ('tabSessions', 'tabToken Cache'):
            disposition = 'protected_backup_or_transfer'
        result[table] = {'columns': sorted(columns.get(table, [])), 'disposition': disposition,
                         'captured_rows': captured.get('count') if captured is not None else None,
                         'protected_fields': captured.get('omitted_secret_fields', []) if captured else []}
    return {'version': 1, 'tables': result,
            'complete_source_preservation_proven': False,
            'remaining_requirement': 'Retain and verify a complete sealed source backup, and review every uncaptured table and protected field.'}


def capture(source, schemas):
    from onerc_vmms_export.history import SECRET_FIELDS, sensitive
    columns = defaultdict(list)
    types = defaultdict(dict)
    for row in source.sql('SELECT TABLE_NAME AS t,COLUMN_NAME AS c,COLUMN_TYPE AS kind FROM information_schema.COLUMNS '
                          'WHERE TABLE_SCHEMA=%s ORDER BY TABLE_NAME,ORDINAL_POSITION', (source.db_name,)):
        columns[row['t']].append(row['c'])
        types[row['t']][row['c']] = row['kind']
    result = inventory(source.tables(), columns, schemas)
    for table in result['tables']:
        result['tables'][table]['column_types'] = types[table]
    result['property_setters'] = source.sql(
        'SELECT doc_type,field_name,property,value,property_type FROM `tabProperty Setter`')
    for prop in result['property_setters']:
        if prop.get('property') == 'default' or prop.get('property_type') == 'Password' or sensitive(prop.get('field_name') or '', SECRET_FIELDS):
            prop['value'] = '[protected; original requires sealed source backup]'
    result['naming'] = {
        'rules': source.select('Document Naming Rule',
            ['document_type', 'disabled', 'priority', 'prefix', 'counter', 'prefix_digits']),
        'series': source.select('Series', ['current']),
    }
    result['naming']['properties'] = source.sql(
        "SELECT doc_type,field_name,property,value FROM `tabProperty Setter` "
        "WHERE field_name='naming_series' OR property IN ('autoname','naming_rule')")
    result['naming']['fields'] = source.sql(
        "SELECT parent,`default`,options FROM `tabDocField` WHERE fieldname='naming_series'")
    conditions = source.children('Document Naming Rule', 'conditions')
    for rule in result['naming']['rules']:
        rule['conditions'] = conditions.get(rule['name'], [])
    return result
