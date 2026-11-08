"""Resolve site overrides before deciding field types or child tables."""


def effective_fields(source):
    fields = {}
    for table, parent in (('DocField', 'parent'), ('Custom Field', 'dt')):
        for row in source.sql(f'SELECT `{parent}` AS dt,fieldname,label,fieldtype,options,reqd,hidden,read_only FROM `tab{table}` ORDER BY idx'):
            fields.setdefault(row['dt'], {})[row['fieldname']] = dict(row)
    if source.has('Property Setter'):
        allowed = {'fieldtype', 'options', 'label', 'reqd', 'hidden', 'read_only'}
        for prop in source.sql('SELECT doc_type,field_name,property,value,property_type FROM `tabProperty Setter` ORDER BY modified,name'):
            field = fields.get(prop['doc_type'], {}).get(prop['field_name'])
            if field is None or prop['property'] not in allowed:
                continue
            value = prop['value']
            if prop.get('property_type') in ('Check', 'Int'):
                try:
                    value = int(value or 0)
                except (ValueError, TypeError):
                    pass  # Keep unusual recorded metadata as evidence; never evaluate it.
            field[prop['property']] = value
    return fields
