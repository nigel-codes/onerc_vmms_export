"""Host-controlled opt-in password-hash export, encrypted to the pinned receiver."""
from onerc_vmms_export import login_crypto


def collect(source, users):
    """Read only local password hashes for users included in the snapshot."""
    if "__Auth" not in source.tables():
        return {}
    rows = source.sql("SELECT name,password FROM __Auth WHERE doctype='User' "
        "AND fieldname='password' AND encrypted=0 AND name NOT IN ('Administrator','Guest')")
    result = {}
    for row in rows:
        if row["name"] not in users:
            continue
        value = row["password"]
        if not isinstance(value, str) or not value.startswith(("$pbkdf2-sha256$", "$argon2")):
            raise login_crypto.LoginTransferError("A source account uses an unsupported password hash format.")
        result[row["name"]] = value
    return result


def audit(source):
    """Credential coverage only; no hashes, tokens or account names leave here."""
    if '__Auth' not in source.tables():
        return {'authentication_table_available': False}
    rows=source.sql("""SELECT COUNT(*) AS users,
        SUM(CASE WHEN a.name IS NOT NULL THEN 1 ELSE 0 END) AS with_local_password,
        SUM(CASE WHEN a.name IS NULL AND u.enabled=1 THEN 1 ELSE 0 END) AS enabled_without_local_password,
        SUM(CASE WHEN a.name IS NULL AND u.last_login IS NOT NULL
            AND u.last_login != '0000-00-00 00:00:00' THEN 1 ELSE 0 END) AS previously_signed_in_without_local_password
        FROM tabUser u LEFT JOIN __Auth a ON a.name=u.name AND a.doctype='User'
            AND a.fieldname='password' AND a.encrypted=0
        WHERE u.name NOT IN ('Administrator','Guest')""")
    return {'authentication_table_available':True,**{k:int(v or 0) for k,v in rows[0].items()},
        'authentication_policy':authentication_policy(source)}


def authentication_policy(source):
    """Non-secret login method settings; no provider credentials or OTP seeds."""
    fields=('login_with_email_link','login_with_email_link_expiry','rate_limit_email_link_login',
        'allow_login_using_user_name','allow_login_using_mobile_number','enable_two_factor_auth')
    values={}
    if 'tabSingles' in source.tables():
        rows=source.sql('SELECT field,value FROM tabSingles WHERE doctype=%s AND field IN ('+
            ','.join(['%s']*len(fields))+')',('System Settings',*fields))
        values={row['field']:row['value'] for row in rows}
    result={field:int(str(values.get(field) or '0').lower() in ('1','true')) for field in fields
        if field not in ('login_with_email_link_expiry','rate_limit_email_link_login')}
    for field,default in (('login_with_email_link_expiry',10),('rate_limit_email_link_login',5)):
        try:result[field]=max(1,int(values.get(field) or default))
        except (ValueError,TypeError):result[field]=default
    return result
