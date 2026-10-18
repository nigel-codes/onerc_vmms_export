from unittest import TestCase
from onerc_vmms_export.logins import authentication_policy


class TestSafeLoginPolicy(TestCase):
    def test_only_nonsecret_authentication_flags_are_requested(self):
        calls=[]
        class Source:
            def tables(self):return {'tabSingles'}
            def sql(self,query,params):
                calls.append((query,params))
                return [{'field':'login_with_email_link','value':'1'},
                    {'field':'login_with_email_link_expiry','value':'20'},
                    {'field':'enable_two_factor_auth','value':'0'}]
        policy=authentication_policy(Source())
        self.assertEqual(policy['login_with_email_link'],1)
        self.assertEqual(policy['login_with_email_link_expiry'],20)
        self.assertEqual(policy['enable_two_factor_auth'],0)
        self.assertEqual(calls[0][1][0],'System Settings')
        self.assertFalse(any('password' in field or 'secret' in field for field in calls[0][1][1:]))
