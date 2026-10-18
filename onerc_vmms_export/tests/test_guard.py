from unittest import TestCase
from onerc_vmms_export.guard import allowed


class TestSourceCutoverFreeze(TestCase):
    def test_default_does_not_change_site_functionality(self):
        for path in ('/','/api/resource/Employee','/api/method/frappe.client.insert'):
            self.assertTrue(allowed(path,None))
            self.assertTrue(allowed(path,'0'))

    def test_freeze_leaves_only_protected_export_methods_open(self):
        self.assertTrue(allowed('/api/method/onerc_vmms_export.api.create_snapshot',1))
        self.assertFalse(allowed('/api/method/frappe.client.insert',1))
        self.assertFalse(allowed('/api/resource/User',1))
        self.assertFalse(allowed('/api/method/frappe.auth.get_logged_user',1))
        self.assertFalse(allowed('/',1))
