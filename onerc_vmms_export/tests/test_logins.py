import copy
import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock

from passlib.hash import pbkdf2_sha256
from onerc_vmms_export import login_crypto, logins, snapshot


class TestProtectedLogins(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private, cls.public = login_crypto.new_keypair()
        cls.password = "Synthetic-Login-Continuity-Only-1"
        cls.hashed = pbkdf2_sha256.hash(cls.password)

    def envelope(self):
        return login_crypto.seal({"volunteer@example.org": self.hashed}, self.public, "source", "a" * 32)

    def test_password_hash_survives_sealed_transport(self):
        envelope = self.envelope()
        self.assertNotIn(self.hashed, json.dumps(envelope))
        self.assertNotIn("volunteer@example.org", json.dumps(envelope))
        value = login_crypto.open_envelope(envelope, self.private, "source", "a" * 32)
        self.assertTrue(pbkdf2_sha256.verify(self.password, value["volunteer@example.org"]))

    def test_wrong_recipient_snapshot_source_and_tampering_are_rejected(self):
        envelope = self.envelope()
        wrong_private, _ = login_crypto.new_keypair()
        corrupt = copy.deepcopy(envelope)
        corrupt["ciphertext"] = "AAAA" + corrupt["ciphertext"][4:]
        for bundle, key, source, sid in ((envelope, wrong_private, "source", "a" * 32),
            (envelope, self.private, "other", "a" * 32),
            (envelope, self.private, "source", "b" * 32), (corrupt, self.private, "source", "a" * 32)):
            with self.assertRaises(login_crypto.LoginTransferError) as caught:
                login_crypto.open_envelope(bundle, key, source, sid)
            self.assertNotIn(self.hashed, str(caught.exception))

    def test_hosting_public_key_formats_preserve_recipient_and_transport(self):
        pem = self.public.decode()
        variants = [pem, pem.replace("\n", " "), pem.replace("\n", ""),
                    pem.replace("\n", "\\n"), pem.replace("\n", "\\r\\n")]
        for value in variants:
            with self.subTest(format=value[:30]):
                self.assertEqual(login_crypto.fingerprint(value), login_crypto.fingerprint(self.public))
                envelope = login_crypto.seal({"volunteer@example.org": self.hashed}, value, "source", "a" * 32)
                self.assertEqual(login_crypto.open_envelope(envelope, self.private, "source", "a" * 32),
                                 {"volunteer@example.org": self.hashed})

    def test_invalid_and_weak_recipient_keys_remain_rejected(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        keys = [rsa.generate_private_key(public_exponent=65537, key_size=1024),
                ec.generate_private_key(ec.SECP256R1())]
        invalid = [None, "", "-----BEGIN PUBLIC KEY----- invalid -----END PUBLIC KEY-----",
                   self.private]
        invalid += [key.public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo) for key in keys]
        for value in invalid:
            with self.assertRaises(login_crypto.LoginTransferError):
                login_crypto.public_key(value)

    def test_collection_is_limited_to_captured_users_and_local_hashes(self):
        source = MagicMock()
        source.tables.return_value = {"__Auth"}
        source.sql.return_value = [{"name": "included", "password": self.hashed}, {"name": "other", "password": self.hashed}]
        self.assertEqual(logins.collect(source, {"included": {}}), {"included": self.hashed})
        query = source.sql.call_args.args[0]
        self.assertIn("encrypted=0", query)
        self.assertIn("fieldname='password'", query)
        self.assertIn("'Administrator','Guest'", query)

    def test_snapshot_sqlite_does_not_contain_login_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sid = "a" * 32
            result = snapshot.build(root, sid, "source", "manager", {"source": {}, "password_hashes": {"volunteer@example.org": self.hashed}}, root,
                login_envelope=self.envelope(), login_metadata={"included": True, "users_with_password": 1,
                    "recipient_fingerprint": login_crypto.fingerprint(self.public)})
            folder = root / "snapshots" / sid
            self.assertNotIn(self.hashed.encode(), (folder / "snapshot.sqlite").read_bytes())
            self.assertNotIn(self.hashed, (folder / "login-envelope.json").read_text())
            self.assertTrue(result["logins"]["included"])
            self.assertTrue(result["include_logins"])
