"""Sealed login-hash transport; plaintext credentials never enter ordinary snapshots."""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "vmms-login-envelope-v1"
MAX_PAYLOAD = 50 * 1024 * 1024


class LoginTransferError(Exception):
    pass


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _b64(value):
    return base64.b64encode(value).decode()


def public_key(pem):
    try:
        key = serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise LoginTransferError("Use a valid RSA recipient public key of at least 2048 bits.") from None


def fingerprint(pem):
    key = public_key(pem)
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def new_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public


def _header(source_id, snapshot_id, recipient):
    return {"format": FORMAT, "source_id": source_id, "snapshot_id": snapshot_id,
            "recipient_fingerprint": recipient}


def seal(password_hashes, pem, source_id, snapshot_id):
    payload = _json({"password_hashes": password_hashes})
    if len(payload) > MAX_PAYLOAD:
        raise LoginTransferError("The login bundle exceeds the supported size.")
    recipient = fingerprint(pem)
    header = _header(source_id, snapshot_id, recipient)
    aes_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, payload, _json(header))
    wrapped = public_key(pem).encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(), label=FORMAT.encode()))
    return {**header, "wrapped_key": _b64(wrapped), "nonce": _b64(nonce), "ciphertext": _b64(encrypted)}


def open_envelope(envelope, private_pem, source_id, snapshot_id):
    try:
        if len(_json(envelope)) > MAX_PAYLOAD * 2:
            raise ValueError()
        key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError()
        public = key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        expected = _header(source_id, snapshot_id, fingerprint(public))
        if any(envelope.get(k) != v for k, v in expected.items()):
            raise ValueError()
        decode = lambda field: base64.b64decode(envelope[field], validate=True)
        aes_key = key.decrypt(decode("wrapped_key"), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(), label=FORMAT.encode()))
        payload = AESGCM(aes_key).decrypt(decode("nonce"), decode("ciphertext"), _json(expected))
        hashes_by_user = json.loads(payload)["password_hashes"]
        if not isinstance(hashes_by_user, dict):
            raise ValueError()
        for name, hashed in hashes_by_user.items():
            if (not isinstance(name, str) or not isinstance(hashed, str)
                or name in ("Administrator", "Guest")
                or not hashed.startswith(("$pbkdf2-sha256$", "$argon2"))):
                raise ValueError()
        return hashes_by_user
    except Exception:
        # Do not include decrypted values, key material or ciphertext in errors.
        raise LoginTransferError("The login bundle could not be verified for this recipient and snapshot.") from None
