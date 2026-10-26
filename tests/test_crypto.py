"""
tests/test_crypto.py
====================
Unit tests for core/crypto.py.

Each test is named to match a specific security requirement so you can
point to it during a viva and explain exactly what it proves.

Run with:
    (venv) python -m pytest tests/test_crypto.py -v
or with unittest:
    (venv) python -m unittest tests.test_crypto -v
"""

import json
import sys
import unittest
from pathlib import Path

# Make sure the package root is importable when tests are run from any CWD
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto import (
    VaultCorruptedError,
    build_aad,
    decrypt_vault,
    derive_enc_key,
    derive_key,
    encrypt_vault,
    hash_master,
    verify_master,
    wipe_key,
)


# ---------------------------------------------------------------------------
# Helper – build a minimal vault-header dict matching vault.json format
# ---------------------------------------------------------------------------

def _make_header(auth_salt_b64: str = "AAAA", enc_salt_b64: str = "BBBB") -> dict:
    """Return a minimal header dict with base64 salt strings."""
    return {
        "version": 1,
        "kdf": {"algorithm": "PBKDF2-HMAC-SHA256", "iterations": 600_000},
        "auth": {"salt": auth_salt_b64},
        "enc": {"salt": enc_salt_b64},
    }


# ---------------------------------------------------------------------------
# 1. Key Derivation
# ---------------------------------------------------------------------------

class TestDeriveKey(unittest.TestCase):
    """PBKDF2-HMAC-SHA256 derivation correctness and properties."""

    def test_output_is_32_bytes_by_default(self):
        """derive_key must return exactly 32 bytes (AES-256 key size)."""
        key = derive_key("password", b"saltsalt")
        self.assertEqual(len(key), 32)

    def test_same_inputs_produce_same_output(self):
        """PBKDF2 is deterministic: same password + salt → same key."""
        k1 = derive_key("MyP@ssword", b"randomsalt")
        k2 = derive_key("MyP@ssword", b"randomsalt")
        self.assertEqual(k1, k2)

    def test_different_passwords_produce_different_keys(self):
        """Different passwords must produce different keys (obvious, but worth asserting)."""
        k1 = derive_key("password1", b"same_salt")
        k2 = derive_key("password2", b"same_salt")
        self.assertNotEqual(k1, k2)

    def test_different_salts_produce_different_keys(self):
        """Same password with different salts must produce different keys.
        This proves that salts defeat rainbow-table / pre-computation attacks."""
        k1 = derive_key("same_password", b"salt_one_")
        k2 = derive_key("same_password", b"salt_two_")
        self.assertNotEqual(k1, k2)

    def test_output_type_is_bytes(self):
        """Return type must be bytes, not str or bytearray."""
        key = derive_key("pwd", b"s" * 16)
        self.assertIsInstance(key, bytes)


# ---------------------------------------------------------------------------
# 2. Authentication Hashing
# ---------------------------------------------------------------------------

class TestHashAndVerifyMaster(unittest.TestCase):
    """hash_master / verify_master correctness."""

    def test_hash_master_returns_salt_and_hash(self):
        """hash_master must return a (salt, hash) tuple, both 32 bytes."""
        salt, h = hash_master("MyMasterPassword123!")
        self.assertIsInstance(salt, bytes)
        self.assertIsInstance(h, bytes)
        self.assertEqual(len(salt), 16)   # AUTH_SALT_SIZE
        self.assertEqual(len(h), 32)      # KEY_LENGTH

    def test_two_calls_produce_different_salts(self):
        """Every call to hash_master must generate a fresh random salt.
        Same password → different hashes because the salt differs."""
        salt1, h1 = hash_master("SamePwd99!")
        salt2, h2 = hash_master("SamePwd99!")
        self.assertNotEqual(salt1, salt2, "Salts should be random, not reused")
        self.assertNotEqual(h1, h2, "Hashes should differ due to different salts")

    def test_verify_correct_password_returns_true(self):
        """verify_master must return True when the correct password is given."""
        pwd = "CorrectHorse#Battery99"
        salt, h = hash_master(pwd)
        self.assertTrue(verify_master(pwd, salt, h))

    def test_verify_wrong_password_returns_false(self):
        """verify_master must return False for any wrong password.
        This is the core gate of the login screen."""
        salt, h = hash_master("RealPassword1!")
        self.assertFalse(verify_master("WrongPassword1!", salt, h))

    def test_verify_empty_string_returns_false(self):
        """An empty string must not pass verification."""
        salt, h = hash_master("ActualPassword1!")
        self.assertFalse(verify_master("", salt, h))


# ---------------------------------------------------------------------------
# 3. Encryption Key Derivation
# ---------------------------------------------------------------------------

class TestDeriveEncKey(unittest.TestCase):
    """derive_enc_key: second PBKDF2 run, returns mutable bytearray."""

    def test_returns_bytearray_of_32_bytes(self):
        """The enc key must be a bytearray (mutable) of exactly 32 bytes."""
        key = derive_enc_key("password", b"enc_salt_16bytes")
        self.assertIsInstance(key, bytearray)
        self.assertEqual(len(key), 32)

    def test_enc_key_differs_from_auth_hash_for_same_password(self):
        """SECURITY: auth hash and enc key must be different values.
        They use different salts, so even the same password yields
        two independent outputs. This ensures the key is never stored."""
        pwd = "SharedPassword1!"
        auth_salt = b"auth_salt_______"   # 16 bytes
        enc_salt  = b"enc__salt_______"   # 16 bytes  (different!)
        _, auth_hash = hash_master.__wrapped__(pwd, auth_salt) if hasattr(hash_master, '__wrapped__') else (auth_salt, derive_key(pwd, auth_salt))
        enc_key = derive_enc_key(pwd, enc_salt)
        # The two outputs must be different (different salts → independent)
        self.assertNotEqual(bytes(enc_key), auth_hash)

    def test_wipe_key_zeroes_bytearray(self):
        """wipe_key must overwrite every byte with 0x00."""
        key = derive_enc_key("pwd", b"s" * 16)
        wipe_key(key)
        self.assertEqual(key, bytearray(32), "All bytes should be 0 after wipe")


# ---------------------------------------------------------------------------
# 4. AAD Construction
# ---------------------------------------------------------------------------

class TestBuildAAD(unittest.TestCase):
    """build_aad must be deterministic and change when header fields change."""

    def test_deterministic_for_same_header(self):
        """Same header → same AAD bytes (needed so encrypt and decrypt agree)."""
        hdr = _make_header()
        self.assertEqual(build_aad(hdr), build_aad(hdr))

    def test_changes_when_version_changes(self):
        """Changing the version field must produce a different AAD.
        This means downgrade attacks are caught by GCM tag verification."""
        hdr1 = _make_header()
        hdr2 = {**hdr1, "version": 99}
        self.assertNotEqual(build_aad(hdr1), build_aad(hdr2))

    def test_changes_when_auth_salt_changes(self):
        """Swapping the auth salt must change the AAD → tag mismatch on decrypt."""
        hdr1 = _make_header(auth_salt_b64="AAAA")
        hdr2 = _make_header(auth_salt_b64="ZZZZ")
        self.assertNotEqual(build_aad(hdr1), build_aad(hdr2))

    def test_changes_when_enc_salt_changes(self):
        """Swapping the enc salt must change the AAD → tag mismatch on decrypt."""
        hdr1 = _make_header(enc_salt_b64="BBBB")
        hdr2 = _make_header(enc_salt_b64="CCCC")
        self.assertNotEqual(build_aad(hdr1), build_aad(hdr2))

    def test_returns_bytes(self):
        """AAD must be bytes (required by pycryptodome AES-GCM update())."""
        aad = build_aad(_make_header())
        self.assertIsInstance(aad, bytes)


# ---------------------------------------------------------------------------
# 5. Encrypt → Decrypt Round-Trip
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundTrip(unittest.TestCase):
    """The most important test: encrypt then decrypt returns original data."""

    def setUp(self):
        """Create a fresh key and AAD for each test."""
        from Crypto.Random import get_random_bytes
        self.key = bytearray(get_random_bytes(32))
        self.aad = build_aad(_make_header())
        self.plaintext = b'[{"id":"1","site":"github.com","password":"s3cr3t"}]'

    def test_round_trip_returns_original_data(self):
        """encrypt then decrypt must return exactly the original plaintext."""
        nonce, tag, ct = encrypt_vault(self.plaintext, self.key, self.aad)
        result = decrypt_vault(ct, tag, nonce, self.key, self.aad)
        self.assertEqual(result, self.plaintext)

    def test_round_trip_with_empty_plaintext(self):
        """Edge case: an empty vault (empty list '[]') must round-trip."""
        pt = b"[]"
        nonce, tag, ct = encrypt_vault(pt, self.key, self.aad)
        result = decrypt_vault(ct, tag, nonce, self.key, self.aad)
        self.assertEqual(result, pt)

    def test_round_trip_with_unicode_content(self):
        """Vault entries may contain Unicode (emoji, non-ASCII site names)."""
        pt = '[{"site":"例え.jp","password":"密码🔑"}]'.encode("utf-8")
        nonce, tag, ct = encrypt_vault(pt, self.key, self.aad)
        result = decrypt_vault(ct, tag, nonce, self.key, self.aad)
        self.assertEqual(result, pt)


# ---------------------------------------------------------------------------
# 6. Wrong Password Fails to Unlock
# ---------------------------------------------------------------------------

class TestWrongPasswordFails(unittest.TestCase):
    """A wrong master password must produce a wrong key → tag mismatch."""

    def test_wrong_password_raises_vault_corrupted_error(self):
        """
        SECURITY: if an attacker (or typo) provides the wrong password,
        derive_enc_key produces a different key. AES-GCM tag verification
        then fails and we raise VaultCorruptedError. The plaintext is never
        returned.
        """
        from Crypto.Random import get_random_bytes
        aad = build_aad(_make_header())
        correct_key = bytearray(get_random_bytes(32))
        wrong_key   = bytearray(get_random_bytes(32))  # different random key

        plaintext = b'[{"site":"secret.com","password":"topsecret"}]'
        nonce, tag, ct = encrypt_vault(plaintext, correct_key, aad)

        with self.assertRaises(VaultCorruptedError):
            decrypt_vault(ct, tag, nonce, wrong_key, aad)


# ---------------------------------------------------------------------------
# 7. Tampered Ciphertext is Detected
# ---------------------------------------------------------------------------

class TestTamperDetection(unittest.TestCase):
    """GCM must detect any modification to ciphertext, tag, or AAD."""

    def setUp(self):
        from Crypto.Random import get_random_bytes
        self.key = bytearray(get_random_bytes(32))
        self.aad = build_aad(_make_header())
        self.pt  = b'[{"id":"abc","password":"hunter2"}]'
        self.nonce, self.tag, self.ct = encrypt_vault(self.pt, self.key, self.aad)

    def test_flip_one_byte_in_ciphertext_raises_error(self):
        """Flipping a single bit in the ciphertext must invalidate the tag."""
        bad_ct = bytearray(self.ct)
        bad_ct[0] ^= 0xFF          # flip all bits of first byte
        with self.assertRaises(VaultCorruptedError):
            decrypt_vault(bytes(bad_ct), self.tag, self.nonce, self.key, self.aad)

    def test_flip_one_byte_in_tag_raises_error(self):
        """Flipping a byte in the GCM tag itself must also raise an error."""
        bad_tag = bytearray(self.tag)
        bad_tag[0] ^= 0x01
        with self.assertRaises(VaultCorruptedError):
            decrypt_vault(self.ct, bytes(bad_tag), self.nonce, self.key, self.aad)

    def test_tampered_aad_raises_error(self):
        """
        SECURITY: changing the header (version, iteration count, salts)
        must be detected. This prevents downgrade attacks where an attacker
        lowers the iteration count to speed up brute force.
        """
        tampered_header = _make_header()
        tampered_header["version"] = 999          # simulated downgrade
        bad_aad = build_aad(tampered_header)
        with self.assertRaises(VaultCorruptedError):
            decrypt_vault(self.ct, self.tag, self.nonce, self.key, bad_aad)

    def test_truncated_ciphertext_raises_error(self):
        """Truncated ciphertext (e.g., partial write) must raise an error."""
        with self.assertRaises((VaultCorruptedError, ValueError)):
            decrypt_vault(self.ct[:-4], self.tag, self.nonce, self.key, self.aad)

    def test_empty_ciphertext_raises_error(self):
        """Completely empty ciphertext must not return garbage data."""
        with self.assertRaises((VaultCorruptedError, ValueError)):
            decrypt_vault(b"", self.tag, self.nonce, self.key, self.aad)


# ---------------------------------------------------------------------------
# 8. Nonce Uniqueness — Two Saves Produce Different Nonces and Ciphertexts
# ---------------------------------------------------------------------------

class TestNonceUniqueness(unittest.TestCase):
    """
    CRITICAL SECURITY: AES-GCM is broken if a (key, nonce) pair is reused.
    Verify that every call to encrypt_vault generates a fresh nonce.
    """

    def test_two_encryptions_of_same_data_produce_different_nonces(self):
        """Even identical plaintext must produce a different nonce each time."""
        from Crypto.Random import get_random_bytes
        key = bytearray(get_random_bytes(32))
        aad = build_aad(_make_header())
        pt  = b'[{"same":"data"}]'

        nonce1, tag1, ct1 = encrypt_vault(pt, key, aad)
        nonce2, tag2, ct2 = encrypt_vault(pt, key, aad)

        self.assertNotEqual(nonce1, nonce2, "Nonces must never be reused")

    def test_two_encryptions_of_same_data_produce_different_ciphertexts(self):
        """Different nonces → different ciphertexts (even for identical input).
        This is semantic security: an attacker cannot tell if two ciphertexts
        encode the same plaintext."""
        from Crypto.Random import get_random_bytes
        key = bytearray(get_random_bytes(32))
        aad = build_aad(_make_header())
        pt  = b'[{"same":"data"}]'

        _, _, ct1 = encrypt_vault(pt, key, aad)
        _, _, ct2 = encrypt_vault(pt, key, aad)

        self.assertNotEqual(ct1, ct2, "Different nonces must yield different ciphertexts")


# ---------------------------------------------------------------------------
# 9. VaultCorruptedError is a proper Exception subclass
# ---------------------------------------------------------------------------

class TestVaultCorruptedError(unittest.TestCase):
    """VaultCorruptedError must be catchable as a standard Exception."""

    def test_is_exception_subclass(self):
        err = VaultCorruptedError("test")
        self.assertIsInstance(err, Exception)

    def test_message_is_preserved(self):
        msg = "vault is tampered"
        err = VaultCorruptedError(msg)
        self.assertIn(msg, str(err))


if __name__ == "__main__":
    unittest.main(verbosity=2)
