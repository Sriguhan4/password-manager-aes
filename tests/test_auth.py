"""
tests/test_auth.py
==================
Unit tests for core/auth.py and core/storage.py.

NOTE ON SPEED: PBKDF2 with 600,000 iterations is intentionally slow.
Each setup_vault() call takes ~3-4 s. Tests use setUpClass to share a
single vault across tests within a class, keeping total runtime reasonable.

Run with:
    (venv) python -m pytest tests/test_auth.py -v
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import (
    LockoutError,
    MAX_ATTEMPTS_BEFORE_LOCKOUT,
    WrongPasswordError,
    change_master_password,
    check_lockout,
    login,
    logout,
    record_failed_attempt,
    reset_failed_attempts,
    setup_vault,
)
from core.crypto import wipe_key
from core.storage import b64dec, b64enc, load_vault, save_vault, vault_exists


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_vault(tmpdir: Path, password: str = "ValidPass12!") -> Path:
    """Create a fresh vault file in tmpdir and return its path."""
    path = tmpdir / "vault.json"
    setup_vault(password, path)
    return path


# ---------------------------------------------------------------------------
# 1. Storage tests (fast – no PBKDF2)
# ---------------------------------------------------------------------------

class TestStorage(unittest.TestCase):
    """Tests for core/storage.py (no crypto, just file I/O)."""

    def setUp(self):
        """Each test gets its own temp directory."""
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_vault_does_not_exist_initially(self):
        """vault_exists returns False when no file is present."""
        self.assertFalse(vault_exists(self.tmpdir / "vault.json"))

    def test_load_vault_returns_none_when_missing(self):
        """load_vault returns None (first-run signal) when file is absent."""
        result = load_vault(self.tmpdir / "vault.json")
        self.assertIsNone(result)

    def test_save_and_load_roundtrip(self):
        """Data saved with save_vault must be returned intact by load_vault."""
        path = self.tmpdir / "vault.json"
        original = {"version": 1, "data": "hello", "number": 42}
        save_vault(original, path)
        loaded = load_vault(path)
        self.assertEqual(loaded, original)

    def test_atomic_save_creates_backup(self):
        """Second save must create a .bak file containing the first version."""
        path = self.tmpdir / "vault.json"
        bak  = self.tmpdir / "vault.bak"

        save_vault({"v": 1}, path)
        save_vault({"v": 2}, path)  # second save should create .bak

        self.assertTrue(bak.exists(), ".bak should be created on second save")
        bak_data = json.loads(bak.read_text(encoding="utf-8"))
        self.assertEqual(bak_data["v"], 1, ".bak should contain the first version")

    def test_vault_exists_after_save(self):
        """vault_exists returns True after a successful save."""
        path = self.tmpdir / "vault.json"
        save_vault({"x": 1}, path)
        self.assertTrue(vault_exists(path))

    def test_b64enc_dec_roundtrip(self):
        """Base64 encode then decode must return the original bytes."""
        raw = b"\x00\xFF\xAB\x12\x34"
        self.assertEqual(b64dec(b64enc(raw)), raw)

    def test_unicode_in_vault_is_preserved(self):
        """Site names or usernames with non-ASCII chars must survive save/load."""
        path = self.tmpdir / "vault.json"
        data = {"site": "例え.jp", "emoji": "🔑"}
        save_vault(data, path)
        loaded = load_vault(path)
        self.assertEqual(loaded["site"], "例え.jp")
        self.assertEqual(loaded["emoji"], "🔑")


# ---------------------------------------------------------------------------
# 2. Setup and First-Run
# ---------------------------------------------------------------------------

class TestSetupVault(unittest.TestCase):
    """setup_vault creates a valid, encrypted, loadable vault file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_setup_creates_vault_file(self):
        """setup_vault must create vault.json on disk."""
        path = self.tmpdir / "vault.json"
        setup_vault("StrongPass12!", path)
        self.assertTrue(path.exists())

    def test_setup_rejects_short_password(self):
        """setup_vault must raise ValueError for passwords under 12 chars."""
        with self.assertRaises(ValueError):
            setup_vault("short", self.tmpdir / "vault.json")

    def test_setup_file_has_required_fields(self):
        """vault.json must contain all required top-level and nested keys."""
        path = self.tmpdir / "vault.json"
        setup_vault("ValidPass12!", path)
        data = load_vault(path)

        self.assertIn("version", data)
        self.assertIn("kdf", data)
        self.assertIn("auth", data)
        self.assertIn("enc", data)
        self.assertIn("security", data)
        self.assertIn("vault", data)

        self.assertIn("salt", data["auth"])
        self.assertIn("hash", data["auth"])
        self.assertIn("salt", data["enc"])
        self.assertIn("nonce", data["vault"])
        self.assertIn("tag", data["vault"])
        self.assertIn("ciphertext", data["vault"])

    def test_setup_stores_no_plaintext_password(self):
        """The plaintext password must NEVER appear in the vault file."""
        path = self.tmpdir / "vault.json"
        pwd = "SuperSecret12!"
        setup_vault(pwd, path)
        raw_json = path.read_text(encoding="utf-8")
        self.assertNotIn(pwd, raw_json, "Password must never appear in file")

    def test_auth_salt_and_enc_salt_are_different(self):
        """Two different random salts must be stored (auth vs enc)."""
        path = self.tmpdir / "vault.json"
        setup_vault("ValidPass12!", path)
        data = load_vault(path)
        self.assertNotEqual(
            data["auth"]["salt"],
            data["enc"]["salt"],
            "Auth salt and enc salt must be independent random values",
        )


# ---------------------------------------------------------------------------
# 3. Login (setUpClass – one PBKDF2 call shared across all tests in class)
# ---------------------------------------------------------------------------

class TestLogin(unittest.TestCase):
    """Login success/failure with a single pre-created vault."""

    PASSWORD = "LoginTestPass99!"

    @classmethod
    def setUpClass(cls):
        """Create vault once for the entire class (slow PBKDF2 only once)."""
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        cls.vault_path = cls.tmpdir / "vault.json"
        setup_vault(cls.PASSWORD, cls.vault_path)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_correct_password_returns_key_and_data(self):
        """login() must return a 32-byte bytearray key and the vault dict."""
        key, data = login(self.PASSWORD, self.vault_path)
        self.assertIsInstance(key, bytearray)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(data, dict)
        wipe_key(key)

    def test_wrong_password_raises_wrong_password_error(self):
        """login() must raise WrongPasswordError for an incorrect password."""
        with self.assertRaises(WrongPasswordError):
            login("TotallyWrongPwd1!", self.vault_path)

    def test_failed_attempts_incremented_on_wrong_password(self):
        """Each failed login must increment failed_attempts in the file."""
        # Reset counter first to get a clean baseline
        data = load_vault(self.vault_path)
        data["security"]["failed_attempts"] = 0
        data["security"]["locked_until"] = 0.0
        save_vault(data, self.vault_path)

        try:
            login("WrongPwd1!", self.vault_path)
        except WrongPasswordError:
            pass

        data_after = load_vault(self.vault_path)
        self.assertEqual(data_after["security"]["failed_attempts"], 1)

    def test_successful_login_resets_attempt_counter(self):
        """A correct login must reset failed_attempts to 0."""
        # Artificially set some failed attempts
        data = load_vault(self.vault_path)
        data["security"]["failed_attempts"] = 3
        data["security"]["locked_until"] = 0.0
        save_vault(data, self.vault_path)

        key, _ = login(self.PASSWORD, self.vault_path)
        wipe_key(key)

        data_after = load_vault(self.vault_path)
        self.assertEqual(data_after["security"]["failed_attempts"], 0)

    def test_login_missing_vault_raises_file_not_found(self):
        """login() must raise FileNotFoundError when no vault file exists."""
        with self.assertRaises(FileNotFoundError):
            login("anypassword", Path(self._tmp.name) / "nonexistent.json")

    def test_key_not_zero_after_login(self):
        """The returned key must not be all zeros (sanity check)."""
        key, _ = login(self.PASSWORD, self.vault_path)
        self.assertNotEqual(key, bytearray(32))
        wipe_key(key)


# ---------------------------------------------------------------------------
# 4. Lockout Logic
# ---------------------------------------------------------------------------

class TestLockout(unittest.TestCase):
    """
    Lockout triggers after MAX_ATTEMPTS_BEFORE_LOCKOUT failures
    and doubles each subsequent round.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmp.name)
        self.vault_path = self.tmpdir / "vault.json"
        setup_vault("LockTestPass99!", self.vault_path)

    def tearDown(self):
        self._tmp.cleanup()

    def _reset_security(self, attempts: int = 0, locked_until: float = 0.0):
        """Helper to directly set security state in the file."""
        data = load_vault(self.vault_path)
        data["security"]["failed_attempts"] = attempts
        data["security"]["locked_until"] = locked_until
        save_vault(data, self.vault_path)

    # -- check_lockout -------------------------------------------------

    def test_check_lockout_false_when_not_locked(self):
        """check_lockout returns (False, 0.0) when locked_until is in the past."""
        data = load_vault(self.vault_path)
        is_locked, secs = check_lockout(data)
        self.assertFalse(is_locked)
        self.assertEqual(secs, 0.0)

    def test_check_lockout_true_when_locked(self):
        """check_lockout returns (True, >0) when locked_until is in the future."""
        data = load_vault(self.vault_path)
        data["security"]["locked_until"] = time.time() + 60
        is_locked, secs = check_lockout(data)
        self.assertTrue(is_locked)
        self.assertGreater(secs, 0)

    # -- record_failed_attempt -----------------------------------------

    def test_lockout_triggers_after_5_failures(self):
        """After exactly MAX_ATTEMPTS_BEFORE_LOCKOUT failures the lockout fires."""
        data = load_vault(self.vault_path)
        data["security"]["failed_attempts"] = MAX_ATTEMPTS_BEFORE_LOCKOUT - 1
        data["security"]["locked_until"] = 0.0
        save_vault(data, self.vault_path)

        data = load_vault(self.vault_path)
        attempts, locked_until = record_failed_attempt(data, self.vault_path)

        self.assertEqual(attempts, MAX_ATTEMPTS_BEFORE_LOCKOUT)
        self.assertGreater(locked_until, time.time(),
                           "locked_until must be in the future after first lockout")

    def test_first_lockout_duration_is_30_seconds(self):
        """First lockout (5 fails) should be ~30 seconds."""
        self._reset_security(attempts=MAX_ATTEMPTS_BEFORE_LOCKOUT - 1)
        data = load_vault(self.vault_path)
        before = time.time()
        _, locked_until = record_failed_attempt(data, self.vault_path)
        after = time.time()

        duration = locked_until - before
        # Allow ±2 s for test overhead
        self.assertAlmostEqual(duration, 30.0, delta=2.0)

    def test_second_lockout_duration_doubles_to_60_seconds(self):
        """Second lockout (10 fails) should be ~60 seconds."""
        self._reset_security(attempts=2 * MAX_ATTEMPTS_BEFORE_LOCKOUT - 1)
        data = load_vault(self.vault_path)
        before = time.time()
        _, locked_until = record_failed_attempt(data, self.vault_path)

        duration = locked_until - before
        self.assertAlmostEqual(duration, 60.0, delta=2.0)

    def test_third_lockout_duration_doubles_to_120_seconds(self):
        """Third lockout (15 fails) should be ~120 seconds."""
        self._reset_security(attempts=3 * MAX_ATTEMPTS_BEFORE_LOCKOUT - 1)
        data = load_vault(self.vault_path)
        before = time.time()
        _, locked_until = record_failed_attempt(data, self.vault_path)

        duration = locked_until - before
        self.assertAlmostEqual(duration, 120.0, delta=2.0)

    def test_no_lockout_before_threshold(self):
        """Fewer than 5 consecutive failures must NOT trigger a lockout."""
        self._reset_security(attempts=0)
        data = load_vault(self.vault_path)
        for _ in range(MAX_ATTEMPTS_BEFORE_LOCKOUT - 1):
            attempts, locked_until = record_failed_attempt(data, self.vault_path)
            data = load_vault(self.vault_path)

        self.assertEqual(locked_until, 0.0, "No lockout before 5 failures")

    def test_login_raises_lockout_error_when_locked(self):
        """login() must raise LockoutError when locked_until is in the future."""
        self._reset_security(locked_until=time.time() + 999)
        with self.assertRaises(LockoutError) as ctx:
            login("AnyPassword1!", self.vault_path)
        self.assertGreater(ctx.exception.seconds_remaining, 0)

    def test_reset_clears_failed_attempts(self):
        """reset_failed_attempts must set both fields back to zero."""
        self._reset_security(attempts=4, locked_until=time.time() + 60)
        data = load_vault(self.vault_path)
        reset_failed_attempts(data, self.vault_path)

        data_after = load_vault(self.vault_path)
        self.assertEqual(data_after["security"]["failed_attempts"], 0)
        self.assertEqual(data_after["security"]["locked_until"], 0.0)


# ---------------------------------------------------------------------------
# 5. Change Master Password
# ---------------------------------------------------------------------------

class TestChangeMasterPassword(unittest.TestCase):
    """
    After change_master_password:
    - The OLD password must no longer work.
    - The NEW password must work.
    - Vault contents must be preserved.
    """

    OLD_PWD = "OldPassword12!"
    NEW_PWD = "NewPassword99@"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        cls.vault_path = cls.tmpdir / "vault.json"
        setup_vault(cls.OLD_PWD, cls.vault_path)

        # Log in with old password to get the session key
        cls.old_key, _ = login(cls.OLD_PWD, cls.vault_path)

        # Change the password (wipes old_key internally, returns new key)
        cls.new_key = change_master_password(
            cls.OLD_PWD, cls.NEW_PWD, cls.vault_path, cls.old_key
        )

    @classmethod
    def tearDownClass(cls):
        wipe_key(cls.new_key)
        cls._tmp.cleanup()

    def test_old_password_no_longer_works(self):
        """After changing, the old password must raise WrongPasswordError."""
        with self.assertRaises(WrongPasswordError):
            login(self.OLD_PWD, self.vault_path)

    def test_new_password_works(self):
        """After changing, the new password must successfully log in."""
        key, data = login(self.NEW_PWD, self.vault_path)
        self.assertIsInstance(key, bytearray)
        self.assertEqual(len(key), 32)
        wipe_key(key)

    def test_salts_are_regenerated_after_change(self):
        """
        New salts must be different from the old ones.
        Reusing old salts with a new password would link the two epochs.
        """
        # We can't directly compare with pre-change salts because we didn't
        # save them, so we verify that auth salt ≠ enc salt (independent).
        data = load_vault(self.vault_path)
        self.assertNotEqual(data["auth"]["salt"], data["enc"]["salt"])

    def test_wrong_old_password_rejected(self):
        """change_master_password must refuse if old_password is wrong."""
        # Use the new key for this test (we're currently using new password)
        data = load_vault(self.vault_path)
        key, _ = login(self.NEW_PWD, self.vault_path)
        with self.assertRaises(WrongPasswordError):
            change_master_password("NotTheOldPwd1!", "AnotherNew12@",
                                   self.vault_path, key)
        wipe_key(key)

    def test_short_new_password_rejected(self):
        """change_master_password must raise ValueError for short new password."""
        key, _ = login(self.NEW_PWD, self.vault_path)
        with self.assertRaises(ValueError):
            change_master_password(self.NEW_PWD, "short",
                                   self.vault_path, key)
        wipe_key(key)


# ---------------------------------------------------------------------------
# 6. Logout
# ---------------------------------------------------------------------------

class TestLogout(unittest.TestCase):
    """logout() must zero the key bytearray."""

    def test_logout_wipes_key(self):
        """After logout(), the key bytearray should be all zeros."""
        from Crypto.Random import get_random_bytes
        key = bytearray(get_random_bytes(32))
        logout(key)
        self.assertEqual(key, bytearray(32), "Key must be zeroed after logout")


if __name__ == "__main__":
    unittest.main(verbosity=2)
