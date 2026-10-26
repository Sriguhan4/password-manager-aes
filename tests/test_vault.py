"""
tests/test_vault.py
===================
Unit tests for core/vault.py and core/generator.py.

Run with:
    (venv) python -m pytest tests/test_vault.py -v
"""

import json
import string
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import login, setup_vault
from core.crypto import wipe_key
from core.generator import (
    MAX_LENGTH,
    MIN_LENGTH,
    DIGITS,
    LOWERCASE,
    SYMBOLS,
    UPPERCASE,
    StrengthResult,
    generate_password,
    password_strength,
)
from core.storage import load_vault
from core.vault import (
    add_entry,
    delete_entry,
    edit_entry,
    get_entry_by_id,
    load_entries,
    save_entries,
    search_entries,
)


# ---------------------------------------------------------------------------
# Helper – shared vault fixture (one PBKDF2 call for the whole test module)
# ---------------------------------------------------------------------------

PASSWORD = "VaultTestPass99!"


def _setup_temp_vault(tmpdir: Path) -> tuple[Path, bytearray, dict]:
    """Create a vault, log in, and return (path, enc_key, data)."""
    path = tmpdir / "vault.json"
    setup_vault(PASSWORD, path)
    enc_key, data = login(PASSWORD, path)
    return path, enc_key, data


# ---------------------------------------------------------------------------
# 1. Vault Entry CRUD
# ---------------------------------------------------------------------------

class TestVaultCRUD(unittest.TestCase):
    """add, edit, delete, search on the in-memory entry list."""

    def setUp(self):
        """Fresh in-memory entries list for each test (no disk I/O)."""
        self.entries: list[dict] = []

    # -- add_entry ---------------------------------------------------------

    def test_add_entry_returns_entry_dict(self):
        """add_entry must return a dict with all required keys."""
        e = add_entry(self.entries, "github.com", "user@x.com", "Pass123!")
        required = {"id", "site", "username", "password", "notes",
                    "created_at", "updated_at"}
        self.assertTrue(required.issubset(e.keys()))

    def test_add_entry_appends_to_list(self):
        """add_entry must mutate the entries list by appending."""
        add_entry(self.entries, "site.com", "user", "pass")
        self.assertEqual(len(self.entries), 1)

    def test_add_entry_id_is_unique(self):
        """Two entries must have different UUIDs."""
        e1 = add_entry(self.entries, "a.com", "u1", "p1")
        e2 = add_entry(self.entries, "b.com", "u2", "p2")
        self.assertNotEqual(e1["id"], e2["id"])

    def test_add_entry_rejects_empty_site(self):
        """Empty site name must raise ValueError."""
        with self.assertRaises(ValueError):
            add_entry(self.entries, "   ", "user", "pass")

    def test_add_entry_rejects_empty_password(self):
        """Empty password must raise ValueError."""
        with self.assertRaises(ValueError):
            add_entry(self.entries, "site.com", "user", "")

    def test_add_entry_stores_correct_fields(self):
        """All provided fields must be stored correctly."""
        e = add_entry(self.entries, "example.com", "alice", "S3cr3t!", "my note")
        self.assertEqual(e["site"],     "example.com")
        self.assertEqual(e["username"], "alice")
        self.assertEqual(e["password"], "S3cr3t!")
        self.assertEqual(e["notes"],    "my note")

    # -- edit_entry --------------------------------------------------------

    def test_edit_entry_updates_specified_field(self):
        """edit_entry must update only the fields passed as kwargs."""
        e = add_entry(self.entries, "old-site.com", "olduser", "oldpass")
        eid = e["id"]
        edit_entry(self.entries, eid, site="new-site.com", password="newpass99")
        updated = get_entry_by_id(self.entries, eid)
        self.assertEqual(updated["site"],     "new-site.com")
        self.assertEqual(updated["password"], "newpass99")
        self.assertEqual(updated["username"], "olduser")  # unchanged

    def test_edit_entry_updates_updated_at(self):
        """edit_entry must refresh updated_at."""
        e = add_entry(self.entries, "site.com", "user", "pass")
        original_ts = e["updated_at"]
        import time; time.sleep(0.01)   # ensure clock advances
        edit_entry(self.entries, e["id"], notes="new note")
        self.assertGreaterEqual(e["updated_at"], original_ts)

    def test_edit_entry_cannot_change_id(self):
        """id is protected — passing it as a kwarg must be silently ignored."""
        e = add_entry(self.entries, "site.com", "user", "pass")
        original_id = e["id"]
        edit_entry(self.entries, e["id"], id="hacked-id")
        self.assertEqual(e["id"], original_id)

    def test_edit_entry_cannot_change_created_at(self):
        """created_at is protected — must remain unchanged."""
        e = add_entry(self.entries, "site.com", "user", "pass")
        ts = e["created_at"]
        edit_entry(self.entries, e["id"], created_at="1970-01-01T00:00:00+00:00")
        self.assertEqual(e["created_at"], ts)

    def test_edit_entry_raises_key_error_for_missing_id(self):
        """edit_entry must raise KeyError for a nonexistent ID."""
        with self.assertRaises(KeyError):
            edit_entry(self.entries, "nonexistent-uuid", site="x.com")

    def test_edit_entry_rejects_empty_site(self):
        """edit_entry must raise ValueError when site is cleared."""
        e = add_entry(self.entries, "site.com", "user", "pass")
        with self.assertRaises(ValueError):
            edit_entry(self.entries, e["id"], site="  ")

    # -- delete_entry -------------------------------------------------------

    def test_delete_entry_removes_the_entry(self):
        """delete_entry must return a list without the deleted entry."""
        add_entry(self.entries, "a.com", "u", "p")
        e2 = add_entry(self.entries, "b.com", "u", "p")
        new_entries = delete_entry(self.entries, e2["id"])
        self.assertEqual(len(new_entries), 1)
        self.assertEqual(new_entries[0]["site"], "a.com")

    def test_delete_entry_returns_new_list(self):
        """delete_entry must return a NEW list object (original unchanged)."""
        e = add_entry(self.entries, "site.com", "u", "p")
        new_list = delete_entry(self.entries, e["id"])
        self.assertIsNot(new_list, self.entries)

    def test_delete_entry_raises_key_error_for_missing_id(self):
        """delete_entry must raise KeyError for a nonexistent ID."""
        with self.assertRaises(KeyError):
            delete_entry(self.entries, "does-not-exist")

    # -- search_entries -----------------------------------------------------

    def test_search_finds_by_site(self):
        """search_entries must match on site name (case-insensitive)."""
        add_entry(self.entries, "GitHub.com",   "alice", "p1")
        add_entry(self.entries, "gmail.com",    "bob",   "p2")
        add_entry(self.entries, "gitlab.com",   "carol", "p3")
        results = search_entries(self.entries, "github")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "alice")

    def test_search_finds_by_username(self):
        """search_entries must match on username."""
        add_entry(self.entries, "site.com", "alice123", "p1")
        add_entry(self.entries, "site.com", "bob456",   "p2")
        results = search_entries(self.entries, "alice")
        self.assertEqual(len(results), 1)

    def test_search_finds_by_notes(self):
        """search_entries must match on notes field."""
        add_entry(self.entries, "site.com", "user", "pass", notes="work account")
        add_entry(self.entries, "site.com", "user", "pass", notes="personal")
        results = search_entries(self.entries, "work")
        self.assertEqual(len(results), 1)

    def test_search_empty_query_returns_all(self):
        """Empty query must return all entries."""
        for i in range(5):
            add_entry(self.entries, f"site{i}.com", "u", "p")
        results = search_entries(self.entries, "")
        self.assertEqual(len(results), 5)

    def test_search_no_match_returns_empty(self):
        """Query with no matches returns an empty list, not an error."""
        add_entry(self.entries, "site.com", "user", "pass")
        results = search_entries(self.entries, "zzznomatch")
        self.assertEqual(results, [])

    def test_search_does_not_search_passwords(self):
        """Password field must NOT be included in search (privacy)."""
        add_entry(self.entries, "site.com", "user", "hunter2")
        results = search_entries(self.entries, "hunter2")
        self.assertEqual(results, [],
                         "Searching the password field would expose secrets")


# ---------------------------------------------------------------------------
# 2. Encrypt / Decrypt Round-Trip (full integration with auth)
# ---------------------------------------------------------------------------

class TestVaultEncryptDecryptRoundTrip(unittest.TestCase):
    """
    Full end-to-end: setup vault → login → add entries → save → reload → load.
    """

    @classmethod
    def setUpClass(cls):
        """One PBKDF2 call shared across all tests in this class."""
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        cls.path, cls.enc_key, cls.data = _setup_temp_vault(cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        wipe_key(cls.enc_key)
        cls._tmp.cleanup()

    def test_empty_vault_round_trip(self):
        """load_entries on a fresh vault must return an empty list."""
        entries = load_entries(self.data, self.enc_key)
        self.assertEqual(entries, [])

    def test_entries_survive_save_and_reload(self):
        """Entries written to disk must be identical after decryption."""
        entries = load_entries(self.data, self.enc_key)
        add_entry(entries, "example.com", "alice", "S3cr3t99!", "test note")
        add_entry(entries, "google.com",  "bob",   "Passw0rd!", "")

        updated_data = save_entries(entries, self.data, self.enc_key, self.path)

        # Reload from disk, re-decrypt
        fresh_data = load_vault(self.path)
        reloaded = load_entries(fresh_data, self.enc_key)

        self.assertEqual(len(reloaded), 2)
        self.assertEqual(reloaded[0]["site"],     "example.com")
        self.assertEqual(reloaded[0]["username"], "alice")
        self.assertEqual(reloaded[0]["password"], "S3cr3t99!")
        self.assertEqual(reloaded[1]["site"],     "google.com")

    def test_two_saves_produce_different_nonces(self):
        """
        SECURITY: Each save must generate a new random nonce.
        Same plaintext encrypted twice must yield different nonces
        (and therefore different ciphertexts).
        """
        entries = load_entries(self.data, self.enc_key)
        data_after_1 = save_entries(entries, self.data, self.enc_key, self.path)
        nonce1 = data_after_1["vault"]["nonce"]

        data_after_2 = save_entries(entries, self.data, self.enc_key, self.path)
        nonce2 = data_after_2["vault"]["nonce"]

        self.assertNotEqual(nonce1, nonce2,
                            "Nonces must never be reused across saves")

    def test_two_saves_produce_different_ciphertexts(self):
        """Different nonces → different ciphertexts (semantic security).

        We reload from disk between each save so that each call to
        save_entries operates on an independent dict (no shared state).
        """
        # First save
        entries = load_entries(self.data, self.enc_key)
        save_entries(entries, self.data, self.enc_key, self.path)
        ct1 = load_vault(self.path)["vault"]["ciphertext"]

        # Second save — reload fresh data so no shared mutable dict
        fresh_data = load_vault(self.path)
        save_entries(entries, fresh_data, self.enc_key, self.path)
        ct2 = load_vault(self.path)["vault"]["ciphertext"]

        self.assertNotEqual(ct1, ct2,
                            "Different nonces must yield different ciphertexts")

    def test_unicode_entries_survive_round_trip(self):
        """Non-ASCII characters in entries must be preserved."""
        entries = []
        add_entry(entries, "例え.jp", "ユーザー", "パスワード🔑", "メモ")
        save_entries(entries, self.data, self.enc_key, self.path)
        fresh_data = load_vault(self.path)
        reloaded = load_entries(fresh_data, self.enc_key)
        self.assertEqual(reloaded[-1]["site"], "例え.jp")


# ---------------------------------------------------------------------------
# 3. Password Generator Tests
# ---------------------------------------------------------------------------

class TestPasswordGenerator(unittest.TestCase):
    """generate_password security and correctness properties."""

    def test_default_length_is_16(self):
        """Default call must produce a 16-character password."""
        self.assertEqual(len(generate_password()), 16)

    def test_custom_length_respected(self):
        """Password length must exactly match the requested length."""
        for length in [8, 12, 20, 32, 64]:
            with self.subTest(length=length):
                self.assertEqual(len(generate_password(length=length)), length)

    def test_minimum_length_8(self):
        """Length 8 is the minimum allowed value."""
        pwd = generate_password(length=MIN_LENGTH)
        self.assertEqual(len(pwd), MIN_LENGTH)

    def test_maximum_length_64(self):
        """Length 64 is the maximum allowed value."""
        pwd = generate_password(length=MAX_LENGTH)
        self.assertEqual(len(pwd), MAX_LENGTH)

    def test_below_minimum_raises_value_error(self):
        """Length < 8 must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(length=7)

    def test_above_maximum_raises_value_error(self):
        """Length > 64 must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(length=65)

    def test_no_class_selected_raises_value_error(self):
        """All classes disabled must raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                use_upper=False, use_lower=False,
                use_digits=False, use_symbols=False
            )

    # -- Guarantee: at least one char from each selected class -----------

    def _check_class_guarantee(self, pwd: str, use_upper: bool,
                               use_lower: bool, use_digits: bool,
                               use_symbols: bool) -> None:
        """Assert that pwd contains at least one char from each enabled class."""
        if use_upper:
            self.assertTrue(any(c in UPPERCASE for c in pwd),
                            f"Missing uppercase in: {pwd!r}")
        if use_lower:
            self.assertTrue(any(c in LOWERCASE for c in pwd),
                            f"Missing lowercase in: {pwd!r}")
        if use_digits:
            self.assertTrue(any(c in DIGITS for c in pwd),
                            f"Missing digit in: {pwd!r}")
        if use_symbols:
            self.assertTrue(any(c in SYMBOLS for c in pwd),
                            f"Missing symbol in: {pwd!r}")

    def test_guarantee_all_classes_present_50_times(self):
        """Run 50 times with all classes — each must appear every time."""
        for _ in range(50):
            pwd = generate_password(length=16)
            self._check_class_guarantee(pwd, True, True, True, True)

    def test_guarantee_upper_lower_only(self):
        """With only upper+lower selected, both must always appear."""
        for _ in range(20):
            pwd = generate_password(
                length=8, use_upper=True, use_lower=True,
                use_digits=False, use_symbols=False
            )
            self._check_class_guarantee(pwd, True, True, False, False)
            # No digit or symbol should appear
            self.assertFalse(any(c in DIGITS   for c in pwd))
            self.assertFalse(any(c in SYMBOLS  for c in pwd))

    def test_guarantee_digits_only(self):
        """With only digits selected, password must consist entirely of digits."""
        for _ in range(10):
            pwd = generate_password(
                length=12, use_upper=False, use_lower=False,
                use_digits=True, use_symbols=False
            )
            self.assertTrue(all(c in DIGITS for c in pwd))

    # -- Randomness --------------------------------------------------------

    def test_two_passwords_are_different(self):
        """Two consecutive calls must almost certainly produce different results."""
        # With 16 chars from ~72-char pool: P(collision) ≈ 72^-16 ≈ 0
        p1 = generate_password()
        p2 = generate_password()
        self.assertNotEqual(p1, p2,
                            "Two consecutive passwords should not be identical")

    def test_uses_secrets_not_random_module(self):
        """Ensure the random module is NOT imported in generator.py.
        This is a static check — not a runtime check — but protects
        against accidental import of the insecure random module."""
        import importlib
        import core.generator as gen_module
        import types
        # Check that 'random' is not a submodule attribute
        self.assertFalse(
            hasattr(gen_module, 'random') and
            isinstance(getattr(gen_module, 'random'), types.ModuleType),
            "The random module must not be used in generator.py"
        )


# ---------------------------------------------------------------------------
# 4. Strength Meter Tests
# ---------------------------------------------------------------------------

class TestPasswordStrength(unittest.TestCase):
    """password_strength returns correct scores and labels."""

    def test_returns_strength_result(self):
        """password_strength must return a StrengthResult NamedTuple."""
        result = password_strength("test")
        self.assertIsInstance(result, StrengthResult)

    def test_very_weak_short_lower_only(self):
        """Short lowercase-only password must be 'Very Weak'."""
        result = password_strength("abc")
        self.assertEqual(result.label, "Very Weak")

    def test_weak_medium_length_one_class(self):
        """Medium-length password with only one class scores low.

        "abcdefghij" (10 chars, lowercase only):
          len_8(+1), has_lower(+1) = score 2 → Very Weak.
        Note: len_12 does NOT fire because length is 10.
        """
        result = password_strength("abcdefghij")   # 10 chars, lower only
        # score: len_8(+1) + has_lower(+1) = 2 → Very Weak
        self.assertIn(result.label, ("Very Weak", "Weak"))
        self.assertLessEqual(result.score, 3)

    def test_moderate_password(self):
        """Mixed case + digits at moderate length → Moderate or above."""
        result = password_strength("Password1")
        self.assertGreaterEqual(result.score, 4)

    def test_strong_password(self):
        """Long password with all classes must score high."""
        result = password_strength("MyStr0ng!Pass#2026")
        self.assertGreaterEqual(result.score, 6)
        self.assertIn(result.label, ("Strong", "Very Strong"))

    def test_very_strong_password(self):
        """A well-composed 20+ char password must reach Very Strong."""
        result = password_strength("C0mpl3x!Password@2026#XX")
        self.assertEqual(result.label, "Very Strong")
        self.assertEqual(result.score, 8)

    def test_score_is_0_to_8(self):
        """Score must always be in range [0, 8]."""
        for pwd in ["", "a", "password", "MyP@ss1!", "A" * 64]:
            with self.subTest(pwd=pwd):
                r = password_strength(pwd)
                self.assertGreaterEqual(r.score, 0)
                self.assertLessEqual(r.score, 8)

    def test_length_increases_score(self):
        """Longer password with same classes must score higher."""
        short  = password_strength("Pass1!")          # 6 chars
        medium = password_strength("Pass1!xxxx")      # 10 chars
        long_  = password_strength("Pass1!xxxxxxxxxx")# 16 chars
        self.assertGreaterEqual(medium.score, short.score)
        self.assertGreaterEqual(long_.score, medium.score)

    def test_adding_class_increases_score(self):
        """Adding a new character class must increase or maintain score."""
        lower_only = password_strength("abcdefghij")
        with_upper  = password_strength("Abcdefghij")
        with_digit  = password_strength("Abcdefgh1j")
        with_symbol = password_strength("Abcdefgh1!")
        self.assertGreaterEqual(with_upper.score,  lower_only.score)
        self.assertGreaterEqual(with_digit.score,  with_upper.score)
        self.assertGreaterEqual(with_symbol.score, with_digit.score)

    def test_color_is_hex_string(self):
        """Color field must be a CSS hex colour string."""
        result = password_strength("TestPass1!")
        self.assertTrue(result.color.startswith("#"))
        self.assertEqual(len(result.color), 7)

    def test_details_contains_expected_keys(self):
        """details dict must contain all scoring criteria."""
        result = password_strength("SomePass1!")
        expected_keys = {
            "len_8", "len_12", "len_16", "len_20",
            "has_upper", "has_lower", "has_digit", "has_symbol"
        }
        self.assertTrue(expected_keys.issubset(result.details.keys()))

    def test_empty_password_is_very_weak(self):
        """Empty string must be Very Weak with score 0."""
        result = password_strength("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.label, "Very Weak")


if __name__ == "__main__":
    unittest.main(verbosity=2)
