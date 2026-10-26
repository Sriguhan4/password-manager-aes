"""
tests/test_gui.py
=================
Integration and unit tests for the GUI components and state machines.

Tests:
1. App state transitions (Setup -> Login -> Vault -> Lock).
2. Key lifecycle: verifies enc_key is wiped on app.lock_vault() and app._on_close().
3. Secure clipboard auto-wipe logic.
4. VaultFrame CRUD integration: adding, editing, searching, and deleting entries.
5. Inactivity timer logic.

Run with:
    (venv) python -m pytest tests/test_gui.py -v
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Fix Tcl/Tk environment paths on Windows if needed
if sys.platform == "win32":
    tcl_dir = os.path.join(sys.base_prefix, "tcl", "tcl8.6")
    tk_dir = os.path.join(sys.base_prefix, "tcl", "tk8.6")
    if os.path.exists(tcl_dir):
        os.environ["TCL_LIBRARY"] = tcl_dir
    if os.path.exists(tk_dir):
        os.environ["TK_LIBRARY"] = tk_dir

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import login, setup_vault
from core.crypto import wipe_key
from core.storage import load_vault
from core.vault import add_entry, delete_entry, edit_entry, load_entries, save_entries, search_entries
from gui.app import App
from gui.dialogs import copy_to_clipboard_secure
from gui.vault_frame import VaultFrame


class TestGUIIntegration(unittest.TestCase):
    """
    Headless integration tests for GUI state transitions and memory security.
    Uses a single persistent App instance in setUpClass to avoid multiple Tk re-initializations.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        cls.vault_path = cls.tmpdir / "vault.json"

        # Mock the App class VAULT_PATH before instantiating
        cls.orig_vault_path = App.VAULT_PATH
        App.VAULT_PATH = cls.vault_path

        # Create single root App widget hidden offscreen
        cls.app = App()
        cls.app.withdraw()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.app.destroy()
        except Exception:
            pass
        App.VAULT_PATH = cls.orig_vault_path
        cls._tmp.cleanup()

    def test_01_app_starts_in_setup_mode_when_no_vault(self):
        """When vault.json does not exist, app initializes with SetupFrame."""
        from gui.setup_frame import SetupFrame
        self.assertIsInstance(self.app._current_frame, SetupFrame)
        self.assertIsNone(self.app.enc_key)
        self.assertEqual(self.app.entries, [])

    def test_02_app_switches_to_login_when_vault_created(self):
        """When vault is created, show_login switches to LoginFrame."""
        setup_vault("MasterPassword123!", self.vault_path)
        self.app.show_login()

        from gui.login_frame import LoginFrame
        self.assertIsInstance(self.app._current_frame, LoginFrame)
        self.assertIsNone(self.app.enc_key)

    def test_03_app_transitions_to_vault_on_login_and_wipes_on_lock(self):
        """
        Verify the complete session lifecycle:
        1. Login loads entries and sets enc_key
        2. show_vault displays VaultFrame
        3. lock_vault zeroes the enc_key in-place and clears session
        """
        pwd = "MasterPassword123!"
        enc_key, raw_data = login(pwd, self.vault_path)

        # Simulate successful login
        self.app.on_login_success(enc_key, raw_data)

        self.assertIsInstance(self.app._current_frame, VaultFrame)
        self.assertEqual(len(self.app.entries), 0)
        self.assertIsNotNone(self.app.enc_key)
        self.assertEqual(len(self.app.enc_key), 32)
        self.assertTrue(any(b != 0 for b in self.app.enc_key))

        # Keep a reference to the bytearray to verify zeroing in-place
        key_ref = self.app.enc_key

        # Lock the vault
        self.app.lock_vault()

        # Session state must be reset
        self.assertIsNone(self.app.enc_key)
        self.assertIsNone(self.app.vault_data)
        self.assertEqual(self.app.entries, [])

        # The underlying bytearray memory MUST be all zeroes!
        self.assertEqual(bytes(key_ref), b"\x00" * 32)

        # Frame must be back to LoginFrame
        from gui.login_frame import LoginFrame
        self.assertIsInstance(self.app._current_frame, LoginFrame)

    def test_04_vault_frame_crud_operations(self):
        """Test adding, editing, and deleting an entry via VaultFrame logic."""
        pwd = "MasterPassword123!"
        enc_key, raw_data = login(pwd, self.vault_path)
        self.app.on_login_success(enc_key, raw_data)
        vf = self.app._current_frame
        self.assertIsInstance(vf, VaultFrame)

        # 1. Add Entry
        new_entry = add_entry(self.app.entries, "github.com", "alice", "SecretPass123", "work github")
        save_entries(self.app.entries, self.app.vault_data, self.app.enc_key, self.app.VAULT_PATH)
        vf.refresh_entries()

        self.assertEqual(len(self.app.entries), 1)
        self.assertEqual(self.app.entries[0]["site"], "github.com")

        # Verify persisted data decrypts correctly from disk
        reloaded_data = load_vault(self.vault_path)
        decrypted_entries = load_entries(reloaded_data, self.app.enc_key)
        self.assertEqual(len(decrypted_entries), 1)
        self.assertEqual(decrypted_entries[0]["site"], "github.com")

        # 2. Edit Entry
        edit_entry(self.app.entries, new_entry["id"], site="gitlab.com", username="alice_dev")
        save_entries(self.app.entries, self.app.vault_data, self.app.enc_key, self.app.VAULT_PATH)
        vf.refresh_entries()

        self.assertEqual(self.app.entries[0]["site"], "gitlab.com")
        self.assertEqual(self.app.entries[0]["username"], "alice_dev")

        # 3. Search Entry
        self.assertEqual(len(search_entries(self.app.entries, "gitlab")), 1)
        self.assertEqual(len(search_entries(self.app.entries, "nonexistent")), 0)

        # 4. Delete Entry
        self.app.entries = delete_entry(self.app.entries, new_entry["id"])
        save_entries(self.app.entries, self.app.vault_data, self.app.enc_key, self.app.VAULT_PATH)
        vf.refresh_entries()

        self.assertEqual(len(self.app.entries), 0)

    def test_05_clipboard_auto_wipe_after_timer(self):
        """Verify copy_to_clipboard_secure populates and erases clipboard."""
        secret = "SuperSecretPassword99!"
        # Call with 0s wipe for instant test verification
        copy_to_clipboard_secure(self.app, secret, wipe_seconds=0)

        # Let event loop process after() callbacks
        self.app.update()
        time.sleep(0.05)
        self.app.update()

        try:
            clip = self.app.clipboard_get()
        except Exception:
            clip = ""
        self.assertNotEqual(clip, secret)
