"""
gui/app.py
==========
Main CustomTkinter application window.

Responsibilities
----------------
- Window setup and theming (dark, purple-accent palette).
- Frame management: switches between Setup / Login / Vault screens.
- Session state: holds enc_key (bytearray), vault_data, and entries
  in memory. These are wiped on lock/logout/close.
- Auto-lock: polls every 30 s; locks after 5 min of inactivity by
  tracking the last mouse/keyboard event timestamp.

Crypto rule: THIS FILE MUST NOT import anything from core.crypto.
It only uses high-level helpers: auth.logout, vault.load_entries,
storage.vault_exists. All crypto stays in core/.
"""

import time
from pathlib import Path
from typing import Optional

import customtkinter as ctk

from core.auth import logout
from core.storage import vault_exists
from core.vault import load_entries

# ---------------------------------------------------------------------------
# App-wide constants
# ---------------------------------------------------------------------------

AUTO_LOCK_SECONDS: int = 300   # 5 minutes of inactivity → auto-lock

# ---- Shared colour palette (used by all frames) ----
# Import these in frames via:  from gui.app import CLR
CLR = {
    "bg":         "#0d0d1a",   # near-black navy — window background
    "panel":      "#13132b",   # slightly lighter — left branding panel
    "card":       "#1e1e3a",   # card / input surface
    "entry":      "#252548",   # entry field background
    "accent":     "#7c6ff7",   # soft indigo-purple — primary action colour
    "accent_hov": "#6355e8",   # darker on hover
    "accent_dim": "#3d3880",   # subtle accent (border, icon)
    "text":       "#e8e8f8",   # primary text (near-white)
    "subtle":     "#7878a0",   # secondary / placeholder text
    "border":     "#2e2e55",   # subtle divider
    "success":    "#4ade80",   # green (match / ok)
    "error":      "#f87171",   # red (wrong password / mismatch)
    "warn":       "#fbbf24",   # amber (lockout countdown)
}


class App(ctk.CTk):
    """
    Root application window.

    Frame switching uses a simple destroy-and-recreate pattern:
    each call to show_*() destroys the current frame widget and
    instantiates a fresh one. This keeps each frame's __init__ as the
    single source of truth for its initial state.

    Session state lives here (not in frames) so it survives frame switches.
    """

    # Path to the vault file — sibling of main.py in the project root.
    VAULT_PATH: Path = Path(__file__).parent.parent / "vault.json"

    def __init__(self) -> None:
        super().__init__()

        # ---- Appearance ----
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=CLR["bg"])
        self.title("🔐 Password Manager")
        self.geometry("960x640")
        self.minsize(820, 560)

        # ---- Session state (None = locked / not logged in) ----
        self.enc_key:    Optional[bytearray] = None
        self.vault_data: Optional[dict]      = None
        self.entries:    list                = []

        # ---- Auto-lock infrastructure ----
        self._last_activity: float       = time.time()
        self._lock_job:      Optional[str] = None
        self._bind_activity_events()

        # ---- Current visible frame ----
        self._current_frame: Optional[ctk.CTkFrame] = None

        # ---- Clean shutdown ----
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # ---- First screen ----
        if vault_exists(self.VAULT_PATH):
            self.show_login()
        else:
            self.show_setup()

    # ------------------------------------------------------------------
    # Frame management
    # ------------------------------------------------------------------

    def _clear_frame(self) -> None:
        """Destroy the currently displayed frame widget."""
        if self._current_frame is not None:
            self._current_frame.destroy()
            self._current_frame = None

    def show_setup(self) -> None:
        """Display the first-run 'Create Master Password' screen."""
        from gui.setup_frame import SetupFrame
        self._clear_frame()
        frame = SetupFrame(master=self, app=self)
        frame.pack(fill="both", expand=True)
        self._current_frame = frame

    def show_login(self) -> None:
        """Display the login screen."""
        from gui.login_frame import LoginFrame
        self._clear_frame()
        frame = LoginFrame(master=self, app=self)
        frame.pack(fill="both", expand=True)
        self._current_frame = frame

    def show_vault(self) -> None:
        """Display the main vault screen (filled in Phase 6)."""
        from gui.vault_frame import VaultFrame
        self._clear_frame()
        frame = VaultFrame(master=self, app=self)
        frame.pack(fill="both", expand=True)
        self._current_frame = frame
        # Start auto-lock only when vault is visible
        self._start_auto_lock()

    # ------------------------------------------------------------------
    # Session callbacks (called by frames)
    # ------------------------------------------------------------------

    def on_setup_complete(self) -> None:
        """
        Called by SetupFrame after the user successfully creates a vault.
        Transition to the login screen so they can unlock immediately.
        """
        self.show_login()

    def on_login_success(self, enc_key: bytearray, vault_data: dict) -> None:
        """
        Called by LoginFrame after the user authenticates.

        Stores the session key in memory and decrypts the entry list.
        The enc_key NEVER leaves this object — it is only passed to
        core functions that need it and is wiped on lock/close.
        """
        self.enc_key    = enc_key
        self.vault_data = vault_data
        # Decrypt the entry list once; keep it in RAM until locked.
        self.entries = load_entries(vault_data, enc_key)
        self.show_vault()

    def lock_vault(self) -> None:
        """
        Lock the vault: wipe key, clear session state, show login.

        Called by the Lock button in the vault toolbar and by auto-lock.
        WHY wipe here? The GUI holds the only reference to enc_key.
        Wiping it here ensures no other code can still reach the key.
        """
        self._stop_auto_lock()
        if self.enc_key is not None:
            logout(self.enc_key)    # zeroes the bytearray in-place
            del self.enc_key        # remove reference
        self.enc_key    = None
        self.vault_data = None
        self.entries    = []
        self.show_login()

    # ------------------------------------------------------------------
    # Auto-lock timer
    # ------------------------------------------------------------------

    def _bind_activity_events(self) -> None:
        """
        Track mouse movement, button clicks, and key presses to reset the
        inactivity timer. Using bind_all means the binding applies to
        every widget inside the window automatically.
        """
        self.bind_all("<Motion>",  self._on_activity, add="+")
        self.bind_all("<Key>",     self._on_activity, add="+")
        self.bind_all("<Button>",  self._on_activity, add="+")

    def _on_activity(self, event=None) -> None:
        """Reset the inactivity timestamp on any user event."""
        self._last_activity = time.time()

    def _start_auto_lock(self) -> None:
        """Begin the periodic inactivity check (every 30 s)."""
        self._stop_auto_lock()
        self._check_auto_lock()

    def _stop_auto_lock(self) -> None:
        """Cancel a pending auto-lock check."""
        if self._lock_job:
            self.after_cancel(self._lock_job)
            self._lock_job = None

    def _check_auto_lock(self) -> None:
        """
        Called every 30 s while the vault is unlocked.
        Locks the vault if the user has been inactive for AUTO_LOCK_SECONDS.

        WHY 30 s polling interval?
        Fine enough to lock within ~35 s of the 5-min threshold, but
        cheap enough to have negligible CPU overhead.
        """
        if self.enc_key is not None:
            idle = time.time() - self._last_activity
            if idle >= AUTO_LOCK_SECONDS:
                self.lock_vault()
                return
        # Reschedule using Tkinter's after() — safe on the main thread.
        self._lock_job = self.after(30_000, self._check_auto_lock)

    # ------------------------------------------------------------------
    # Clean shutdown
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        """
        Intercept the window-close event to wipe the key before exit.

        WHY? If the user closes the window without explicitly locking,
        the key would linger in memory until the process exits. Wiping it
        here is best-effort mitigation (Python may have internal copies).
        """
        if self.enc_key is not None:
            logout(self.enc_key)
        self.destroy()
