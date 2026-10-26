"""
gui/login_frame.py
==================
Login screen: enter master password to unlock the vault.

UI elements
-----------
- Left branding panel (shared visual identity with SetupFrame)
- Right form panel:
    * Password entry with show/hide toggle
    * "Unlock" button
    * Attempt counter (shown after first wrong attempt)
    * Lockout countdown (shown when locked, disabled button)

Lockout behaviour
-----------------
- Calls core.auth.login(), which raises LockoutError or WrongPasswordError.
- On LockoutError: starts a countdown that ticks every 1 s using after().
  Displays "🔒 Locked – try again in Xs". Re-enables the button when
  the countdown reaches 0 (i.e. once the lockout period has expired).
- On WrongPasswordError: reloads the vault file to get the fresh
  failed_attempts count and displays "Attempt N of 5".

Crypto rule: NO crypto code in this file.
Calls: core.auth.login, core.auth.check_lockout, core.storage.load_vault
"""

from typing import TYPE_CHECKING, Optional

import customtkinter as ctk

from core.auth import (
    LockoutError,
    MAX_ATTEMPTS_BEFORE_LOCKOUT,
    WrongPasswordError,
    check_lockout,
    login,
)
from core.storage import load_vault
from gui.app import CLR

if TYPE_CHECKING:
    from gui.app import App


class LoginFrame(ctk.CTkFrame):
    """
    Login screen displayed whenever the vault is locked.

    Layout: same two-panel split as SetupFrame for visual consistency.
    """

    def __init__(self, master: ctk.CTk, app: "App") -> None:
        super().__init__(master, fg_color=CLR["bg"], corner_radius=0)
        self.app = app
        self._pwd_visible = False
        self._countdown_job: Optional[str] = None
        self._remaining_secs: int = 0

        self._build_layout()
        # Check if already locked when the frame opens (e.g. after restart)
        self._check_initial_lockout()

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        # Left branding panel
        self.left = ctk.CTkFrame(
            self, width=310, fg_color=CLR["panel"], corner_radius=0
        )
        self.left.pack(side="left", fill="y")
        self.left.pack_propagate(False)

        # Separator
        ctk.CTkFrame(self, width=1, fg_color=CLR["border"], corner_radius=0).pack(
            side="left", fill="y"
        )

        # Right form panel
        self.right = ctk.CTkFrame(self, fg_color=CLR["bg"], corner_radius=0)
        self.right.pack(side="left", fill="both", expand=True)

        self._build_left()
        self._build_right()

    def _build_left(self) -> None:
        """Branding panel — identical style to SetupFrame."""
        ctk.CTkFrame(self.left, fg_color="transparent").pack(fill="both", expand=True)

        ctk.CTkLabel(
            self.left, text="🔐",
            font=ctk.CTkFont(size=60), text_color=CLR["accent"]
        ).pack(pady=(0, 12))

        ctk.CTkLabel(
            self.left, text="Password\nManager",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=CLR["text"], justify="center"
        ).pack()

        ctk.CTkLabel(
            self.left, text="Your vault is locked.",
            font=ctk.CTkFont(size=12), text_color=CLR["subtle"]
        ).pack(pady=(8, 0))

        ctk.CTkFrame(self.left, fg_color="transparent", height=40).pack()

        for icon, text in [
            ("🛡", "AES-256-GCM encrypted"),
            ("🔑", "600K-round PBKDF2 hashing"),
            ("⏱", "Auto-lock after 5 min"),
        ]:
            row = ctk.CTkFrame(self.left, fg_color="transparent")
            row.pack(fill="x", padx=28, pady=3)
            ctk.CTkLabel(
                row, text=icon,
                font=ctk.CTkFont(size=14), text_color=CLR["accent"]
            ).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                row, text=text,
                font=ctk.CTkFont(size=12), text_color=CLR["subtle"], anchor="w"
            ).pack(side="left")

        ctk.CTkFrame(self.left, fg_color="transparent").pack(fill="both", expand=True)

        ctk.CTkLabel(
            self.left, text="v1.0 · CNS Mini Project",
            font=ctk.CTkFont(size=10), text_color=CLR["border"]
        ).pack(pady=(0, 12))

    def _build_right(self) -> None:
        """Login form vertically centered in the right panel."""
        # Top spacer
        ctk.CTkFrame(self.right, fg_color="transparent").pack(fill="both", expand=True)

        # Form card
        card = ctk.CTkFrame(
            self.right, fg_color=CLR["card"], corner_radius=16
        )
        card.pack(padx=60, fill="x")

        # Title
        ctk.CTkLabel(
            card, text="Unlock Your Vault",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=CLR["text"]
        ).pack(pady=(28, 4), padx=32, anchor="w")

        ctk.CTkLabel(
            card,
            text="Enter your master password to continue.",
            font=ctk.CTkFont(size=12), text_color=CLR["subtle"]
        ).pack(padx=32, anchor="w", pady=(0, 20))

        ctk.CTkFrame(card, height=1, fg_color=CLR["border"]).pack(
            fill="x", padx=32, pady=(0, 20)
        )

        # Password field label
        ctk.CTkLabel(
            card, text="Master Password",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=CLR["subtle"]
        ).pack(anchor="w", padx=32)

        # Password row (entry + show button)
        pwd_row = ctk.CTkFrame(card, fg_color="transparent")
        pwd_row.pack(fill="x", padx=32, pady=(4, 0))

        self.password_var = ctk.StringVar()
        self.password_entry = ctk.CTkEntry(
            pwd_row,
            textvariable=self.password_var,
            show="●",
            height=42,
            font=ctk.CTkFont(size=14),
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            text_color=CLR["text"],
            placeholder_text="Enter master password",
            placeholder_text_color=CLR["subtle"],
        )
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.password_entry.bind("<Return>", lambda e: self._on_unlock())

        self._show_btn = ctk.CTkButton(
            pwd_row, text="Show", width=60, height=42,
            fg_color=CLR["entry"], hover_color=CLR["border"],
            text_color=CLR["subtle"],
            font=ctk.CTkFont(size=12),
            border_width=1, border_color=CLR["border"],
            corner_radius=6,
            command=self._toggle_password,
        )
        self._show_btn.pack(side="left", padx=(6, 0))

        # Attempt counter (hidden initially)
        self.attempt_label = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(size=12),
            text_color=CLR["error"]
        )
        self.attempt_label.pack(anchor="w", padx=32, pady=(8, 0))

        # Countdown label (hidden until locked)
        self.countdown_label = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=CLR["warn"]
        )
        self.countdown_label.pack(anchor="w", padx=32, pady=(2, 0))

        # Error label (generic errors)
        self.error_label = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(size=12),
            text_color=CLR["error"], wraplength=360
        )
        self.error_label.pack(pady=(4, 0), padx=32)

        # Unlock button
        self.unlock_btn = ctk.CTkButton(
            card,
            text="Unlock Vault",
            height=46,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=CLR["accent"],
            hover_color=CLR["accent_hov"],
            text_color="#ffffff",
            corner_radius=10,
            command=self._on_unlock,
        )
        self.unlock_btn.pack(fill="x", padx=32, pady=(16, 28))

        # Bottom spacer
        ctk.CTkFrame(self.right, fg_color="transparent").pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _toggle_password(self) -> None:
        """Toggle password visibility."""
        self._pwd_visible = not self._pwd_visible
        self.password_entry.configure(show="" if self._pwd_visible else "●")
        self._show_btn.configure(text="Hide" if self._pwd_visible else "Show")

    def _set_locked_ui(self) -> None:
        """Disable the unlock button and entry when locked out."""
        self.unlock_btn.configure(state="disabled", text="🔒  Locked")
        self.password_entry.configure(state="disabled")
        self._show_btn.configure(state="disabled")

    def _set_unlocked_ui(self) -> None:
        """Re-enable the unlock button and entry after lockout expires."""
        self.unlock_btn.configure(state="normal", text="Unlock Vault")
        self.password_entry.configure(state="normal")
        self._show_btn.configure(state="normal")
        self.countdown_label.configure(text="")

    # ------------------------------------------------------------------
    # Lockout countdown (uses Tkinter after() — no threads needed)
    # ------------------------------------------------------------------

    def _check_initial_lockout(self) -> None:
        """
        Called when the frame is created.

        If the vault is already locked (e.g. the user was locked out before
        restarting the app), immediately show the countdown.
        """
        data = load_vault(self.app.VAULT_PATH)
        if data is None:
            return
        is_locked, secs_left = check_lockout(data)
        if is_locked:
            attempts = data["security"]["failed_attempts"]
            self._show_attempt_count(attempts)
            self._start_countdown(secs_left)

    def _start_countdown(self, seconds: float) -> None:
        """
        Begin the lockout countdown display.

        Uses Tkinter's after() to update the label every second on the
        main thread. No threading required — after() is safe and avoids
        the need for thread-to-GUI communication.

        Args:
            seconds: How many seconds remain in the lockout.
        """
        self._remaining_secs = max(0, int(seconds))
        self._set_locked_ui()
        self._tick_countdown()

    def _tick_countdown(self) -> None:
        """Decrement the countdown and reschedule itself every second."""
        if self._remaining_secs <= 0:
            self._on_lockout_expired()
            return

        self.countdown_label.configure(
            text=f"🔒  Locked – try again in {self._remaining_secs}s",
            text_color=CLR["warn"]
        )
        self._remaining_secs -= 1
        # Schedule next tick in 1 000 ms (Tkinter main-thread safe)
        self._countdown_job = self.after(1000, self._tick_countdown)

    def _on_lockout_expired(self) -> None:
        """Called when the countdown reaches 0 — re-enable login."""
        self._set_unlocked_ui()
        self.attempt_label.configure(
            text="Lockout expired — you may try again.",
            text_color=CLR["subtle"]
        )
        self.password_entry.focus()

    def _show_attempt_count(self, attempts: int) -> None:
        """Display 'Attempt N of 5' in the attempt counter label."""
        self.attempt_label.configure(
            text=(
                f"Wrong password.  "
                f"Attempt {attempts} of {MAX_ATTEMPTS_BEFORE_LOCKOUT}."
            ),
            text_color=CLR["error"]
        )

    # ------------------------------------------------------------------
    # Unlock action
    # ------------------------------------------------------------------

    def _on_unlock(self) -> None:
        """
        Attempt to authenticate with the typed master password.

        Catches:
          LockoutError       → start countdown, disable UI.
          WrongPasswordError → update attempt counter.
          FileNotFoundError  → should not happen here (button disabled on
                               first-run), but handled defensively.
          Exception          → show generic error, do not crash.

        On success: calls app.on_login_success(enc_key, vault_data).
        The GUI never touches the enc_key directly — it passes it straight
        to the App which is the sole keeper of session state.
        """
        # Cancel any running countdown (shouldn't be running if button is enabled,
        # but defensive clean-up)
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
            self._countdown_job = None

        self.error_label.configure(text="")
        password = self.password_var.get()

        if not password:
            self.error_label.configure(text="Please enter your master password.")
            self.password_entry.focus()
            return

        # Disable button while PBKDF2 runs (~1-2 s)
        self.unlock_btn.configure(state="disabled", text="Verifying…")
        self.update()  # repaint before the slow call

        try:
            enc_key, vault_data = login(password, self.app.VAULT_PATH)

        except LockoutError as exc:
            # Locked out — show countdown
            data = load_vault(self.app.VAULT_PATH)
            if data:
                self._show_attempt_count(data["security"]["failed_attempts"])
            self._start_countdown(exc.seconds_remaining)
            return

        except WrongPasswordError:
            # Re-enable button; show attempt count
            self.unlock_btn.configure(state="normal", text="Unlock Vault")
            data = load_vault(self.app.VAULT_PATH)
            if data:
                attempts = data["security"]["failed_attempts"]
                self._show_attempt_count(attempts)
                # If this wrong attempt triggered a lockout, start countdown
                is_locked, secs = check_lockout(data)
                if is_locked:
                    self._start_countdown(secs)
            self.password_entry.delete(0, "end")
            self.password_entry.focus()
            return

        except FileNotFoundError:
            self.error_label.configure(
                text="Vault file not found. Please restart the app."
            )
            self.unlock_btn.configure(state="normal", text="Unlock Vault")
            return

        except Exception as exc:
            self.error_label.configure(text=f"Unexpected error: {exc}")
            self.unlock_btn.configure(state="normal", text="Unlock Vault")
            return

        # ---- Success: hand off to App ----
        # enc_key is a bytearray. The App becomes its sole owner.
        self.app.on_login_success(enc_key, vault_data)

    def destroy(self) -> None:
        """Cancel the countdown timer when this frame is destroyed."""
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
        super().destroy()
