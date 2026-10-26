"""
gui/setup_frame.py
==================
First-run screen: "Create Master Password".

UI elements
-----------
- Left branding panel (logo, tagline, security notice)
- Right form panel:
    * Password entry with show/hide toggle
    * Live strength meter (progress bar + label, updates on every key)
    * Confirm password entry with show/hide toggle
    * Match indicator (✓/✗)
    * "Create Vault" button
    * Inline error label

Crypto rule: NO crypto code in this file.
Calls:  core.auth.setup_vault
Reads:  core.generator.password_strength  (for the strength meter only)
"""

from typing import TYPE_CHECKING

import customtkinter as ctk

from core.auth import setup_vault
from core.generator import password_strength
from gui.app import CLR

if TYPE_CHECKING:
    from gui.app import App   # import only for type hints (avoids circular import)


class SetupFrame(ctk.CTkFrame):
    """
    First-run frame shown when no vault.json exists.

    Layout: two-panel split
      ┌──────────────┬─────────────────────────────────┐
      │  Left panel  │          Right panel             │
      │  (branding)  │  (form: password + confirm)      │
      └──────────────┴─────────────────────────────────┘
    """

    def __init__(self, master: ctk.CTk, app: "App") -> None:
        super().__init__(master, fg_color=CLR["bg"], corner_radius=0)
        self.app = app
        self._pwd_visible     = False
        self._confirm_visible = False

        self._build_layout()

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        """Create the two-panel split."""
        # Left: branding panel (fixed width)
        self.left = ctk.CTkFrame(
            self, width=310, fg_color=CLR["panel"], corner_radius=0
        )
        self.left.pack(side="left", fill="y")
        self.left.pack_propagate(False)   # keep fixed width

        # Vertical separator
        ctk.CTkFrame(self, width=1, fg_color=CLR["border"], corner_radius=0).pack(
            side="left", fill="y"
        )

        # Right: form panel (expands)
        self.right = ctk.CTkFrame(self, fg_color=CLR["bg"], corner_radius=0)
        self.right.pack(side="left", fill="both", expand=True)

        self._build_left()
        self._build_right()

    def _build_left(self) -> None:
        """Branding content centered vertically in the left panel."""
        # Vertical spacer top
        ctk.CTkFrame(self.left, fg_color="transparent").pack(fill="both", expand=True)

        # Lock icon
        ctk.CTkLabel(
            self.left, text="🔐",
            font=ctk.CTkFont(size=60), text_color=CLR["accent"]
        ).pack(pady=(0, 12))

        # App name
        ctk.CTkLabel(
            self.left, text="Password\nManager",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=CLR["text"], justify="center"
        ).pack()

        # Tagline
        ctk.CTkLabel(
            self.left, text="Secure. Private. Yours.",
            font=ctk.CTkFont(size=12),
            text_color=CLR["subtle"]
        ).pack(pady=(8, 0))

        # Vertical spacer middle
        ctk.CTkFrame(self.left, fg_color="transparent", height=40).pack()

        # Security callouts
        for icon, text in [
            ("🛡", "AES-256-GCM encrypted"),
            ("🔑", "600K-round PBKDF2 hashing"),
            ("💾", "Atomic saves, auto-backup"),
        ]:
            row = ctk.CTkFrame(self.left, fg_color="transparent")
            row.pack(fill="x", padx=28, pady=3)
            ctk.CTkLabel(
                row, text=icon,
                font=ctk.CTkFont(size=14), text_color=CLR["accent"]
            ).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                row, text=text,
                font=ctk.CTkFont(size=12), text_color=CLR["subtle"],
                anchor="w"
            ).pack(side="left")

        # Vertical spacer bottom
        ctk.CTkFrame(self.left, fg_color="transparent").pack(fill="both", expand=True)

        # Version footer
        ctk.CTkLabel(
            self.left, text="v1.0 · CNS Mini Project",
            font=ctk.CTkFont(size=10), text_color=CLR["border"]
        ).pack(pady=(0, 12))

    def _build_right(self) -> None:
        """Form content vertically centered in the right panel."""
        # ---- Vertical centering spacer (top) ----
        ctk.CTkFrame(self.right, fg_color="transparent").pack(fill="both", expand=True)

        # ---- Form card ----
        card = ctk.CTkFrame(
            self.right, fg_color=CLR["card"],
            corner_radius=16
        )
        card.pack(padx=60, pady=0, fill="x")

        # Title
        ctk.CTkLabel(
            card, text="Create Master Password",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=CLR["text"]
        ).pack(pady=(28, 4), padx=32, anchor="w")

        ctk.CTkLabel(
            card,
            text="This password is never stored — it encrypts your vault.",
            font=ctk.CTkFont(size=12), text_color=CLR["subtle"]
        ).pack(padx=32, anchor="w", pady=(0, 20))

        # ---- Divider ----
        ctk.CTkFrame(card, height=1, fg_color=CLR["border"]).pack(
            fill="x", padx=32, pady=(0, 20)
        )

        # ---- Password field ----
        ctk.CTkLabel(
            card, text="Master Password",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=CLR["subtle"]
        ).pack(anchor="w", padx=32)

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
            placeholder_text="At least 12 characters",
            placeholder_text_color=CLR["subtle"],
        )
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.password_entry.bind("<Return>", lambda e: self.confirm_entry.focus())

        self._show_pwd_btn = ctk.CTkButton(
            pwd_row, text="Show", width=60, height=42,
            fg_color=CLR["entry"], hover_color=CLR["border"],
            text_color=CLR["subtle"],
            font=ctk.CTkFont(size=12),
            border_width=1, border_color=CLR["border"],
            corner_radius=6,
            command=self._toggle_password,
        )
        self._show_pwd_btn.pack(side="left", padx=(6, 0))

        # ---- Strength meter ----
        strength_frame = ctk.CTkFrame(card, fg_color="transparent")
        strength_frame.pack(fill="x", padx=32, pady=(8, 0))

        self.strength_bar = ctk.CTkProgressBar(
            strength_frame, height=6, corner_radius=4,
            fg_color=CLR["border"], progress_color=CLR["error"]
        )
        self.strength_bar.set(0)
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.strength_label = ctk.CTkLabel(
            strength_frame, text="—",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=CLR["subtle"], width=80, anchor="e"
        )
        self.strength_label.pack(side="left")

        # Trace password changes for live strength update
        self.password_var.trace_add("write", self._update_strength)

        # ---- Confirm field ----
        ctk.CTkLabel(
            card, text="Confirm Password",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=CLR["subtle"]
        ).pack(anchor="w", padx=32, pady=(16, 0))

        confirm_row = ctk.CTkFrame(card, fg_color="transparent")
        confirm_row.pack(fill="x", padx=32, pady=(4, 0))

        self.confirm_var = ctk.StringVar()
        self.confirm_entry = ctk.CTkEntry(
            confirm_row,
            textvariable=self.confirm_var,
            show="●",
            height=42,
            font=ctk.CTkFont(size=14),
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            text_color=CLR["text"],
            placeholder_text="Repeat your password",
            placeholder_text_color=CLR["subtle"],
        )
        self.confirm_entry.pack(side="left", fill="x", expand=True)
        self.confirm_entry.bind("<Return>", lambda e: self._on_create())

        self._show_confirm_btn = ctk.CTkButton(
            confirm_row, text="Show", width=60, height=42,
            fg_color=CLR["entry"], hover_color=CLR["border"],
            text_color=CLR["subtle"],
            font=ctk.CTkFont(size=12),
            border_width=1, border_color=CLR["border"],
            corner_radius=6,
            command=self._toggle_confirm,
        )
        self._show_confirm_btn.pack(side="left", padx=(6, 0))

        # Match indicator
        self.match_label = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(size=11),
            text_color=CLR["subtle"]
        )
        self.match_label.pack(anchor="w", padx=32, pady=(6, 0))
        self.confirm_var.trace_add("write", self._update_match)
        self.password_var.trace_add("write", self._update_match)

        # ---- Error label ----
        self.error_label = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(size=12),
            text_color=CLR["error"], wraplength=360
        )
        self.error_label.pack(pady=(8, 0), padx=32)

        # ---- Create button ----
        self.create_btn = ctk.CTkButton(
            card,
            text="Create Vault",
            height=46,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color=CLR["accent"],
            hover_color=CLR["accent_hov"],
            text_color="#ffffff",
            corner_radius=10,
            command=self._on_create,
        )
        self.create_btn.pack(fill="x", padx=32, pady=(16, 28))

        # ---- Vertical centering spacer (bottom) ----
        ctk.CTkFrame(self.right, fg_color="transparent").pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _toggle_password(self) -> None:
        """Toggle the master password field between hidden and visible."""
        self._pwd_visible = not self._pwd_visible
        self.password_entry.configure(show="" if self._pwd_visible else "●")
        self._show_pwd_btn.configure(
            text="Hide" if self._pwd_visible else "Show"
        )

    def _toggle_confirm(self) -> None:
        """Toggle the confirm field between hidden and visible."""
        self._confirm_visible = not self._confirm_visible
        self.confirm_entry.configure(show="" if self._confirm_visible else "●")
        self._show_confirm_btn.configure(
            text="Hide" if self._confirm_visible else "Show"
        )

    def _update_strength(self, *_) -> None:
        """
        Called on every keystroke in the password field.

        Uses password_strength() from core.generator (no crypto — purely
        string analysis). Updates the progress bar colour and label.
        """
        pwd = self.password_var.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_bar.configure(progress_color=CLR["border"])
            self.strength_label.configure(text="—", text_color=CLR["subtle"])
            return

        result = password_strength(pwd)
        self.strength_bar.set(result.score / 8.0)
        self.strength_bar.configure(progress_color=result.color)
        self.strength_label.configure(text=result.label, text_color=result.color)

    def _update_match(self, *_) -> None:
        """Show whether the two password fields match."""
        pwd     = self.password_var.get()
        confirm = self.confirm_var.get()
        if not confirm:
            self.match_label.configure(text="", text_color=CLR["subtle"])
        elif pwd == confirm:
            self.match_label.configure(
                text="✓  Passwords match", text_color=CLR["success"]
            )
        else:
            self.match_label.configure(
                text="✗  Passwords do not match", text_color=CLR["error"]
            )

    def _set_error(self, msg: str) -> None:
        self.error_label.configure(text=msg)

    def _clear_error(self) -> None:
        self.error_label.configure(text="")

    def _on_create(self) -> None:
        """
        Validate and create the vault.

        Validation order:
          1. Password must be ≥ 12 characters.
          2. Password must meet at least 'Moderate' strength (score ≥ 5).
          3. Confirm field must match.

        On success: calls app.on_setup_complete() → switches to LoginFrame.
        On failure: shows inline error, does NOT crash.
        """
        self._clear_error()
        pwd     = self.password_var.get()
        confirm = self.confirm_var.get()

        # ---- Validation ----
        if len(pwd) < 12:
            self._set_error("Password must be at least 12 characters.")
            self.password_entry.focus()
            return

        strength = password_strength(pwd)
        if strength.score < 3:
            self._set_error(
                f"Password is too weak ({strength.label}). "
                "Add uppercase, numbers or symbols."
            )
            return

        if pwd != confirm:
            self._set_error("Passwords do not match. Please re-enter.")
            self.confirm_entry.focus()
            return

        # ---- Attempt vault creation ----
        self.create_btn.configure(state="disabled", text="Creating…")
        self.update()   # repaint before the slow PBKDF2 call

        try:
            setup_vault(pwd, self.app.VAULT_PATH)
        except Exception as exc:
            self._set_error(f"Error: {exc}")
            self.create_btn.configure(state="normal", text="Create Vault")
            return

        # ---- Success ----
        self.app.on_setup_complete()
