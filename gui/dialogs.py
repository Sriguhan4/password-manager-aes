"""
gui/dialogs.py
==============
Dialog windows for the Password Manager:
1. EntryDialog         – Add / Edit vault entry with live strength meter and generator integration.
2. GeneratorDialog     – Configurable CSPRNG password generator with custom rules.
3. ChangePasswordDialog– Change master password with PBKDF2 re-derivation and re-encryption.
4. Clipboard Helper    – Secure clipboard copy with 30-second automatic wipe.

Security note:
Clipboard auto-wipe prevents sensitive passwords from lingering indefinitely
in the system clipboard where other unprivileged processes can harvest them.
"""

from typing import TYPE_CHECKING, Any, Callable, Optional

import customtkinter as ctk

from core.generator import generate_password, password_strength
from gui.app import CLR

if TYPE_CHECKING:
    from gui.app import App


# ---------------------------------------------------------------------------
# Secure Clipboard Helper (30-second auto-wipe)
# ---------------------------------------------------------------------------

def copy_to_clipboard_secure(
    widget: ctk.CTkBaseClass,
    secret_text: str,
    feedback_label: Optional[ctk.CTkLabel] = None,
    wipe_seconds: int = 30,
) -> None:
    """
    Copy a secret string to the system clipboard and schedule an auto-wipe.

    WHY 30-second wipe?
    The OS clipboard is accessible to any running process without permissions.
    If a user copies a password to paste into a browser, leaving it on the
    clipboard indefinitely creates a large attack surface for credential scrapers.
    Clearing it after 30 seconds limits that exposure window.

    Args:
        widget: Any Tkinter/CustomTkinter widget with access to .clipboard_*()
        secret_text: Plaintext password or credential to copy.
        feedback_label: Optional CTkLabel to display transient confirmation.
        wipe_seconds: Time in seconds before erasing (default 30).
    """
    try:
        widget.clipboard_clear()
        widget.clipboard_append(secret_text)
        widget.update()  # Flush to OS clipboard
    except Exception:
        # Fallback in case OS clipboard access is momentarily locked
        pass

    # Provide UI feedback if a label was supplied
    if feedback_label is not None:
        original_text = feedback_label.cget("text")
        original_color = feedback_label.cget("text_color")
        feedback_label.configure(
            text=f"✓ Copied! (Auto-wipes in {wipe_seconds}s)",
            text_color=CLR["success"]
        )

        def restore_feedback():
            try:
                feedback_label.configure(text=original_text, text_color=original_color)
            except Exception:
                pass

        widget.after(3000, restore_feedback)

    # Schedule clipboard wipe after wipe_seconds
    def wipe_clipboard():
        try:
            # Only wipe if the clipboard still contains the exact secret
            # (i.e. don't overwrite if user has already copied something else)
            current_clip = widget.clipboard_get()
            if current_clip == secret_text:
                widget.clipboard_clear()
                widget.clipboard_append("")
                widget.update()
        except Exception:
            pass

    widget.after(wipe_seconds * 1000, wipe_clipboard)


# ---------------------------------------------------------------------------
# 1. Entry Dialog (Add or Edit Account)
# ---------------------------------------------------------------------------

class EntryDialog(ctk.CTkToplevel):
    """
    Modal dialog for adding a new entry or editing an existing one.

    Features:
    - Input fields: Site / App Name, Username / Email, Password, Notes.
    - Password visibility toggle (👁️).
    - Quick "⚡ Generate" button opening the CSPRNG generator.
    - Live strength meter with color coding and score.
    - Input validation (site and password required).
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        app: "App",
        mode: str = "add",
        entry: Optional[dict[str, Any]] = None,
        on_save: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.app = app
        self.mode = mode
        self.entry = entry or {}
        self.on_save = on_save

        self._pwd_visible = False

        # Window setup
        title_text = "Add New Entry" if mode == "add" else f"Edit Entry: {self.entry.get('site', '')}"
        self.title(title_text)
        self.geometry("540x650")
        self.minsize(480, 580)
        self.configure(fg_color=CLR["bg"])

        # Make modal
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        # Center on parent
        self._center_window(parent.winfo_toplevel())

        self._build_ui()
        self._populate_initial()

    def _center_window(self, parent_win: ctk.CTkBaseClass) -> None:
        self.update_idletasks()
        try:
            px = parent_win.winfo_x()
            py = parent_win.winfo_y()
            pw = parent_win.winfo_width()
            ph = parent_win.winfo_height()
            w, h = 540, 650
            x = px + max(0, (pw - w) // 2)
            y = py + max(0, (ph - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build_ui(self) -> None:
        main_frame = ctk.CTkFrame(self, fg_color=CLR["card"], corner_radius=12)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header Title
        heading = "➕ Add Account Entry" if self.mode == "add" else "✏️ Edit Account Entry"
        ctk.CTkLabel(
            main_frame,
            text=heading,
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=CLR["text"]
        ).pack(anchor="w", padx=24, pady=(20, 15))

        # Form container
        form = ctk.CTkFrame(main_frame, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=24)

        # 1. Site / Service Name
        ctk.CTkLabel(form, text="Website / Service *", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(anchor="w", pady=(4, 2))
        self.site_entry = ctk.CTkEntry(
            form,
            placeholder_text="e.g. github.com, Google, Netflix",
            height=38,
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            text_color=CLR["text"],
            placeholder_text_color=CLR["subtle"]
        )
        self.site_entry.pack(fill="x", pady=(0, 10))

        # 2. Username / Email
        ctk.CTkLabel(form, text="Username / Email", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(anchor="w", pady=(4, 2))
        self.user_entry = ctk.CTkEntry(
            form,
            placeholder_text="e.g. user@example.com or alice_dev",
            height=38,
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            text_color=CLR["text"],
            placeholder_text_color=CLR["subtle"]
        )
        self.user_entry.pack(fill="x", pady=(0, 10))

        # 3. Password field row with Eye & Generate buttons
        pwd_hdr = ctk.CTkFrame(form, fg_color="transparent")
        pwd_hdr.pack(fill="x", pady=(4, 2))
        ctk.CTkLabel(pwd_hdr, text="Password *", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(side="left")

        gen_btn = ctk.CTkButton(
            pwd_hdr,
            text="⚡ Generate Secure",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=24,
            width=120,
            fg_color=CLR["accent_dim"],
            hover_color=CLR["accent"],
            text_color=CLR["text"],
            command=self._open_generator
        )
        gen_btn.pack(side="right")

        pwd_row = ctk.CTkFrame(form, fg_color="transparent")
        pwd_row.pack(fill="x", pady=(0, 4))

        self.pwd_entry = ctk.CTkEntry(
            pwd_row,
            placeholder_text="Account password",
            show="•",
            height=38,
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            text_color=CLR["text"],
            placeholder_text_color=CLR["subtle"]
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.pwd_entry.bind("<KeyRelease>", self._on_password_change)

        self.eye_btn = ctk.CTkButton(
            pwd_row,
            text="👁️",
            width=42,
            height=38,
            fg_color=CLR["entry"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            command=self._toggle_password_visibility
        )
        self.eye_btn.pack(side="right")

        # Live Strength Indicator
        meter_row = ctk.CTkFrame(form, fg_color="transparent")
        meter_row.pack(fill="x", pady=(2, 10))

        self.strength_bar = ctk.CTkProgressBar(
            meter_row,
            height=6,
            fg_color=CLR["entry"],
            progress_color=CLR["border"]
        )
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.strength_bar.set(0.0)

        self.strength_lbl = ctk.CTkLabel(
            meter_row,
            text="Strength: —",
            font=ctk.CTkFont(size=11),
            text_color=CLR["subtle"],
            width=100,
            anchor="e"
        )
        self.strength_lbl.pack(side="right")

        # 4. Notes
        ctk.CTkLabel(form, text="Notes (Optional)", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(anchor="w", pady=(4, 2))
        self.notes_txt = ctk.CTkTextbox(
            form,
            height=90,
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            border_width=1,
            text_color=CLR["text"]
        )
        self.notes_txt.pack(fill="x", pady=(0, 12))

        # Inline Error Label
        self.error_lbl = ctk.CTkLabel(
            form,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=CLR["error"]
        )
        self.error_lbl.pack(anchor="w", pady=(0, 8))

        # Bottom Action Buttons
        btn_row = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(10, 20))

        cancel_btn = ctk.CTkButton(
            btn_row,
            text="Cancel",
            height=40,
            fg_color=CLR["card"],
            border_color=CLR["border"],
            border_width=1,
            hover_color=CLR["entry"],
            text_color=CLR["text"],
            command=self.destroy
        )
        cancel_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))

        save_btn = ctk.CTkButton(
            btn_row,
            text="💾 Save Entry" if self.mode == "add" else "💾 Update Entry",
            height=40,
            fg_color=CLR["accent"],
            hover_color=CLR["accent_hov"],
            text_color="#ffffff",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._handle_save
        )
        save_btn.pack(side="right", fill="x", expand=True)

    def _populate_initial(self) -> None:
        if self.mode == "edit" and self.entry:
            self.site_entry.insert(0, self.entry.get("site", ""))
            self.user_entry.insert(0, self.entry.get("username", ""))
            pwd = self.entry.get("password", "")
            self.pwd_entry.insert(0, pwd)
            self.notes_txt.insert("1.0", self.entry.get("notes", ""))
            self._update_strength_meter(pwd)

    def _toggle_password_visibility(self) -> None:
        self._pwd_visible = not self._pwd_visible
        self.pwd_entry.configure(show="" if self._pwd_visible else "•")
        self.eye_btn.configure(text="🔒" if self._pwd_visible else "👁️")

    def _on_password_change(self, event=None) -> None:
        pwd = self.pwd_entry.get()
        self._update_strength_meter(pwd)

    def _update_strength_meter(self, password: str) -> None:
        if not password:
            self.strength_bar.set(0.0)
            self.strength_bar.configure(progress_color=CLR["border"])
            self.strength_lbl.configure(text="Strength: —", text_color=CLR["subtle"])
            return

        result = password_strength(password)
        progress = max(0.125, min(1.0, result.score / 8.0))
        self.strength_bar.set(progress)
        self.strength_bar.configure(progress_color=result.color)
        self.strength_lbl.configure(text=f"{result.label} ({result.score}/8)", text_color=result.color)

    def _open_generator(self) -> None:
        def on_use(generated_pwd: str):
            self.pwd_entry.delete(0, "end")
            self.pwd_entry.insert(0, generated_pwd)
            self._update_strength_meter(generated_pwd)

        GeneratorDialog(parent=self, on_use_password=on_use)

    def _handle_save(self) -> None:
        site = self.site_entry.get().strip()
        username = self.user_entry.get().strip()
        password = self.pwd_entry.get()
        notes = self.notes_txt.get("1.0", "end-1c").strip()

        if not site:
            self.error_lbl.configure(text="Website / Service name is required.")
            self.site_entry.focus_set()
            return

        if not password:
            self.error_lbl.configure(text="Password is required.")
            self.pwd_entry.focus_set()
            return

        data = {
            "site": site,
            "username": username,
            "password": password,
            "notes": notes,
        }
        if self.mode == "edit":
            data["id"] = self.entry["id"]

        if self.on_save:
            self.on_save(data)

        self.destroy()


# ---------------------------------------------------------------------------
# 2. Generator Dialog (Configurable CSPRNG Tool)
# ---------------------------------------------------------------------------

class GeneratorDialog(ctk.CTkToplevel):
    """
    Dedicated dialog for generating cryptographically secure random passwords.

    Features:
    - Length slider (8–64 characters).
    - Checkboxes for Uppercase, Lowercase, Digits, Symbols.
    - Guarantee: At least one character from each checked pool.
    - Secure shuffle: Fisher-Yates with secrets.randbelow.
    - One-click copy with 30s auto-wipe.
    - Optional "Use Password" button to populate parent form.
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        on_use_password: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.on_use_password = on_use_password

        self.title("⚡ Password Generator")
        self.geometry("500x560")
        self.minsize(440, 500)
        self.configure(fg_color=CLR["bg"])

        self.transient(parent.winfo_toplevel())
        self.grab_set()
        self._center_window(parent.winfo_toplevel())

        self._build_ui()
        self._generate()

    def _center_window(self, parent_win: ctk.CTkBaseClass) -> None:
        self.update_idletasks()
        try:
            px = parent_win.winfo_x()
            py = parent_win.winfo_y()
            pw = parent_win.winfo_width()
            ph = parent_win.winfo_height()
            w, h = 500, 560
            x = px + max(0, (pw - w) // 2)
            y = py + max(0, (ph - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build_ui(self) -> None:
        main_frame = ctk.CTkFrame(self, fg_color=CLR["card"], corner_radius=12)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            main_frame,
            text="⚡ Secure Password Generator",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=CLR["text"]
        ).pack(anchor="w", padx=24, pady=(20, 15))

        # Output box with generated password
        display_frame = ctk.CTkFrame(main_frame, fg_color=CLR["entry"], corner_radius=8)
        display_frame.pack(fill="x", padx=24, pady=(0, 10))

        self.pwd_display = ctk.CTkEntry(
            display_frame,
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            fg_color="transparent",
            border_width=0,
            text_color=CLR["text"],
            height=45
        )
        self.pwd_display.pack(side="left", fill="x", expand=True, padx=12)

        copy_btn = ctk.CTkButton(
            display_frame,
            text="📋 Copy",
            width=70,
            height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=CLR["accent_dim"],
            hover_color=CLR["accent"],
            command=self._copy_password
        )
        copy_btn.pack(side="right", padx=8)

        # Live Strength Bar for Generated Password
        st_row = ctk.CTkFrame(main_frame, fg_color="transparent")
        st_row.pack(fill="x", padx=24, pady=(0, 15))

        self.strength_bar = ctk.CTkProgressBar(st_row, height=5, fg_color=CLR["entry"])
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.strength_lbl = ctk.CTkLabel(
            st_row, text="—", font=ctk.CTkFont(size=11), text_color=CLR["subtle"], width=90, anchor="e"
        )
        self.strength_lbl.pack(side="right")

        # Feedback notification label
        self.notify_lbl = ctk.CTkLabel(main_frame, text="", font=ctk.CTkFont(size=12), text_color=CLR["success"])
        self.notify_lbl.pack(anchor="w", padx=24, pady=(0, 8))

        # Slider: Length
        len_hdr = ctk.CTkFrame(main_frame, fg_color="transparent")
        len_hdr.pack(fill="x", padx=24, pady=(5, 4))

        ctk.CTkLabel(len_hdr, text="Password Length:", font=ctk.CTkFont(size=13, weight="bold"), text_color=CLR["text"]).pack(side="left")
        self.len_lbl = ctk.CTkLabel(len_hdr, text="16 characters", font=ctk.CTkFont(size=13), text_color=CLR["accent"])
        self.len_lbl.pack(side="right")

        self.slider = ctk.CTkSlider(
            main_frame,
            from_=8,
            to=64,
            number_of_steps=56,
            command=self._on_slider_change,
            button_color=CLR["accent"],
            progress_color=CLR["accent"]
        )
        self.slider.set(16)
        self.slider.pack(fill="x", padx=24, pady=(0, 15))

        # Checkboxes for character classes
        classes_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        classes_frame.pack(fill="x", padx=24, pady=(0, 15))

        self.chk_upper = ctk.CTkCheckBox(
            classes_frame, text="Uppercase (A–Z)", font=ctk.CTkFont(size=12),
            text_color=CLR["text"], fg_color=CLR["accent"], hover_color=CLR["accent_hov"],
            command=self._generate
        )
        self.chk_upper.select()
        self.chk_upper.grid(row=0, column=0, sticky="w", padx=(0, 15), pady=6)

        self.chk_lower = ctk.CTkCheckBox(
            classes_frame, text="Lowercase (a–z)", font=ctk.CTkFont(size=12),
            text_color=CLR["text"], fg_color=CLR["accent"], hover_color=CLR["accent_hov"],
            command=self._generate
        )
        self.chk_lower.select()
        self.chk_lower.grid(row=0, column=1, sticky="w", pady=6)

        self.chk_digits = ctk.CTkCheckBox(
            classes_frame, text="Digits (0–9)", font=ctk.CTkFont(size=12),
            text_color=CLR["text"], fg_color=CLR["accent"], hover_color=CLR["accent_hov"],
            command=self._generate
        )
        self.chk_digits.select()
        self.chk_digits.grid(row=1, column=0, sticky="w", padx=(0, 15), pady=6)

        self.chk_symbols = ctk.CTkCheckBox(
            classes_frame, text="Symbols (!@#$...)", font=ctk.CTkFont(size=12),
            text_color=CLR["text"], fg_color=CLR["accent"], hover_color=CLR["accent_hov"],
            command=self._generate
        )
        self.chk_symbols.select()
        self.chk_symbols.grid(row=1, column=1, sticky="w", pady=6)

        # Buttons row
        btn_row = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(15, 20))

        regen_btn = ctk.CTkButton(
            btn_row,
            text="🔄 Regenerate",
            height=38,
            fg_color=CLR["entry"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            command=self._generate
        )
        regen_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))

        if self.on_use_password:
            use_btn = ctk.CTkButton(
                btn_row,
                text="✓ Use in Form",
                height=38,
                fg_color=CLR["accent"],
                hover_color=CLR["accent_hov"],
                text_color="#ffffff",
                font=ctk.CTkFont(weight="bold"),
                command=self._use_in_form
            )
            use_btn.pack(side="right", fill="x", expand=True)
        else:
            close_btn = ctk.CTkButton(
                btn_row,
                text="Close",
                height=38,
                fg_color=CLR["accent"],
                hover_color=CLR["accent_hov"],
                text_color="#ffffff",
                command=self.destroy
            )
            close_btn.pack(side="right", fill="x", expand=True)

    def _on_slider_change(self, value: float) -> None:
        length = int(value)
        self.len_lbl.configure(text=f"{length} characters")
        self._generate()

    def _generate(self) -> None:
        length = int(self.slider.get())
        upper = bool(self.chk_upper.get())
        lower = bool(self.chk_lower.get())
        digits = bool(self.chk_digits.get())
        symbols = bool(self.chk_symbols.get())

        # If user unchecks all, recheck lower so we never error
        if not any([upper, lower, digits, symbols]):
            self.chk_lower.select()
            lower = True

        pwd = generate_password(
            length=length,
            use_upper=upper,
            use_lower=lower,
            use_digits=digits,
            use_symbols=symbols,
        )

        self.pwd_display.delete(0, "end")
        self.pwd_display.insert(0, pwd)

        # Strength update
        res = password_strength(pwd)
        self.strength_bar.set(max(0.125, res.score / 8.0))
        self.strength_bar.configure(progress_color=res.color)
        self.strength_lbl.configure(text=f"{res.label}", text_color=res.color)

    def _copy_password(self) -> None:
        pwd = self.pwd_display.get()
        if pwd:
            copy_to_clipboard_secure(self, pwd, feedback_label=self.notify_lbl)

    def _use_in_form(self) -> None:
        pwd = self.pwd_display.get()
        if pwd and self.on_use_password:
            self.on_use_password(pwd)
        self.destroy()


# ---------------------------------------------------------------------------
# 3. Change Master Password Dialog
# ---------------------------------------------------------------------------

class ChangePasswordDialog(ctk.CTkToplevel):
    """
    Modal dialog allowing the user to change their master password.

    Calls core.auth.change_master_password, which:
      1. Verifies old master password
      2. Decrypts vault
      3. Generates fresh auth & enc salts
      4. Re-hashes with PBKDF2 (600,000 rounds)
      5. Re-encrypts with fresh AES-256-GCM key and nonce
      6. Wipes old key from memory
      7. Saves vault atomically
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        app: "App",
        on_success: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.app = app
        self.on_success = on_success

        self.title("🔑 Change Master Password")
        self.geometry("520x620")
        self.minsize(460, 560)
        self.configure(fg_color=CLR["bg"])

        self.transient(parent.winfo_toplevel())
        self.grab_set()
        self._center_window(parent.winfo_toplevel())

        self._build_ui()

    def _center_window(self, parent_win: ctk.CTkBaseClass) -> None:
        self.update_idletasks()
        try:
            px = parent_win.winfo_x()
            py = parent_win.winfo_y()
            pw = parent_win.winfo_width()
            ph = parent_win.winfo_height()
            w, h = 520, 620
            x = px + max(0, (pw - w) // 2)
            y = py + max(0, (ph - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build_ui(self) -> None:
        main_frame = ctk.CTkFrame(self, fg_color=CLR["card"], corner_radius=12)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="🔑 Change Master Password",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=CLR["text"]
        ).pack(anchor="w", padx=24, pady=(20, 8))

        ctk.CTkLabel(
            main_frame,
            text="This will re-encrypt your entire vault with new salts\nand PBKDF2 key derivation.",
            font=ctk.CTkFont(size=12),
            text_color=CLR["subtle"],
            justify="left"
        ).pack(anchor="w", padx=24, pady=(0, 15))

        form = ctk.CTkFrame(main_frame, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=24)

        # 1. Current Password
        ctk.CTkLabel(form, text="Current Master Password *", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(anchor="w", pady=(4, 2))
        self.old_entry = ctk.CTkEntry(
            form, show="•", height=38, fg_color=CLR["entry"], border_color=CLR["border"], text_color=CLR["text"]
        )
        self.old_entry.pack(fill="x", pady=(0, 12))

        # 2. New Password
        ctk.CTkLabel(form, text="New Master Password (min 12 chars) *", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(anchor="w", pady=(4, 2))
        self.new_entry = ctk.CTkEntry(
            form, show="•", height=38, fg_color=CLR["entry"], border_color=CLR["border"], text_color=CLR["text"]
        )
        self.new_entry.pack(fill="x", pady=(0, 4))
        self.new_entry.bind("<KeyRelease>", self._on_new_password_change)

        # Strength Bar
        st_row = ctk.CTkFrame(form, fg_color="transparent")
        st_row.pack(fill="x", pady=(0, 12))
        self.strength_bar = ctk.CTkProgressBar(st_row, height=5, fg_color=CLR["entry"])
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.strength_bar.set(0.0)
        self.strength_lbl = ctk.CTkLabel(st_row, text="—", font=ctk.CTkFont(size=11), text_color=CLR["subtle"], width=90, anchor="e")
        self.strength_lbl.pack(side="right")

        # 3. Confirm New Password
        ctk.CTkLabel(form, text="Confirm New Password *", font=ctk.CTkFont(size=12, weight="bold"), text_color=CLR["text"]).pack(anchor="w", pady=(4, 2))
        self.confirm_entry = ctk.CTkEntry(
            form, show="•", height=38, fg_color=CLR["entry"], border_color=CLR["border"], text_color=CLR["text"]
        )
        self.confirm_entry.pack(fill="x", pady=(0, 10))

        # Status / Error Label
        self.status_lbl = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=12), text_color=CLR["error"])
        self.status_lbl.pack(anchor="w", pady=(0, 10))

        # Buttons
        btn_row = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(10, 20))

        cancel_btn = ctk.CTkButton(
            btn_row,
            text="Cancel",
            height=40,
            fg_color=CLR["card"],
            border_color=CLR["border"],
            border_width=1,
            hover_color=CLR["entry"],
            command=self.destroy
        )
        cancel_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.save_btn = ctk.CTkButton(
            btn_row,
            text="Update Master Password",
            height=40,
            fg_color=CLR["accent"],
            hover_color=CLR["accent_hov"],
            font=ctk.CTkFont(weight="bold"),
            command=self._handle_change
        )
        self.save_btn.pack(side="right", fill="x", expand=True)

    def _on_new_password_change(self, event=None) -> None:
        pwd = self.new_entry.get()
        if not pwd:
            self.strength_bar.set(0.0)
            self.strength_lbl.configure(text="—", text_color=CLR["subtle"])
            return
        res = password_strength(pwd)
        self.strength_bar.set(max(0.125, res.score / 8.0))
        self.strength_bar.configure(progress_color=res.color)
        self.strength_lbl.configure(text=f"{res.label}", text_color=res.color)

    def _handle_change(self) -> None:
        old_pwd = self.old_entry.get()
        new_pwd = self.new_entry.get()
        confirm_pwd = self.confirm_entry.get()

        if not old_pwd:
            self.status_lbl.configure(text="Enter your current master password.", text_color=CLR["error"])
            return

        if len(new_pwd) < 12:
            self.status_lbl.configure(text="New password must be at least 12 characters.", text_color=CLR["error"])
            return

        if new_pwd != confirm_pwd:
            self.status_lbl.configure(text="New passwords do not match.", text_color=CLR["error"])
            return

        # Disable button and show computing indicator (PBKDF2 takes ~3-4 s)
        self.save_btn.configure(state="disabled", text="Re-encrypting (PBKDF2)...")
        self.status_lbl.configure(
            text="Computing 600,000 PBKDF2 rounds & re-encrypting...", text_color=CLR["warn"]
        )
        self.update()

        # Perform change
        import threading
        from core.auth import WrongPasswordError, change_master_password

        def worker():
            try:
                new_key = change_master_password(
                    old_password=old_pwd,
                    new_password=new_pwd,
                    path=self.app.VAULT_PATH,
                    enc_key=self.app.enc_key,
                )
                self.app.enc_key = new_key
                self.after(0, self._on_success_callback)
            except WrongPasswordError:
                self.after(0, lambda: self._on_error("Incorrect current master password."))
            except Exception as e:
                self.after(0, lambda: self._on_error(f"Error: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_error(self, message: str) -> None:
        self.save_btn.configure(state="normal", text="Update Master Password")
        self.status_lbl.configure(text=message, text_color=CLR["error"])

    def _on_success_callback(self) -> None:
        if self.on_success:
            self.on_success()
        self.destroy()
