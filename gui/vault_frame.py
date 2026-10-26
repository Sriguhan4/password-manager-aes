"""
gui/vault_frame.py
==================
Main vault screen displayed after successful master password authentication.

UI Architecture
---------------
- Top Navbar:
    * Vault branding & live account counter badge
    * Real-time search entry (searches site, username, notes)
    * Action buttons: "+ Add Entry", "⚡ Generator", "🔑 Change Master", "🔒 Lock"
- Main View:
    * Scrollable list of credential cards
    * Card features:
        - Site name, username, notes preview
        - Copy username button
        - Copy password button (with 30-second clipboard wipe)
        - Reveal / Hide password toggle button
        - Edit entry button (opens EntryDialog)
        - Delete entry button (with confirmation modal)
    * Empty state graphic when no entries exist or search yields no results
- Bottom Status Bar:
    * Cryptographic security badge (AES-256-GCM + PBKDF2)
    * Transient feedback / toast notifications
    * Inactivity auto-lock indicator
"""

from typing import TYPE_CHECKING, Any, Optional

import customtkinter as ctk

from core.vault import add_entry, delete_entry, edit_entry, search_entries, save_entries
from gui.app import CLR
from gui.dialogs import (
    ChangePasswordDialog,
    EntryDialog,
    GeneratorDialog,
    copy_to_clipboard_secure,
)

if TYPE_CHECKING:
    from gui.app import App


class VaultFrame(ctk.CTkFrame):
    """
    Main dashboard for managing encrypted passwords.

    Interacts with the App session state:
      - self.app.entries: list of decrypted entry dicts
      - self.app.vault_data: in-memory copy of vault header/structure
      - self.app.enc_key: in-memory AES-256 key
    """

    def __init__(self, master: ctk.CTk, app: "App") -> None:
        super().__init__(master, fg_color=CLR["bg"], corner_radius=0)
        self.app = app

        # Track which cards currently have password revealed {entry_id: bool}
        self._revealed_passwords: dict[str, bool] = {}

        self._build_layout()
        self.refresh_entries()

    # ------------------------------------------------------------------
    # UI Layout Construction
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        """Construct top navbar, scrollable card container, and bottom status bar."""
        # 1. Top Navbar
        self.navbar = ctk.CTkFrame(self, fg_color=CLR["panel"], height=70, corner_radius=0)
        self.navbar.pack(fill="x", side="top")
        self.navbar.pack_propagate(False)

        # 2. Bottom Status Bar
        self.statusbar = ctk.CTkFrame(self, fg_color=CLR["panel"], height=32, corner_radius=0)
        self.statusbar.pack(fill="x", side="bottom")
        self.statusbar.pack_propagate(False)

        # 3. Main Content Area (Scrollable entries frame)
        self.content_frame = ctk.CTkFrame(self, fg_color=CLR["bg"], corner_radius=0)
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=15)

        self._build_navbar()
        self._build_statusbar()
        self._build_scroll_area()

    def _build_navbar(self) -> None:
        """Populate the top navigation and action bar."""
        # Left: Logo & Title
        left_box = ctk.CTkFrame(self.navbar, fg_color="transparent")
        left_box.pack(side="left", padx=(20, 10), pady=12)

        ctk.CTkLabel(
            left_box,
            text="🔐",
            font=ctk.CTkFont(size=24)
        ).pack(side="left", padx=(0, 8))

        ctk.CTkLabel(
            left_box,
            text="My Vault",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=CLR["text"]
        ).pack(side="left", padx=(0, 10))

        self.count_badge = ctk.CTkLabel(
            left_box,
            text="0 accounts",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=CLR["accent"],
            fg_color=CLR["card"],
            corner_radius=10,
            padx=10,
            pady=3
        )
        self.count_badge.pack(side="left")

        # Right: Action Buttons (Lock, Change Master, Generator, Add)
        right_box = ctk.CTkFrame(self.navbar, fg_color="transparent")
        right_box.pack(side="right", padx=(10, 20), pady=12)

        lock_btn = ctk.CTkButton(
            right_box,
            text="🔒 Lock",
            width=75,
            height=36,
            fg_color="#3b1d28",
            hover_color="#5c2638",
            text_color="#fca5a5",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_lock
        )
        lock_btn.pack(side="right", padx=(6, 0))

        chg_pwd_btn = ctk.CTkButton(
            right_box,
            text="🔑 Master",
            width=80,
            height=36,
            fg_color=CLR["card"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            font=ctk.CTkFont(size=12),
            command=self._open_change_master_dialog
        )
        chg_pwd_btn.pack(side="right", padx=(6, 0))

        gen_btn = ctk.CTkButton(
            right_box,
            text="⚡ Generator",
            width=95,
            height=36,
            fg_color=CLR["card"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            font=ctk.CTkFont(size=12),
            command=self._open_generator_dialog
        )
        gen_btn.pack(side="right", padx=(6, 0))

        add_btn = ctk.CTkButton(
            right_box,
            text="➕ Add Entry",
            width=110,
            height=36,
            fg_color=CLR["accent"],
            hover_color=CLR["accent_hov"],
            text_color="#ffffff",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._open_add_dialog
        )
        add_btn.pack(side="right", padx=(6, 0))

        # Center: Live Search Bar
        search_box = ctk.CTkFrame(self.navbar, fg_color="transparent")
        search_box.pack(side="left", fill="x", expand=True, padx=20, pady=12)

        self.search_entry = ctk.CTkEntry(
            search_box,
            placeholder_text="🔍 Search accounts, usernames, notes...",
            height=36,
            fg_color=CLR["entry"],
            border_color=CLR["border"],
            text_color=CLR["text"],
            placeholder_text_color=CLR["subtle"]
        )
        self.search_entry.pack(fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self._on_search_query_change)

    def _build_statusbar(self) -> None:
        """Populate bottom status bar with security info and toast notifications."""
        # Left: Crypto security indicator
        sec_box = ctk.CTkFrame(self.statusbar, fg_color="transparent")
        sec_box.pack(side="left", padx=15)

        ctk.CTkLabel(
            sec_box,
            text="● AES-256-GCM (Authenticated)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=CLR["success"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            sec_box,
            text="|  PBKDF2-HMAC-SHA256 (600,000 rounds)",
            font=ctk.CTkFont(size=11),
            text_color=CLR["subtle"]
        ).pack(side="left")

        # Center/Toast: Notification label
        self.toast_lbl = ctk.CTkLabel(
            self.statusbar,
            text="",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=CLR["success"]
        )
        self.toast_lbl.pack(side="left", fill="x", expand=True, padx=10)

        # Right: Auto-lock status
        ctk.CTkLabel(
            self.statusbar,
            text="⏱️ Auto-lock: 5 min idle",
            font=ctk.CTkFont(size=11),
            text_color=CLR["subtle"]
        ).pack(side="right", padx=15)

    def _build_scroll_area(self) -> None:
        """Create scrollable frame for cards."""
        self.cards_scroll = ctk.CTkScrollableFrame(
            self.content_frame,
            fg_color="transparent",
            scrollbar_button_color=CLR["border"],
            scrollbar_button_hover_color=CLR["accent_dim"]
        )
        self.cards_scroll.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Data Refresh & Rendering
    # ------------------------------------------------------------------

    def refresh_entries(self, query: str = "") -> None:
        """
        Filter and render entries based on search query.
        Wipes existing child widgets from the scrollable frame and rebuilds.
        """
        for child in self.cards_scroll.winfo_children():
            child.destroy()

        entries = self.app.entries or []
        total_count = len(entries)
        self.count_badge.configure(
            text=f"{total_count} account{'s' if total_count != 1 else ''}"
        )

        filtered = search_entries(entries, query)

        if not filtered:
            self._render_empty_state(is_search_empty=bool(query and total_count > 0))
            return

        for entry in filtered:
            self._render_entry_card(entry)

    def _render_empty_state(self, is_search_empty: bool) -> None:
        """Show helpful placeholder when there are no entries to display."""
        empty_box = ctk.CTkFrame(self.cards_scroll, fg_color="transparent")
        empty_box.pack(fill="both", expand=True, pady=80)

        icon = "🔍" if is_search_empty else "🛡️"
        ctk.CTkLabel(
            empty_box,
            text=icon,
            font=ctk.CTkFont(size=54)
        ).pack(pady=(0, 10))

        if is_search_empty:
            msg = "No entries match your search."
            submsg = "Try searching for a different keyword or clear the search box."
        else:
            msg = "Your vault is empty"
            submsg = "Click '+ Add Entry' above to store your first secure credential."

        ctk.CTkLabel(
            empty_box,
            text=msg,
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=CLR["text"]
        ).pack(pady=(0, 4))

        ctk.CTkLabel(
            empty_box,
            text=submsg,
            font=ctk.CTkFont(size=13),
            text_color=CLR["subtle"]
        ).pack()

        if not is_search_empty:
            ctk.CTkButton(
                empty_box,
                text="➕ Add First Entry",
                font=ctk.CTkFont(weight="bold"),
                fg_color=CLR["accent"],
                hover_color=CLR["accent_hov"],
                height=38,
                command=self._open_add_dialog
            ).pack(pady=(20, 0))

    def _render_entry_card(self, entry: dict[str, Any]) -> None:
        """Render a single credential card."""
        entry_id = entry.get("id", "")
        site = entry.get("site", "Unnamed")
        username = entry.get("username", "")
        password = entry.get("password", "")
        notes = entry.get("notes", "")

        is_revealed = self._revealed_passwords.get(entry_id, False)

        card = ctk.CTkFrame(
            self.cards_scroll,
            fg_color=CLR["card"],
            corner_radius=10,
            border_width=1,
            border_color=CLR["border"]
        )
        card.pack(fill="x", pady=6, padx=4)

        # Top line container
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=16, pady=12)

        # Left: Icon badge (First letter of site)
        initial = (site[:1] if site else "?").upper()
        badge = ctk.CTkLabel(
            top_row,
            text=initial,
            width=42,
            height=42,
            fg_color=CLR["panel"],
            corner_radius=8,
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=CLR["accent"]
        )
        badge.pack(side="left", padx=(0, 14))

        # Center-Left: Site & Username
        info_col = ctk.CTkFrame(top_row, fg_color="transparent")
        info_col.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            info_col,
            text=site,
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=CLR["text"],
            anchor="w"
        ).pack(fill="x")

        user_display = username if username else "No username"
        ctk.CTkLabel(
            info_col,
            text=user_display,
            font=ctk.CTkFont(size=12),
            text_color=CLR["subtle"],
            anchor="w"
        ).pack(fill="x")

        # Center-Right: Password display (Hidden or Revealed)
        pwd_col = ctk.CTkFrame(top_row, fg_color="transparent")
        pwd_col.pack(side="left", padx=15)

        pwd_display_text = password if is_revealed else "••••••••••••"
        pwd_lbl = ctk.CTkLabel(
            pwd_col,
            text=pwd_display_text,
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=CLR["text"] if is_revealed else CLR["subtle"],
            width=130,
            anchor="w"
        )
        pwd_lbl.pack(side="left")

        # Reveal toggle button
        reveal_text = "🔒" if is_revealed else "👁️"
        reveal_btn = ctk.CTkButton(
            pwd_col,
            text=reveal_text,
            width=32,
            height=30,
            fg_color=CLR["entry"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            command=lambda eid=entry_id: self._toggle_reveal_password(eid)
        )
        reveal_btn.pack(side="left", padx=(4, 0))

        # Right: Action Buttons (Copy User, Copy Pass, Edit, Delete)
        act_box = ctk.CTkFrame(top_row, fg_color="transparent")
        act_box.pack(side="right")

        if username:
            copy_user_btn = ctk.CTkButton(
                act_box,
                text="👤 User",
                width=65,
                height=30,
                font=ctk.CTkFont(size=11),
                fg_color=CLR["entry"],
                hover_color=CLR["border"],
                text_color=CLR["text"],
                command=lambda u=username: self._copy_username(u)
            )
            copy_user_btn.pack(side="left", padx=4)

        copy_pwd_btn = ctk.CTkButton(
            act_box,
            text="🔑 Pass",
            width=65,
            height=30,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=CLR["accent_dim"],
            hover_color=CLR["accent"],
            text_color=CLR["text"],
            command=lambda p=password: self._copy_password(p)
        )
        copy_pwd_btn.pack(side="left", padx=4)

        edit_btn = ctk.CTkButton(
            act_box,
            text="✏️",
            width=32,
            height=30,
            fg_color=CLR["entry"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            command=lambda e=entry: self._open_edit_dialog(e)
        )
        edit_btn.pack(side="left", padx=4)

        del_btn = ctk.CTkButton(
            act_box,
            text="🗑️",
            width=32,
            height=30,
            fg_color=CLR["entry"],
            hover_color="#5c2638",
            text_color="#fca5a5",
            command=lambda eid=entry_id, s=site: self._confirm_delete(eid, s)
        )
        del_btn.pack(side="left", padx=(4, 0))

        # Notes section (if present)
        if notes:
            notes_row = ctk.CTkFrame(card, fg_color=CLR["entry"], corner_radius=6)
            notes_row.pack(fill="x", padx=16, pady=(0, 10))

            ctk.CTkLabel(
                notes_row,
                text=f"📝 {notes}",
                font=ctk.CTkFont(size=11),
                text_color=CLR["subtle"],
                anchor="w",
                justify="left"
            ).pack(fill="x", padx=10, pady=4)

    # ------------------------------------------------------------------
    # User Interactions & Handlers
    # ------------------------------------------------------------------

    def _on_search_query_change(self, event=None) -> None:
        """Filter list as the user types in search entry."""
        query = self.search_entry.get().strip()
        self.refresh_entries(query)

    def _toggle_reveal_password(self, entry_id: str) -> None:
        """Toggle in-place password plaintext visibility for an entry."""
        current = self._revealed_passwords.get(entry_id, False)
        self._revealed_passwords[entry_id] = not current
        self.refresh_entries(self.search_entry.get().strip())

    def _copy_username(self, username: str) -> None:
        """Copy username to clipboard."""
        self.app.clipboard_clear()
        self.app.clipboard_append(username)
        self.app.update()
        self._show_toast("✓ Username copied to clipboard!")

    def _copy_password(self, password: str) -> None:
        """Copy password with secure 30-second clipboard auto-wipe."""
        copy_to_clipboard_secure(
            self.app,
            password,
            feedback_label=self.toast_lbl,
            wipe_seconds=30
        )

    def _show_toast(self, message: str, duration_ms: int = 3000) -> None:
        """Display transient notification in status bar."""
        self.toast_lbl.configure(text=message, text_color=CLR["success"])

        def clear():
            try:
                self.toast_lbl.configure(text="")
            except Exception:
                pass

        self.after(duration_ms, clear)

    # ------------------------------------------------------------------
    # Dialog Openers & Persistence
    # ------------------------------------------------------------------

    def _open_add_dialog(self) -> None:
        """Open EntryDialog in 'add' mode."""
        def on_save(data: dict[str, Any]):
            add_entry(
                self.app.entries,
                site=data["site"],
                username=data["username"],
                password=data["password"],
                notes=data.get("notes", "")
            )
            # Persist atomically to disk
            save_entries(
                self.app.entries,
                self.app.vault_data,
                self.app.enc_key,
                self.app.VAULT_PATH
            )
            self.refresh_entries()
            self._show_toast(f"✓ Added credential for '{data['site']}'.")

        EntryDialog(parent=self, app=self.app, mode="add", on_save=on_save)

    def _open_edit_dialog(self, entry: dict[str, Any]) -> None:
        """Open EntryDialog in 'edit' mode."""
        def on_save(data: dict[str, Any]):
            edit_entry(
                self.app.entries,
                entry_id=data["id"],
                site=data["site"],
                username=data["username"],
                password=data["password"],
                notes=data.get("notes", "")
            )
            save_entries(
                self.app.entries,
                self.app.vault_data,
                self.app.enc_key,
                self.app.VAULT_PATH
            )
            self.refresh_entries()
            self._show_toast(f"✓ Updated credential for '{data['site']}'.")

        EntryDialog(parent=self, app=self.app, mode="edit", entry=entry, on_save=on_save)

    def _confirm_delete(self, entry_id: str, site_name: str) -> None:
        """Show delete confirmation modal."""
        confirm_win = ctk.CTkToplevel(self)
        confirm_win.title("Confirm Delete")
        confirm_win.geometry("400x200")
        confirm_win.configure(fg_color=CLR["bg"])
        confirm_win.transient(self.winfo_toplevel())
        confirm_win.grab_set()

        # Center
        self.update_idletasks()
        try:
            px = self.winfo_toplevel().winfo_x()
            py = self.winfo_toplevel().winfo_y()
            pw = self.winfo_toplevel().winfo_width()
            ph = self.winfo_toplevel().winfo_height()
            w, h = 400, 200
            confirm_win.geometry(f"{w}x{h}+{px + (pw - w)//2}+{py + (ph - h)//2}")
        except Exception:
            pass

        box = ctk.CTkFrame(confirm_win, fg_color=CLR["card"], corner_radius=10)
        box.pack(fill="both", expand=True, padx=15, pady=15)

        ctk.CTkLabel(
            box,
            text=f"Delete '{site_name}'?",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=CLR["text"]
        ).pack(pady=(15, 6))

        ctk.CTkLabel(
            box,
            text="This action cannot be undone.",
            font=ctk.CTkFont(size=12),
            text_color=CLR["subtle"]
        ).pack(pady=(0, 15))

        btn_row = ctk.CTkFrame(box, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(5, 10))

        def do_delete():
            self.app.entries = delete_entry(self.app.entries, entry_id)
            save_entries(
                self.app.entries,
                self.app.vault_data,
                self.app.enc_key,
                self.app.VAULT_PATH
            )
            confirm_win.destroy()
            self.refresh_entries()
            self._show_toast(f"🗑️ Deleted '{site_name}'.")

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            fg_color=CLR["entry"],
            hover_color=CLR["border"],
            text_color=CLR["text"],
            command=confirm_win.destroy
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))

        ctk.CTkButton(
            btn_row,
            text="Delete",
            fg_color="#ef4444",
            hover_color="#dc2626",
            text_color="#ffffff",
            font=ctk.CTkFont(weight="bold"),
            command=do_delete
        ).pack(side="right", fill="x", expand=True)

    def _open_generator_dialog(self) -> None:
        """Open standalone CSPRNG Password Generator."""
        GeneratorDialog(parent=self)

    def _open_change_master_dialog(self) -> None:
        """Open dialog to re-encrypt vault with a new master password."""
        def on_success():
            self._show_toast("✓ Master password changed & vault re-encrypted!")

        ChangePasswordDialog(parent=self, app=self.app, on_success=on_success)

    def _on_lock(self) -> None:
        """Lock the vault immediately."""
        self.app.lock_vault()
