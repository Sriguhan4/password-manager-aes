"""
core/vault.py
=============
CRUD operations on vault entries (add, edit, delete, search).

The vault is a JSON list of entry dicts. This list is kept ENCRYPTED
on disk at all times. To read or write entries the caller must supply
the AES key (enc_key bytearray) obtained from auth.login().

Entry schema
------------
Each entry is a dict with these keys:
    id          – UUID4 string, unique identifier
    site        – Website / service name  (e.g. "github.com")
    username    – Login username or email
    password    – The stored password (plaintext inside encrypted vault)
    notes       – Optional free-text notes
    created_at  – ISO-8601 UTC timestamp string
    updated_at  – ISO-8601 UTC timestamp string

Design decisions
----------------
WHY store entries as a JSON list inside an encrypted blob?
  A single encrypted blob means an attacker with the file cannot even
  count how many passwords are stored or see site names. Every field
  (site, username, password, notes) is equally protected by AES-256-GCM.

WHY UUID4 for entry IDs?
  UUID4 is randomly generated, so IDs are unique without a central
  counter. They survive edits and are safe to expose in the GUI since
  they carry no information about the entry's content or position.

WHY ISO-8601 UTC for timestamps?
  Portable, human-readable, unambiguous across timezones, and sortable
  as a string. We use the standard library datetime module only.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.crypto import build_aad, decrypt_vault, encrypt_vault
from core.storage import b64dec, b64enc, load_vault, save_vault


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    """Return the current UTC time as an ISO-8601 string (e.g. 2026-10-26T15:00:00+00:00)."""
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Load and Save (encryption layer)
# ---------------------------------------------------------------------------

def load_entries(
    data: dict[str, Any],
    enc_key: bytearray,
) -> list[dict[str, Any]]:
    """
    Decrypt the vault blob and return the list of entry dicts.

    Reads the nonce, tag, and ciphertext from the vault data dict,
    decrypts with AES-256-GCM, and parses the resulting JSON list.

    Args:
        data:    The full vault dict (as returned by storage.load_vault).
        enc_key: The AES-256 session key (bytearray, 32 bytes).

    Returns:
        A list of entry dicts. Empty list if the vault has no entries.

    Raises:
        VaultCorruptedError: If GCM tag verification fails (wrong key or
                             tampered data). The GUI should catch this.
    """
    nonce      = b64dec(data["vault"]["nonce"])
    tag        = b64dec(data["vault"]["tag"])
    ciphertext = b64dec(data["vault"]["ciphertext"])

    # build_aad re-creates the same header bytes used during encryption.
    # If ANY header field changed, the tag check fails → VaultCorruptedError.
    aad = build_aad(data)

    plaintext = decrypt_vault(ciphertext, tag, nonce, enc_key, aad)
    return json.loads(plaintext.decode("utf-8"))


def save_entries(
    entries: list[dict[str, Any]],
    data: dict[str, Any],
    enc_key: bytearray,
    path: Path,
) -> dict[str, Any]:
    """
    Encrypt the entry list and write the vault file atomically.

    Generates a NEW random 12-byte nonce on every call.
    WHY? AES-GCM is catastrophically insecure if a (key, nonce) pair
    is ever reused. A fresh nonce on every save eliminates that risk.

    Args:
        entries: The list of entry dicts to encrypt.
        data:    The current vault dict (header fields are kept intact;
                 only the vault section is updated).
        enc_key: The AES-256 session key (bytearray, 32 bytes).
        path:    Destination file path.

    Returns:
        The updated vault dict (same object as `data`, mutated).
    """
    plaintext = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    aad = build_aad(data)  # AAD covers the existing header fields

    nonce, tag, ciphertext = encrypt_vault(plaintext, enc_key, aad)

    # Update only the vault section; leave header, auth, enc, security intact.
    data["vault"]["nonce"]      = b64enc(nonce)
    data["vault"]["tag"]        = b64enc(tag)
    data["vault"]["ciphertext"] = b64enc(ciphertext)

    save_vault(data, path)
    return data


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------

def add_entry(
    entries: list[dict[str, Any]],
    site: str,
    username: str,
    password: str,
    notes: str = "",
) -> dict[str, Any]:
    """
    Create a new vault entry and append it to the list.

    The caller must call save_entries() afterwards to persist the change.
    We separate mutation from persistence so the GUI can batch operations
    or validate before committing.

    Args:
        entries:  The current list of entries (modified in-place).
        site:     Website or service name.
        username: Login username or email address.
        password: The password to store.
        notes:    Optional free-text notes.

    Returns:
        The newly created entry dict.
    """
    if not site.strip():
        raise ValueError("Site name cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    now = _now_utc()
    entry: dict[str, Any] = {
        "id":         str(uuid.uuid4()),  # Random UUID – no info leakage
        "site":       site.strip(),
        "username":   username.strip(),
        "password":   password,           # Stored in plaintext INSIDE the encrypted blob
        "notes":      notes.strip(),
        "created_at": now,
        "updated_at": now,
    }
    entries.append(entry)
    return entry


def edit_entry(
    entries: list[dict[str, Any]],
    entry_id: str,
    **fields: Any,
) -> dict[str, Any]:
    """
    Update one or more fields of an existing entry.

    Only the fields explicitly passed as keyword arguments are changed.
    `id`, `created_at` are protected — they cannot be overwritten by
    the caller. `updated_at` is always refreshed automatically.

    Args:
        entries:  The current list of entries (modified in-place).
        entry_id: The UUID string of the entry to edit.
        **fields: Keyword arguments for fields to update
                  (site, username, password, notes).

    Returns:
        The updated entry dict.

    Raises:
        KeyError: If no entry with the given ID exists.
        ValueError: If an attempt is made to clear a required field.
    """
    # Fields the caller is NOT allowed to change directly
    PROTECTED = {"id", "created_at"}

    for entry in entries:
        if entry["id"] == entry_id:
            for key, value in fields.items():
                if key in PROTECTED:
                    continue  # silently ignore protected fields
                if key == "site" and not str(value).strip():
                    raise ValueError("Site name cannot be empty.")
                if key == "password" and not value:
                    raise ValueError("Password cannot be empty.")
                entry[key] = value
            entry["updated_at"] = _now_utc()
            return entry

    raise KeyError(f"No entry found with id='{entry_id}'.")


def delete_entry(
    entries: list[dict[str, Any]],
    entry_id: str,
) -> list[dict[str, Any]]:
    """
    Remove an entry from the list by its ID.

    Returns a NEW list with the entry removed (does not mutate in-place)
    so the caller can confirm before committing.

    Args:
        entries:  The current list of entries.
        entry_id: UUID string of the entry to delete.

    Returns:
        A new list without the deleted entry.

    Raises:
        KeyError: If no entry with the given ID exists.
    """
    original_len = len(entries)
    new_entries = [e for e in entries if e["id"] != entry_id]

    if len(new_entries) == original_len:
        raise KeyError(f"No entry found with id='{entry_id}'.")

    return new_entries


def search_entries(
    entries: list[dict[str, Any]],
    query: str,
) -> list[dict[str, Any]]:
    """
    Return entries whose site, username, or notes contain the query string.

    Case-insensitive substring match. An empty query returns all entries.
    Password and ID fields are intentionally excluded from search to
    avoid accidentally revealing passwords in search results.

    Args:
        entries: The full list of decrypted entries.
        query:   Search string (case-insensitive).

    Returns:
        Filtered list of matching entries (same dicts, not copies).
    """
    q = query.strip().lower()
    if not q:
        return entries  # Empty query → return everything

    return [
        e for e in entries
        if q in e.get("site",     "").lower()
        or q in e.get("username", "").lower()
        or q in e.get("notes",    "").lower()
    ]


def get_entry_by_id(
    entries: list[dict[str, Any]],
    entry_id: str,
) -> dict[str, Any]:
    """
    Retrieve a single entry by its UUID.

    Args:
        entries:  The full list of decrypted entries.
        entry_id: UUID string.

    Returns:
        The matching entry dict.

    Raises:
        KeyError: If not found.
    """
    for entry in entries:
        if entry["id"] == entry_id:
            return entry
    raise KeyError(f"No entry found with id='{entry_id}'.")
