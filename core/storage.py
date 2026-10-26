"""
core/storage.py
===============
Vault file I/O: load, atomic save, backup, and schema defaults.

Design decisions:
-----------------
1. WHY atomic write (write-to-tmp then os.replace)?
   os.replace is atomic on all major OS at the filesystem level.
   If the program crashes mid-write, the original vault.json is still
   intact because we only replace it AFTER the new file is fully written.
   A plain open("vault.json","w") would leave a half-written file if
   the process crashes during the write.

2. WHY keep a .bak copy?
   One level of backup against accidental deletion or corruption.
   The user can rename vault.json.bak → vault.json to recover.

3. WHY base64 for binary fields in JSON?
   JSON only handles text. Salt, nonce, tag, ciphertext are raw bytes.
   Base64 is the standard way to embed arbitrary bytes in a text format.
   We use the standard base64 alphabet (not URL-safe) for readability.

4. WHY store failed_attempts and locked_until in the file?
   If the app is restarted after a lockout, the lockout must still
   be honoured. Keeping it in memory only would let an attacker bypass
   it by restarting the app.
"""

import base64
import json
import os
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Default path (project root)
# ---------------------------------------------------------------------------

DEFAULT_VAULT_PATH = Path("vault.json")

# ---------------------------------------------------------------------------
# Base64 helpers – all binary fields go through these
# ---------------------------------------------------------------------------

def b64enc(data: bytes) -> str:
    """Encode bytes to a base64 string (for JSON storage)."""
    return base64.b64encode(data).decode("ascii")


def b64dec(s: str) -> bytes:
    """Decode a base64 string back to bytes (from JSON storage)."""
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Default vault skeleton
# ---------------------------------------------------------------------------

def default_vault_data() -> dict[str, Any]:
    """
    Return a fresh, empty vault data structure.

    This matches the file format specification exactly.
    All binary fields are empty strings at this stage; they are filled
    in by auth.setup_vault() before the first save.
    """
    return {
        "version": 1,
        "kdf": {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 600_000,
        },
        "auth": {
            "salt": "",    # base64-encoded 16-byte random salt (set during setup)
            "hash": "",    # base64-encoded PBKDF2 output (set during setup)
        },
        "enc": {
            "salt": "",    # base64-encoded 16-byte random salt (set during setup)
        },
        "security": {
            "failed_attempts": 0,
            "locked_until": 0.0,   # Unix timestamp; 0 means not locked
        },
        "vault": {
            "nonce": "",       # base64-encoded 12-byte AES-GCM nonce
            "tag":   "",       # base64-encoded 16-byte GCM auth tag
            "ciphertext": "",  # base64-encoded encrypted vault bytes
        },
    }


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def load_vault(path: Path = DEFAULT_VAULT_PATH) -> dict[str, Any] | None:
    """
    Read and parse vault.json.

    Returns the parsed dict, or None if the file does not exist yet
    (first run). Any JSON parse error is re-raised so the caller can
    show a meaningful error in the GUI.

    Args:
        path: Path to vault.json (override for testing).

    Returns:
        Parsed vault dict, or None on first run.

    Raises:
        json.JSONDecodeError: If the file exists but is invalid JSON.
        OSError: If the file exists but cannot be read (permissions etc.).
    """
    if not path.exists():
        return None  # First run – no vault file yet

    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Atomic save
# ---------------------------------------------------------------------------

def save_vault(data: dict[str, Any], path: Path = DEFAULT_VAULT_PATH) -> None:
    """
    Save vault data to disk atomically.

    Steps:
      1. Serialise data to JSON.
      2. Write to <path>.tmp (a temporary sibling file).
      3. If <path> already exists, copy it to <path>.bak (backup).
      4. os.replace(<path>.tmp, <path>) — atomic rename.

    WHY this order?
    If the process dies between steps 2 and 4, the original file is
    untouched. After step 4 succeeds the new file is in place. This is
    the standard pattern for crash-safe file updates.

    Args:
        data: The full vault dict (will be serialised to JSON).
        path: Destination path (default vault.json).
    """
    tmp_path = path.with_suffix(".tmp")   # e.g. vault.tmp
    bak_path = path.with_suffix(".bak")   # e.g. vault.bak

    # Step 1 + 2: write to temporary file
    # ensure_ascii=False preserves Unicode in site/username fields.
    json_bytes = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    with open(tmp_path, "wb") as fh:
        fh.write(json_bytes)
        fh.flush()
        os.fsync(fh.fileno())   # flush OS write buffer to disk

    # Step 3: backup the current vault before replacing it
    if path.exists():
        # os.replace is atomic on the same filesystem
        os.replace(path, bak_path)

    # Step 4: atomic rename – this is the "commit" step
    os.replace(tmp_path, path)


# ---------------------------------------------------------------------------
# Convenience check
# ---------------------------------------------------------------------------

def vault_exists(path: Path = DEFAULT_VAULT_PATH) -> bool:
    """Return True if a vault file exists at the given path."""
    return path.exists()
