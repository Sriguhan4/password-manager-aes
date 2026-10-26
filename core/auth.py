"""
core/auth.py
============
Setup, login, lockout logic, and change-master-password.

This module coordinates crypto.py and storage.py for all
authentication-related operations. The GUI calls only these
high-level functions — it never touches raw crypto primitives.

Security decisions (explain in viva):
--------------------------------------
1. WHY separate auth and enc salts?
   See crypto.py. Short: the stored auth hash and the in-memory AES key
   must be independent values. Using different salts achieves this.

2. WHY lockout with doubling delay?
   This mimics an Intrusion Prevention System (IPS) response: the more
   attempts, the longer the penalty. It slows online guessing attacks
   within the application. However, it does NOT stop offline attacks
   (someone who copies vault.json and runs hashcat). Real protection
   against offline attacks is provided by the 600,000-iteration PBKDF2
   and the strength of the master password.

3. WHY store locked_until as a Unix timestamp in the file?
   If the app is closed and reopened during a lockout, the lockout
   must still be active. An in-memory counter would be bypassed by
   simply restarting the app.

4. WHY return a bytearray for the enc key?
   The caller (GUI or auth module) holds the only reference to this
   mutable bytearray. On logout, wipe_key() zeroes it. A bytes object
   is immutable and cannot be wiped.
"""

import json
import time
from pathlib import Path
from typing import Any

from Crypto.Random import get_random_bytes

from core.crypto import (
    VaultCorruptedError,
    build_aad,
    decrypt_vault,
    derive_enc_key,
    encrypt_vault,
    hash_master,
    verify_master,
    wipe_key,
)
from core.storage import (
    b64dec,
    b64enc,
    default_vault_data,
    load_vault,
    save_vault,
)

# ---------------------------------------------------------------------------
# Constants – lockout policy
# ---------------------------------------------------------------------------

MAX_ATTEMPTS_BEFORE_LOCKOUT: int = 5   # Fail this many times → locked
BASE_LOCKOUT_SECONDS: float = 30.0     # First lockout duration
# Each subsequent lockout doubles: 30 → 60 → 120 → 240 …

# ---------------------------------------------------------------------------
# First-run setup
# ---------------------------------------------------------------------------

def setup_vault(password: str, path: Path) -> None:
    """
    Initialise a brand-new encrypted vault for a first-time user.

    Steps:
      1. Generate random salts for auth and encryption (different salts!).
      2. Hash the master password for storage (auth hash).
      3. Derive the AES encryption key (NOT stored).
      4. Encrypt an empty entry list as the initial vault content.
      5. Save everything atomically to disk.

    After this function returns, the key is wiped from memory.
    The caller (GUI login flow) will call login() next, which re-derives
    the key and keeps it for the session.

    Args:
        password: The chosen master password (plaintext, never stored).
        path:     Where to write vault.json.

    Raises:
        ValueError: If the password is shorter than 12 characters.
    """
    if len(password) < 12:
        raise ValueError("Master password must be at least 12 characters.")

    data = default_vault_data()

    # --- Step 1: Generate two INDEPENDENT random salts ---
    # WHY independent? So the auth hash and encryption key are unrelated.
    auth_salt = get_random_bytes(16)
    enc_salt  = get_random_bytes(16)

    # --- Step 2: Hash the master password (FIRST PBKDF2 run) ---
    # auth_hash goes into the file so we can verify the password at login.
    # get_random_bytes inside hash_master generates its OWN salt;
    # we supply ours here to keep full control over the data dict.
    from core.crypto import derive_key
    auth_hash = derive_key(password, auth_salt)   # 600K iterations

    # --- Step 3: Derive the AES-256 encryption key (SECOND PBKDF2 run) ---
    # Different salt → completely different 256-bit value → never stored.
    enc_key = derive_enc_key(password, enc_salt)   # 600K iterations

    # --- Step 4: Encrypt an empty vault (empty JSON list) ---
    # Populate the data dict so build_aad() has the salts available.
    data["auth"]["salt"] = b64enc(auth_salt)
    data["auth"]["hash"] = b64enc(auth_hash)
    data["enc"]["salt"]  = b64enc(enc_salt)

    aad = build_aad(data)                         # header bytes for GCM AAD
    empty_entries: bytes = json.dumps([]).encode("utf-8")
    nonce, tag, ciphertext = encrypt_vault(empty_entries, enc_key, aad)

    data["vault"]["nonce"]      = b64enc(nonce)
    data["vault"]["tag"]        = b64enc(tag)
    data["vault"]["ciphertext"] = b64enc(ciphertext)

    # --- Step 5: Atomic save ---
    save_vault(data, path)

    # --- Wipe the key from memory immediately ---
    # The session key will be re-derived by login() when the user logs in.
    wipe_key(enc_key)
    del enc_key


# ---------------------------------------------------------------------------
# Lockout helpers
# ---------------------------------------------------------------------------

def check_lockout(data: dict[str, Any]) -> tuple[bool, float]:
    """
    Check whether the login is currently locked out.

    Args:
        data: The loaded vault dict.

    Returns:
        (is_locked, seconds_remaining)
        If is_locked is False, seconds_remaining is 0.0.
    """
    locked_until: float = data["security"].get("locked_until", 0.0)
    now = time.time()
    if locked_until > now:
        return True, locked_until - now
    return False, 0.0


def record_failed_attempt(
    data: dict[str, Any],
    path: Path,
) -> tuple[int, float]:
    """
    Increment the failed-attempt counter and apply a lockout if needed.

    Lockout schedule (IPS-inspired doubling policy):
      - After every MAX_ATTEMPTS_BEFORE_LOCKOUT failures a lockout triggers.
      - First lockout: BASE_LOCKOUT_SECONDS (30 s).
      - Each subsequent lockout: double the previous duration.
      - 5 fails → 30 s | 10 fails → 60 s | 15 fails → 120 s | …

    NOTE: This only prevents guessing *within* the application.
    An attacker who has the vault.json file can run PBKDF2 directly
    (offline attack). The real defence there is the 600K-iteration PBKDF2
    combined with a strong master password.

    Args:
        data: The loaded (and currently-being-modified) vault dict.
        path: Vault file path (so we can save the updated attempt count).

    Returns:
        (new_attempt_count, locked_until_timestamp)
        locked_until_timestamp is 0.0 if no lockout was triggered.
    """
    data["security"]["failed_attempts"] += 1
    attempts: int = data["security"]["failed_attempts"]
    locked_until: float = 0.0

    if attempts % MAX_ATTEMPTS_BEFORE_LOCKOUT == 0:
        # Determine how many lockout rounds have elapsed (1-indexed)
        lockout_round = (attempts // MAX_ATTEMPTS_BEFORE_LOCKOUT) - 1
        duration = BASE_LOCKOUT_SECONDS * (2 ** lockout_round)
        locked_until = time.time() + duration
        data["security"]["locked_until"] = locked_until

    save_vault(data, path)
    return attempts, locked_until


def reset_failed_attempts(data: dict[str, Any], path: Path) -> None:
    """
    Reset the failed-attempt counter after a successful login.

    Called immediately after a successful password verification so that
    a legitimate user starts fresh next time.

    Args:
        data: The loaded vault dict.
        path: Vault file path (so we can save the reset state).
    """
    data["security"]["failed_attempts"] = 0
    data["security"]["locked_until"]    = 0.0
    save_vault(data, path)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class LockoutError(Exception):
    """
    Raised when a login attempt is made during an active lockout period.

    Attributes:
        seconds_remaining: How many more seconds the lockout lasts.
    """
    def __init__(self, seconds_remaining: float) -> None:
        self.seconds_remaining = seconds_remaining
        super().__init__(f"Locked out for {seconds_remaining:.1f} more seconds.")


class WrongPasswordError(Exception):
    """Raised when the master password fails verification."""


def login(
    password: str,
    path: Path,
) -> tuple[bytearray, dict[str, Any]]:
    """
    Attempt to log in with the provided master password.

    Steps:
      1. Load vault file.
      2. Check lockout — raise LockoutError if active.
      3. Verify the password with constant-time compare.
         On failure: record failed attempt (possibly trigger lockout),
                     raise WrongPasswordError.
      4. On success: reset attempt counter, derive enc key, return it.

    Args:
        password: The master password typed by the user.
        path:     Path to vault.json.

    Returns:
        (enc_key, vault_data)
        enc_key is a bytearray — keep it in memory for the session,
        wipe it on logout. vault_data is the full parsed vault dict.

    Raises:
        LockoutError:       If currently locked out.
        WrongPasswordError: If the password is incorrect.
        FileNotFoundError:  If no vault file exists (call setup_vault first).
    """
    data = load_vault(path)
    if data is None:
        raise FileNotFoundError(f"No vault found at {path}. Run setup first.")

    # --- Step 2: Lockout check ---
    is_locked, secs_left = check_lockout(data)
    if is_locked:
        raise LockoutError(secs_left)

    # --- Step 3: Password verification (constant-time) ---
    auth_salt = b64dec(data["auth"]["salt"])
    auth_hash = b64dec(data["auth"]["hash"])

    if not verify_master(password, auth_salt, auth_hash):
        _attempts, _locked_until = record_failed_attempt(data, path)
        raise WrongPasswordError(
            f"Wrong password. Attempt {_attempts}."
        )

    # --- Step 4: Success — reset counter, derive session key ---
    reset_failed_attempts(data, path)

    enc_salt = b64dec(data["enc"]["salt"])
    enc_key  = derive_enc_key(password, enc_salt)   # NEVER stored to disk

    # Reload data after the save in reset_failed_attempts so caller has
    # the freshest copy (failed_attempts = 0).
    data = load_vault(path)

    return enc_key, data  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def logout(enc_key: bytearray) -> None:
    """
    Securely wipe the AES key from memory and end the session.

    Args:
        enc_key: The session key bytearray returned by login().
                 Modified in-place (all bytes set to 0).
    """
    wipe_key(enc_key)
    # The caller should also `del enc_key` after this call.


# ---------------------------------------------------------------------------
# Change Master Password
# ---------------------------------------------------------------------------

def change_master_password(
    old_password: str,
    new_password: str,
    path: Path,
    enc_key: bytearray,
) -> bytearray:
    """
    Change the master password while keeping the vault data intact.

    Steps:
      1. Verify the old password.
      2. Decrypt the vault using the current enc_key.
      3. Generate brand-new auth salt, enc salt.
      4. Hash new password → new auth hash (stored).
      5. Derive new encryption key → new enc key (never stored).
      6. Re-encrypt the vault with the new key and fresh nonce.
      7. Wipe the OLD enc_key and return the new one.
      8. Atomic save.

    WHY generate new salts?
    Reusing the old salts with a new password would link the two password
    epochs and could reveal information to an attacker with old file copies.
    Fresh salts make old and new completely independent.

    Args:
        old_password: Current master password (for verification).
        new_password: The new master password (min 12 characters).
        path:         Path to vault.json.
        enc_key:      Current session key (will be wiped after use).

    Returns:
        A new bytearray enc_key derived from the new password.
        Caller should replace their reference to the old key with this.

    Raises:
        WrongPasswordError: If old_password is incorrect.
        ValueError:         If new_password is too short.
        VaultCorruptedError: If decryption of the existing vault fails.
    """
    if len(new_password) < 12:
        raise ValueError("New master password must be at least 12 characters.")

    data = load_vault(path)
    if data is None:
        raise FileNotFoundError("No vault file found.")

    # --- Step 1: Verify old password ---
    auth_salt = b64dec(data["auth"]["salt"])
    auth_hash = b64dec(data["auth"]["hash"])
    if not verify_master(old_password, auth_salt, auth_hash):
        raise WrongPasswordError("Old password is incorrect.")

    # --- Step 2: Decrypt current vault with the existing key ---
    aad = build_aad(data)
    nonce      = b64dec(data["vault"]["nonce"])
    tag        = b64dec(data["vault"]["tag"])
    ciphertext = b64dec(data["vault"]["ciphertext"])

    # This raises VaultCorruptedError on any integrity failure.
    plaintext = decrypt_vault(ciphertext, tag, nonce, enc_key, aad)

    # --- Step 3: New random salts (completely independent) ---
    from core.crypto import derive_key
    new_auth_salt = get_random_bytes(16)
    new_enc_salt  = get_random_bytes(16)

    # --- Step 4: Hash new password ---
    new_auth_hash = derive_key(new_password, new_auth_salt)

    # --- Step 5: Derive new encryption key (not stored) ---
    new_enc_key = derive_enc_key(new_password, new_enc_salt)

    # --- Step 6: Re-encrypt vault with new key ---
    data["auth"]["salt"] = b64enc(new_auth_salt)
    data["auth"]["hash"] = b64enc(new_auth_hash)
    data["enc"]["salt"]  = b64enc(new_enc_salt)

    # Reset security counters — a password change is a fresh start.
    data["security"]["failed_attempts"] = 0
    data["security"]["locked_until"]    = 0.0

    new_aad = build_aad(data)   # AAD must match the NEW header
    new_nonce, new_tag, new_ct = encrypt_vault(plaintext, new_enc_key, new_aad)

    data["vault"]["nonce"]      = b64enc(new_nonce)
    data["vault"]["tag"]        = b64enc(new_tag)
    data["vault"]["ciphertext"] = b64enc(new_ct)

    # --- Step 7: Wipe old key ---
    wipe_key(enc_key)

    # --- Step 8: Atomic save ---
    save_vault(data, path)

    return new_enc_key
