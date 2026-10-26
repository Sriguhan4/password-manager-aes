"""
core/crypto.py
==============
All cryptographic operations for the Password Manager.

Design decisions (explain these in your viva):
------------------------------------------------
1. WHY PBKDF2-HMAC-SHA256 with 600,000 iterations?
   A brute-force attacker must run 600,000 SHA-256 hashes just to test ONE
   password guess. At modern GPU speeds that makes offline cracking
   extremely slow. NIST SP 800-132 recommends >= 600,000 iterations (2023).

2. WHY two separate PBKDF2 runs (auth vs enc)?
   The auth hash goes into the file so the app can check your password.
   The encryption key must NEVER be written to disk. Using the same
   output for both would leak the key if someone could reverse the hash.
   Different salts + different use → two independent, unrelated values.

3. WHY AES-256-GCM and not AES-CBC?
   GCM is an Authenticated Encryption with Associated Data (AEAD) mode.
   It gives us BOTH confidentiality (ciphertext is unreadable) AND
   integrity/authenticity (a 16-byte tag detects any tampering).
   CBC only provides confidentiality; a separate MAC is needed for integrity.

4. WHY Associated Data (AAD)?
   We pass the file header (version, kdf info, both salts) as AAD.
   GCM's tag covers the AAD too, so any change to the header is detected
   even though the header itself is not encrypted.

5. WHY a new random nonce on every save?
   GCM is catastrophically broken if a (key, nonce) pair is ever reused.
   A 96-bit random nonce from os.urandom gives us negligible collision
   probability across billions of saves.

6. WHY hmac.compare_digest for auth?
   A normal == comparison short-circuits on the first differing byte,
   leaking timing information. hmac.compare_digest always takes the same
   time regardless of where the mismatch is (constant-time comparison).

7. WHY overwrite the key with zeros on logout?
   Python's garbage collector does not guarantee when memory is freed or
   zeroed. We store the key as a bytearray (mutable) so we can write
   zeros ourselves. NOTE: Python cannot fully guarantee memory wiping
   because objects may be copied internally, but this is best-effort
   mitigation and is the standard practice.
"""

import hashlib
import hmac
import json
import os
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 600_000   # NIST SP 800-132 recommended minimum (2023)
KEY_LENGTH = 32             # 32 bytes = 256 bits → AES-256
AUTH_SALT_SIZE = 16         # 128-bit random salt for authentication hash
ENC_SALT_SIZE = 16          # 128-bit random salt for encryption key
NONCE_SIZE = 12             # 96-bit nonce — recommended for AES-GCM


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------

def derive_key(
    password: str,
    salt: bytes,
    iterations: int = KDF_ITERATIONS,
    key_length: int = KEY_LENGTH,
) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    WHY: Raw passwords are short and guessable. PBKDF2 stretches them into
    a uniformly random-looking key and makes brute-force expensive by
    running many iterations of HMAC-SHA256.

    Args:
        password:   The master password (plaintext, in memory only).
        salt:       A random salt (prevents rainbow-table attacks — each
                    user's hash is unique even with the same password).
        iterations: Number of PBKDF2 rounds (default 600,000).
        key_length: Output byte length (default 32 = AES-256).

    Returns:
        A bytes object of length `key_length` suitable for use as an AES key
        or as an authentication hash. NEVER write this to disk directly.
    """
    # hashlib.pbkdf2_hmac is part of the standard library and uses
    # OpenSSL under the hood for performance.
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),  # must be bytes
        salt=salt,
        iterations=iterations,
        dklen=key_length,
    )


# ---------------------------------------------------------------------------
# Authentication: hash the master password for storage
# ---------------------------------------------------------------------------

def hash_master(password: str) -> tuple[bytes, bytes]:
    """
    Produce a verifiable hash of the master password for storage.

    This is the FIRST PBKDF2 run. Its output is stored in vault.json
    so we can check the password at login. It is NOT the encryption key.

    Returns:
        (auth_salt, auth_hash) — both bytes objects.
        Store both in the vault file. The hash can be public; the password
        cannot be recovered from it.
    """
    auth_salt = get_random_bytes(AUTH_SALT_SIZE)
    auth_hash = derive_key(password, auth_salt)
    return auth_salt, auth_hash


def verify_master(
    password: str,
    stored_salt: bytes,
    stored_hash: bytes,
) -> bool:
    """
    Verify a master password against its stored hash.

    WHY hmac.compare_digest?
    A plain `==` comparison leaks timing info (stops early on mismatch).
    hmac.compare_digest always runs in constant time, preventing
    timing-based side-channel attacks.

    Args:
        password:    The password the user just typed.
        stored_salt: The auth_salt read from vault.json.
        stored_hash: The auth_hash read from vault.json.

    Returns:
        True if the password is correct, False otherwise.
    """
    candidate_hash = derive_key(password, stored_salt)
    # constant-time comparison — NEVER use plain ==
    return hmac.compare_digest(candidate_hash, stored_hash)


def derive_enc_key(password: str, enc_salt: bytes) -> bytearray:
    """
    Derive the AES-256 encryption key. This is the SECOND PBKDF2 run.

    WHY a separate run?
    The encryption key is NEVER written to disk. By using a completely
    different random salt (enc_salt ≠ auth_salt), the resulting key is
    mathematically independent of the auth hash even for the same password.

    Returns:
        A bytearray (mutable!) so we can zero it on logout.
        WHY bytearray? bytes objects are immutable — you cannot overwrite
        their contents. bytearray lets us do `key[:] = b'\\x00' * len(key)`.
    """
    raw = derive_key(password, enc_salt)
    return bytearray(raw)  # wrap in mutable container for safe wiping


def wipe_key(key: bytearray) -> None:
    """
    Overwrite the AES key in memory with zeros, then delete the reference.

    WHY: Once logged out the key should not sit in memory waiting to be
    found by another process or a memory dump. We zero it ourselves because
    Python's GC does not guarantee timely memory reuse.

    LIMITATION: Python may have made internal copies of the bytearray
    during operations (e.g., slicing). This wipe covers the primary
    reference but cannot guarantee all copies. A language like Rust or C
    with explicit memory control would be safer. For a college project this
    is the accepted best-effort approach.

    Args:
        key: The bytearray holding the AES key. Modified in-place.
    """
    for i in range(len(key)):
        key[i] = 0
    # The caller should also `del` their reference after calling this.


# ---------------------------------------------------------------------------
# Build Associated Data (AAD) from vault header
# ---------------------------------------------------------------------------

def build_aad(data: dict[str, Any]) -> bytes:
    """
    Serialise the vault file header into bytes to use as GCM Associated Data.

    WHY AAD?
    GCM's authentication tag covers both the ciphertext AND the AAD.
    By including the header (version, kdf params, both salts) in the AAD,
    any attacker who changes even one byte of the header will cause tag
    verification to fail when we try to decrypt. This protects against
    downgrade attacks (e.g. lowering iteration count) and salt swaps.

    The AAD is deterministically derived from the header fields so that
    encrypt and decrypt produce the identical bytes without storing extra data.

    Args:
        data: The full vault dict (only header fields are used; vault
              ciphertext is ignored here).

    Returns:
        A bytes object that is passed as `mac_len`/`nonce` to AES-GCM.
    """
    header = {
        "version": data.get("version"),
        "kdf": data.get("kdf"),
        "auth": {
            "salt": data["auth"]["salt"],          # base64 string
        },
        "enc": {
            "salt": data["enc"]["salt"],            # base64 string
        },
    }
    # Use separators to produce compact, deterministic JSON
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Vault Encryption / Decryption (AES-256-GCM)
# ---------------------------------------------------------------------------

def encrypt_vault(
    plaintext: bytes,
    key: bytearray,
    aad: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt vault contents with AES-256-GCM.

    WHY GCM mode?
    GCM (Galois/Counter Mode) provides authenticated encryption:
      - Confidentiality: data is encrypted (XOR with a keystream like CTR).
      - Integrity/Authenticity: a 16-byte tag detects any modification.
    No separate HMAC is needed. Compare with CBC which only encrypts and
    needs a separate MAC for integrity.

    WHY a new nonce every save?
    GCM security COLLAPSES if the same (key, nonce) pair is ever reused
    with different plaintexts — an attacker can recover the key.
    Generating a fresh 12-byte random nonce on every save makes reuse
    practically impossible (birthday bound is ~2^48 saves).

    WHY 12 bytes (96 bits) for the nonce?
    NIST SP 800-38D recommends 96-bit nonces for GCM because they are used
    directly without an extra hashing step, which is both faster and avoids
    subtle implementation pitfalls present with other nonce sizes.

    Args:
        plaintext: The serialised JSON of the vault entry list (bytes).
        key:       The AES-256 key (bytearray, 32 bytes).
        aad:       Associated data bytes (from build_aad). Authenticated
                   but NOT encrypted.

    Returns:
        (nonce, tag, ciphertext) — all bytes objects.
        nonce and tag must be stored alongside the ciphertext in vault.json.
    """
    # get_random_bytes uses os.urandom internally — cryptographically secure.
    nonce = get_random_bytes(NONCE_SIZE)

    # Convert bytearray → bytes for the cipher (pycryptodome accepts both,
    # but explicit conversion makes the intent clear).
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)

    # update() feeds the AAD into the MAC computation. The AAD is NOT
    # encrypted; it is only authenticated (included in the tag calculation).
    cipher.update(aad)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, tag, ciphertext


def decrypt_vault(
    ciphertext: bytes,
    tag: bytes,
    nonce: bytes,
    key: bytearray,
    aad: bytes,
) -> bytes:
    """
    Decrypt and verify vault contents with AES-256-GCM.

    WHY verify before using?
    GCM tag verification confirms that:
      (a) the ciphertext was not modified (integrity),
      (b) the correct key was used (authenticity),
      (c) the AAD (header) was not tampered with.
    If the tag check fails we raise VaultCorruptedError rather than
    returning partial plaintext — using unauthenticated data is dangerous.

    Args:
        ciphertext: The encrypted vault bytes.
        tag:        The 16-byte GCM authentication tag.
        nonce:      The 12-byte nonce used during encryption.
        key:        The AES-256 key (bytearray, 32 bytes).
        aad:        The same associated data bytes used during encryption.

    Returns:
        The original plaintext bytes if verification succeeds.

    Raises:
        VaultCorruptedError: If tag verification fails (wrong key, tampered
                             ciphertext, or tampered header).
    """
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        # pycryptodome raises ValueError when the tag does not match.
        # We re-raise as our own error so the GUI can catch it cleanly.
        raise VaultCorruptedError(
            "GCM tag verification failed — vault is corrupted or tampered."
        ) from exc

    return plaintext


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class VaultCorruptedError(Exception):
    """
    Raised when AES-GCM tag verification fails.

    This happens when:
    - The master password is wrong (wrong key → wrong tag).
    - The ciphertext was modified (bit-flip, truncation, etc.).
    - The vault file header was tampered with (AAD mismatch).
    The GUI should catch this and display a clear message rather than
    crashing with an unhandled exception.
    """
