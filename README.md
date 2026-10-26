# 🔐 Password Manager with AES Encryption & Secure Master Authentication

> **College Cryptography & Network Security (CNS) Mini Project**  
> Built with Python 3.10+, PyCryptodome (AES-256-GCM), and CustomTkinter.

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Cryptographic Architecture](#-cryptographic-architecture)
3. [Key Security Decisions (Why We Built It This Way)](#-key-security-decisions)
4. [File & Directory Structure](#-file--directory-structure)
5. [Installation & Running](#-installation--running)
6. [Test Suite](#-test-suite)
7. [Viva & Examiner Q&A Guide](#-viva--examiner-qa-guide)

---

## 🎯 Project Overview

This project implements a secure, desktop password manager following modern security standards and NIST guidelines. All credentials are encrypted inside a single `vault.json` file using **AES-256-GCM** authenticated encryption.

### Core Guarantees
- **Zero-Knowledge Master Password:** The master password is never written to disk and never stored in any form.
- **Dual-Salt Key Derivation:** Completely separates authentication (`auth_hash`) from encryption (`enc_key`). Knowing the stored auth hash reveals nothing about the AES encryption key.
- **Authenticated Encryption (AES-GCM):** Any bit flipped in ciphertext or header metadata is detected immediately before decryption.
- **In-Memory Hygiene:** The AES key is stored in a mutable `bytearray` that is securely zeroed in-place on lock, logout, or window close.
- **Brute-Force Protection:** Exponential backoff lockout kicks in after failed attempts.
- **Clipboard Auto-Wipe:** Copied passwords are automatically expunged from the system clipboard after 30 seconds.

---

## 🛡️ Cryptographic Architecture

```
                    ┌───────────────────────────┐
                    │  Master Password (User)   │
                    └─────────────┬─────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         │                                                 │
         ▼                                                 ▼
┌───────────────────────────────┐         ┌───────────────────────────────┐
│     PBKDF2-HMAC-SHA256        │         │     PBKDF2-HMAC-SHA256        │
│  Iterations: 600,000          │         │  Iterations: 600,000          │
│  Salt: auth_salt (16 bytes)   │         │  Salt: enc_salt (16 bytes)    │
│  Output: 32 bytes             │         │  Output: 32 bytes             │
└──────────────┬────────────────┘         └──────────────┬────────────────┘
               │                                         │
               ▼                                         ▼
      ┌─────────────────┐                       ┌─────────────────┐
      │  Stored on Disk │                       │   NEVER STORED  │
      │   (auth.hash)   │                       │  AES-256 Key    │
      └─────────────────┘                       │   (bytearray)   │
                                                └────────┬────────┘
                                                         │
                                  ┌──────────────────────┴──────────────────────┐
                                  │                                             │
                                  ▼                                             ▼
                       ┌──────────────────────┐                     ┌──────────────────────┐
                       │  AES-256-GCM Encrypt │                     │  AES-256-GCM Decrypt │
                       │  + 12-byte Nonce     │                     │  + Nonce & Tag Check │
                       │  + Associated Data   │                     │  + Associated Data   │
                       └──────────────────────┘                     └──────────────────────┘
```

---

## 🧠 Key Security Decisions

### 1. Why PBKDF2-HMAC-SHA256 with 600,000 Iterations?
- **Resistance to GPU/ASIC attacks:** SHA-256 computed once takes less than 1 microsecond. An attacker with a modern GPU could test billions of candidate passwords per second.
- **OWASP 2023+ Recommendation:** OWASP recommends at least 600,000 rounds for PBKDF2-HMAC-SHA256. This introduces a noticeable ~0.2–0.5s computation cost per verification, making offline brute-force attacks computationally infeasible.

### 2. Why Two Distinct Salts (`auth_salt` and `enc_salt`)?
- If we derived both the auth hash and the AES encryption key using the same salt, or used the auth hash as the AES key, anyone with read access to `vault.json` would immediately possess the decryption key!
- Using two completely independent 16-byte random salts ensures **cryptographic separation**:
  $$\text{auth\_hash} = \text{PBKDF2}(\text{password}, \text{auth\_salt})$$
  $$\text{enc\_key} = \text{PBKDF2}(\text{password}, \text{enc\_salt})$$
- Even if an attacker reads `auth_hash` and `auth_salt` from disk, they cannot compute `enc_key` without knowing the original master password.

### 3. Why AES-256-GCM (Authenticated Encryption)?
- Older modes like **AES-CBC** require an external HMAC (Encrypt-then-MAC). Without MAC, CBC is vulnerable to padding oracle attacks and bit-flipping attacks.
- **AES-GCM** natively provides both:
  1. **Confidentiality:** Plaintext entries cannot be read without the key.
  2. **Integrity & Authenticity:** The 16-byte GMAC authentication tag guarantees that the ciphertext has not been modified or corrupted.

### 4. Why Associated Data (AAD)?
- GCM allows authenticating unencrypted data (AAD).
- We bind `version`, `auth_salt`, and `enc_salt` into the GCM AAD. If an adversary attempts to swap salts or downgrade the file format in the JSON file, the GCM tag verification fails immediately.

### 5. Why a Fresh 12-Byte Nonce on Every Save?
- In AES-GCM, reusing the same $(Key, Nonce)$ pair across two different messages allows an attacker to compute the XOR of the plaintexts and recover the GHASH authentication subkey.
- Every save operation generates a brand-new 12-byte nonce via `get_random_bytes(12)` (CSPRNG), guaranteeing semantic security.

### 6. Why In-Memory Zeroing (`bytearray`)?
- Python strings (`str`) and `bytes` are immutable; when deleted, they linger in heap memory until garbage collected.
- We store `enc_key` in a mutable `bytearray`. On logout, auto-lock, or app close, we overwrite every byte with `0x00`:
  ```python
  def wipe_key(key: bytearray) -> None:
      for i in range(len(key)):
          key[i] = 0
  ```

### 7. Why `secrets` Instead of `random` for Password Generation?
- The standard `random` module uses the **Mersenne Twister (MT19937)** PRNG, which is completely deterministic and non-cryptographic (observing 624 outputs allows predicting all future values).
- The `secrets` module uses OS-level entropy (`/dev/urandom` or Windows `CryptGenRandom`), providing unpredictable cryptographic randomness.

---

## 📂 File & Directory Structure

```
password_manager/
│
├── main.py                     # Entry point & OS environment initialization
├── requirements.txt            # pycryptodome, customtkinter
├── README.md                   # Complete documentation & viva guide
│
├── core/                       # Cryptographic & business logic (NO GUI code)
│   ├── __init__.py
│   ├── crypto.py               # AES-256-GCM, PBKDF2 derivation, AAD, key wiping
│   ├── auth.py                 # Setup, Login, Rate limiting, Lockout, Password Change
│   ├── vault.py                # CRUD operations, JSON serialization, atomic save
│   ├── generator.py            # CSPRNG password generation & strength scoring
│   └── storage.py              # Atomic disk I/O, base64 encoding/decoding
│
├── gui/                        # Presentation layer (CustomTkinter)
│   ├── __init__.py
│   ├── app.py                  # Main App window, theming, session lifecycle & auto-lock
│   ├── setup_frame.py          # Master password creation screen (live strength meter)
│   ├── login_frame.py          # Login screen (lockout countdown, attempt tracking)
│   ├── vault_frame.py          # Dashboard (search, credential cards, quick copy)
│   └── dialogs.py              # Entry dialog, Generator modal, Password change, Clipboard wipe
│
└── tests/                      # Automated test suite (119 automated tests)
    ├── __init__.py
    ├── test_crypto.py          # 31 crypto & tamper resistance tests
    ├── test_auth.py            # 33 authentication, lockout, & password change tests
    ├── test_vault.py           # 50 vault CRUD, generator, & strength scoring tests
    └── test_gui.py             # 5 headless GUI integration & memory hygiene tests
```

---

## 🚀 Installation & Running

### 1. Prerequisites
- Python 3.10 or higher.

### 2. Setup Virtual Environment
```bash
cd password_manager
python -m venv venv

# Windows (Command Prompt / PowerShell):
.\venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate
```

### 3. Install Requirements
```bash
pip install -r requirements.txt
```

### 4. Launch the Application
```bash
python main.py
```

---

## 🧪 Test Suite

The test suite covers 119 unit and integration tests across all security layers:
- Key derivation determinism and uniqueness
- Bit-flip tamper detection on ciphertext, tag, and AAD
- Rate limiting and exponential backoff lockout
- GCM nonce uniqueness (semantic security)
- In-memory key zeroing (`bytearray` memory sanitation)
- Headless GUI state transitions and 30-second clipboard wipe

### Run all tests:
```bash
pytest tests/ -v
```

Output:
```
================== 119 passed, 10 subtests passed in 45.42s ===================
```

---

## 🎓 Viva & Examiner Q&A Guide

#### Q1: Where is the master password stored?
> **Answer:** It is **never** stored. Neither the plaintext master password nor its reversible representation is ever written to disk. Only an irreversible PBKDF2-HMAC-SHA256 authentication hash computed with a random 16-byte salt is stored to verify login credentials using constant-time comparison (`hmac.compare_digest`).

#### Q2: How is the vault encrypted?
> **Answer:** All credentials are stored as a JSON array encrypted with **AES-256 in Galois/Counter Mode (GCM)**. The encryption key is derived on the fly from the master password and a dedicated `enc_salt` using 600,000 PBKDF2 rounds.

#### Q3: What happens if an attacker modifies one byte in `vault.json`?
> **Answer:** AES-GCM calculates a 16-byte GMAC authentication tag over both the ciphertext and the Associated Authenticated Data (AAD). If even a single bit of the file is flipped or altered, tag verification fails and `VaultCorruptedError` is raised before any plaintext is processed.

#### Q4: Why can't we use standard `random.choice()` for generating passwords?
> **Answer:** Standard `random` uses the Mersenne Twister PRNG, which is designed for numerical simulations, not security. Its internal state can be reconstructed by observing just 624 outputs. We use Python's `secrets` module, which interfaces directly with the OS cryptographic randomness source (`/dev/urandom` or `CryptGenRandom`).

#### Q5: How does the application protect against memory dump attacks?
> **Answer:** The AES key is stored in a mutable Python `bytearray`. As soon as the vault is locked, the user logs out, or the window closes, the key is overwritten in-place with `0x00` bytes before the variable reference is deleted.

#### Q6: How are brute-force attacks mitigated?
> **Answer:** Through two layers:
> 1. **High Computational Work Factor:** 600,000 rounds of PBKDF2 enforce ~0.3s computation per guess.
> 2. **Progressive Rate Limiting:** After 5 failed attempts, exponential backoff locks the vault (30s, 60s, 120s...). The lockout timestamp is persisted in the vault file to prevent bypassing it via application restarts.
