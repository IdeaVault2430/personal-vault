# 🔐 Personal Vault

A secure CLI-based password manager built with Python.

Personal Vault allows users to securely store and retrieve credentials using strong cryptographic standards.

---

## 🚀 Features

- Master Password Authentication
- PBKDF2-HMAC Key Derivation
- Fernet (AES) Encryption
- Encrypted credential storage
- Auto-lock on inactivity
- Clipboard auto-clear protection
- Secure JSON storage format

---

## 🛡 Security Architecture

Personal Vault uses industry-standard cryptographic practices:

- Master password is NEVER stored
- PBKDF2-HMAC (SHA256) for secure key derivation
- Unique salt per vault
- AES-based symmetric encryption via Fernet
- All credentials stored locally in encrypted format

---

## 🧰 Tech Stack

- Python 3
- cryptography
- hashlib
- json
- os
- base64

---

## ▶️ Installation

```bash
pip install -r requirements.txt
```
▶️ Run the Application
python vault.py

📌 Future Improvements

GUI version

2FA integration

Encrypted cloud backup

Password strength checker

Secure export/import feature

👤 Author

A. Aravind Reddy