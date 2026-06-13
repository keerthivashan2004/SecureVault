# 🔒 SecureVault — Folder Encryption System

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-green)

Protect any folder on Windows with a right-click.
AES-256-GCM encryption — no admin privileges required.

## ✨ Features
- 🔐 AES-256-GCM authenticated encryption
- 🔑 PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
- 🔒 Double-layer encryption support
- ☁️ OneDrive compatibility (auto-pause/resume)
- 🎨 Animated modern dark-themed GUI
- ⚠️ Lockout after 5 failed attempts
- 🖱️ Windows right-click context menu integration

## 📦 Installation
1. Run `INSTALL.bat` as **Administrator** (one-time setup)
2. Right-click any folder → **Protect with SecureVault**
3. Set password → files are encrypted instantly

## 🔓 How to Unlock
1. Right-click locked folder → **Protect with SecureVault**
2. Enter password → original files restored

## 🛡️ Security Details
| Property | Detail |
|----------|--------|
| Encryption | AES-256-GCM |
| Key Derivation | PBKDF2-HMAC-SHA256 |
| Iterations | 100,000 |
| Salt | 256-bit random per lock |
| Auth Tag | 128-bit (tamper detection) |
| Max Attempts | 5 (then lockout) |

## 📁 File Structure
SecureVault/

├── secure_vault.py   ← Main application

├── INSTALL.bat       ← One-time registry setup

├── UNINSTALL.bat     ← Remove context menu

└── README.md

## ⚙️ Requirements
- Windows 10 / 11
- Python 3.9+
- `pip install cryptography`

> ⚠️ No password recovery. Do not forget your password.