# AESecure Vault - File Encryptor/Decryptor

AESecure Vault is a user-friendly desktop application for encrypting and decrypting files securely using AES encryption. Built with Python and Tkinter, it offers a visual interface for selecting files, entering passwords, and managing encrypted data with ease.

## 🔐 Features

- AES-256 encryption and decryption
- Password-based key derivation using PBKDF2
- SHA-256 hash verification for data integrity
- User-friendly graphical interface (Tkinter)
- Password strength indicator in real-time
- Drag and drop support
- Clipboard paste (Ctrl+V) file support
- File history log

## 📦 How It Works

### Encryption
1. Select or drop a file into the interface.
2. Enter a strong password (6+ characters recommended).
3. The app encrypts the file and saves it with a `.enc` extension in the same folder.

### Decryption
1. Select or drop the `.enc` file.
2. Enter the same password used to encrypt.
3. The file is restored with its original extension and verified via SHA-256 hash.

## 🧰 Requirements

- Python 3.8+
- Required libraries:
  - `cryptography`
  - `tkinterdnd2`

To install them:

```bash
pip install cryptography tkinterdnd2
```

## 🚀 Running the App

```bash
python main.py
```

Or, if you're using a virtual environment:

```bash
venv\Scripts\activate
python main.py
```

## 📁 Project Structure

```
/project-root
│
├── main.py               # App entry point
├── gui.py                # Graphical interface
├── encrypt_decrypt.py    # Cryptographic logic (AES + PBKDF2 + SHA256)
└── README.md             # This file
```

## 🛡️ Disclaimer

This tool is intended for educational and personal use. Always back up your files and use strong passwords. No liability for data loss or misuse.
