# 🛡️ OxyCrypt Pro - AES-256 File Encryption Tool

**OxyCrypt Pro** is a secure desktop application for encrypting and decrypting files using **AES-256 encryption**. Built with Python and Tkinter, it features a modern dark-themed interface and military-grade encryption to protect your sensitive data.

---

## 🚀 Features

- **AES-256 Encryption**  
  Industry-standard encryption algorithm for strong file security.

- **File Protection**  
  Secure documents, images, videos, and archive files.

- **Modern UI**  
  Dark-themed, user-friendly interface with intuitive controls.

- **Password Security**  
  Uses `PBKDF2HMAC` with **600,000 iterations** for robust key derivation.

- **Flexible File Handling**
  - Option to **overwrite original files**
  - Or create **encrypted/decrypted copies**
  - Encrypted files saved with `.enc` extension

- **Progress Tracking**  
  Real-time visual progress bar and operation timer.

- **Responsive Design**  
  Clean layout that adjusts to different screen sizes.

---

## 📦 Requirements

- **Python 3.7+**
- Install required package:

```bash
pip install cryptography
```

---

## 📝 How to Use

### 1. Select a File
- Click **"Browse Files"** to choose any file.
- Selected files display their **name and size**.

### 2. Set Password
- Enter a **strong password** in the field.
- Toggle visibility with the **"Show Password"** checkbox.

### 3. Choose Options
- Enable **"Overwrite original file"** to replace it.
- Or leave disabled to create **new encrypted copies**.

### 4. Encrypt/Decrypt
- Click **"Encrypt File"** to generate a `.enc` file.
- Click **"Decrypt File"** to restore the original.
- Progress bar and operation duration are shown.

---

## 🔐 Security Best Practices

- Always use **strong, unique passwords**.
- **Passwords cannot be recovered** – store them securely.
- **Back up important files** before overwriting them.

---

## ⚙️ Technical Details

- **Encryption Algorithm**: AES-256 in CBC mode with PKCS7 padding  
- **Key Derivation**: PBKDF2HMAC-SHA256 with 600,000 iterations  
- **File Structure**:
  ```
  [16-byte salt] + [AES-encrypted payload]
  ```
- **Supported Files**: All types (documents, media, archives, etc.)

---

## 🛡️ Security Notes

- **Passwords are never stored or transmitted**.
- Overwritten files are **securely deleted**.
- Always **verify decrypted files** after restoration.
- **Not recommended** for highly sensitive military/government applications.



![Fox Logo](https://i.postimg.cc/tTmS4qhF/Screenshot-2025-06-24-190356.png)
