OxyCrypt Pro - AES-256 File Encryption Tool
OxyCrypt Pro is a secure desktop application for encrypting and decrypting files using AES-256 encryption. Built with Python and Tkinter, it features a modern dark-themed interface and military-grade encryption to protect your sensitive data.

Features
AES-256 Encryption: Industry-standard encryption algorithm

File Protection: Secure documents, images, media files, and archives

Modern UI: Dark-themed interface with intuitive controls

Password Security: PBKDF2HMAC key derivation with 600,000 iterations

File Handling:

Overwrite original files or create encrypted copies

Preserve file types with .enc extension for encrypted files

Progress Tracking: Visual progress bar and operation timing

Responsive Design: Clean layout that adapts to different screen sizes

Requirements
Python 3.7+

Required packages:
pip install cryptography

How to Use
Select a File:

Click "Browse Files" and choose any file type

Selected files appear with their name and size

Set Password:

Enter a strong password in the security field

Toggle visibility with "Show Password" checkbox

Choose Options:

Enable "Overwrite original file" to replace files

Leave disabled to create new encrypted/decrypted copies

Encrypt/Decrypt:

Click "Encrypt File" to create a protected .enc file

Click "Decrypt File" to restore original files

Progress bar shows operation status

Operation time displays after completion

Security Best Practices:

Use strong, unique passwords

Remember passwords - they cannot be recovered

Back up important files before overwriting

Technical Details
Encryption: AES-256 in CBC mode with PKCS7 padding

Key Derivation: PBKDF2HMAC-SHA256 with 600,000 iterations

File Structure:
[16-byte salt] + [Fernet encrypted payload]
Supported Files: All file types (documents, images, media, archives)


Security Notes
Passwords are never stored or transmitted

Original files are securely deleted when overwriting

Always verify decrypted files match originals

Not recommended for highly sensitive government/military use

![Fox Logo](https://i.postimg.cc/tTmS4qhF/Screenshot-2025-06-24-190356.png)
