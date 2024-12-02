# Secret Ops System

A secure communication system built with RSA and AES encryption, digital signatures, and logging. This project is designed for sending and receiving encrypted messages while ensuring message integrity with digital signatures. It also maintains a secure history of all communication activities, utilizing AES encryption to protect sensitive data.

## Features
- **RSA Encryption**: Public-key encryption to securely send messages.
- **AES Encryption**: Symmetric encryption used for securely saving communication history.
- **Digital Signatures**: Ensures message integrity by signing messages with a private key and verifying them with a public key.
- **Communication History**: Maintains a secure history of sent and received messages using AES encryption.
- **Logging**: Keeps a log of important system activities for transparency and audit purposes.
- **Public Key Export**: Allows exporting the RSA public key to a file for sharing with others.

## Requirements
- Python 3.7 or higher
- `cryptography` library
- `pyfiglet` library
- `prettytable` library

You can install the necessary dependencies with the following command:

```bash
pip install cryptography pyfiglet prettytable
