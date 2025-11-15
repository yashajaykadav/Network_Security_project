# Symmetric Encryption & MITM Attack Simulator

A Python application suite illustrating how symmetric encryption can be vulnerable to Man-in-the-Middle (MITM) attacks. The toolkit showcases how attackers might intercept, decrypt, and modify messages encrypted with a shared secret key.

**Author**: Yash Kadav  

***

## Project Overview

This educational project demonstrates the risks in communication systems that use only symmetric encryption. It consists of three main desktop applications:
- `sender.py`: Encrypts messages and sends them using a selected algorithm.
- `receiver.py`: Listens for messages and decrypts them using the shared key.
- `mitm_proxy.py`: Acts as an interceptor, capable of logging, decrypting, and modifying messages if the key is known.

***

## Core Components & Features

- **encryption_handler.py**  
  Central logic for multiple symmetric encryption schemes:
    - AES-256, AES-128, Fernet, 3DES, XOR, Caesar Cipher  
  Uses `hashlib` (SHA-256, MD5) to derive keys from passwords.

- **sender.py (Client GUI)**  
  Compose messages, choose an encryption algorithm, and send securely or through the MITM proxy.

- **receiver.py (Server GUI)**  
  Listens for incoming encrypted messages and displays decrypted plaintext.

- **mitm_proxy.py (Attacker GUI)**  
  Demonstrates MITM attack capabilities:
    - **Passive Mode**: Log encrypted traffic.
    - **Active Decrypt Mode**: Log decrypted messages (if the key is known).
    - **Attack Mode**: Decrypt, modify, re-encrypt, and forward messages. Example: Replace “10 AM” with “2 PM” in transit.

***

## MITM Attack Demonstration

1. Launch all three apps.
2. `receiver.py` listens on `127.0.0.1:5555`.
3. `mitm_proxy.py` listens on `127.0.0.1:4444`, targeting `127.0.0.1:5555`.
4. Configure `sender.py` to use the MITM Proxy (`127.0.0.1:4444`).
5. Send a message using a chosen algorithm and shared key (e.g., “AES-256”, “password123”).
6. In Attack Mode, proxy modifies the message and forwards it. The receiver displays the tampered message, unaware of any attack.

***

## How to Run

1. Install dependencies:
   ```bash
   pip install cryptography pycryptodome
   ```
2. Start the receiver:
   ```bash
   python receiver.py
   ```
   Enter your shared key and click "START RECEIVER".
3. Start the MITM proxy:
   ```bash
   python mitm_proxy.py
   ```
   Set target port to 5555, choose mode, enter the same key, and click "START".
4. Start the sender:
   ```bash
   python sender.py
   ```
   Enable "Use Proxy (MITM)", select port 4444, algorithm and key, type your message, and send.

Observe how the MITM proxy intercepts, decrypts, and modifies messages in real time across all three interfaces.

***

## Disclaimer

**For educational purposes only.**  
This simulator is meant to demonstrate vulnerabilities in symmetric key encryption when keys are compromised. It is not a secure communications tool and should not be used for actual secure messaging.
