Symmetric Encryption & MITM Attack Simulator

A Python-based application suite that demonstrates the principles of symmetric encryption and simulates how a Man-in-the-Middle (MITM) attack can intercept, read, and even modify encrypted data.

Author: Yash Kadav

Email: yashkadav52@gmail.com

ADCET CSE (Class of 2026)

1. Project Overview

This project is an interactive tool designed for educational purposes to show the vulnerabilities of a communication system that relies solely on shared secret (symmetric) encryption.

It consists of three main components that run as separate desktop applications:

🔐 Sender (sender.py): A client that encrypts a message using a chosen algorithm and a shared secret key, then sends it.

📥 Receiver (receiver.py): A server that listens for messages, then decrypts them using the same shared secret key.

🕵️ MITM Proxy (mitm_proxy.py): An "attacker" tool that sits between the Sender and Receiver. It can intercept, log, decrypt, and even modify messages in transit if the attacker knows the shared key.

2. Core Components & Features

encryption_handler.py

This file is the core logic library for the project.

Provides a unified class for handling multiple symmetric encryption algorithms:

AES-256

AES-128

Fernet

3DES

XOR

Caesar Cipher

Uses hashlib (e.g., SHA-256, MD5) to derive encryption keys from a user-provided password.

sender.py (The Client)

A GUI for composing a message.

User selects an encryption algorithm and enters the shared secret key.

User can send the message directly to the Receiver or via the MITM Proxy.

receiver.py (The Server)

A GUI that listens on a specific port for incoming connections.

User must enter the same shared secret key as the sender.

When an encrypted message arrives, it attempts to decrypt it and displays the original plaintext.

mitm_proxy.py (The Attacker)

This is the most powerful tool in the suite. It demonstrates the attack.

Passive Mode: Intercepts and logs the raw encrypted traffic as it passes from Sender to Receiver.

Active Decrypt Mode: If the attacker (the proxy user) enters the correct shared secret key, it will decrypt and log the plaintext of the messages.

Attack Mode (Modify): The attacker can:

Intercept and decrypt the message (using the stolen key).

Perform a "Find and Replace" on the plaintext message.

Re-encrypt the modified message.

Send the modified, re-encrypted message to the Receiver.

3. How the MITM Attack is Demonstrated

This project perfectly shows why simply encrypting a message isn't enough security. The weakness is the shared secret key.

Attack Scenario:

Start all three apps.

receiver.py listens on 127.0.0.1:5555.

mitm_proxy.py listens on 127.0.0.1:4444 and targets 127.0.0.1:5555.

Configure the Sender.

The Sender checks the "Use Proxy (MITM)" box and sends to 127.0.0.1:4444.

Share the Key.

The Sender, Receiver, and MITM Proxy are all configured with the same secret key (e.g., "password123") and algorithm (e.g., "AES-256").

Execute the Attack.

The Sender types "The meeting is at 10 AM." and clicks "Encrypt & Send".

The MITM Proxy (in Attack Mode) is set to find "10 AM" and replace it with "2 PM".

The proxy intercepts the message, decrypts it, logs "Original: The meeting is at 10 AM."

The proxy modifies the text, re-encrypts "The meeting is at 2 PM.", and forwards it.

The Receiver gets the message, decrypts it successfully, and confidently displays: "Decrypted message: The meeting is at 2 PM."

The Receiver has no idea the message was tampered with, as it was validly encrypted with the shared secret key.

4. How to Run

Install the required Python libraries:

pip install cryptography pycryptodome


Start the Receiver:

python receiver.py


Enter a key (e.g., "mysecretkey") and click "START RECEIVER".

Start the MITM Proxy:

python mitm_proxy.py


Set Target Port to 5555.

Set Attack Mode (e.g., "Active Mode").

Enter the same key ("mysecretkey").

Click "START".

Start the Sender:

python sender.py


Check "Use Proxy (MITM)".

Set Proxy Port to 4444.

Select the algorithm (e.g., "AES-256") and enter the key ("mysecretkey").

Type a message and send it.

Observe all three windows to see the interception, decryption, and modification in real-time.

5. Disclaimer

This project is for educational use only. It is designed to demonstrate a common cyber-attack vector and highlight the vulnerabilities of symmetric key encryption when the key is compromised. It is not intended to be used as a secure communication tool.
