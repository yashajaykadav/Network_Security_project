SecureChat 🔒

A concept for a secure messaging application designed with a strong focus on privacy and resistance to Man-in-the-Middle (MITM) attacks.

Author: Yash Kadav

Email: yashkadav52@gmail.com

1. Project Goal

The primary goal of SecureChat is to provide a safe and private communication channel. Unlike traditional messaging apps where server administrators (or attackers) can potentially read messages, this app is built on the principle of End-to-End Encryption (E2EE).

This design specifically aims to neutralize the threat of Man-in-the-Middle (MITM) attacks, where an attacker intercepts and relays messages between two parties to eavesdrop or alter the conversation.

2. Core Security Features

This app's security model is built on two key pillars:

🔒 End-to-End Encryption (E2EE)

All messages, voice calls, and files are encrypted on your device before being sent and are only decrypted on the recipient's device.

How it works: When you start a chat, you and your contact exchange public keys. Your messages are encrypted with their public key, and only their corresponding private key (stored securely on their device) can decrypt them.

MITM Defense: This means that even if an attacker intercepts the encrypted message, they cannot read it. It will be meaningless ciphertext without the private key.

🤝 Trust & Key Verification

E2EE alone doesn't stop an attacker from impersonating your contact at the start of a conversation and performing an MITM attack. This is where user-based verification becomes critical.

How it works: SecureChat provides a "Safety Number" or "Security QR Code" for every conversation. This code is unique to you and your contact.

MITM Defense: To ensure you are talking directly to your friend and not an attacker, you must verify this safety number through an external channel (e.g., meeting in person, a phone call, or another trusted service).

If you scan your friend's QR code in person and it matches, you can mark the user as "Verified."

If the safety number ever changes, the app will notify you. This could be a sign of a potential MITM attack (or just that your friend re-installed the app).

3. Other Security Measures

Certificate Pinning: The mobile app will only trust the server's specific, hard-coded SSL certificate. This prevents attackers from using a fake (but otherwise valid) SSL certificate to intercept the connection between your app and the server (e.g., on public Wi-Fi).

Minimal Metadata: The server only knows the bare minimum required to route messages (e.g., who to send a message to and when) but never the content of the message.

4. Disclaimer

This is a project concept outlining a secure architecture. Real-world cryptographic implementations are complex and require rigorous auditing by security professionals.

Project by Yash Kadav, ADCET CSE (Class of 2026)
