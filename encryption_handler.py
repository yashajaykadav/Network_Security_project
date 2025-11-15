import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
import os


class EncryptionHandler:
    """Handles multiple encryption algorithms"""
    
    def __init__(self):
        self.algorithms = {
            'AES-256': self.aes_encrypt,
            'AES-128': self.aes128_encrypt,
            'Fernet': self.fernet_encrypt,
            'XOR': self.xor_encrypt,
            'Caesar': self.caesar_encrypt,
            '3DES': self.triple_des_encrypt
        }
        
        self.decryption_methods = {
            'AES-256': self.aes_decrypt,
            'AES-128': self.aes128_decrypt,
            'Fernet': self.fernet_decrypt,
            'XOR': self.xor_decrypt,
            'Caesar': self.caesar_decrypt,
            '3DES': self.triple_des_decrypt
        }
    
    def get_available_algorithms(self):
        return list(self.algorithms.keys())
    
    def encrypt(self, message, algorithm, key):
        """Encrypt message using specified algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        return self.algorithms[algorithm](message, key)
    
    def decrypt(self, encrypted_message, algorithm, key):
        """Decrypt message using specified algorithm"""
        if algorithm not in self.decryption_methods:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        return self.decryption_methods[algorithm](encrypted_message, key)
    
    # =============== AES-256 ===============
    def aes_encrypt(self, message, key):
        """AES-256 encryption"""
        # Create 32-byte key from password
        key_bytes = hashlib.sha256(key.encode()).digest()
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad message to 16-byte blocks
        padded_message = self._pad(message.encode())
        
        # Encrypt
        encrypted = encryptor.update(padded_message) + encryptor.finalize()
        
        # Return IV + encrypted data as base64
        return base64.b64encode(iv + encrypted).decode()
    
    def aes_decrypt(self, encrypted_message, key):
        """AES-256 decryption"""
        # Create 32-byte key from password
        key_bytes = hashlib.sha256(key.encode()).digest()
        
        # Decode base64
        data = base64.b64decode(encrypted_message)
        
        # Extract IV and encrypted message
        iv = data[:16]
        encrypted = data[16:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        
        # Remove padding
        decrypted = self._unpad(decrypted_padded)
        
        return decrypted.decode()
    
    # =============== AES-128 ===============
    def aes128_encrypt(self, message, key):
        """AES-128 encryption using PyCrypto"""
        # Create 16-byte key
        key_bytes = hashlib.md5(key.encode()).digest()
        
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        
        # Return IV + encrypted data as base64
        return base64.b64encode(cipher.iv + encrypted).decode()
    
    def aes128_decrypt(self, encrypted_message, key):
        """AES-128 decryption"""
        key_bytes = hashlib.md5(key.encode()).digest()
        
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        encrypted = data[16:]
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        
        return decrypted.decode()
    
    # =============== 3DES ===============
    def triple_des_encrypt(self, message, key):
        """Triple DES encryption"""
        # Create 24-byte key (3DES requires 16 or 24 bytes)
        key_bytes = hashlib.sha256(key.encode()).digest()[:24]
        
        cipher = DES3.new(key_bytes, DES3.MODE_CBC)
        encrypted = cipher.encrypt(pad(message.encode(), DES3.block_size))
        
        return base64.b64encode(cipher.iv + encrypted).decode()
    
    def triple_des_decrypt(self, encrypted_message, key):
        """Triple DES decryption"""
        key_bytes = hashlib.sha256(key.encode()).digest()[:24]
        
        data = base64.b64decode(encrypted_message)
        iv = data[:8]  # DES uses 8-byte blocks
        encrypted = data[8:]
        
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES3.block_size)
        
        return decrypted.decode()
    
    # =============== Fernet ===============
    def fernet_encrypt(self, message, key):
        """Fernet encryption (symmetric)"""
        # Generate Fernet key from password
        key_bytes = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
        f = Fernet(key_bytes)
        
        encrypted = f.encrypt(message.encode())
        return encrypted.decode()
    
    def fernet_decrypt(self, encrypted_message, key):
        """Fernet decryption"""
        key_bytes = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
        f = Fernet(key_bytes)
        
        decrypted = f.decrypt(encrypted_message.encode())
        return decrypted.decode()
    
    # =============== XOR Cipher ===============
    def xor_encrypt(self, message, key):
        """Simple XOR cipher"""
        if not key:
            key = "default"
        
        encrypted = []
        key_length = len(key)
        
        for i, char in enumerate(message):
            encrypted_char = ord(char) ^ ord(key[i % key_length])
            encrypted.append(encrypted_char)
        
        return base64.b64encode(bytes(encrypted)).decode()
    
    def xor_decrypt(self, encrypted_message, key):
        """XOR decryption (same as encryption)"""
        if not key:
            key = "default"
        
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted = []
        key_length = len(key)
        
        for i, byte in enumerate(encrypted_bytes):
            decrypted_char = byte ^ ord(key[i % key_length])
            decrypted.append(chr(decrypted_char))
        
        return ''.join(decrypted)
    
    # =============== Caesar Cipher ===============
    def caesar_encrypt(self, message, key):
        """Caesar cipher with shift based on key"""
        try:
            shift = int(key) if key else 3
        except ValueError:
            shift = sum(ord(c) for c in key) % 26
        
        encrypted = []
        for char in message:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                encrypted_char = chr((ord(char) - base + shift) % 26 + base)
                encrypted.append(encrypted_char)
            else:
                encrypted.append(char)
        
        result = ''.join(encrypted)
        return base64.b64encode(result.encode()).decode()
    
    def caesar_decrypt(self, encrypted_message, key):
        """Caesar cipher decryption"""
        try:
            shift = int(key) if key else 3
        except ValueError:
            shift = sum(ord(c) for c in key) % 26
        
        decoded = base64.b64decode(encrypted_message).decode()
        decrypted = []
        
        for char in decoded:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                decrypted_char = chr((ord(char) - base - shift) % 26 + base)
                decrypted.append(decrypted_char)
            else:
                decrypted.append(char)
        
        return ''.join(decrypted)
    
    # =============== Helper Methods ===============
    def _pad(self, data):
        """PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]