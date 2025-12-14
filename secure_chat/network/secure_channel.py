import os
import base64
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import SESSION_TIMEOUT, MAX_NONCE_CACHE


class SecureChannel:
    def __init__(self, crypto_manager):
        self.crypto_manager = crypto_manager
        self.aes_key = None
        self.peer_public_key = None
        self.handshake_complete = False
        self.session_start = None
        self.seen_nonces = set()
        self.last_nonce_cleanup = time.time()

    def generate_aes_key(self):
        self.aes_key = os.urandom(32)
        self.session_start = time.time()
        return self.aes_key

    def is_session_valid(self):
        if not self.session_start:
            return False
        return time.time() - self.session_start < SESSION_TIMEOUT

    def cleanup_old_nonces(self):
        now = time.time()
        if now - self.last_nonce_cleanup > 60:
            if len(self.seen_nonces) > MAX_NONCE_CACHE:
                self.seen_nonces = set(list(self.seen_nonces)[MAX_NONCE_CACHE//2:])
            self.last_nonce_cleanup = now

    def encrypt_message(self, plaintext):
        if not self.aes_key:
            raise Exception("AES key not set")
        
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt_message(self, encrypted_data):
        if not self.aes_key:
            raise Exception("AES key not set")
        
        data = base64.b64decode(encrypted_data)
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
