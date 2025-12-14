import base64
import hashlib
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from config import TRUSTED_FINGERPRINTS

logger = logging.getLogger(__name__)


class CryptoManager:
    def __init__(self, private_key_path, public_key_path):
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        with open(public_key_path, 'rb') as f:
            self.public_key_pem_bytes = f.read()
            self.public_key = serialization.load_pem_public_key(
                self.public_key_pem_bytes, backend=default_backend()
            )
        
        self.key_fingerprint = hashlib.sha256(self.public_key_pem_bytes).hexdigest()
        logger.info("✓ Loaded RSA keys")
        logger.info(f"✓ Key fingerprint: sha256:{self.key_fingerprint}")

    def get_public_key_pem(self):
        return base64.b64encode(self.public_key_pem_bytes).decode()

    def load_public_key_from_b64(self, public_key_b64):
        pem = base64.b64decode(public_key_b64)
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def verify_peer_identity(self, peer_name, public_key_b64):
        if peer_name not in TRUSTED_FINGERPRINTS:
            logger.warning(f"⚠ No trusted fingerprint for {peer_name} - accepting (INSECURE)")
            return True
        
        pem = base64.b64decode(public_key_b64)
        key_hash = hashlib.sha256(pem).hexdigest()
        expected = TRUSTED_FINGERPRINTS[peer_name].replace("sha256:", "")
        
        if key_hash != expected:
            logger.error(f"✗ Key fingerprint mismatch for {peer_name}!")
            return False
        
        logger.info(f"✓ Verified {peer_name}'s identity")
        return True

    def encrypt_aes_key(self, aes_key, peer_public_key_b64):
        peer_public_key = self.load_public_key_from_b64(peer_public_key_b64)
        encrypted = peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    def decrypt_aes_key(self, encrypted_aes_key):
        encrypted = base64.b64decode(encrypted_aes_key)
        decrypted = self.private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def sign_message(self, message):
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, message, signature_b64, peer_public_key_b64):
        try:
            if not peer_public_key_b64:
                return False
            peer_public_key = self.load_public_key_from_b64(peer_public_key_b64)
            signature = base64.b64decode(signature_b64)
            peer_public_key.verify(
                signature, message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
