import os
import base64
import zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Parâmetros de configuração
SALT_SIZE = 16      # em bytes
NONCE_SIZE = 12     # em bytes (recomendado para AES-GCM)
KEY_SIZE = 32       # 32 bytes para AES-256
KDF_ITERATIONS = 100000

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Deriva uma chave a partir da senha e do salt utilizando PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password)

def encrypt_data(plaintext: bytes, password: str) -> str:
    """
    Criptografa o dado, comprime e codifica em Base64.
    Retorna o resultado como string Base64.
    """
    password_bytes = password.encode('utf-8')
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password_bytes, salt)
    
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    payload = salt + nonce + ciphertext
    compressed_payload = zlib.compress(payload)
    return base64.b64encode(compressed_payload).decode('utf-8')

def decrypt_data(encoded_data: str, password: str) -> bytes:
    """
    Decodifica, descomprime e descriptografa o dado.
    Retorna o texto plano em bytes.
    """
    password_bytes = password.encode('utf-8')
    compressed_payload = base64.b64decode(encoded_data)
    payload = zlib.decompress(compressed_payload)
    
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = payload[SALT_SIZE + NONCE_SIZE:]
    
    key = derive_key(password_bytes, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
