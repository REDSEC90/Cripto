import os
import base64
import zlib
import argparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Parâmetros de configuração
SALT_SIZE = 16      # em bytes
NONCE_SIZE = 12     # em bytes (recomendado para AES-GCM)
KEY_SIZE = 32       # 32 bytes para AES-256
KDF_ITERATIONS = 100000

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Deriva uma chave a partir da senha e do salt utilizando PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password)
    return key

def encrypt_data(plaintext: bytes, password: str) -> str:
    """
    Criptografa o dado, comprime e codifica em Base64.
    
    Passos:
      1. Gerar salt e nonce.
      2. Derivar a chave com a senha e salt.
      3. Criptografar com AES-GCM.
      4. Concatenar salt + nonce + ciphertext.
      5. Comprimir o payload.
      6. Codificar o resultado em Base64.
    """
    password_bytes = password.encode('utf-8')
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password_bytes, salt)
    
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt já inclui a tag de autenticação no final do ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Monta o payload: salt + nonce + ciphertext
    payload = salt + nonce + ciphertext

    # Comprime o payload
    compressed_payload = zlib.compress(payload)
    
    # Codifica em Base64 para facilitar o transporte/armazenamento
    encoded_data = base64.b64encode(compressed_payload).decode('utf-8')
    return encoded_data

def decrypt_data(encoded_data: str, password: str) -> bytes:
    """
    Decodifica, descomprime e descriptografa o dado.
    
    Passos:
      1. Decodificar Base64.
      2. Descomprimir o payload.
      3. Extrair salt, nonce e ciphertext.
      4. Derivar a chave com a senha e salt.
      5. Descriptografar com AES-GCM (verifica autenticidade).
    """
    password_bytes = password.encode('utf-8')
    
    # Decodifica e descomprime
    compressed_payload = base64.b64decode(encoded_data)
    payload = zlib.decompress(compressed_payload)
    
    # Extrai os componentes
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = payload[SALT_SIZE+NONCE_SIZE:]
    
    key = derive_key(password_bytes, salt)
    aesgcm = AESGCM(key)
    
    # Tenta descriptografar; se a autenticação falhar, uma exceção será lançada.
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

def main():
    parser = argparse.ArgumentParser(description="Script para criptografar/comprimir/codificar e o inverso.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Parser para encriptação
    parser_encrypt = subparsers.add_parser('encrypt', help="Criptografa um arquivo.")
    parser_encrypt.add_argument('--input', '-i', required=True, help="Caminho do arquivo de entrada (texto plano).")
    parser_encrypt.add_argument('--output', '-o', required=True, help="Caminho do arquivo de saída (dados codificados).")
    parser_encrypt.add_argument('--password', '-p', required=True, help="Senha para criptografia.")

    # Parser para decriptação
    parser_decrypt = subparsers.add_parser('decrypt', help="Descriptografa um arquivo.")
    parser_decrypt.add_argument('--input', '-i', required=True, help="Caminho do arquivo de entrada (dados codificados).")
    parser_decrypt.add_argument('--output', '-o', required=True, help="Caminho do arquivo de saída (texto decifrado).")
    parser_decrypt.add_argument('--password', '-p', required=True, help="Senha para decriptação.")

    args = parser.parse_args()

    if args.command == 'encrypt':
        try:
            with open(args.input, 'rb') as f_in:
                plaintext = f_in.read()
            encoded_data = encrypt_data(plaintext, args.password)
            with open(args.output, 'w') as f_out:
                f_out.write(encoded_data)
            print("Arquivo criptografado, comprimido e codificado com sucesso.")
        except Exception as e:
            print(f"Erro durante a encriptação: {e}")

    elif args.command == 'decrypt':
        try:
            with open(args.input, 'r') as f_in:
                encoded_data = f_in.read()
            plaintext = decrypt_data(encoded_data, args.password)
            with open(args.output, 'wb') as f_out:
                f_out.write(plaintext)
            print("Arquivo decodificado, descomprimido e descriptografado com sucesso.")
        except Exception as e:
            print(f"Erro durante a decriptação: {e}")

if __name__ == '__main__':
    main()
