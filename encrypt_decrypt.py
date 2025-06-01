from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import secrets

# Constantes
BACKEND = default_backend()
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16  # En CBC el IV debe ser del tamaño del bloque AES (16 bytes)
ITERATIONS = 100000
EXT_LEN_SIZE = 4  # para almacenar la longitud de la extensión

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Hash del archivo original
    sha256_hash = hashlib.sha256(plaintext).digest()

    # Padding (AES requiere que el tamaño sea múltiplo del bloque en CBC)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Generar salt e IV
    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(IV_SIZE)
    key = derive_key(password, salt)

    # Cifrar con AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Guardar la extensión del archivo original
    ext = os.path.splitext(file_path)[1].encode()
    ext_len = len(ext).to_bytes(EXT_LEN_SIZE, byteorder='big')

    encrypted_path = file_path + ".enc"
    with open(encrypted_path, 'wb') as f:
        f.write(ext_len + ext + salt + iv + sha256_hash + ciphertext)

    return encrypted_path

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Extraer la extensión
    ext_len = int.from_bytes(data[:EXT_LEN_SIZE], byteorder='big')
    ext = data[EXT_LEN_SIZE:EXT_LEN_SIZE + ext_len].decode()

    offset = EXT_LEN_SIZE + ext_len
    salt = data[offset:offset+SALT_SIZE]
    iv = data[offset+SALT_SIZE:offset+SALT_SIZE+IV_SIZE]
    stored_hash = data[offset+SALT_SIZE+IV_SIZE:offset+SALT_SIZE+IV_SIZE+32]
    ciphertext = data[offset+SALT_SIZE+IV_SIZE+32:]

    key = derive_key(password, salt)

    # Descifrar con AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Quitar padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Verificar integridad
    if hashlib.sha256(plaintext).digest() != stored_hash:
        raise ValueError("Integrity verification failed.")

    decrypted_path = file_path.replace(".enc", "") + "_decrypted" + ext
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_path
