from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os
import hashlib
import secrets

BACKEND = default_backend()
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 12
TAG_SIZE = 16
ITERATIONS = 100000
EXT_LEN_SIZE = 4  # para guardar longitud de extensión

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

    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(IV_SIZE)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    sha256_hash = hashlib.sha256(plaintext).digest()

    ext = os.path.splitext(file_path)[1].encode()
    ext_len = len(ext).to_bytes(EXT_LEN_SIZE, byteorder='big')

    encrypted_path = file_path + ".enc"
    with open(encrypted_path, 'wb') as f:
        f.write(ext_len + ext + salt + iv + tag + sha256_hash + ciphertext)

    return encrypted_path

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    ext_len = int.from_bytes(data[:EXT_LEN_SIZE], byteorder='big')
    ext = data[EXT_LEN_SIZE:EXT_LEN_SIZE + ext_len].decode()

    offset = EXT_LEN_SIZE + ext_len
    salt = data[offset:offset+SALT_SIZE]
    iv = data[offset+SALT_SIZE:offset+SALT_SIZE+IV_SIZE]
    tag = data[offset+SALT_SIZE+IV_SIZE:offset+SALT_SIZE+IV_SIZE+TAG_SIZE]
    stored_hash = data[offset+SALT_SIZE+IV_SIZE+TAG_SIZE:offset+SALT_SIZE+IV_SIZE+TAG_SIZE+32]
    ciphertext = data[offset+SALT_SIZE+IV_SIZE+TAG_SIZE+32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=BACKEND)
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("La contraseña es incorrecta o los datos están corruptos.")

    if hashlib.sha256(plaintext).digest() != stored_hash:
        raise ValueError("La verificación de integridad ha fallado.")

    decrypted_path = file_path.replace(".enc", "") + "_descifrado" + ext
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_path
