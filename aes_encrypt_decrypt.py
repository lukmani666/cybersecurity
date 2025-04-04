"AES (Advanced Encryption Standard) – A symmetric encryption algorithm (same key for encryption & decryption)."

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


key = os.urandom(16)
iv = os.urandom(16)

def encrypt_message(plaintext, key, iv):
    """Encrypt a message using AES (Advance Encryption Standard)"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + (' ' * padding_length)

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()

    return ciphertext


def decrypt_message(ciphertext, key, iv):
    """Decrypt an AES-encrypt message"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_text.decode().strip()


message = "Hello, CyberSecurity Expert!"
ciphertext = encrypt_message(message, key, iv)
decrypted_text = decrypt_message(ciphertext, key, iv)

print(f"Original Message: {message}")
print(f"Encrypted Message: {ciphertext.hex()}")
print(f"Decrypted Message: {decrypted_text}")
