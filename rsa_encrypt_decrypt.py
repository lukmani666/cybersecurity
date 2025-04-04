"RSA (Rivest-Shamir-Adleman) – An asymmetric encryption algorithm (public & private key pair)."

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_rsa_keys():
    """Generate RSA key pair (private & public key)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    return private_key, public_key


private_key, public_key = generate_rsa_keys()


private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

print(f"Private Key:\n {private_pem}")
print(f"Public Key:\n {public_pem}")



def encrypt_message_rsa(message, public_key):
    """Encrypt a message using RSA public key"""
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_message_rsa(ciphertext, private_key):
    """Decrypt a message using RSA private key"""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode()


message = "Hello, Secure World!"
ciphertext = encrypt_message_rsa(message, public_key)
decrypt_message = decrypt_message_rsa(ciphertext, private_key)

print(f"Original Message: {message}")
print(f"Encrypted Message: {ciphertext.hex()}")
print(f"Decrypted Message: {decrypt_message}")


def sign_message(message, private_key):
    """Sign a message with RSA private key"""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message, signature, public_key):
    """Verify a digital signature with RSA public key"""
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

message = "This is a secure message!"
signature = sign_message(message, private_key)

is_valid = verify_signature(message, signature, public_key)

print(f"Original Message: {message}")
print(f"Digital Signature: {signature.hex()}")
print(f"Signaure Valid? {is_valid}")


def sign_large_file(file_path, private_key):
    """Sign a large file by hashing it in chunks."""
    hasher = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    
    file_hash = hasher.digest()

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

file_path = "Block-3.pdf"
signature = sign_large_file(file_path, private_key)

with open("block-3.sig", "wb") as sig_file:
    sig_file.write(signature)

print(f"File '{file_path}' signed successfully!")


def verify_large_file(file_path, signature, public_key):
    """Verify a signed large file."""
    hasher = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    
    file_hash = hasher.digest()

    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


with open("block-3.sig", "rb") as sig_file:
    saved_signature = sig_file.read()

is_valid = verify_large_file(file_path, saved_signature, public_key)
print(f"Signature Valid? {is_valid}")


def encrypt_large_file(file_path, public_key):
    """Encrypt a large file using AES, then encrypt the AES key with RSA."""

    aes_key = os.urandom(32)
    iv = os.urandom(16)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted_file_path = file_path + ".enc"
    with open(file_path, "rb") as f_in, open(encrypted_file_path, "wb") as f_out:
        f_out.write(encrypted_aes_key)
        f_out.write(iv)

        while chunk := f_in.read(16):
            if len(chunk) % 16 != 0:
                chunk += b" " * (16 - len(chunk) % 16)
            
            f_out.write(encryptor.update(chunk))
        
        f_out.write(encryptor.finalize())
    
    print(f"File '{file_path}' encrypted successfully!")

encrypt_large_file("Block-3.pdf", public_key)


def decrypt_large_file(encrypted_file_path, private_key):
    """Decrypt a large file using RSA + AES."""

    with open(encrypted_file_path, "rb") as f_in:
        encrypted_aes_key = f_in.read(256)
        iv = f_in.read(16)

        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
        with open(decrypted_file_path, "wb") as f_out:
            while chunk := f_in.read(16):
                f_out.write(decryptor.update(chunk))

            f_out.write(decryptor.finalize())
    
    print(f"File '{decrypted_file_path}' decrypted successfully!")


decrypt_large_file("Block-3.pdf.enc", private_key)



