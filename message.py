# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes

# def encrypt_message_rsa(message, public_key):
#     """Encrypt a message using RSA public key"""
#     ciphertext = public_key.encrypt(
#         message.encode(),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return ciphertext


# def decrypt_message_rsa(ciphertext, private_key):
#     """Decrypt a message using RSA private key"""
#     plaintext = private_key.decrypt(
#         ciphertext,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )

#     return plaintext.decode()


# message = "Hello, Secure World!"
# ciphertext = encrypt_message_rsa(message, public_key)