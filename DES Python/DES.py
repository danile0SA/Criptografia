from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Función para cifrar usando AES-CBC
def aes_cbc_encrypt(data, secret_key, initialization_vector):
    padding_scheme = padding.PKCS7(128).padder()
    padded_data = padding_scheme.update(data.encode('utf-8'))
    padded_data += padding_scheme.finalize()
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(initialization_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# Función para descifrar usando AES-CBC
def aes_cbc_decrypt(encrypted_data, secret_key, initialization_vector):
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(initialization_vector), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadding_scheme = padding.PKCS7(128).unpadder()
    decrypted_data = unpadding_scheme.update(decrypted_padded_data)
    decrypted_data += unpadding_scheme.finalize()

    return decrypted_data.decode('utf-8')

secret_key = b'SuperSecureEncryptionKey_AES256_'  # 32 bytes para AES-256
initialization_vector = b'IVForEncryption_'  # 16 bytes para el IV
message = "Texto cifrado"  # Texto para cifrar

# Cifrar el mensaje
encrypted_message = aes_cbc_encrypt(message, secret_key, initialization_vector)
print(f'Mensaje cifrado: {encrypted_message}')

# Descifrar el mensaje
decrypted_message = aes_cbc_decrypt(encrypted_message, secret_key, initialization_vector)
print(f'Mensaje descifrado: {decrypted_message}')
