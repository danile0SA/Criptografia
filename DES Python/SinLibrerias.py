import os

# Funciones auxiliares para operaciones de bytes
def xor_bytes(block1, block2):
    return bytes(a ^ b for a, b in zip(block1, block2))

# Función para agregar padding (PKCS7)
def pad(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

# Función para remover padding (PKCS7)
def unpad(padded_data):
    padding_len = padded_data[-1]
    return padded_data[:-padding_len]

# Cifrar un solo bloque con AES simple
def aes_encrypt_block(block, key):
    # Implementación simplificada de AES. Aquí debería ir el cifrado real de AES, pero se omite por brevedad.
    return block  # Este paso es donde el bloque se cifraría con la clave AES. Necesitarías implementar AES a mano o usar tablas S-box.

# Función para cifrar usando AES-CBC
def aes_cbc_encrypt(data, secret_key, initialization_vector, block_size=16):
    # Agregar padding al mensaje
    padded_data = pad(data.encode('utf-8'), block_size)
    
    blocks = [padded_data[i:i+block_size] for i in range(0, len(padded_data), block_size)]
    encrypted_blocks = []
    previous_block = initialization_vector

    for block in blocks:
        block_to_encrypt = xor_bytes(block, previous_block)
        encrypted_block = aes_encrypt_block(block_to_encrypt, secret_key)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return b''.join(encrypted_blocks)

# Función para descifrar usando AES-CBC
def aes_cbc_decrypt(encrypted_data, secret_key, initialization_vector, block_size=16):
    blocks = [encrypted_data[i:i+block_size] for i in range(0, len(encrypted_data), block_size)]
    decrypted_blocks = []
    previous_block = initialization_vector

    for block in blocks:
        decrypted_block = aes_encrypt_block(block, secret_key)  # Aquí se supone que es la inversa del AES (que no está implementado en este código)
        decrypted_block = xor_bytes(decrypted_block, previous_block)
        decrypted_blocks.append(decrypted_block)
        previous_block = block

    decrypted_padded_data = b''.join(decrypted_blocks)
    return unpad(decrypted_padded_data).decode('utf-8')

# Ejemplo de uso
secret_key = b'SuperSecureEncryptionKey_'  # 32 bytes para AES-256
initialization_vector = b'IVForEncryption_'  # 16 bytes para el IV
message = "Texto cifrado"

# Cifrar el mensaje
encrypted_message = aes_cbc_encrypt(message, secret_key, initialization_vector)
print(f'Mensaje cifrado: {encrypted_message}')

# Descifrar el mensaje
decrypted_message = aes_cbc_decrypt(encrypted_message, secret_key, initialization_vector)
print(f'Mensaje descifrado: {decrypted_message}')
