import struct
from PIL import Image
import numpy as np

# TEA encryption and decryption functions
def tea_encrypt_block(v, k):
    v0, v1 = v
    delta = 0x9E3779B9
    sum = 0

    for _ in range(32):
        sum = (sum + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF

    return v0, v1


def tea_decrypt_block(v, k):
    v0, v1 = v
    delta = 0x9E3779B9
    sum = (delta << 5) & 0xFFFFFFFF

    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF

    return v0, v1


def bytes_to_blocks(data):
    return [struct.unpack('>2I', data[i:i + 8]) for i in range(0, len(data), 8)]

def blocks_to_bytes(blocks):
    return b''.join([struct.pack('>2I', *block) for block in blocks])

def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Ensure the key is correctly unpacked into 32-bit integers
def prepare_key(key):
    return struct.unpack('>4I', key)

# ECB mode implementation
def tea_ecb_encrypt(data, key):
    key = prepare_key(key)
    data = pad(data)
    blocks = bytes_to_blocks(data)
    encrypted_blocks = []

    for block in blocks:
        encrypted_blocks.append(tea_encrypt_block(block, key))

    return blocks_to_bytes(encrypted_blocks)

def tea_ecb_decrypt(data, key):
    key = prepare_key(key)
    blocks = bytes_to_blocks(data)
    decrypted_blocks = []

    for block in blocks:
        decrypted_blocks.append(tea_decrypt_block(block, key))

    return blocks_to_bytes(decrypted_blocks)

# CBC mode implementation
def tea_cbc_encrypt(data, key, iv):
    key = prepare_key(key)
    iv = bytes(iv)
    data = pad(data)
    blocks = bytes_to_blocks(data)
    encrypted_blocks = []
    prev_block = iv
    for block in blocks:
        block = (block[0] ^ prev_block[0], block[1] ^ prev_block[1])
        encrypted_block = tea_encrypt_block(block, key)
        encrypted_blocks.append(encrypted_block)
        prev_block = encrypted_block

    return blocks_to_bytes(encrypted_blocks)
def tea_cbc_decrypt(data, key, iv):
    key = prepare_key(key)
    iv = bytes(iv)
    blocks = bytes_to_blocks(data)
    decrypted_blocks = []
    prev_block = iv
    for block in blocks:
        decrypted_block = tea_decrypt_block(block, key)
        decrypted_block = (decrypted_block[0] ^ prev_block[0], decrypted_block[1] ^ prev_block[1])
        decrypted_blocks.append(decrypted_block)
        prev_block = block
    decrypted_data = blocks_to_bytes(decrypted_blocks)
    return decrypted_data

# Read image file and convert to bytes
def read_image(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

# Write bytes to image file
def write_image(file_path, data):
    with open(file_path, 'wb') as f:
        f.write(data)



# Encrypt/Decrypt image file
def process_image(input_path, output_path, key, iv=None, mode='ECB', operation='encrypt'):
    # Read image data
    with Image.open(input_path) as img:
        img_data = img.tobytes()
        img_header = img.info

    # Process image data
    if operation == 'encrypt':
        if mode == 'ECB':
            processed_data = tea_ecb_encrypt(img_data, key)
        elif mode == 'CBC':
            processed_data = tea_cbc_encrypt(img_data, key, iv)
    elif operation == 'decrypt':
        if mode == 'ECB':
            processed_data = tea_ecb_decrypt(img_data, key)
        elif mode == 'CBC':
            processed_data = tea_cbc_decrypt(img_data, key, iv)

    # Create a new image with the processed data
    img_processed = Image.frombytes(img.mode, img.size, processed_data)
    img_processed.save(output_path, **img_header)


# Example Key and IV
key_str = input("Enter the key : ").encode()
iv_str = input("Enter the IV :  ").encode()
input_image_path =  input("Enter the path of input image : ")

key = bytes(key_str)
iv = bytes(iv_str)

# Encrypt and decrypt image in ECB mode
output_image_path_ecb_encrypted = 'output_image_ecb_encrypted.png'
output_image_path_ecb_decrypted = 'output_image_ecb_decrypted.png'

print("\nProcessing TEA-ECB Mode")
process_image(input_image_path, output_image_path_ecb_encrypted, key, mode='ECB', operation='encrypt')
process_image(output_image_path_ecb_encrypted, output_image_path_ecb_decrypted, key, mode='ECB', operation='decrypt')

# Encrypt and decrypt image in CBC mode
output_image_path_cbc_encrypted = 'output_image_cbc_encrypted.png'
output_image_path_cbc_decrypted = 'output_image_cbc_decrypted.png'

print("\nProcessing TEA-CBC Mode")
process_image(input_image_path, output_image_path_cbc_encrypted, key, iv, mode='CBC', operation='encrypt')
process_image(output_image_path_cbc_encrypted, output_image_path_cbc_decrypted, key, iv, mode='CBC', operation='decrypt')
