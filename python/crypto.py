from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import binascii

block_size = AES.block_size

def encrypt(key, plaintext):
    
    # Ensure plaintext is smaller than 128 bits (16 bytes)
    if len(plaintext) > block_size:
        raise ValueError("Plaintext size must be 128 bits or smaller.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Generate a random value 'r' of the same length as the block size
    r = get_random_bytes(block_size)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)
    
    # Pad the plaintext with zeros if it's smaller than the block size
    plaintext_padded = plaintext + bytes(block_size - len(plaintext))

    # XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    ciphertext = bytes(x ^ y for x, y in zip(encrypted_r, plaintext_padded))

    return ciphertext, r

def decrypt(key, r, ciphertext):
    
    if len(ciphertext) != block_size:
        raise ValueError("Ciphertext size must be 128 bits.")
    
    # Ensure key size is 128 bits (16 bytes)
    if len(key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Ensure random size is 128 bits (16 bytes)
    if len(r) != block_size:
        raise ValueError("Random size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    plaintext = bytes(x ^ y for x, y in zip(encrypted_r, ciphertext))

    return plaintext

def load_aes_key(file_path):
    # Read the hex-encoded contents of the file
    with open(file_path, 'r') as file:
        hex_key = file.read().strip()

    # Decode the hex string to binary
    key = binascii.unhexlify(hex_key)

    # Ensure the key is the correct length
    if len(key) != block_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {block_size} bytes")

    return key

def write_aes_key(file_path, key):
    # Ensure the key is the correct length
    if len(key) != block_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {block_size} bytes")

    # Encode the key to hex string
    hex_key = binascii.hexlify(key).decode()

    # Write the hex-encoded key to the file
    with open(file_path, 'w') as file:
        file.write(hex_key)

def generate_aes_key():
    # Generate a random 128-bit AES key
    key = get_random_bytes(block_size)

    return key
