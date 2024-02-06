from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import binascii
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_utils.crypto import keccak
from web3 import Web3


block_size = AES.block_size
address_size = 160
signature_size = 4
nonce_size = 8
ct_size = 32
key_size = 32

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

def sign(sender, addr, func_sig, nonce, ct, key):
    # Ensure all input sizes are the correct length
    if len(sender) != address_size:
        raise ValueError(f"Invalid sender address length: {len(sender)} bytes, must be {address_size} bytes")
    if len(addr) != address_size:
        raise ValueError(f"Invalid contract address length: {len(addr)} bytes, must be {address_size} bytes")
    if len(func_sig) != signature_size:
        raise ValueError(f"Invalid signature size: {len(func_sig)} bytes, must be {signature_size} bytes")
    if len(nonce) != nonce_size:
        raise ValueError(f"Invalid nonce length: {len(nonce)} bytes, must be {nonce_size} bytes")
    if len(ct) != ct_size:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be {ct_size} bytes")
    # Ensure the key is the correct length
    if len(key) != key_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {key_size} bytes")

    # Create the message to be signed by appending all inputs
    message = sender + addr + func_sig + nonce + ct

    # Hash the message using Keccak-256
    message_hash = keccak(message)
    print("Message hash:", message_hash.hex())
    # Convert the message to a signable message object
    signable_message = encode_defunct(message_hash)
    
    # Sign the message
    signature = Account.sign_message(signable_message, private_key=key)

    return signature
