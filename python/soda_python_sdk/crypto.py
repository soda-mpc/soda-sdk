from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import keccak
import os
import binascii
import struct
from eth_keys import keys
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from eth_account import Account
from eth_account.messages import encode_defunct

BLOCK_SIZE = AES.block_size
ADDRESS_SIZE = 20
FUNC_SIG_SIZE = 4
CT_SIZE = 32
KEY_SIZE = 32
MAX_PLAINTEXT_BIT_SIZE = 256

def encrypt(key, plaintext):

    # Ensure plaintext is smaller than 128 bits (16 bytes)
    if len(plaintext) > BLOCK_SIZE:
        raise ValueError("Plaintext size must be 128 bits or smaller.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != BLOCK_SIZE:
        raise ValueError("Key size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Generate a random value 'r' of the same length as the block size
    r = get_random_bytes(BLOCK_SIZE)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # Pad the plaintext with zeros if it's smaller than the block size
    plaintext_padded = bytes(BLOCK_SIZE - len(plaintext)) + plaintext

    # XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    ciphertext = bytes(x ^ y for x, y in zip(encrypted_r, plaintext_padded))

    return ciphertext, r

def decrypt(key, r, ciphertext, r2=None, ciphertext2=None):

    if len(ciphertext) != BLOCK_SIZE:
        raise ValueError("Ciphertext size must be 128 bits.")

    # Ensure key size is 128 bits (16 bytes)
    if len(key) != BLOCK_SIZE:
        raise ValueError("Key size must be 128 bits.")

    # Ensure random size is 128 bits (16 bytes)
    if len(r) != BLOCK_SIZE:
        raise ValueError("Random size must be 128 bits.")

    # If r2 is not None, then ciphertext2 is required and vice versa
    # Ensure the sizes of r2 and ciphertext2 are correct
    if r2 is not None:
        if len(r2) != BLOCK_SIZE:
            raise ValueError("Random size must be 128 bits.")
        if ciphertext2 is None:
            raise ValueError("Ciphertext2 is required.")

    if ciphertext2 is not None:
        if len(ciphertext2) != BLOCK_SIZE:
            raise ValueError("Ciphertext size must be 128 bits.")
        
        if r2 is None:
            raise ValueError("Random2 is required.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    plaintext = bytes(x ^ y for x, y in zip(encrypted_r, ciphertext))

    if r2 is not None and ciphertext2 is not None:
        # Encrypt the random value 'r2' using AES in ECB mode
        encrypted_r2 = cipher.encrypt(r2)

        # XOR the encrypted random value 'r2' with the ciphertext2 to obtain the plaintext2
        plaintext2 = bytes(x ^ y for x, y in zip(encrypted_r2, ciphertext2))

        plaintext = plaintext + plaintext2

    return plaintext

def load_aes_key(file_path):
    # Read the hex-encoded contents of the file
    with open(file_path, 'r') as file:
        hex_key = file.read().strip()

    # Decode the hex string to binary
    key = binascii.unhexlify(hex_key)

    # Ensure the key is the correct length
    if len(key) != BLOCK_SIZE:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {BLOCK_SIZE} bytes")

    return key

def write_aes_key(file_path, key):
    # Ensure the key is the correct length
    if len(key) != BLOCK_SIZE:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {BLOCK_SIZE} bytes")

    # Encode the key to hex string
    hex_key = binascii.hexlify(key).decode()

    # Write the hex-encoded key to the file
    with open(file_path, 'w') as file:
        file.write(hex_key)

def generate_aes_key():
    # Generate a random 128-bit AES key
    key = get_random_bytes(BLOCK_SIZE)

    return key

def generate_ECDSA_private_key():

    # Generate a new ECDSA private key
    private_key = ECC.generate(curve='P-256')


    # Get the raw bytes of the private key
    return private_key.d.to_bytes(private_key.d.size_in_bytes(), byteorder='big')


def validate_input_lengths(sender, addr, func_sig, ct, key):
    """Validate the lengths of inputs."""
    if len(sender) != ADDRESS_SIZE:
        raise ValueError(f"Invalid sender address length: {len(sender)} bytes, must be {ADDRESS_SIZE} bytes")
    if len(addr) != ADDRESS_SIZE:
        raise ValueError(f"Invalid contract address length: {len(addr)} bytes, must be {ADDRESS_SIZE} bytes")
    if len(func_sig) != FUNC_SIG_SIZE:
        raise ValueError(f"Invalid signature size: {len(func_sig)} bytes, must be {FUNC_SIG_SIZE} bytes")
    if len(ct) != CT_SIZE and len(ct) != 2*CT_SIZE:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be {CT_SIZE} bytes in case of 128 bits plaintext or less, or {2*CT_SIZE} bytes in case of plaintext between 128 and 256")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {KEY_SIZE} bytes")


def signIT(sender, addr, func_sig, ct, key, eip191=False):
    """Sign the message using either standard signing or EIP-191 signing."""
    # Validate input lengths
    validate_input_lengths(sender, addr, func_sig, ct, key)

    # Create the message to be signed by appending all inputs
    message = sender + addr + func_sig + ct

    # Sign the message
    if eip191:
        return sign_eip191(message, key)
    else:
        return sign(message, key)


def sign(message, key):
    # Sign the message
    pk = keys.PrivateKey(key)
    signature = pk.sign_msg(message).to_bytes()
    return signature


def sign_eip191(message, key):
    signed_message = Account.sign_message(encode_defunct(primitive=message), key)
    return signed_message.signature

def prepare_IT(plaintext, user_aes_key, sender, contract, func_sig, signing_key, eip191=False):
    if (plaintext.bit_length() > MAX_PLAINTEXT_BIT_SIZE/2):
        raise ValueError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepare_IT_256 instead.")

    # Create the function signature
    func_hash = get_func_sig(func_sig)

    return inner_prepare_IT(plaintext, user_aes_key, sender, contract, func_hash, signing_key, eip191, False)

def prepare_IT_256(plaintext, user_aes_key, sender, contract, func_sig, signing_key, eip191=False):

    if (plaintext.bit_length() > MAX_PLAINTEXT_BIT_SIZE):
        raise ValueError("Plaintext size must be 256 bits or smaller.")

    # Create the function signature
    func_hash = get_func_sig(func_sig)

    ct, signature =  inner_prepare_IT(plaintext, user_aes_key, sender, contract, func_hash, signing_key, eip191, True)

    # Convert integer back to bytes to check length
    ct_bytes = ct.to_bytes(CT_SIZE * 2, 'big')
    ctHigh = ct_bytes[:CT_SIZE]
    ctLow = ct_bytes[CT_SIZE:]
    # Convert the ct into two integers
    ctIntHigh = int.from_bytes(ctHigh, byteorder='big')
    ctIntLow = int.from_bytes(ctLow, byteorder='big')
    return ((ctIntHigh, ctIntLow), signature)

def inner_prepare_IT(plaintext, user_aes_key, sender, contract, func_sig_hash, signing_key, eip191, is256bit):
    # Get addresses as bytes
    sender_address_bytes = bytes.fromhex(sender.address[2:])
    contract_address_bytes = bytes.fromhex(contract.address[2:])

    # Convert the integer to a byte slice with size aligned to 8.
    plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')

    if len(plaintext_bytes) > BLOCK_SIZE*2:
        raise ValueError("Plaintext size must be 256 bits or smaller.")

    if len(plaintext_bytes) <= BLOCK_SIZE:
        # Encrypt the plaintext with the user's AES key
        ciphertext, r = encrypt(user_aes_key, plaintext_bytes)
        if (is256bit):
            zero = 0
            zero_bytes = zero.to_bytes((zero.bit_length() + 7) // 8, 'big')
            ciphertextHigh, rHigh = encrypt(user_aes_key, zero_bytes)
            ct = ciphertextHigh + rHigh + ciphertext + r
        else:
            ct = ciphertext + r
    else:
        padded_plaintext_bytes = bytes(BLOCK_SIZE*2 - len(plaintext_bytes)) + plaintext_bytes
        # Encrypt the plaintext with the user's AES key
        ciphertextHigh, rHigh = encrypt(user_aes_key, padded_plaintext_bytes[:BLOCK_SIZE])
        ciphertextLow, rLow = encrypt(user_aes_key, padded_plaintext_bytes[BLOCK_SIZE:])
        ct = ciphertextHigh + rHigh + ciphertextLow + rLow

    # Sign the message
    signature = signIT(sender_address_bytes, contract_address_bytes, func_sig_hash, ct, signing_key, eip191)

    # Convert the ct to an integer
    ctInt = int.from_bytes(ct, byteorder='big')

    return ctInt, signature


def generate_rsa_keypair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Get public key
    public_key = private_key.public_key()
    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes

def encrypt_rsa(public_key_bytes, plaintext):
    # Load public key
    public_key = serialization.load_der_public_key(public_key_bytes)
    # Encrypt plaintext
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key_bytes, ciphertext):
    # Load private key
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    # Decrypt ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def recover_user_key(private_key_bytes, encrypted_key_share0, encrypted_key_share1):
    """
    This function recovers a user's key by decrypting two encrypted key shares with the given private key,
    and then XORing the two key shares together.

    Args:
        private_key_bytes (bytes): The private key used to decrypt the key shares.
        encrypted_key_share0 (bytes): The first encrypted key share.
        encrypted_key_share1 (bytes): The second encrypted key share.

    Returns:
        bytes: The recovered user key.
    """
    key_share0 = decrypt_rsa(private_key_bytes, encrypted_key_share0)
    key_share1 = decrypt_rsa(private_key_bytes, encrypted_key_share1)

    # XOR both key shares to get the user key
    return bytes([a ^ b for a, b in zip(key_share0, key_share1)])

# Function to compute Keccak-256 hash
def keccak256(data):
    # Create Keccak-256 hash object
    hash_obj = keccak.new(digest_bits=256)

    # Update hash object with data
    hash_obj.update(data)

    # Compute hash and return
    return hash_obj.digest()


def get_func_sig(functionSig):
    # Convert function signature to bytes
    functionSigBytes = functionSig.encode('utf-8')

    # Compute Keccak-256 hash on the function signature
    hash = keccak256(functionSigBytes)

    # Take first 4 bytes of the hash 
    return hash[:4]



