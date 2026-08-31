from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import keccak
import binascii
from eth_keys import keys
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from web3 import Web3

BLOCK_SIZE = AES.block_size
ADDRESS_SIZE = 20
FUNC_SIG_SIZE = 4
CT_SIZE = 32
KEY_SIZE = 32
MAX_PLAINTEXT_BIT_SIZE = 256
SIGNATURE_SIZE = 65
EC_PUBLIC_KEY_SIZE = 65
BYTES32_SIZE = 32  # size of an EIP-712 bytes32 element (e.g. an encrypt-to-user handle)
EIP712_DOMAIN_NAME = "SodaLabs MPC"
EIP712_DOMAIN_VERSION = "1"

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


def validate_input_lengths(sender, addr, ct, key):
    """Validate the lengths of inputs."""
    if len(sender) != ADDRESS_SIZE:
        raise ValueError(f"Invalid sender address length: {len(sender)} bytes, must be {ADDRESS_SIZE} bytes")
    if len(addr) != ADDRESS_SIZE:
        raise ValueError(f"Invalid contract address length: {len(addr)} bytes, must be {ADDRESS_SIZE} bytes")
    if len(ct) != CT_SIZE and len(ct) != 2*CT_SIZE:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be {CT_SIZE} bytes in case of 128 bits plaintext or less, or {2*CT_SIZE} bytes in case of 256 bits plaintext or less")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {KEY_SIZE} bytes")


def signIT(sender, addr, ct, key, eip191=False):
    """Sign the message using either standard signing or EIP-191 signing."""
    # Validate input lengths
    validate_input_lengths(sender, addr, ct, key)

    # Create the message to be signed by appending all inputs
    message = sender + addr + ct

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


def _eip712_domain(chain_id):
    return {
        "name": EIP712_DOMAIN_NAME,
        "version": EIP712_DOMAIN_VERSION,
        "chainId": chain_id,
    }


def _eip712_domain_types():
    return {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
    }


def build_onboard_user_typed_data(rsa_public_key, address, chain_id=0):
    """Build EIP-712 typed data for user onboarding.

    chain_id defaults to 0 on purpose: onboarding is a bubble-level identity
    operation with no chain in the middle. The signature is verified off-chain
    by bubble (not by a per-chain on-chain verifier), and the onboarded identity
    is reused across every chain, so there is no chain to bind it to. Contrast
    with build_encrypt_to_user_typed_data, where the handle belongs to a
    specific chain and chain_id is therefore required.
    """
    address = Web3.to_checksum_address(address)
    if isinstance(rsa_public_key, (bytes, bytearray)):
        rsa_public_key = "0x" + bytes(rsa_public_key).hex()
    return {
        "types": {
            **_eip712_domain_types(),
            "OnboardUser": [
                {"name": "rsaPublicKey", "type": "bytes"},
                {"name": "address", "type": "address"},
            ],
        },
        "primaryType": "OnboardUser",
        "domain": _eip712_domain(chain_id),
        "message": {
            "rsaPublicKey": rsa_public_key,
            "address": address,
        },
    }


def build_encrypt_to_user_typed_data(handles, owner, chain_id):
    """Build EIP-712 typed data for encrypt-to-user requests."""
    if not owner:
        owner = "0x" + "0" * (ADDRESS_SIZE * 2)
    else:
        owner = Web3.to_checksum_address(owner)

    handle_values = []
    for i, handle in enumerate(handles):
        if isinstance(handle, int):
            if not 0 <= handle < 2 ** (BYTES32_SIZE * 8):
                raise ValueError(f"handles[{i}] does not fit in bytes32 (must be 0 <= x < 2**{BYTES32_SIZE * 8})")
            handle = handle.to_bytes(BYTES32_SIZE, byteorder="big")
        if not isinstance(handle, (bytes, bytearray)) or len(handle) != BYTES32_SIZE:
            got = f"{len(handle)} bytes" if isinstance(handle, (bytes, bytearray)) else type(handle).__name__
            raise ValueError(f"handles[{i}] must be exactly {BYTES32_SIZE} bytes (bytes32), got {got}")
        handle_values.append("0x" + bytes(handle).hex())

    return {
        "types": {
            **_eip712_domain_types(),
            "EncryptToUser": [
                {"name": "handles", "type": "bytes32[]"},
                {"name": "owner", "type": "address"},
            ],
        },
        "primaryType": "EncryptToUser",
        "domain": _eip712_domain(chain_id),
        "message": {
            "handles": handle_values,
            "owner": owner,
        },
    }


def sign_eip712(typed_data, key):
    """Sign EIP-712 typed data with the given private key."""
    signed_message = Account.sign_typed_data(private_key=key, full_message=typed_data)
    return signed_message.signature


def recover_address_from_eip712_signature(typed_data, signature):
    """Recover the signer address from an EIP-712 signature."""
    signable_message = encode_typed_data(full_message=typed_data)
    return Account.recover_message(signable_message, signature=signature)


def prepare_IT(plaintext, user_aes_key, sender):

    if (plaintext.bit_length() > MAX_PLAINTEXT_BIT_SIZE/2):
        raise ValueError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepare_IT_256 instead.")

    return inner_prepare_IT(plaintext, user_aes_key, sender, False)

def prepare_IT_256(plaintext, user_aes_key, sender):

    if (plaintext.bit_length() > MAX_PLAINTEXT_BIT_SIZE):
        raise ValueError("Plaintext size must be 256 bits or smaller.")

    # Create the function signature
    sender, ct =  inner_prepare_IT(plaintext, user_aes_key, sender, True)

    # Convert integer back to bytes to check length
    ct_bytes = ct.to_bytes(CT_SIZE * 2, 'big')
    ctHigh = ct_bytes[:CT_SIZE]
    ctLow = ct_bytes[CT_SIZE:]
    # Convert the ct into two integers
    ctIntHigh = int.from_bytes(ctHigh, byteorder='big')
    ctIntLow = int.from_bytes(ctLow, byteorder='big')
    return (sender, (ctIntHigh, ctIntLow))

def inner_prepare_IT(plaintext, user_aes_key, sender, is256bit):
    
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

    
    # Convert the ct to an integer
    ctInt = int.from_bytes(ct, byteorder='big')

    return sender, ctInt

def verify_signatures(message, signatures, signers, N=1, T=1):
    """Verify that at least T of the N evaluators signed the message.

    Each evaluator is run by two parties - an operator (external) instance and a Soda (internal) one - and
    each signs with its own key. An evaluator has attested a result only once both of its instances have
    signed it, so `signers` holds two addresses per evaluator: every operator instance first, then every Soda
    instance, so the final N entries are Soda's, one per evaluator, and within either block entry i belongs to
    evaluator i % N.

    That ordering is what says which evaluator a recovered signer belongs to, so a differently ordered list
    does not fail - it attributes signatures to the wrong evaluators. get_signers_addresses returns them in
    this order.

    It counts evaluators rather than signatures, which is the whole point: five signatures from five
    different evaluators' operators plus one Soda signature is six valid signatures and not one evaluator
    that attested the result in full, so a signature count would accept a result no evaluator stands behind.

    It mirrors _verifySignaturesDigest in GCDecryptionVerifier.sol, the normative statement of the rule.
    Where the two differ the contract is right: a result the chain accepts and this rejects, or the reverse,
    is a bug here.

    The defaults describe a single evaluator, which is what an unreplicated deployment has, and for which
    this reduces exactly to the previous rule - every signer must have signed.
    """

    if len(signers) == 0:
        raise ValueError("Signers must be non-empty")
    if N < 1 or len(signers) % N != 0:
        raise ValueError(f"{len(signers)} signers do not divide among {N} evaluator(s)")
    if T < 1 or T > N:
        raise ValueError(f"T must be in [1, {N}], got {T}")

    # Position by address, so a recovered signer says which evaluator it belongs to. Checksummed on both
    # sides, since a case difference would otherwise read as an unregistered signer.
    position_of = {Web3.to_checksum_address(signer): position for position, signer in enumerate(signers)}

    # The Soda instances are the last N entries, one per evaluator, so everything before them is an operator
    # instance.
    soda_offset = len(signers) - N
    # How many operator instances must sign before an evaluator has spoken. Written out rather than assumed
    # to be one, so a deployment running more instances per evaluator cannot quietly come to mean "any one
    # of them".
    operators_per_evaluator = len(signers) // N - 1

    # Counted rather than flagged: an evaluator with several operators has not spoken until all have.
    operators_signed = [0] * N
    soda_signed = [False] * N
    # Which positions have already been counted, so one instance signing twice adds nothing.
    position_seen = set()

    for signature in signatures:
        recovered_address = Web3.to_checksum_address(recover_address_from_signature(message, signature))

        position = position_of.get(recovered_address)
        if position is None:
            print(f"Recovered address {recovered_address} not in the list of signers")
            return False
        if position in position_seen:
            continue
        position_seen.add(position)

        if position < soda_offset:
            operators_signed[position % N] += 1
        else:
            soda_signed[position - soda_offset] = True

    # T evaluators must have had every operator sign, and at least one of those same evaluators must also
    # carry its Soda signature. Requiring that Soda signature to come from an evaluator already counted is
    # what ties the two sides together: otherwise the instance attesting the result could belong to an
    # evaluator none of the counted operators ever ran alongside.
    evaluators_heard_from = 0
    counted_evaluator_has_soda = False
    for evaluator in range(N):
        if operators_signed[evaluator] == operators_per_evaluator:
            evaluators_heard_from += 1
            if soda_signed[evaluator]:
                counted_evaluator_has_soda = True

    return evaluators_heard_from >= T and counted_evaluator_has_soda
    

def recover_address_from_signature(message, signature):
    """Recover the address from the signature."""

    if not isinstance(message, (bytes, bytearray)):  
        raise TypeError("message must be of type bytes or bytearray")  
    if len(message) == 0:  
        raise ValueError("message must be non-empty")  

    if not isinstance(signature, (bytes, bytearray)):  
        raise TypeError("signature must be of type bytes or bytearray")  
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"Invalid signature length: {len(signature)} bytes, must be {SIGNATURE_SIZE} bytes")

    # Hash the message
    message_hash = keccak256(message)
    
    # Use eth_keys to recover public key from raw hash (not EIP-191 formatted) and signature
    sig = keys.Signature(signature_bytes=signature)
    public_key = sig.recover_public_key_from_msg_hash(message_hash)
    
    # Get the address from the public key
    return public_key.to_address()

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



