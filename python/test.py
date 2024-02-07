import unittest
import tempfile
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crypto import encrypt, decrypt, load_aes_key, write_aes_key, generate_aes_key, sign, generate_rsa_keypair, encrypt_rsa, decrypt_rsa
from crypto import block_size, address_size, signature_size, nonce_size, key_size
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_utils.crypto import keccak
from eth_keys.backends import NativeECCBackend

class TestMpcHelper(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for key files
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        # Clean up the temporary directory
        self.temp_dir.cleanup()

    def test_encrypt_decrypt(self):
        # Generate a key
        key = generate_aes_key()

        # Provide plaintext integer
        plaintext_integer = 100
        
        # Convert the integer to a byte slice with size aligned to 8.
        plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'little')

        # Call the encrypt function
        ciphertext, r = encrypt(key, plaintext_message)

        # Call the decrypt function
        decrypted_message = decrypt(key, r, ciphertext)

        decrypted_integer = int.from_bytes(decrypted_message, 'little')

        # Ensure the decrypted message is equal to the original plaintext
        self.assertEqual(plaintext_integer, decrypted_integer)

    def test_load_write_aes_key(self):
        # Generate a key
        key = generate_aes_key()
        
        # Create the file path for the key
        key_file_path = os.path.join(self.temp_dir.name, "key.txt")
        write_aes_key(key_file_path, key)

        # Load the key from the file
        loaded_key = load_aes_key(key_file_path)

        # Ensure the loaded key is equal to the original key
        self.assertEqual(loaded_key, key)

        # Remove the key file
        os.remove(key_file_path)

    def test_invalid_plaintext_size(self):
        # Generate a key
        key = generate_aes_key()

        # Invalid plaintext size (more than block_size)
        invalid_plaintext = bytes(block_size + 1)

        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            encrypt(key, invalid_plaintext)

    def test_invalid_ciphertext_size(self):
        # Generate a key
        key = generate_aes_key()

        # Invalid ciphertext size (less than block_size)
        invalid_ciphertext = b'\x01\x02\x03'

        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            decrypt(key, get_random_bytes(block_size), invalid_ciphertext)

    def test_invalid_random_size(self):
        # Generate a key
        key = generate_aes_key()

        # Invalid ciphertext size (less than block_size)
        invalid_random = b'\x01\x02\x03'

        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            decrypt(key, invalid_random, get_random_bytes(block_size))

    def test_invalid_key_length(self):
        # Invalid key length (less than block_size)
        invalid_key = get_random_bytes(3)

        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            write_aes_key(os.path.join(self.temp_dir.name, "/invalid_key.txt"), invalid_key)

        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            encrypt(invalid_key, get_random_bytes(3))
        
        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            decrypt(invalid_key, get_random_bytes(3), get_random_bytes(3))

    def test_signature(self):
        sender = os.urandom(address_size)
        addr = os.urandom(address_size)
        func_sig = os.urandom(signature_size)
        nonce = os.urandom(nonce_size)

        key = os.urandom(key_size)

        # Create plaintext with the value 100 as a big integer with less than 128 bits
        plaintext_integer = 100
        # Convert the integer to a byte slice with size aligned to 8.
        plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'little')
        # Call the encrypt function
        ciphertext, r = encrypt(generate_aes_key(), plaintext_message)
        ct = ciphertext + r

        sender = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        addr = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        func_sig = bytes.fromhex("00000000")
        nonce = bytes.fromhex("0000000000000000")
        ct = bytes.fromhex("1d87ced4fd3f916ea7474dfe320a5de096a89dcf3d8a6d9dd318e38ea9f23189")
        key = bytes.fromhex("f14edf53952e2886057b3afdd23a24b63a577ebe474880f76d86aa7ca11da370")

        # Call the sign function
        signature = sign(sender, addr, func_sig, nonce, ct, key)
        print("Signature:", signature)
        
        # Create the message to be 
        message = sender + addr + func_sig + nonce + ct

        pk = keys.PrivateKey(key)
        # Verify the signature against the message hash and the public key
        verified = signature.verify_msg(message, pk.public_key)
       
        self.assertEqual(verified, True)
    
    def test_rsa_encryption(self):
        plaintext = b"hello world"
        private_key, public_key = generate_rsa_keypair()
        ciphertext = encrypt_rsa(public_key, plaintext)
        decrypted = decrypt_rsa(private_key, ciphertext)
        self.assertEqual(plaintext, decrypted)

if __name__ == '__main__':
    unittest.main()