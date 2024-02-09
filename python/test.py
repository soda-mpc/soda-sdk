import unittest
import tempfile
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crypto import encrypt, decrypt, load_aes_key, write_aes_key, generate_aes_key, sign, generate_rsa_keypair, encrypt_rsa, decrypt_rsa
from crypto import block_size, address_size, signature_size, nonce_size, key_size
from eth_keys import keys
import sys

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

        # Call the sign function
        signature_bytes = sign(sender, addr, func_sig, nonce, ct, key)
        
        # Create the message to be 
        message = sender + addr + func_sig + nonce + ct

        pk = keys.PrivateKey(key)
        signature = keys.Signature(signature_bytes)
        # Verify the signature against the message hash and the public key
        verified = signature.verify_msg(message, pk.public_key)
       
        self.assertEqual(verified, True)

    def test_fixedMSG_Signature(self):
        sender = bytes.fromhex("ee706584bf9a9414997840785b14d157bf315abab2745f60ebe2ba4d9971718181dcdf99154cdfed368256fe1f0fb4bd952296377b70f19817a0511d5a45a28e69a2c0f6cf28e4e7d52f6d966081579d115a22173b91efe5411622df117324d0b23bb13f5dd5f95d72a32aeb559f859179ffa2c84db6a4315af1aab83b03a2b02e7dd9501dd68e7529c9cc8a7140d011b2bf9845a5325a8e2703cae75713a871")
        addr = bytes.fromhex("f2c401492410f9f8842a1b028a88c057f92539c14ca814dc67baad26884b65b3d8491accac662aee08353aed84e00bb856d12e6d816072be64cb87379347ab921e9772b31d47ee70c0bac432366bd669f58a8791a945ddee9a8f2b5d8b8c2a3b891b81d294ddf91bd9176875ce83887dedd6a62e70500bd9017d74dca4f2e284c69cd46ec889ffb9196dbd250e7e0183a2a1502d086baa8e4de2f6c8715cdf3c")
        func_sig = bytes.fromhex("eb7dcb05")
        nonce = bytes.fromhex("0cdab3e6457ec793")
        ct = bytes.fromhex("195c6bbabb9483f5f6d0b95fa5486ebe1ad365fa21bf55f7158b87d560212207")
        key = bytes.fromhex("e96d2e93781c3ee08d98d650c4a9888cc272675dddde76fdedc699871765d7a1")

        # Call the sign function
        signature_bytes = sign(sender, addr, func_sig, nonce, ct, key)
        # Write hexadecimal string to a file
        with open("pythonSignature.txt", "w") as f:
            f.write(signature_bytes.hex())
        
        # Create the message to be 
        message = sender + addr + func_sig + nonce + ct

        pk = keys.PrivateKey(key)
        signature = keys.Signature(signature_bytes)
        # Verify the signature against the message hash and the public key
        verified = signature.verify_msg(message, pk.public_key)
       
        self.assertEqual(verified, True)
    
    def test_rsa_encryption(self):
        plaintext = b"hello world"
        private_key, public_key = generate_rsa_keypair()
        ciphertext = encrypt_rsa(public_key, plaintext)

        with open("pythonRSAEncryption.txt", "w") as f:
            f.write(private_key.hex())
            f.write("\n")
            f.write(public_key.hex())

        decrypted = decrypt_rsa(private_key, ciphertext)
        self.assertEqual(plaintext, decrypted)

class TestDecrypt(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for key files
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        # Clean up the temporary directory
        self.temp_dir.cleanup()
        

    def readEncFromFileAndCheck(self, file_path):
        plaintext = b"hello world"
        private_key_hex = ""
        public_key_hex = ""
        cipher_hex = ""

        with open(file_path, "r") as file:
            private_key_hex = file.readline().strip()  # Read the first line containing hexadecimal data
            public_key_hex = file.readline().strip()  # Read the first line containing hexadecimal data
            cipher_hex = file.readline().strip()  # Read the second line containing hexadecimal data

        private_key = bytes.fromhex(private_key_hex)  # Convert the first hexadecimal string to bytes
        public_key = bytes.fromhex(public_key_hex)  # Convert the first hexadecimal string to bytes
        ciphertext = bytes.fromhex(cipher_hex)  # Convert the second hexadecimal string to bytes
        
        decrypted = decrypt_rsa(private_key, ciphertext)
        self.assertEqual(plaintext, decrypted)

        os.remove(file_path)

    def test_rsa_decryption(self):
        self.readEncFromFileAndCheck("pythonRSAEncryption.txt")
        self.readEncFromFileAndCheck("../golang_cli/crypto/goRSAEncryption.txt")


if __name__ == '__main__':
    unittest.main()