import unittest
import tempfile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crypto import encrypt, decrypt, load_aes_key, write_aes_key, generate_and_write_aes_key

class TestMpcHelper(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for key files
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        # Clean up the temporary directory
        self.temp_dir.cleanup()

    def test_encrypt_decrypt(self):
        # Generate a key
        key = generate_and_write_aes_key(self.temp_dir.name + "/key.txt")

        # Provide plaintext integer
        plaintext_integer = 100
        
        # Convert the integer to a byte slice
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
        key = generate_and_write_aes_key(self.temp_dir.name + "/key.txt")

        # Load the key from the file
        loaded_key = load_aes_key(self.temp_dir.name + "/key.txt")

        # Ensure the loaded key is equal to the original key
        self.assertEqual(loaded_key, key)

    def test_invalid_plaintext_size(self):
        # Generate a key
        key = generate_and_write_aes_key(self.temp_dir.name + "/key.txt")

        # Invalid ciphertext size (less than block_size)
        invalid_plaintext = bytes(AES.block_size + 1)

        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            encrypt(key, invalid_plaintext)

    def test_invalid_ciphertext_size(self):
        # Generate a key
        key = generate_and_write_aes_key(self.temp_dir.name + "/key.txt")

        # Invalid ciphertext size (less than block_size)
        invalid_ciphertext = b'\x01\x02\x03'

        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            decrypt(key, get_random_bytes(AES.block_size), invalid_ciphertext)

    def test_invalid_random_size(self):
        # Generate a key
        key = generate_and_write_aes_key(self.temp_dir.name + "/key.txt")

        # Invalid ciphertext size (less than block_size)
        invalid_random = b'\x01\x02\x03'

        # Expect an error to be thrown when decrypting
        with self.assertRaises(ValueError):
            decrypt(key, invalid_random, get_random_bytes(AES.block_size))

    def test_invalid_key_length(self):
        # Invalid key length (less than block_size)
        invalid_key = get_random_bytes(3)

        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            write_aes_key(self.temp_dir.name + "/invalid_key.txt", invalid_key)

        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            encrypt(invalid_key, get_random_bytes(3))
        
        # Expect an error to be thrown when writing the key
        with self.assertRaises(ValueError):
            decrypt(invalid_key, get_random_bytes(3), get_random_bytes(3))

        

if __name__ == '__main__':
    unittest.main()