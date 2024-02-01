# main.py

import binascii
from crypto import encrypt
from crypto import decrypt
from crypto import generate_aes_key
from crypto import load_aes_key


def main():
    # Generate a key 
    key = generate_aes_key()
    print("key:", binascii.hexlify(key).decode())

    # Provide the plaintext integer
    plaintext_integer = 100  

    # Convert the integer to a byte slice
    plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'little')

    # Call the encrypt function from mpcHelper.py
    ciphertext, random_value_r = encrypt(key, plaintext_message)

    # Display results
    print("Plaintext:", plaintext_integer)
    print("Ciphertext:", binascii.hexlify(ciphertext).decode())
    print("Random value 'r':", binascii.hexlify(random_value_r).decode())

    # Call the decrypt function from mpcHelper.py
    decrypted_message = decrypt(key, random_value_r, ciphertext)
    print("Decrypted message:", int.from_bytes(decrypted_message, 'little'))

if __name__ == "__main__":
    main()
