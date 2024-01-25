# main.py

import binascii
from mpcHelper import encrypt
from mpcHelper import decrypt
from mpcHelper import generate_and_write_aes_key
from mpcHelper import load_aes_key


def main():
    # Load or generate a key (replace this with your actual key-loading logic)
    key = generate_and_write_aes_key("key.txt")
    print("key:", binascii.hexlify(key).decode())

    # Provide the plaintext integer
    plaintext_integer = 100  

    # Convert the integer to a byte slice
    plaintext_message = plaintext_integer.to_bytes((plaintext_integer.bit_length() + 7) // 8, 'big')

    print("plaintext size = ", len(plaintext_message))

    # Call the encrypt function from mpcHelper.py
    ciphertext, random_value_r = encrypt(key, plaintext_message)

    print("r size = ", len(random_value_r))
    print("ciphertext size = ", len(ciphertext))

    # Display results
    print("Plaintext:", plaintext_message.decode())
    print("Ciphertext:", binascii.hexlify(ciphertext).decode())
    print("Random value 'r':", binascii.hexlify(random_value_r).decode())

    # Load key from file
    loaded_key = load_aes_key("key.txt")
    print("loaded_key:", binascii.hexlify(loaded_key).decode())

    # Call the decrypt function from mpcHelper.py
    decrypted_message = decrypt(loaded_key, random_value_r, ciphertext)
    print("decrypted_message size = ", len(decrypted_message))

    print("Decrypted message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
