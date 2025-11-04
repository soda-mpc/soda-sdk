# Soda-sdk

This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalities used for working with sodalabs interface.

## Table of Contents

- [Available functionalities](#available-functionalities)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Running tests](#running-tests)


## Available functionalities

The SDK supports the following functionalities:

* AES encryption scheme:

    * Generate AES key  
    * Write AES key
    * Load AES key
    * Encrypt
    * Decrypt

* RSA encryption scheme:

    * Generate RSA key pair
    * Encrypt
    * Decrypt

* ECDSA signature scheme:
    * Generate ECDSA private key
    * Sign

* Hash:
    * Keccak 256

* Functionalities related to sodalabs InputText: 
    * Sign InputText function

        This function gets:
        - sender address bytes
        - contract address bytes
        - hashed function signature bytes
        - ciphertext bytes
        - ECDSA private key bytes.

        It appends the addresses, signature and ciphertext and signs the appended string using the private key.

    * Verify IT (Available only in Golang)
        This function gets:
        - sender address bytes
        - contract address bytes
        - hashed function signature bytes
        - ciphertext bytes
        - signature

        It verify the signature against the received data

    * Prepare InputText function

        This function gets:
        - plaintext 
        - AES key 
        - sender address
        - contract address
        - function signature (as string in go and python case, or hashed in js case)
        - ECDSA private key.

        It encrypt the plaintext using the AES key to get the ciphertext, then sign the concatination of the addresses, hashed function signature and ciphertext using the ECDSA private key.
    * Get function signature

        This function get the function signature as a string and returned the keccak-256 value on the signature


### Prerequisites

Python should be installed on your system.

### Installation

```bash
pip install gcevm-sdk
```


### Usage

In order to use the functionalities of python SDK, first import the required modules. For example:

```python
from soda_python_sdk import prepare_IT, decrypt, get_func_sig, BLOCK_SIZE
from web3 import Account
from eth_keys import keys
```

Below is an example function that demonstrates using some of the SDK functionality. Let's break it down:

```python
def test_prepareIT(self):
    # Create inputs for prepare_IT function
    plaintext = 100                                                     # plaintext 
    userKey = bytes.fromhex("b3c3fe73c1bb91862b166a29fe1d63e9")         # AES key
    sender = Account()                                                  # Sender account
    sender.address = "0xd67fe7792f18fbd663e29818334a050240887c28"
    contract = Account()                                                # Contract account
    contract.address = "0x69413851f025306dbe12c48ff2225016fc5bbe1b"
    func_sig = "test(bytes)"                                            # function signature as string
    signingKey = bytes.fromhex("3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e")  # ECDSA private key

    # Call prepare_IT function with the plaintext, AES key, sender and contract accounts, function signature and ECDSA private key
    ct, signature = prepare_IT(plaintext, userKey, sender, contract, func_sig, signingKey)
    # prepare_IT returns the ciphertext and the signature

    # Verify the signature
    sender_address_bytes = bytes.fromhex(sender.address[2:])     # Get the bytes of the accounts addresses
    contract_address_bytes = bytes.fromhex(contract.address[2:])
    func_hash = get_func_sig(func_sig)                           # Create the function signature
    
    # Convert the integer to a byte slice with size aligned to 8
    ctBytes = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')
    
    # Create the signed message 
    message = sender_address_bytes + contract_address_bytes + func_hash + ctBytes
    pk = keys.PrivateKey(signingKey)
    signature_obj = keys.Signature(signature)
    # Verify the signature against the message hash and the public key
    verified = signature_obj.verify_msg(message, pk.public_key)
    self.assertEqual(verified, True)

    # Decrypt the ciphertext using the AES key and check the decrypted value against the original plaintext
    # ctBytes is divided into two components: random and encrypted data. The decrypt function processes each component separately. 
    decrypted = decrypt(userKey, ctBytes[BLOCK_SIZE:], ctBytes[:BLOCK_SIZE])
    decrypted_integer = int.from_bytes(decrypted, 'big')
    self.assertEqual(plaintext, decrypted_integer)
```

This example uses the prepare_IT and decrypt functionalities of the python SDK.
More examples can be found in the test.py file.
