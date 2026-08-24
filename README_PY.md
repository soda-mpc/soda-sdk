# Soda-sdk

This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalties used for working with sodalabs interface.

## Table of Contents

- [Available functionalitioes](#available-functionalities)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Running tests](#running-tests)


## Available functionalities

The SDK support provide the following functionalities:

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

        It encrypt the plaintext using the AES key to get the ciphertext, then sign the concatination of the addresses, hashed function signature and ciphertext using the ECDSA private key.
    * Get function signature

        This function get the function signature as a string and returned the keccak-256 value on the signature


### Prerequisites

Python should be installed on your system.

### Installation

```bash
pip install soda-sdk
```


### Usage

In order to use the functionalities of python SDK, first import the modules from 'crypto' file.
for example:

```bash 
from soda_python_sdk.crypto import prepare_IT, decrypt
```

Below is an example function from the python test file that demonstrate using some of the SDK functionality. Lets break it down:

```bash
from soda_python_sdk.crypto import prepare_IT, decrypt

block_size = 16

# Create inputs for prepare_IT
plaintext = 100                                               # plaintext
user_key = bytes.fromhex("b3c3fe73c1bb91862b166a29fe1d63e9")  # AES key from onboarding
sender = "0xd67fe7792f18fbd663e29818334a050240887c28"         # sender address

# prepare_IT returns the sender address and the ciphertext as an integer.
# No contract address, function signature or ECDSA key is involved.
sender, ct = prepare_IT(plaintext, user_key, sender)

# Decrypt the ciphertext with the same AES key and check it round-trips
ct_bytes = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')
# ct_bytes holds the encrypted data followed by the random r; decrypt takes them separately
decrypted = decrypt(user_key, ct_bytes[block_size:], ct_bytes[:block_size])
assert int.from_bytes(decrypted, 'big') == plaintext

# For 256-bit values use prepare_IT_256, which returns (sender, (ctHigh, ctLow))
```

This example uses the prepare_IT and decrypt functionalities of the python SDK.
More examples can be found in the test.py file.
