# Tools

This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalties used for working with sodalabs interface.
The SDK provide the all functionalities in three common widely used languages - Golang, Python and JavaScript.

The SDK also provides a CLI in Golang that provides functionalities for AES encryption scheme.

## Table of Contents

- [Available functionalitioes](#available-functionalities)
- [Installation](#installation)
- [Golang](#golang)
    - [Prerequisites](#prerequisites)
    - [Compilation](#compilation)
    - [Usage](#usage)
- [Python](#python)
    - [Prerequisites](#prerequisites-1)
    - [Usage](#usage-1)
- [JavaScript](#javascript)
    - [Prerequisites](#prerequisites-2)
    - [Usage](#usage-2)
- [Running tests](#running-tests)
- [Golang CLI](#golang-cli-tool-for-a-random-aes-encryption-and-decryption)
    - [Usage](#usage-3)
    - [Options](#options)
    - [Examples](#examples)

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
        - contract address
        - function signature (as string in go and python case, or hashed in js case)
        - ECDSA private key.

        It encrypt the plaintext using the AES key to get the ciphertext, then sign the concatination of the addresses, hashed function signature and ciphertext using the ECDSA private key.
    * Get function signature

        This function get the function signature as a string and returned the keccak-256 value on the signature

## Installation

Clone the repository:

```bash
git clone https://github.com/soda-mpc/tools.git
```

## Golang 

### Prerequisites

    Go (Golang) installed on your system.

### Compilation

Navigate to the project directory:

```bash
cd tools/golang_cli
```

Build the project:

```bash
go build
```

### Usage

Below is an example function from the Golang test file that demonstrate the signature functionality. Lets break it down:

```bash
func TestSignature(t *testing.T) {
    # Create random values for the sender and contract addresses and function signature
	sender := make([]byte, AddressSize)
	_, err := rand.Read(sender)
	addr := make([]byte, AddressSize)
	_, err = rand.Read(addr)
	funcSig := make([]byte, FuncSigSize)
	_, err = rand.Read(funcSig)

    # Generate ECDSA private key
	key := GenerateECDSAPrivateKey()
	require.NoError(t, err, "Failed to generate random key")

	# Create plaintext with the value 100 
	plaintextValue := big.NewInt(100)
	plaintextBytes := plaintextValue.Bytes()
    # Encrypt the plaintext 
	ciphertext, r, err := Encrypt(key, plaintextBytes)
	require.NoError(t, err, "Encrypt should not return an error")

	ct := append(ciphertext, r...)

	# Sign the sender, contract, function signature and ct using the generated ECDSA private key
	signature, err := SignIT(sender, addr, funcSig, ct, key)
	require.NoError(t, err, "Sign should not return an error")

	# Verify the signature
	verified := VerifyIT(sender, addr, funcSig, ct, signature)
	assert.Equal(t, verified, true, "Verify signature should return true")
}
```



## Python 

### Prerequisites

Python should be installed on your system.

Additionally, install the required libraries using the following commands:

```bash 
pip install pycryptodome
pip install eth-keys
pip install cryptography
pip install web3
```

### Usage

In order to use the functionalities of python SDK, first import the modules from 'crypto' file.
for example:

```bash 
from crypto import prepare_IT, decrypt
```

Below is an example function from the python test file that demonstrate using some of the SDK functionality. Lets break it down:

```bash
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
    # Create the signed message 
    message = sender_address_bytes + contract_address_bytes + func_hash + ctBytes
    pk = keys.PrivateKey(signingKey)
    signature = keys.Signature(signature)
    # Verify the signature against the message hash and the public key
    verified = signature.verify_msg(message, pk.public_key)
    self.assertEqual(verified, True)

    # Decrypt the ciphertext using the AES key and check the decrypted value agains the original plaintext
    ctBytes = ct.to_bytes((ct.bit_length() + 7) // 8, 'big')
    decrypted = decrypt(userKey, ctBytes[block_size:], ctBytes[:block_size])
    decrypted_integer = int.from_bytes(decrypted, 'big')
    self.assertEqual(plaintext, decrypted_integer)
```

This example uses the prepare_IT and decrypt functionalities of the python SDK.
More examples can be found in the test.py file.

## JavaScript 

### Prerequisites

JavaScript should be installed on your system.
Additionally, navigate to the js directory and install the necessary JavaScript libraries by:

```bash 
npm install
```

### Usage

In order to use the functionalities of JavaScript SDK, first import the modules from 'crypto' file.
for example:

```bash 
import { encrypt } from './crypto.js';
```

Below is an example of RSA encryption scheme. The code can be found in the test.mjs file, lets break it down:

```bash
const plaintext = Buffer.from('hello world');
# Generate RSA key pair
const { publicKey, privateKey } = generateRSAKeyPair();

# Encrypt the plaintext using the public key
const ciphertext = encryptRSA(publicKey, plaintext);

# Decrypt the ciphertext
const decrypted = decryptRSA(privateKey, ciphertext);

# Check the decrypted value agains the original plaintext
assert.deepStrictEqual(plaintext, decrypted);
```

## Running tests

We offer a test file for each supported language. 

It's important to note that running tests from inner directories is not advisable. Some tests rely on the output of others, and the execution order is critical. Running tests out of order may lead to failures. 

To run the tests correctly, use a bash file that executes the tests in the proper sequence. Navigate to the main directory and execute the following command:

```bash 
./testAll.sh
```

After running the tests using the provided bash file, the outcomes of the tests will be shown in your terminal or command prompt window. This output typically includes information about which tests passed, failed, or encountered errors, along with any additional details or logs generated during the testing process. It's essential to review this output to ensure that all tests have executed as expected and to address any issues that may have arisen.


## Golang CLI Tool for a random AES Encryption and Decryption

This command-line tool provides functionalities for encrypting and decrypting data using AES encryption. It also supports key generation and storage.

### Usage

```bash
cli-tool [OPTIONS]
```

#### Options:

- `--help`: Show help message

- `--encrypt`: Encrypt data.Provide a filename and plaintext as an additional argument.

- `--decrypt`: Decrypt data. Provide a filename and two encrypted hex strings as additional arguments.

- `--generate-key`: Generate key and save to specified file. Provide a filename.

### Examples:

#### Encryption:

```bash
cli-tool --encrypt keyfile.txt 1234567890123456
```

#### Decryption:

```bash
cli-tool --decrypt keyfile.txt <encrypted-hex-string> <random-hex-string>
```

#### Generate Key:

```bash
cli-tool --generate-key mykey.txt
```
