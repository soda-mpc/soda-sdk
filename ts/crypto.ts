import forge from 'node-forge'
import fs from 'fs';
import crypto from 'crypto';
import {ethers} from "ethers";
import { toBuffer, ecrecover, keccak256, pubToAddress, toChecksumAddress } from 'ethereumjs-util';

export const BLOCK_SIZE = 16; // AES block size in bytes
export const ADDRESS_SIZE = 20; // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
export const FUNC_SIG_SIZE = 4;
export const CT_SIZE = 32;
export const KEY_SIZE = 32;
export const HEX_BASE = 16;
export const MAX_PLAINTEXT_BIT_SIZE = 256;
export const SIGNATURE_SIZE = 65; // r (32 bytes) + s (32 bytes) + v (1 byte)
export const EC_PUBLIC_KEY_SIZE = 65; // Uncompressed public key (0x04 + X + Y)

/**
 * Encrypts a plaintext using AES encryption with a given key.
 * @param {Buffer} key - The AES key (16 bytes).
 * @param {Buffer} plaintext - The plaintext to encrypt (must be 16 bytes or smaller).
 * @returns {Object} - An object containing the ciphertext and the random value 'r' used during encryption.
 * @throws {RangeError} - Throws if plaintext is larger than 16 bytes or if the key size is not 16 bytes.
 */
export function encrypt(key: Uint8Array, plaintext: Uint8Array):{ ciphertext: Buffer; r: Buffer } {
    if (plaintext.length > BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.");
    }

    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Create a new AES cipher using the provided key
    const r = forge.random.getBytesSync(BLOCK_SIZE);
    const encryptedR = aesEcbEncrypt(r, key);
    const plaintext_padded = Buffer.concat([Buffer.alloc(BLOCK_SIZE - plaintext.length), plaintext]);

    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }

    const uint8ArrayR = new Uint8Array(r.split('').map(c => c.charCodeAt(0)));
    return { ciphertext, r: Buffer.from(uint8ArrayR) };
}


/**
 * Decrypts a ciphertext using AES decryption with a given key and random value 'r'.
 * @param {Buffer} key - The AES key (16 bytes).
 * @param {Buffer} r - The random value used during encryption (16 bytes).
 * @param {Buffer} ciphertext - The ciphertext to decrypt (16 bytes).
 * @param {Buffer} r2 - In case of 256 bits plaintext, there is a second random value.
 * @param {Buffer} ciphertext2 - In case of 256 bits plaintext, there is a second ciphertext.
 * @returns {Uint8Array} - The decrypted plaintext.
 * @throws {RangeError} - Throws if any input size is incorrect.
 */
export function decrypt(key: Uint8Array, r: Uint8Array, ciphertext: Uint8Array, r2: Uint8Array | null = null, ciphertext2: Uint8Array | null = null): Uint8Array {
    // Ensure ciphertext size is 128 bits (16 bytes)
    if (ciphertext.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Ensure random value size is 128 bits (16 bytes)
    if (r.length !== BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits.");
    }

    if (r2 !== null) {
        if (r2.length !== BLOCK_SIZE) {
            throw new RangeError("Random2 size must be 128 bits, received " + r2.length + " bytes.");
        }
        if (ciphertext2 === null) {
            throw new RangeError("Ciphertext2 is required.");
        }
    }

    if (ciphertext2 !== null) {
        if (ciphertext2.length !== BLOCK_SIZE) {
            throw new RangeError("Ciphertext2 size must be 128 bits, received " + ciphertext2.length + " bytes.");
        }

        if (r2 === null) {
            throw new RangeError("Random2 is required.");
        }
    }

    const encryptedR = aesEcbEncrypt(r, key);
    let plaintext = new Uint8Array(BLOCK_SIZE);

    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i];
    }

    if (r2 !== null && ciphertext2 !== null) {
        // Encrypt the random value 'r2' using AES in ECB mode
        const encryptedR2 = aesEcbEncrypt(r2, key);

        // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
        const plaintext2 = new Uint8Array(BLOCK_SIZE);
        for (let i = 0; i < encryptedR2.length; i++) {
            plaintext2[i] = encryptedR2[i] ^ ciphertext2[i];
        }

        plaintext = new Uint8Array([...plaintext, ...plaintext2]);
    }

    return plaintext;
}

/**
 * Generates a random 128-bit AES key.
 * @returns {Buffer} - A Buffer containing a random 16-byte AES key.
 */
export function generateAesKey(): Buffer {
    const key = forge.random.getBytesSync(BLOCK_SIZE);
    const uint8ArrayKey = new Uint8Array(key.split('').map(c => c.charCodeAt(0)));
    return Buffer.from(uint8ArrayKey);
}

/**
 * Loads an AES key from a hex-encoded file.
 * @param {string} filePath - The path to the file containing the hex-encoded key.
 * @returns {Buffer} - A Buffer containing the 16-byte AES key.
 * @throws {RangeError} - Throws if the key length is not 16 bytes.
 */
export function loadAesKey(filePath: string): Buffer {
    // Read the hex-encoded contents of the file
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();

    // Decode the hex string to binary
    const key = Buffer.from(hexKey, 'hex');

    // Ensure the key is the correct length
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    return key;
}

/**
 * Writes an AES key to a file as a hex-encoded string.
 * @param {string} filePath - The path to the file where the key should be written.
 * @param {Buffer} key - The AES key to write (16 bytes).
 * @throws {RangeError} - Throws if the key length is not 16 bytes.
 */
export function writeAesKey(filePath: string, key: Buffer): void {
    // Ensure the key is the correct length
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    // Encode the key to hex string
    const hexKey = Buffer.from(key).toString('hex');

    // Write the hex-encoded key to the file
    fs.writeFileSync(filePath, hexKey, 'utf8');
}

/**
 * Generates a new ECDSA private key using the secp256k1 curve.
 * @returns {Buffer} - A Buffer containing a 32-byte private key.
 */
export function generateECDSAPrivateKey(): Buffer {
    // Generate a new random wallet
    const wallet = ethers.Wallet.createRandom();
    const privateKeyHex = wallet.privateKey;
    // Return the private key as a Buffer without the '0x' prefix
    return Buffer.from(privateKeyHex.slice(2), 'hex');
}

/**
 * Signs a message using the provided parameters and a given key.
 * Supports optional EIP-191 signing.
 * @param {Buffer} sender - The sender's address (20 bytes).
 * @param {Buffer} addr - The contract address (20 bytes).
 * @param {Buffer} ct - The ciphertext (32 bytes in case of 128 bits plaintext or less, or 64 bytes in case of 256 bits plaintext).
 * @param {Buffer} key - The signing key (32 bytes).
 * @param {boolean} eip191 - Whether to use EIP-191 signing (default: false).
 * @returns {Buffer} - The signature as a Buffer.
 * @throws {RangeError} - Throws if input sizes are incorrect.
 */
export function signIT(sender:Buffer, addr:Buffer, ct:Buffer, key:Buffer, eip191 = false) {
    if (sender.length !== ADDRESS_SIZE) {
        throw new RangeError(`Invalid sender address length: ${sender.length} bytes, must be ${ADDRESS_SIZE} bytes`);
    }
    if (addr.length !== ADDRESS_SIZE) {
        throw new RangeError(`Invalid contract address length: ${addr.length} bytes, must be ${ADDRESS_SIZE} bytes`);
    }
    if (ct.length !== CT_SIZE && ct.length !== 2*CT_SIZE) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${CT_SIZE} bytes in case of 128 bits plaintext or less, or ${2*CT_SIZE} bytes in case of 256 bits plaintext or less`);
    }
    if (key.length !== KEY_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${KEY_SIZE} bytes`);
    }

    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, ct]);
    if (eip191) {
        return signEIP191(message, key);
    } else {
        return sign(message, key);
    }
}

/**
 * Signs a message using the standard signing process.
 * @param {Buffer} message - The message to sign.
 * @param {Buffer} key - The signing key (32 bytes).
 * @returns {Buffer} - The signature as a concatenation of r, s, and v values.
 */
export function sign(message: Buffer, key:Buffer):Buffer {
    const hash = ethers.keccak256(message);
    const signingKey = new ethers.SigningKey(key);
    const signature = signingKey.sign(hash);
    // Concatenate r, s, and v bytes
    return Buffer.concat([
        ethers.getBytes(signature.r),
        ethers.getBytes(signature.s),
        ethers.getBytes(`0x0${signature.v - 27}`)
    ]);
}

/**
 * Signs a message using EIP-191.
 * @param {Buffer} message - The message to sign.
 * @param {Buffer} key - The signing key (32 bytes).
 * @returns {Buffer} - The signature as a concatenation of r, s, and v values.
 */
export function signEIP191(message: Buffer, key: Buffer): Buffer {
    const hash = ethers.hashMessage(message);
    const signingKey = new ethers.SigningKey(key);
    const signature = signingKey.sign(hash);
    const vBytes = new Uint8Array([signature.v]);

    // Concatenate r, s, and v bytes
    return Buffer.concat([
        ethers.getBytes(signature.r),
        ethers.getBytes(signature.s),
        vBytes
    ]);
}

/**
 * Prepares a message by encrypting the given plaintext and constructing the message. This message needs to be signed to create an IT.
 * @param {bigint} plaintext - The plaintext value to be encrypted as a BigInt.
 * @param {string} signerAddress - The address of the signer (Ethereum address).
 * @param {string} aesKey - The AES key used for encryption (32 bytes as a hex string).
 * @param {string} contractAddress - The address of the contract (Ethereum address).
 * @returns {Object} - An object containing the encrypted integer and the message.
 * @throws {TypeError} - Throws if any of the input parameters are of invalid types or have incorrect lengths.
 */
export function prepareMessage(
  plaintext: bigint,
  signerAddress: string,
  aesKey: string,
  contractAddress: string,
): {
  encryptedInt: bigint;
  message: string
} {
    // Validate signerAddress (Ethereum address)
    if (typeof signerAddress !== "string" || !ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid signer address");
    }

    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length !== 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }

    // Validate contractAddress (Ethereum address)
    if (typeof contractAddress !== "string" || !ethers.isAddress(contractAddress)) {
        throw new TypeError("Invalid contract address");
    }

    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8); // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(plaintext); // Write the uint64 value to the buffer as little-endian

    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encrypt(Buffer.from(aesKey, 'hex'), plaintextBytes);
    const ct = Buffer.concat([ciphertext, r]);

    // Create the packed message
    const message = ethers.solidityPacked(
        ["address", "address", "uint256"],
        [signerAddress, contractAddress, BigInt("0x" + ct.toString("hex"))],
    );

    // Convert the ciphertext to BigInt
    const encryptedInt = BigInt("0x" + ct.toString("hex"));

    return { encryptedInt, message };
}

/**
 * Writes a uint128 value to a buffer as big-endian.
 * @param {Buffer} buffer - The buffer to write the value to.
 * @param {bigint} value - The value to write to the buffer.
 * @param {number} offset - The offset to write the value to.
 */
function writeBigUInt128BE(buffer: Buffer, value: bigint, offset = 0) {
    const hexString = value.toString(HEX_BASE).padStart(CT_SIZE, '0');
    const bytes = Buffer.from(hexString, 'hex');
    bytes.copy(buffer, offset);
}

/**
 * Writes a uint256 value to a buffer as big-endian.
 * @param {Buffer} buffer - The buffer to write the value to.
 * @param {bigint} value - The value to write to the buffer.
 * @param {number} offset - The offset to write the value to.
 */
export function writeBigUInt256BE(buffer: Buffer, value: bigint, offset = 0) {
    const hexString = value.toString(HEX_BASE).padStart(CT_SIZE*2, '0');
    const bytes = Buffer.from(hexString, 'hex');
    if (buffer.length > bytes.length) {
        offset = buffer.length - bytes.length;
    }
    bytes.copy(buffer, offset);
}

/**
 * Prepares an IT by encrypting the plaintext, signing the encrypted message,
 * and packaging the resulting data. This data represents encrypted data that can be sent to the contract.
 * @param {bigint} plaintext - The plaintext value to be encrypted as a BigInt.
 * @param {Buffer} userAesKey - The AES key used for encryption (16 bytes).
 * @param {Buffer} sender - The sender's address as a Buffer.
 * @param {Buffer} contract - The contract's address as a Buffer.
 * @param {Buffer} signingKey - The ECDSA signing key (32 bytes).
 * @param {boolean} [eip191=false] - Whether to use EIP-191 signing (default: false).
 * @returns {Object} - An object containing the encrypted integer (as `ctInt`) and the signature.
 */
export function prepareIT(
  plaintext:bigint,
  userAesKey:Buffer,
  sender:Buffer,
  contract:Buffer,
  signingKey:Buffer,
  eip191 = false
):{ctInt:bigint, signature:Buffer} {
    // Get the bytes of the sender, contract
    // todo: check if sender and contract are already in bytes
    const senderBytes = sender;
    const contractBytes = contract;

    // Convert the plaintext to bytes
    const plaintextBigInt = BigInt(plaintext);
    const bitSize = plaintextBigInt.toString(2).length;
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE/2) {
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepareIT256 instead.");
    }

    const plaintextBytes = Buffer.alloc(BLOCK_SIZE); // Allocate a buffer of size 16 bytes
    writeBigUInt128BE(plaintextBytes, plaintextBigInt); // Write the uint128 value to the buffer as big-endian

    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encrypt(userAesKey, plaintextBytes);
    let ct = Buffer.concat([ciphertext, r]);

    // Sign the message
    const signature = signIT(senderBytes, contractBytes, ct, signingKey, eip191);

    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + ct.toString('hex'));

    return { ctInt, signature };
}

/**
 * Prepares a 256 bit IT by encrypting both parts of the plaintext, signing the encrypted message,
 * and packaging the resulting data. This data represents encrypted data that can be sent to the contract.
 * @param {bigint} plaintext - The plaintext value to be encrypted as a BigInt.
 * @param {Buffer} userAesKey - The AES key used for encryption (16 bytes).
 * @param {Buffer} sender - The sender's address as a Buffer.
 * @param {Buffer} contract - The contract's address as a Buffer.
 * @param {Buffer} signingKey - The ECDSA signing key (32 bytes).
 * @param {boolean} [eip191=false] - Whether to use EIP-191 signing (default: false).
 */
export function prepareIT256(plaintext:bigint, userAesKey:Buffer, sender:Buffer, contract:Buffer, signingKey:Buffer, eip191=false) {

    // todo: check if sender and contract are already in bytes (as in regular prepareIT)
    // Convert the plaintext to bytes
    const plaintextBigInt = BigInt(plaintext);
    const bitSize = plaintextBigInt.toString(2).length;
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE) {
        throw new RangeError("Plaintext size must be 256 bits or smaller.");
    }

    let ct = Buffer.alloc(0);

    // In case of 128 bits plaintext, encrypt it as the low part of the ct, and then encrypt the high part of the ct with zeros
    if (bitSize <= MAX_PLAINTEXT_BIT_SIZE/2) {
        const plaintextBytes = Buffer.alloc(BLOCK_SIZE); // Allocate a buffer of size 16 bytes
        writeBigUInt128BE(plaintextBytes, plaintextBigInt); // Write the uint128 value to the buffer as big-endian
        // Encrypt the plaintext using AES key
        const {ciphertext, r} = encrypt(userAesKey, plaintextBytes);

        // Encrypt the high part of the ct with zeros
        const zero = BigInt(0);
        const zeroBytes = Buffer.alloc(BLOCK_SIZE);
        writeBigUInt128BE(zeroBytes, zero);
        const {ciphertext: ciphertextHigh, r: rHigh} = encrypt(userAesKey, zeroBytes);
        ct = Buffer.concat([ciphertextHigh, rHigh, ciphertext, r]);

    } else { // bitSize > 128 and bitSize <= 256
        const plaintextBytes = Buffer.alloc(CT_SIZE); // Allocate a buffer of size 32 bytes
        writeBigUInt256BE(plaintextBytes, plaintextBigInt); // Write the uint256 value to the buffer as big-endian

        // Encrypt each part of the plaintext using AES key
        const resultHigh = encrypt(userAesKey, plaintextBytes.slice(0, BLOCK_SIZE));
        const resultLow = encrypt(userAesKey, plaintextBytes.slice(BLOCK_SIZE));

        // Now destructure
        const { ciphertext: ciphertextHigh, r: rHigh } = resultHigh;
        const { ciphertext: ciphertextLow, r: rLow } = resultLow;

        ct = Buffer.concat([ciphertextHigh, rHigh, ciphertextLow, rLow]);
    } 

    // Sign the message
    const signature = signIT(sender, contract, ct, signingKey, eip191);

    const ciphertextHigh = ct.slice(0, CT_SIZE);
    const ciphertextLow = ct.slice(CT_SIZE);

    // Convert Buffer to uint256 (BigInt) for Solidity compatibility
    const ciphertextHighUint = BigInt('0x' + ciphertextHigh.toString('hex'));
    const ciphertextLowUint = BigInt('0x' + ciphertextLow.toString('hex'));

    return { ciphertext: {ciphertextHigh: ciphertextHighUint, ciphertextLow: ciphertextLowUint}, signature };
}

/**
 * Verifies the signatures of the message.
 * @param {Buffer|Uint8Array} message - The message to be verified.
 * @param {Buffer|Uint8Array} signatures - The signatures to be verified.
 * @param {string[]} signers - The list of signers.
 * @returns {boolean} - Returns true if the signatures are valid, false otherwise.
 */
export function verifySignatures(message: Buffer | Uint8Array, signatures: (Buffer | Uint8Array)[], signers: string[]){  
    // Validate the number of signatures and signers
    if (signatures.length !== signers.length) {
        throw new RangeError("Number of signatures and signers must be the same");
    }
    if (signers.length === 0) {
        throw new RangeError("Signers must be non-empty");
    }

    const recoveredAddresses: Set<string> = new Set();
    for (const signature of signatures) {
        const recoveredAddress = recoverAddressFromSignature(message, signature);
        if (!signers.includes(recoveredAddress)) {
            console.log("Recovered address " + recoveredAddress + " not in the list of signers")
            return false;
        }
        if (recoveredAddresses.has(recoveredAddress)) {
            console.log("Same address recovered multiple times")
            return false;
        }
        recoveredAddresses.add(recoveredAddress);
    }
    return true;
}

/**
 * Recovers the address from the signature.
 * @param {Buffer|Uint8Array} message - The message to be signed.
 * @param {Buffer|Uint8Array} signature - The signature in r||s||v format (65 bytes).
 * @returns {string} - The address recovered from the signature.
 */
export function recoverAddressFromSignature(message: Buffer | Uint8Array, signature: Buffer | Uint8Array) {
    // Validate input types
    if (!(message instanceof Buffer) && !(message instanceof Uint8Array)) {
        throw new TypeError("message must be Buffer or Uint8Array");
    }
    if (message.length === 0) {
        throw new RangeError("message must be non-empty");
    }

    // Validate signature length
    if (!(signature instanceof Buffer) && !(signature instanceof Uint8Array)) {
        throw new TypeError("signature must be Buffer or Uint8Array");
    }
    if (signature.length !== SIGNATURE_SIZE) {
        throw new RangeError(`Invalid signature length: ${signature.length} bytes, must be ${SIGNATURE_SIZE} bytes`);
    }

    // Hash the message
    const messageToHash = Buffer.from(message);
    const messageHash = keccak256(messageToHash);

    // Convert signature components (r, s, v)
    const { rBytes, sBytes, vByte } = extractSignatureComponents(Buffer.from(signature));

    // Convert v from 0-1 to 27-28 for ecrecover
    // vByte is a Buffer, so we need to access the first byte
    const vValue = vByte[0];
    const v = vValue === 0 || vValue === 1 ? vValue + 27 : vValue;

    // Recover the public key from the signature
    const recoveredPublicKey = ecrecover(messageHash, v, rBytes, sBytes);

    // Get the address from the recovered public key
    const addressBuffer = pubToAddress(recoveredPublicKey);
    return toChecksumAddress('0x' + addressBuffer.toString('hex'));
}

/**
 * Extracts the signature components from the signature bytes.
 * This function does not validate the signature bytes, it only extracts the components. 
 * The function expects the signature bytes to be in the correct format (r||s||v).
 * @param {Buffer|Uint8Array} signatureBytes - The signature bytes to extract the components from.
 * @returns {Object} - An object containing the r, s, and v components.
 * @throws {TypeError} - Throws if the signature bytes are of invalid types.
 * @throws {RangeError} - Throws if the signature bytes are empty or have incorrect lengths.
 */
export function extractSignatureComponents(signatureBytes: Buffer | Uint8Array): { rBytes: Buffer; sBytes: Buffer; vByte: Buffer } {
    const rSize = (SIGNATURE_SIZE - 1) / 2;
    const sSize = rSize;
    
    // Convert to Buffer if needed
    const sigBuf = Buffer.from(signatureBytes);
    
    // Allocate buffers for r, s, and v
    let rBytes = Buffer.alloc(rSize);
    let sBytes = Buffer.alloc(sSize);
    let vByte = Buffer.alloc(1);

    // Copy the corresponding bytes from the signature
    sigBuf.copy(rBytes, 0, 0, rSize);
    sigBuf.copy(sBytes, 0, rSize, rSize + sSize);
    sigBuf.copy(vByte, 0, rSize + sSize);

    // Return the components as an object
    return { rBytes, sBytes, vByte };
}

/**
 * Generates a new RSA key pair.
 * @returns {Object} - An object containing the private key and public key as Buffers.
 */
export function generateRSAKeyPair():{privateKey:Buffer, publicKey:Buffer} {
    // Generate a new RSA key pair with 2048 bits
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    // Convert the private and public keys to DER format
    const privateKey = forge.asn1.toDer(forge.pki.privateKeyToAsn1(rsaKeyPair.privateKey)).data;
    // Convert the public key to DER format
    const publicKey = forge.asn1.toDer(forge.pki.publicKeyToAsn1(rsaKeyPair.publicKey)).data;

    // Return the private and public keys as Buffers
    return {
        privateKey: Buffer.from(encodeString(privateKey)),
        publicKey: Buffer.from(encodeString(publicKey))
    };
}

/**
 * Encrypts plaintext using RSA with the provided public key.
 * @param {Uint8Array} publicKeyUint8Array - The RSA public key in Uint8Array format.
 * @param {string} plaintext - The plaintext to be encrypted.
 * @returns {Uint8Array} - The encrypted data as a Uint8Array.
 * @throws {Error} - Throws if the encryption fails or if the input format is incorrect.
 */
export function encryptRSA(publicKeyUint8Array:Uint8Array, plaintext:string):Uint8Array {
    // Convert the Uint8Array to a binary string for forge
    const binaryDerString = String.fromCharCode(...publicKeyUint8Array);

    // Decode the binary DER string into an ASN.1 object
    const asn1PublicKey = forge.asn1.fromDer(binaryDerString);

    // Convert the ASN.1 object to an RSA public key
    const forgePublicKey = forge.pki.publicKeyFromAsn1(asn1PublicKey);

    // Encrypt the plaintext using RSA-OAEP with SHA-256 as the hash function
    const encrypted = forgePublicKey.encrypt(plaintext, 'RSA-OAEP', {
        md: forge.md.sha256.create()  // Use SHA-256 for OAEP padding
    });

    // Convert the encrypted binary string to a Uint8Array
    return new Uint8Array(forge.util.createBuffer(encrypted, 'raw').bytes().split('').map(c => c.charCodeAt(0)));
}

/**
 * Decrypts RSA-encrypted data using the provided private key.
 * @param {Uint8Array} privateKey - The RSA private key in Uint8Array format.
 * @param {Uint8Array|string} ciphertext - The encrypted data to decrypt (Uint8Array or hex string).
 * @returns {Uint8Array} - The decrypted plaintext as a Uint8Array.
 * @throws {Error} - Throws if the decryption fails or if the input format is incorrect.
 */
export function decryptRSA(privateKey: Uint8Array, ciphertext: string): Uint8Array {
    // Convert privateKey from Uint8Array to PEM format
    const privateKeyBuffer = Buffer.from(privateKey);
    const privateKeyPEM = forge.pki.privateKeyToPem(forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(privateKeyBuffer.toString('binary')))));

    // Decrypt using RSA-OAEP
    const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

    const decrypted = rsaPrivateKey.decrypt(forge.util.hexToBytes(ciphertext), 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    return encodeString(decrypted)
}

/**
 * Generates the function selector for a given function signature.
 * @param {string} functionSig - The function signature (e.g., 'test(bytes)').
 * @returns {Buffer} - A Buffer containing the first 4 bytes of the Keccak-256 hash of the function signature.
 */
export function getFuncSig(functionSig:string):Buffer {
    const functionSelector = ethers.id(functionSig).slice(0, 10);
    return Buffer.from(functionSelector.slice(2, 10), 'hex');
}

/**
 * Encodes a string into a Uint8Array of hexadecimal values.
 * @param {string} str - The input string to encode.
 * @returns {Uint8Array} - A Uint8Array representing the encoded hexadecimal values of the input string.
 */
export function encodeString(str: string): Uint8Array {
    return new Uint8Array([...str.split('').map((char) => parseInt(char.codePointAt(0)?.toString(HEX_BASE)!, HEX_BASE))])
}

/**
 * This function recovers a user's key by decrypting two encrypted key shares with the given private key,
 * and then XORing the two key shares together.
 *
 * @param {Buffer} privateKey - The private key used to decrypt the key shares.
 * @param {string} encryptedKeyShare0 - The first encrypted key share.
 * @param {string} encryptedKeyShare1 - The second encrypted key share.
 *
 * @returns {Buffer} - The recovered user key.
 */
export function reconstructUserKey(privateKey:Buffer, encryptedKeyShare0:string, encryptedKeyShare1:string) {
    const decryptedKeyShare0 = decryptRSA(privateKey, encryptedKeyShare0);
    const decryptedKeyShare1 = decryptRSA(privateKey, encryptedKeyShare1);

    const aesKey = Buffer.alloc(decryptedKeyShare0.length);
    for (let i = 0; i < decryptedKeyShare0.length; i++) {
        aesKey[i] = decryptedKeyShare0[i] ^ decryptedKeyShare1[i];
    }

    return aesKey;
}


/**
 * Encrypts a random value 'r' using AES in ECB mode with the provided key.
 * @param {string} r - The random value to be encrypted (16 bytes).
 * @param {Buffer} key - The AES key (16 bytes).
 * @returns {Uint8Array} - A Uint8Array containing the encrypted random value.
 * @throws {RangeError} - Throws if the key size is not 16 bytes.
 */
export function aesEcbEncrypt(r: string | Uint8Array, key: Uint8Array) {
    // Ensure key size is 128 bits (16 bytes)
    if (key.length != BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Convert key to binary string for forge
    const keyBuffer = Buffer.from(key);
    const keyBinary = keyBuffer.toString('binary');

    // Create a new AES cipher using the provided key
    const cipher = forge.cipher.createCipher('AES-ECB', forge.util.createBuffer(keyBinary))

    // Encrypt the random value 'r' using AES in ECB mode
    // Convert r to binary string if it's a Uint8Array
    const rBinary = typeof r === 'string' ? r : Buffer.from(r).toString('binary');
    cipher.start()
    cipher.update(forge.util.createBuffer(rBinary))
    cipher.finish()

    // Get the encrypted random value 'r' as a Buffer and ensure it's exactly 16 bytes
    const encryptedR = encodeString(cipher.output.data).slice(0, BLOCK_SIZE)

    return encryptedR
}

export function decryptUint(ciphertext: bigint, userKey: string): bigint {
    // Convert ciphertext to Uint8Array
    let ctArray = new Uint8Array()

    while (ciphertext > 0) {
        const temp = new Uint8Array([Number(ciphertext & BigInt(255))])
        ctArray = new Uint8Array([...temp, ...ctArray])
        ciphertext >>= BigInt(8)
    }

    ctArray = new Uint8Array([...new Uint8Array(32 - ctArray.length), ...ctArray])

    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, BLOCK_SIZE)
    const r = ctArray.subarray(BLOCK_SIZE)

    const userKeyBytes = encodeKey(userKey)

    // Decrypt the cipher
    const decryptedMessage = decrypt(userKeyBytes, r, cipher)

    return decodeUint(decryptedMessage)
}

export function encodeKey(userKey: string): Uint8Array {
    const keyBytes = new Uint8Array(16)

    for (let i = 0; i < 32; i += 2) {
        keyBytes[i / 2] = parseInt(userKey.slice(i, i + 2), HEX_BASE)
    }

    return keyBytes
}

export function decodeUint(plaintextBytes: Uint8Array): bigint {
    const plaintext: Array<string> = []

    let byte = ''

    for (let i = 0; i < plaintextBytes.length; i++) {
        byte = plaintextBytes[i].toString(HEX_BASE).padStart(2, '0') // ensure that the zero byte is represented using two digits

        plaintext.push(byte)
    }

    return BigInt("0x" + plaintext.join(""))
}