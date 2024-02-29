import crypto from 'crypto';
import fs from 'fs';
import ethereumjsUtil  from 'ethereumjs-util';
import { Address, toBuffer } from 'ethereumjs-util';
import pkg from 'elliptic';
const EC = pkg.ec;

export const block_size = 16; // AES block size in bytes
export const addressSize = 20; // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
export const funcSigSize = 4;
export const ctSize = 32;
export const keySize = 32;
export const hexBase = 16;

export function encrypt(key, plaintext) {
    
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > block_size) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Create a new AES cipher using the provided key
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);

    // Generate a random value 'r' of the same length as the block size
    const r = crypto.randomBytes(block_size);

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r);
    
    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintext_padded = Buffer.concat([Buffer.alloc(block_size - plaintext.length), plaintext]);

    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }
    
    return { ciphertext, r };
}

export function decrypt(key, r, ciphertext) {

    if (ciphertext.length !== block_size) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length != block_size) {
        throw new RangeError("Random size must be 128 bits.");
    }

    // Create a new AES decipher using the provided key
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r);

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i];
    }

    return plaintext;
}

export function loadAesKey(filePath) {
    // Read the hex-encoded contents of the file
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();

    // Decode the hex string to binary
    const key = Buffer.from(hexKey, 'hex');

    // Ensure the key is the correct length
    if (key.length !== block_size) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    return key;
}

export function writeAesKey(filePath, key) {
    // Ensure the key is the correct length
    if (key.length !== block_size) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    // Encode the key to hex string
    const hexKey = key.toString('hex');

    // Write the hex-encoded key to the file
    fs.writeFileSync(filePath, hexKey, 'utf8');
}

export function generateAesKey() {
    // Generate a random 128-bit AES key
    const key = crypto.randomBytes(block_size);

    return key;
}

export function generateECDSAPrivateKey(){
    // Create an elliptic curve instance using secp256k1 curve
    const ec = new EC('secp256k1');

    // Generate a key pair
    const keyPair = ec.genKeyPair();

    // Get the raw bytes of the private key
    return keyPair.getPrivate().toArrayLike(Buffer, 'be', 32);

}

export function signIT(sender, addr, funcSig, ct, key) {
    // Ensure all input sizes are the correct length
    if (sender.length !== addressSize) {
        throw new RangeError(`Invalid sender address length: ${sender.length} bytes, must be ${addressSize} bytes`);
    }
    if (addr.length !== addressSize) {
        throw new RangeError(`Invalid contract address length: ${addr.length} bytes, must be ${addressSize} bytes`);
    }
    if (funcSig.length !== funcSigSize) {
        throw new RangeError(`Invalid signature size: ${funcSig.length} bytes, must be ${funcSigSize} bytes`);
    }
    if (ct.length !== ctSize) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${ctSize} bytes`);
    }
    // Ensure the key is the correct length
    if (key.length !== keySize) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${keySize} bytes`);
    }

    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, funcSig, ct]);

    // Concatenate r, s, and v bytes
    return sign(message, key);
}

export function sign(message, key) {

    // Hash the concatenated message using Keccak-256
    const hash = ethereumjsUtil.keccak256(message);
    
    // Sign the message
    let signature = ethereumjsUtil.ecsign(hash, key);
    signature.v = (signature.v - 27) // Convert v from 27-28 to 0-1 in order to match the ecrecover of ethereum
    
    // Convert r, s, and v components to bytes
    let rBytes = Buffer.from(signature.r);
    let sBytes = Buffer.from(signature.s);
    let vByte = Buffer.from([signature.v]);

    // Concatenate r, s, and v bytes
    return Buffer.concat([rBytes, sBytes, vByte]);
}

export function prepareIT(plaintext, userAesKey, sender, contract, func, signingKey) {

    // Get the bytes of the sender, contract, and function signature
    const senderBytes = toBuffer(sender)
    const contractBytes = toBuffer(contract)
    
    const encodedABI = func.encodeABI();
    const hashFunc = Buffer.from(encodedABI.substr(2, 8), 'hex');
    
    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8); // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(BigInt(plaintext)); // Write the uint64 value to the buffer as little-endian

    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encrypt(userAesKey, plaintextBytes);
    let ct = Buffer.concat([ciphertext, r]);

    // Sign the message
    const signature = signIT(senderBytes, contractBytes, hashFunc, ct, signingKey);

    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + ct.toString('hex'));

    return { ctInt, signature };
}

export function generateRSAKeyPair() {
    // Generate a new RSA key pair
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'der' // Specify 'der' format for binary data
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'der' // Specify 'der' format for binary data
        }
    });
}

export function encryptRSA(publicKey, plaintext) {
    // Load the public key in PEM format
    let publicKeyPEM = publicKey.toString('base64');
    publicKeyPEM = `-----BEGIN PUBLIC KEY-----\n${publicKeyPEM}\n-----END PUBLIC KEY-----`;
    
    // Encrypt the plaintext using RSA-OAEP
    return crypto.publicEncrypt({
        key: publicKeyPEM,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, plaintext);
}

export function decryptRSA(privateKey, ciphertext) {
    // Load the private key in PEM format
    let privateKeyPEM = privateKey.toString('base64');
    privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyPEM}\n-----END PRIVATE KEY-----`;

    // Decrypt the ciphertext using RSA-OAEP
    return crypto.privateDecrypt({
        key: privateKeyPEM,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, ciphertext);
}

export function getFuncSig(functionSig) {
    // Encode the string to a Buffer
    const functionBytes = Buffer.from(functionSig, "utf8");

    // Hash the function signature using Keccak-256
    const hash = ethereumjsUtil.keccak256(functionBytes);

    return hash.subarray(0, 4);
}