import crypto from 'crypto';
import fs from 'fs';
import ethereumjsUtil  from 'ethereumjs-util';

export const block_size = 16; // AES block size in bytes
export const addressSize = 160;
export const signatureSize = 4;
export const nonceSize = 8;
export const ctSize = 32;
export const keySize = 32;

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
    const plaintext_padded = Buffer.concat([plaintext, Buffer.alloc(block_size - plaintext.length)]);

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

export function sign(sender, addr, funcSig, nonce, ct, key) {
    // Ensure all input sizes are the correct length
    if (sender.length !== addressSize) {
        throw new RangeError(`Invalid sender address length: ${sender.length} bytes, must be ${addressSize} bytes`);
    }
    if (addr.length !== addressSize) {
        throw new RangeError(`Invalid contract address length: ${addr.length} bytes, must be ${addressSize} bytes`);
    }
    if (funcSig.length !== signatureSize) {
        throw new RangeError(`Invalid signature size: ${funcSig.length} bytes, must be ${signatureSize} bytes`);
    }
    if (nonce.length !== nonceSize) {
        throw new RangeError(`Invalid nonce length: ${nonce.length} bytes, must be ${nonceSize} bytes`);
    }
    if (ct.length !== ctSize) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${ctSize} bytes`);
    }
    // Ensure the key is the correct length
    if (key.length !== keySize) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${keySize} bytes`);
    }

    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, funcSig, nonce, ct]);

    // Hash the concatenated message using Keccak-256
    const hash = ethereumjsUtil.keccak256(message);
    console.log('hashed message = ' + hash.toString('hex'));

    // Sign the message
    let signature = ethereumjsUtil.ecsign(hash, key);
    console.log('signature = ' + signature.r.toString('hex') + signature.s.toString('hex') + signature.v.toString(16));
    return signature;
}