const crypto = require('crypto');
const fs = require('fs');

const block_size = 16; // AES block size in bytes

function encrypt(key, plaintext) {
    
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > block_size) {
        throw new Error("Plaintext size must be 128 bits or smaller.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new Error("Key size must be 128 bits.");
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

function decrypt(key, r, ciphertext) {

    if (ciphertext.length !== block_size) {
        throw new Error("Ciphertext size must be 128 bits.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new Error("Key size must be 128 bits.");
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length != block_size) {
        throw new Error("Random size must be 128 bits.");
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

function loadAesKey(filePath) {
    // Read the hex-encoded contents of the file
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();

    // Decode the hex string to binary
    const key = Buffer.from(hexKey, 'hex');

    // Ensure the key is the correct length
    if (key.length !== block_size) {
        throw new Error(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    return key;
}

function writeAesKey(filePath, key) {
    // Ensure the key is the correct length
    if (key.length !== block_size) {
        throw new Error(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    // Encode the key to hex string
    const hexKey = key.toString('hex');

    // Write the hex-encoded key to the file
    fs.writeFileSync(filePath, hexKey, 'utf8');
}

function generateAesKey() {
    // Generate a random 128-bit AES key
    const key = crypto.randomBytes(block_size);

    return key;
}

module.exports = {
    encrypt,
    decrypt,
    loadAesKey,
    writeAesKey,
    generateAesKey,
};