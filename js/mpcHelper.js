const crypto = require('crypto');
const fs = require('fs');

function encrypt(key, plaintext) {
    const block_size = 16; // AES block size in bytes
    console.log("plaintext Size:", plaintext.length);
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > block_size) {
        throw new Error("Plaintext size must be 128 bits or smaller.");
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
    const ciphertext = Buffer.from(encryptedR.map((byte, index) => byte ^ plaintext_padded[index]));
    console.log("Ciphertext Size:", ciphertext.length);
    return { ciphertext, r };
}

function decrypt(key, r, ciphertext) {
    const block_size = 16; // AES block size in bytes

    if (ciphertext.length !== block_size) {
        throw new Error("Ciphertext size must be 128 bits.");
    }

    // Create a new AES decipher using the provided key
    const decipher = crypto.createCipheriv('aes-128-ecb', key, null);

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = decipher.update(r);

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintext = Buffer.from(encryptedR.map((byte, index) => byte ^ ciphertext[index]));

    return plaintext;
}

function loadAesKey(filePath) {
    // Read the hex-encoded contents of the file
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();

    // Decode the hex string to binary
    const key = Buffer.from(hexKey, 'hex');

    // Ensure the key is the correct length
    if (key.length !== 16) {
        throw new Error(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    return key;
}

function writeAesKey(filePath, key) {
    // Ensure the key is the correct length
    if (key.length !== 16) {
        throw new Error(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    // Encode the key to hex string
    const hexKey = key.toString('hex');

    // Write the hex-encoded key to the file
    fs.writeFileSync(filePath, hexKey, 'utf8');
}

function generateAndWriteAesKey(fileName) {
    // Generate a random 128-bit AES key
    const key = crypto.randomBytes(16);

    // Write the key to the file
    writeAesKey(fileName, key);

    return key;
}

module.exports = {
    encrypt,
    decrypt,
    loadAesKey,
    writeAesKey,
    generateAndWriteAesKey,
};