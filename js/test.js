const assert = require('assert');
const { encrypt, decrypt, loadAesKey, writeAesKey, generateAesKey } = require('./crypto');
const fs = require('fs');

// Test case for encrypt and decrypt
const testEncryptDecrypt = () => {

    const plaintextInteger = 100; // Example integer value
    const plaintextBuffer = Buffer.alloc(1); // Assuming a 8-bit integer
    plaintextBuffer.writeUInt8(plaintextInteger);

    const key = generateAesKey();

    const { ciphertext, r } = encrypt(key, plaintextBuffer);
    const decryptedBuffer = decrypt(key, r, ciphertext);

    const decryptedInteger = decryptedBuffer.readUInt8();

    assert.strictEqual(decryptedInteger, plaintextInteger);
};

// Test case for load and write AES key
const testLoadWriteAesKey = () => {
    const key = generateAesKey();
    writeAesKey('key.txt', key);
    const loadedKey = loadAesKey('key.txt');

    assert.deepStrictEqual(loadedKey, key);

    // Delete the key file
    fs.unlink('key.txt', (err) => {
        if (err) {
            console.error('Error deleting file:', err);
        } 
    });
};

const test_invalid_plaintext_size = () => {
    const key = generateAesKey();
    
    const plaintextBuffer = Buffer.alloc(20); // Bigger than 128 bit

    assert.throws(() => encrypt(key, plaintextBuffer), { name: 'RangeError'});
};

const test_invalid_ciphertext_size = () => {
    const key = generateAesKey();
    
    const ciphertext = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bit
    const r = Buffer.alloc(16);

    assert.throws(() => decrypt(key, r, ciphertext), { name: 'RangeError'});
};

const test_invalid_random_size = () => {
    const key = generateAesKey();
    
    const r = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bit
    const ciphertext = Buffer.alloc(16);

    assert.throws(() => decrypt(key, r, ciphertext), { name: 'RangeError'});
};

const test_invalid_key_size = () => {
    const key = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bit

    assert.throws(() => writeAesKey('key.txt', key), { name: 'RangeError'});

    const plaintextBuffer = Buffer.alloc(16);

    assert.throws(() => encrypt(key, plaintextBuffer), { name: 'RangeError'});

    const ciphertext = Buffer.alloc(16);
    const r = Buffer.alloc(16);

    assert.throws(() => decrypt(key, r, ciphertext), { name: 'RangeError'});
};

// Run the tests
try {
    testEncryptDecrypt();
    testLoadWriteAesKey();
    test_invalid_plaintext_size();
    test_invalid_ciphertext_size();
    test_invalid_random_size();
    test_invalid_key_size();
    console.log('All tests passed!');
} catch (error) {
    console.error('Test failed:', error.message);
}
