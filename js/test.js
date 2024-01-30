const assert = require('assert');
const { encrypt, decrypt, loadAesKey, writeAesKey, generateAndWriteAesKey } = require('./crypto');

// Test case for encrypt and decrypt
const testEncryptDecrypt = () => {

    const plaintextInteger = 100; // Example integer value
    const plaintextBuffer = Buffer.alloc(1); // Assuming a 8-bit integer
    plaintextBuffer.writeUInt8(plaintextInteger);

    const key = generateAndWriteAesKey('key.txt');

    const { ciphertext, r } = encrypt(key, plaintextBuffer);
    const decryptedBuffer = decrypt(key, r, ciphertext);

    const decryptedInteger = decryptedBuffer.readUInt8();

    assert.strictEqual(decryptedInteger, plaintextInteger);
};

// Test case for load and write AES key
const testLoadWriteAesKey = () => {
    const key = generateAndWriteAesKey('key.txt');
    const loadedKey = loadAesKey('key.txt');

    assert.deepStrictEqual(loadedKey, key);
};

const test_invalid_plaintext_size = () => {
    const key = generateAndWriteAesKey('key.txt');
    
    const plaintextBuffer = Buffer.alloc(20); // Bigger than 128 bit

    assert.throws(() => encrypt(key, plaintextBuffer), { name: 'Error', message: 'Plaintext size must be 128 bits or smaller.' });
};

const test_invalid_ciphertext_size = () => {
    const key = generateAndWriteAesKey('key.txt');
    
    const ciphertext = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bit
    const r = Buffer.alloc(16);

    assert.throws(() => decrypt(key, r, ciphertext), { name: 'Error', message: 'Ciphertext size must be 128 bits.' });
};

const test_invalid_random_size = () => {
    const key = generateAndWriteAesKey('key.txt');
    
    const r = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bit
    const ciphertext = Buffer.alloc(16);

    assert.throws(() => decrypt(key, r, ciphertext), { name: 'Error', message: 'Random size must be 128 bits.' });
};

const test_invalid_key_size = () => {
    const key = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bit

    assert.throws(() => writeAesKey('key.txt', key), { name: 'Error', message: 'Invalid key length: 3 bytes, must be 16 bytes' });

    const plaintextBuffer = Buffer.alloc(16);

    assert.throws(() => encrypt(key, plaintextBuffer), { name: 'Error', message: 'Key size must be 128 bits.' });

    const ciphertext = Buffer.alloc(16);
    const r = Buffer.alloc(16);

    assert.throws(() => decrypt(key, r, ciphertext), { name: 'Error', message: 'Key size must be 128 bits.' });
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
