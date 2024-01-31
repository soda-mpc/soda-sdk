import { assert } from 'chai';
import { encrypt, decrypt, loadAesKey, writeAesKey, generateAesKey } from './crypto.js';
import fs from 'fs';

describe('Crypto Tests', () => {

    // Test case for encrypt and decrypt
    it('should encrypt and decrypt successfully', () => {
        const plaintextInteger = 100;
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(plaintextInteger);

        const key = generateAesKey();

        const { ciphertext, r } = encrypt(key, plaintextBuffer);
        const decryptedBuffer = decrypt(key, r, ciphertext);

        const decryptedInteger = decryptedBuffer.readUInt8();

        assert.strictEqual(decryptedInteger, plaintextInteger);
    });

    // Test case for load and write AES key
    it('should load and write AES key successfully', () => {
        const key = generateAesKey();
        writeAesKey('key.txt', key);
        const loadedKey = loadAesKey('key.txt');

        assert.deepStrictEqual(loadedKey, key);

        // Delete the key file
        fs.unlinkSync('key.txt', (err) => {
            if (err) {
                console.error('Error deleting file:', err);
            } 
        });
    });

    // Test case for invalid plaintext size
    it('should throw error for invalid plaintext size', () => {
        const key = generateAesKey();
        const plaintextBuffer = Buffer.alloc(20); // Bigger than 128 bits

        assert.throws(() => encrypt(key, plaintextBuffer), RangeError);
        
    });

    // Test case for invalid ciphertext size
    it('should throw error for invalid ciphertext size', () => {
        const key = generateAesKey();
        const ciphertext = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        const r = Buffer.alloc(16);

        assert.throws(() => decrypt(key, r, ciphertext), RangeError);
    });

    // Test case for invalid random size
    it('should throw error for invalid random size', () => {
        const key = generateAesKey();
        const r = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        const ciphertext = Buffer.alloc(16);

        assert.throws(() => decrypt(key, r, ciphertext), RangeError);
    });

    // Test case for invalid key size
    it('should throw error for invalid key size', () => {
        const key = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits

        // Test invalid key size when writing key
        assert.throws(() => writeAesKey('key.txt', key), RangeError);

        // Test invalid key size when encrypting
        const plaintextBuffer = Buffer.alloc(16);
        assert.throws(() => encrypt(key, plaintextBuffer), RangeError);

        // Test invalid key size when decrypting
        const ciphertext = Buffer.alloc(16);
        const r = Buffer.alloc(16);
        assert.throws(() => decrypt(key, r, ciphertext), RangeError);
    });

});
