import { assert } from 'chai';
import { encrypt, decrypt, loadAesKey, writeAesKey, generateAesKey, sign } from './crypto.js';
import { block_size, addressSize, signatureSize, nonceSize, ctSize, keySize } from './crypto.js';
import fs from 'fs';
import crypto from 'crypto';
import ethereumjsUtil  from 'ethereumjs-util';

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

    // Test case for invalid key size
    it('should sign and verify the signature', () => {
        // Simulate the generation of random bytes
        const sender = crypto.randomBytes(addressSize);
        const addr = crypto.randomBytes(addressSize);
        const funcSig = crypto.randomBytes(signatureSize);
        const nonce = crypto.randomBytes(nonceSize);
        let key = crypto.randomBytes(keySize);
        // const sender = Buffer.alloc(addressSize); // All zeros with length AddressSize
        // const addr = Buffer.alloc(addressSize); // All zeros with length AddressSize
        // const funcSig = Buffer.alloc(signatureSize); // All zeros with length SignatureSize
        // const nonce = Buffer.alloc(nonceSize); // All zeros with length NonceSize

        // Create a ciphertext
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(100);
        const aeskey = generateAesKey();
        const { ciphertext, r } = encrypt(aeskey, plaintextBuffer);
        let ct = Buffer.concat([ciphertext, r]);

        // Decode hex strings
        // ct = Buffer.from('1d87ced4fd3f916ea7474dfe320a5de096a89dcf3d8a6d9dd318e38ea9f23189', 'hex');
        // key = Buffer.from('f14edf53952e2886057b3afdd23a24b63a577ebe474880f76d86aa7ca11da370', 'hex');

        // Generate the signature
        const signature = sign(sender, addr, funcSig, nonce, ct, key);

        // Verify the signature
        const expectedPublicKey = ethereumjsUtil.privateToPublic(key);
        const expectedAddress = ethereumjsUtil.toChecksumAddress('0x' + expectedPublicKey.toString('hex'));
        
        const message = Buffer.concat([sender, addr, funcSig, nonce, ct]);
        const hash = ethereumjsUtil.keccak256(message);
        
        // Recover the public key from the signature
        const publicKey = ethereumjsUtil.ecrecover(hash, signature.v, signature.r, signature.s);
        // Derive the Ethereum address from the recovered public key
        const address = ethereumjsUtil.toChecksumAddress('0x' + publicKey.toString('hex'));

        // Compare the derived address with the expected signer's address
        const isVerified = address === expectedAddress;

        assert.strictEqual(isVerified, true);
    });
});
