import { assert } from 'chai';
import { encrypt, decrypt, loadAesKey, writeAesKey, generateAesKey, sign, generateRSAKeyPair, encryptRSA, decryptRSA } from './crypto.js';
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

    // Test case for verify signature
    it('should sign and verify the signature', () => {
        // Simulate the generation of random bytes
        const sender = crypto.randomBytes(addressSize);
        const addr = crypto.randomBytes(addressSize);
        const funcSig = crypto.randomBytes(signatureSize);
        const nonce = crypto.randomBytes(nonceSize);
        let key = crypto.randomBytes(keySize);
        
        // Create a ciphertext
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(100);
        const aeskey = generateAesKey();
        const { ciphertext, r } = encrypt(aeskey, plaintextBuffer);
        let ct = Buffer.concat([ciphertext, r]);

        // Generate the signature
        const signatureBytes = sign(sender, addr, funcSig, nonce, ct, key);
        
        // Extract r, s, and v as buffers
        let rBytes = Buffer.alloc(32);
        let sBytes = Buffer.alloc(32);
        let vByte = Buffer.alloc(1);

        signatureBytes.copy(rBytes, 0, 0, 32);
        signatureBytes.copy(sBytes, 0, 32, 64);
        signatureBytes.copy(vByte, 0, 64);

        // Convert v buffer back to integer
        let v = vByte.readUInt8();

        // Add 27 to v if necessary to make it compatible with Ethereum
        if (v !== 27 && v !== 28) {
            v += 27;
        }

        // Verify the signature
        const expectedPublicKey = ethereumjsUtil.privateToPublic(key);
        const expectedAddress = ethereumjsUtil.toChecksumAddress('0x' + expectedPublicKey.toString('hex'));
        
        const message = Buffer.concat([sender, addr, funcSig, nonce, ct]);
        const hash = ethereumjsUtil.keccak256(message);
        
        // Recover the public key from the signature
        const publicKey = ethereumjsUtil.ecrecover(hash, v, rBytes, sBytes);
        // Derive the Ethereum address from the recovered public key
        const address = ethereumjsUtil.toChecksumAddress('0x' + publicKey.toString('hex'));
        
        // Compare the derived address with the expected signer's address
        const isVerified = address === expectedAddress;

        assert.strictEqual(isVerified, true);
    });

    // Test case for verify signature
    it('should sign a fixed message and write the signature to a file', () => {
        // Simulate the generation of random bytes
        const sender = Buffer.from('ee706584bf9a9414997840785b14d157bf315abab2745f60ebe2ba4d9971718181dcdf99154cdfed368256fe1f0fb4bd952296377b70f19817a0511d5a45a28e69a2c0f6cf28e4e7d52f6d966081579d115a22173b91efe5411622df117324d0b23bb13f5dd5f95d72a32aeb559f859179ffa2c84db6a4315af1aab83b03a2b02e7dd9501dd68e7529c9cc8a7140d011b2bf9845a5325a8e2703cae75713a871', 'hex');
        const addr = Buffer.from('f2c401492410f9f8842a1b028a88c057f92539c14ca814dc67baad26884b65b3d8491accac662aee08353aed84e00bb856d12e6d816072be64cb87379347ab921e9772b31d47ee70c0bac432366bd669f58a8791a945ddee9a8f2b5d8b8c2a3b891b81d294ddf91bd9176875ce83887dedd6a62e70500bd9017d74dca4f2e284c69cd46ec889ffb9196dbd250e7e0183a2a1502d086baa8e4de2f6c8715cdf3c', 'hex');
        const funcSig = Buffer.from('eb7dcb05', 'hex');
        const nonce = Buffer.from('0cdab3e6457ec793', 'hex');
        const ct = Buffer.from('195c6bbabb9483f5f6d0b95fa5486ebe1ad365fa21bf55f7158b87d560212207', 'hex');
        const key = Buffer.from('e96d2e93781c3ee08d98d650c4a9888cc272675dddde76fdedc699871765d7a1', 'hex');

        // Generate the signature
        const signature = sign(sender, addr, funcSig, nonce, ct, key);

        const filename = 'jsSignature.txt'; // Name of the file to write to

        // Convert hexadecimal string to buffer
        let sigString = signature.toString('hex');

        // Write buffer to the file
        fs.writeFile(filename, sigString, (err) => {
            if (err) {
                console.error('Error writing to file:', err);
                return;
            }
        });
    });

    // Test case for test rsa encryption scheme
    it('should encrypt and decrypt a message using RSA scheme', () => {
        const plaintext = Buffer.from('hello world');

        const { publicKey, privateKey } = generateRSAKeyPair();

        const ciphertext = encryptRSA(publicKey, plaintext);
        
        const hexString = privateKey.toString('hex') + "\n" + publicKey.toString('hex');

        // Write buffer to the file
        const filename = 'jsRSAEncryption.txt'; // Name of the file to write to
        fs.writeFile(filename, hexString, (err) => {
            if (err) {
                console.error('Error writing to file:', err);
                return;
            }
        });

        const decrypted = decryptRSA(privateKey, ciphertext);

        assert.deepStrictEqual(plaintext, decrypted);
    });

    function readHexFromFile(filename) {
        return new Promise((resolve, reject) => {
            fs.readFile(filename, 'utf8', (err, data) => {
                if (err) {
                    reject(err);
                    return;
                }
    
                const lines = data.trim().split('\n');
                if (lines.length >= 3) {
                    const hexData1 = lines[0].trim();
                    const hexData2 = lines[1].trim();
                    const hexData3 = lines[2].trim();
                    resolve([hexData1, hexData2, hexData3]);
                } else {
                    reject(new Error('Not enough lines in the file.'));
                }
            });
        });
    }

    // Test case for test rsa decryption scheme
    it('should decrypt a message using RSA scheme', () => {
        const plaintext = Buffer.from('hello world');

        // Define private key and ciphertext
        
        readHexFromFile('jsRSAEncryption.txt')
            .then(([hexData1, hexData2, hexData3]) => {
                const privateKey = Buffer.from(hexData1, 'hex');
                const ciphertext = Buffer.from(hexData3, 'hex');

                const decrypted = decryptRSA(privateKey, ciphertext);
                assert.deepStrictEqual(plaintext, decrypted);
            })
            .catch(error => {
                console.error("Error reading file:", error);
        });
        
        fs.unlinkSync('jsRSAEncryption.txt');
    });

});


