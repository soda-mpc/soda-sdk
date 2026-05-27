import {
    ADDRESS_SIZE,
    BLOCK_SIZE,
    decrypt, decryptRSA,
    encrypt, encryptRSA,
    generateAesKey,
    generateECDSAPrivateKey, generateRSAKeyPair, getFuncSig, HEX_BASE, prepareIT, prepareMessage, signIT, prepareIT256, writeBigUInt256BE, CT_SIZE,
    verifySignatures, extractSignatureComponents,
    loadAesKey, writeAesKey, signEIP712, buildOnboardUserTypedData, buildEncryptToUserTypedData, recoverAddressFromEIP712Signature
} from "./crypto"
import fs from 'fs';
import crypto from 'crypto';
import {
    Address,
    ecrecover,
    hashPersonalMessage,
    pubToAddress,
    privateToPublic,
    toBuffer,
    toChecksumAddress
} from "ethereumjs-util";
import {ethers} from "ethers";
import * as assert from "node:assert";

function uint8ArrayToBigInt(uint8Array: Uint8Array): bigint {
    let value = BigInt(0);
    for (let i = 0; i < uint8Array.length; i++) {
        value = (value << 8n) | BigInt(uint8Array[i]);
    }
    return value;
}

describe('Crypto Tests', () => {

    // Test case for encrypt and decrypt
    it('should encrypt and decrypt successfully', () => {
        // Arrange
        const plaintextInteger = 100;
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(plaintextInteger);

        // Act
        const key = generateAesKey();

        const { ciphertext, r } = encrypt(key, plaintextBuffer);

        const decryptedBuffer = decrypt(key, r, ciphertext);

        // Write Buffer to file to later check in Go
        fs.writeFileSync("test_tsEncryption.txt", key.toString('hex') + "\n" + ciphertext.toString('hex') + "\n" + r.toString('hex'));

        const decryptedInteger =  uint8ArrayToBigInt(decryptedBuffer)

        // Assert
        assert.strictEqual(decryptedInteger, BigInt(plaintextInteger));
    });

    // Test case for load and write AES key
    it('should load and write AES key successfully', () => {
        // Arrange
        const key = generateAesKey();

        // Act
        writeAesKey('key.txt', key);
        const loadedKey = loadAesKey('key.txt');

        // Assert
        assert.deepStrictEqual(loadedKey, key);

        // Delete the key file
        fs.unlink('key.txt', (err: NodeJS.ErrnoException | null) => {
            if (err) {
                console.error('Error deleting file:', err);
            }
        });

    });

    // Test case for invalid plaintext size
    it('should throw error for invalid plaintext size', () => {
        // Arrange
        const key = generateAesKey();
        const plaintextBuffer = Buffer.alloc(20); // Bigger than 128 bits

        // Act and Assert
         assert.throws(() => encrypt(key, plaintextBuffer), RangeError);

    });

    // Test case for invalid ciphertext size
    it('should throw error for invalid ciphertext size', () => {
        // Arrange
        const key = generateAesKey();
        const ciphertext = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        const r = Buffer.alloc(BLOCK_SIZE);

        // Act and Assert
        assert.throws(() => decrypt(key, r, ciphertext), RangeError);
    });

    // Test case for invalid random size
    it('should throw error for invalid random size', () => {
        // Arrange
        const key = generateAesKey();
        const r = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits
        const ciphertext = Buffer.alloc(BLOCK_SIZE);

        // Act and Assert
        assert.throws(() => decrypt(key, r, ciphertext), RangeError);
    });

    // Test case for invalid key size
    it('should throw error for invalid key size', () => {
        // Arrange
        const key = Buffer.from([0x01, 0x02, 0x03]); // Smaller than 128 bits

        // Act and Assert
        // Test invalid key size when writing key
        assert.throws(() => writeAesKey('key.txt', key), RangeError);

        // Test invalid key size when encrypting
        const plaintextBuffer = Buffer.alloc(BLOCK_SIZE);
        assert.throws(() => encrypt(key, plaintextBuffer), RangeError);

        // Test invalid key size when decrypting
        const ciphertext = Buffer.alloc(BLOCK_SIZE);
        const r = Buffer.alloc(BLOCK_SIZE);
        assert.throws(() => decrypt(key, r, ciphertext), RangeError);
    });

    // Test case for verify signature
    it('should sign and verify the signature', () => {
        // Arrange
        // Simulate the generation of random bytes
        const sender = crypto.randomBytes(ADDRESS_SIZE);
        const addr = crypto.randomBytes(ADDRESS_SIZE);
        let key = generateECDSAPrivateKey();

        // Create a ciphertext
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(100);
        const aeskey = generateAesKey();
        const { ciphertext, r } = encrypt(aeskey, plaintextBuffer);
        let ct = Buffer.concat([ciphertext, r]);

        // Act
        // Generate the signature
        const signatureBytes = signIT(sender, addr, ct, key);

        const publicKey = privateToPublic(key);
        const signerAddress = toChecksumAddress('0x' + pubToAddress(publicKey).toString('hex'));
        const message = Buffer.concat([sender, addr, ct]);
        const verified = verifySignatures(message, [signatureBytes], [signerAddress]);

        // Assert
        assert.strictEqual(verified, true);
    });

    // Test case for verify signature
    it('should sign and verify the EIP191 signature', () => {
        // Arrange
        // Simulate the generation of random bytes
        const sender = crypto.randomBytes(ADDRESS_SIZE);
        const addr = crypto.randomBytes(ADDRESS_SIZE);
        let key = generateECDSAPrivateKey();

        // Create a ciphertext
        const plaintextBuffer = Buffer.alloc(1);
        plaintextBuffer.writeUInt8(100);
        const aeskey = generateAesKey();
        const { ciphertext, r } = encrypt(aeskey, plaintextBuffer);
        let ct = Buffer.concat([ciphertext, r]);

        // Act
        // Generate the signature
        const signatureBytes = signIT(sender, addr, ct, key, true);

        const {rBytes, sBytes, vByte} = extractSignatureComponents(signatureBytes);

        // Verify the signature
        const expectedPublicKey = privateToPublic(key);
        const expectedAddress = toChecksumAddress('0x' + expectedPublicKey.toString('hex'));

        const message = Buffer.concat([sender, addr, ct]);
        const hash = hashPersonalMessage(message);

        // Recover the public key from the signature
        const publicKey = ecrecover(hash, vByte, rBytes, sBytes);
        // Derive the Ethereum address from the recovered public key
        const address = toChecksumAddress('0x' + publicKey.toString('hex'));

        // Compare the derived address with the expected signer's address
        const isVerified = address === expectedAddress;

        // Assert
        assert.strictEqual(isVerified, true);
    });

    it('should sign and recover the EIP712 onboard signature', async () => {
        const { publicKey } = generateRSAKeyPair();
        const key = generateECDSAPrivateKey();
        const wallet = new ethers.Wallet(ethers.hexlify(key));
        const address = Buffer.from(wallet.address.slice(2), 'hex');

        const typedData = buildOnboardUserTypedData(publicKey, address, 0);
        const signature = await signEIP712(typedData, key);
        const recoveredAddress = recoverAddressFromEIP712Signature(typedData, signature);

        assert.strictEqual(recoveredAddress.toLowerCase(), wallet.address.toLowerCase());
    });

    it('should sign and recover the EIP712 encrypt-to-user signature', async () => {
        const key = generateECDSAPrivateKey();
        const wallet = new ethers.Wallet(ethers.hexlify(key));
        const handle = Buffer.from('81ff8a56f19f4ffd576e57a01f3c0f256de80517a4e4385470d1c33fe7804fe7', 'hex');

        const typedData = buildEncryptToUserTypedData([handle], null, 11155111);
        const signature = await signEIP712(typedData, key);
        const recoveredAddress = recoverAddressFromEIP712Signature(typedData, signature);

        assert.strictEqual(recoveredAddress.toLowerCase(), wallet.address.toLowerCase());
    });

    // Test case for verify signature
    it('should sign a fixed message and write the signature to a file', () => {
        // Arrange
        // Simulate the generation of random bytes
        const sender = Buffer.from('8f01160c98e5cdfa625197849c85cf5fc1f76b1b', 'hex');
        const addr = Buffer.from('69413851f025306dbe12c48ff2225016fc5bbe1b', 'hex');
        const ct = Buffer.from('81ff8a56f19f4ffd576e57a01f3c0f256de80517a4e4385470d1c33fe7804fe7', 'hex');
        const key = Buffer.from('3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e', 'hex');

        // Act
        // Generate the signature
        const signature = signIT(sender, addr, ct, key);

        const filename = 'test_tsSignature.txt'; // Name of the file to write to

        // Convert hexadecimal string to buffer
        let sigString = signature.toString('hex');

        // Write buffer to the file, this simulates the communication between the evm (golang) and the user (python/js)
        fs.writeFile(filename, sigString, (err) => {
            if (err) {
                console.error('Error writing to file:', err);
                return;
            }
        });
    });

    it('should prepareMessage using fixed data', async () => {
        // Arrange
        // Simulate the generation of random bytes
        const plaintext = BigInt("100");
        const userKey = 'b3c3fe73c1bb91862b166a29fe1d63e9';
        const senderAddress ='0x8f01160c98e5cdfa625197849c85cf5fc1f76b1b';
        const contractAddress = '0x69413851f025306dbe12c48ff2225016fc5bbe1b';
        const signingKey = '0x3840f44be5805af188e9b42dda56eb99eefc88d7a6db751017ff16d0c5f8143e';

        // Act
        // Generate the signature
        const {
            message
        } = prepareMessage(plaintext, senderAddress, userKey, contractAddress);

        const wallet = new ethers.Wallet(signingKey);
        const signature = await wallet.signMessage(message);

        const recoveredAddress = ethers.verifyMessage(message, signature);

        assert.strictEqual(recoveredAddress.toLowerCase(), senderAddress.toLowerCase());
    });


    // Test case for verify signature
    it('should prepare IT using fixed data', () => {
        // Arrange
        // Simulate the generation of random bytes
        const plaintext = BigInt("100");
        const userKey = Buffer.from('b3c3fe73c1bb91862b166a29fe1d63e9', 'hex');;
        const sender = new Address(toBuffer(Buffer.from('8f01160c98e5cdfa625197849c85cf5fc1f76b1b', 'hex')));
       
        // Act
        // Generate the signature
        const {userAddress, ctInt} = prepareIT(plaintext, userKey, sender.toBuffer());

        const ctHex = ctInt.toString(HEX_BASE).padStart(CT_SIZE * 2, '0');
        // Create a Buffer to hold the bytes (CT_SIZE = 32 bytes = 2 * BLOCK_SIZE)
        const ctBuffer = Buffer.from(ctHex, 'hex');

        // Write Buffer to file to later check in Go
        fs.writeFileSync("test_tsIT.txt", ctHex);

        // Decrypt the ct and check the decrypted value is equal to the plaintext
        const decryptedBuffer = decrypt(userKey, ctBuffer.subarray(BLOCK_SIZE, ctBuffer.length), ctBuffer.subarray(0, BLOCK_SIZE));

        // Convert the plaintext to bytes
        const hexString = plaintext.toString(16);
        const plaintextBytes = Buffer.from(hexString, 'hex');
        // Assert
        const expectedBytes = decryptedBuffer.subarray(decryptedBuffer.length - plaintextBytes.length, decryptedBuffer.length)
        assert.deepStrictEqual(plaintextBytes.toString('hex'), Buffer.from(expectedBytes).toString('hex'));
        const intResult = uint8ArrayToBigInt(decryptedBuffer);
        assert.deepStrictEqual(plaintext, intResult);
    });

    // Test case for verify signature
    it('should prepare IT 256 bits using fixed data', () => {
        // Arrange
        // Simulate the generation of random bytes
        const plaintext = BigInt("34028236692093846346337460743176821145600");
        const userKey = Buffer.from('b3c3fe73c1bb91862b166a29fe1d63e9', 'hex');;
        const sender = new Address(toBuffer(Buffer.from('8f01160c98e5cdfa625197849c85cf5fc1f76b1b', 'hex')));
        
        // Act
        // Generate the signature
        const {userAddress, ciphertext} = prepareIT256(plaintext, userKey, sender.toBuffer());

        const ctHighBytes = Buffer.alloc(CT_SIZE); // Allocate a buffer of size 32 bytes
        writeBigUInt256BE(ctHighBytes, ciphertext.ciphertextHigh); // Write the uint256 value to the buffer as big-endian
        const ctLowBytes = Buffer.alloc(CT_SIZE); // Allocate a buffer of size 32 bytes
        writeBigUInt256BE(ctLowBytes, ciphertext.ciphertextLow); // Write the uint256 value to the buffer as big-endian
        // Decrypt the ct and check the decrypted value is equal to the plaintext
        const decryptedBuffer = decrypt(userKey, ctHighBytes.subarray(BLOCK_SIZE, ctHighBytes.length), ctHighBytes.subarray(0, BLOCK_SIZE), ctLowBytes.subarray(BLOCK_SIZE, ctLowBytes.length), ctLowBytes.subarray(0, BLOCK_SIZE));

        // Convert the plaintext to bytes
        const hexString = plaintext.toString(16).padStart(64, '0');
        const plaintextBytes = Buffer.from(hexString, 'hex'); 

        // Assert
        const expectedBytes = decryptedBuffer.subarray(decryptedBuffer.length - plaintextBytes.length, decryptedBuffer.length)
        assert.deepStrictEqual(plaintextBytes.toString('hex'), Buffer.from(expectedBytes).toString('hex'));
        const intResult = uint8ArrayToBigInt(decryptedBuffer);
        assert.deepStrictEqual(plaintext, intResult);
    });

    // Test case for test rsa encryption scheme
    it('should encrypt and decrypt a message using RSA scheme', () => {
        // Arrange
        const plaintext ='hello world';
        const plaintextBuffer = Buffer.from(plaintext);

        const { publicKey, privateKey } = generateRSAKeyPair();

        // Act
        const ciphertext = encryptRSA(publicKey, plaintext);

        const hexString = privateKey.toString('hex') + "\n" + publicKey.toString('hex') + "\n" + Buffer.from(ciphertext).toString('hex');

        // Write buffer to the file
        const filename = 'test_tsRSAEncryption.txt'; // Name of the file to write to
        fs.writeFileSync(filename, hexString);

        const decrypted = decryptRSA(privateKey, Buffer.from(ciphertext).toString('hex'));

        // Assert
        assert.deepStrictEqual(plaintextBuffer, Buffer.from(decrypted));
    });

    function readHexFromFile(filename:string) {
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
    it('should decrypt a message using RSA scheme', async () => {
        // Arrange
        const plaintext = Buffer.from('hello world');

        // Act
        // Read private key and ciphertext
        // Reading from file simulates the communication between the evm (golang) and the user (python/js)
        try {
            const value = await readHexFromFile('test_tsRSAEncryption.txt');
            const [hexData1, hexData2, hexData3] = value as [string, string, string];
            const privateKey = Buffer.from(hexData1, 'hex');
            const ciphertext = Buffer.from(hexData3, 'hex').toString('hex');

            const decrypted = decryptRSA(privateKey, ciphertext);

            const decryptedBuffer = Buffer.from(decrypted);

            // Assert
            assert.deepStrictEqual(plaintext, decryptedBuffer);
            fs.unlinkSync('test_tsRSAEncryption.txt');
        } catch (error) {
            console.error("Error reading file:", error);
            throw error;
        }
    });

    // Test case for test function signature
    it('should hash a function signature', () => {
        // Arrange
        const functionSig = 'sign(bytes)';

        // Act
        const hash = getFuncSig(functionSig);

        const filename = 'test_tsFunctionKeccak.txt'; // Name of the file to write to
        // Write Buffer to file
        fs.writeFileSync(filename, hash.toString('hex'));

    });
});


