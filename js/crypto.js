import crypto from 'crypto';
import fs from 'fs';
import ethereumjsUtil from 'ethereumjs-util';
import { isValidAddress, hashPersonalMessage, toBuffer } from 'ethereumjs-util';
import pkg from 'elliptic';
const EC = pkg.ec;

export const block_size = 16; // AES block size in bytes
export const addressSize = 20; // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
export const funcSigSize = 4;
export const ctSize = 32;
export const keySize = 32;
export const hexBase = 16;
export const maxPlaintextBitSize = 256;


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

export function decrypt(key, r, ciphertext, r2=null, ciphertext2=null) {

    if (ciphertext.length !== block_size) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new RangeError("Key size must be 128 bits, received " + key.length + " bytes.");
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length != block_size) {
        throw new RangeError("Random size must be 128 bits, received " + r.length + " bytes.");
    }

    if (r2 !== null) {
        if (r2.length !== block_size) {
            throw new RangeError("Random2 size must be 128 bits, received " + r2.length + " bytes.");
        }
        if (ciphertext2 === null) {
            throw new RangeError("Ciphertext2 is required.");
        }
    }

    if (ciphertext2 !== null) {
        if (ciphertext2.length !== block_size) {
            throw new RangeError("Ciphertext2 size must be 128 bits, received " + ciphertext2.length + " bytes.");
        }

        if (r2 === null) {
            throw new RangeError("Random2 is required.");
        }
    }

    // Create a new AES decipher using the provided key
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r);

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    let plaintext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i];
    }

    if (r2 !== null && ciphertext2 !== null) {
        // Encrypt the random value 'r' using AES in ECB mode
        const encryptedR2 = cipher.update(r2);

        // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
        const plaintext2 = Buffer.alloc(encryptedR2.length);
        for (let i = 0; i < encryptedR2.length; i++) {
            plaintext2[i] = encryptedR2[i] ^ ciphertext2[i];
        }

        plaintext = Buffer.concat([plaintext, plaintext2]);
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

export function signIT(sender, addr, funcSig, ct, key, eip191=false) {
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
    if (ct.length !== ctSize && ct.length !== 2*ctSize) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${ctSize} bytes in case of 128 bits plaintext or less, or ${2*ctSize} bytes in case of 256 bits plaintext or less`);
    }
    // Ensure the key is the correct length
    if (key.length !== keySize) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${keySize} bytes`);
    }

    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, funcSig, ct]);

    // Concatenate r, s, and v bytes
    if (eip191) {
        return signEIP191(message, key);
    }else {
        return sign(message, key);
    }
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

export function signEIP191(message, key) {
    // Hash the concatenated message using Keccak-256
    const hash = hashPersonalMessage(message);
    // Sign the message
    const signature =  ethereumjsUtil.ecsign(hash, key);
    // Convert r, s, and v components to bytes
    return Buffer.concat([Buffer.from(signature.r), Buffer.from(signature.s), Buffer.from([signature.v])]);
}

function writeBigUInt128BE(buffer, value, offset = 0) {
    const hexString = value.toString(hexBase).padStart(ctSize, '0');
    const bytes = Buffer.from(hexString, 'hex');
    bytes.copy(buffer, offset);
}

export function writeBigUInt256BE(buffer, value, offset = 0) {
    const hexString = value.toString(hexBase).padStart(ctSize*2, '0');
    const bytes = Buffer.from(hexString, 'hex');
    if (buffer.length > bytes.length) {
        offset = buffer.length - bytes.length;
    }
    bytes.copy(buffer, offset);
}

export function prepareCompactIT(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191=false) {
    const bitSize = plaintext.toString(2).length;
    if (bitSize > maxPlaintextBitSize/2) {
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepareCompactIT256 instead.");
    }
    const { ct, signature } = prepareIT(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191, false);
    // Convert Buffer to uint256 (BigInt) for Solidity compatibility
    const ciphertextUint = BigInt('0x' + ct.toString('hex'));
    return { ciphertext: ciphertextUint, signature };
}

export function prepareCompactIT256(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191=false) {
    const bitSize = plaintext.toString(2).length;
    if (bitSize > maxPlaintextBitSize) {
        throw new RangeError("Plaintext size must be between 128 and 256 bits.");
    }

    const { ct, signature } = prepareIT(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191, true);
    const ciphertextHigh = ct.slice(0, ctSize);
    const ciphertextLow = ct.slice(ctSize);

    // Convert Buffer to uint256 (BigInt) for Solidity compatibility
    const ciphertextHighUint = BigInt('0x' + ciphertextHigh.toString('hex'));
    const ciphertextLowUint = BigInt('0x' + ciphertextLow.toString('hex'));

    return { ciphertext: {ciphertextHigh: ciphertextHighUint, ciphertextLow: ciphertextLowUint}, signature };
    
}

export function prepareIT(plaintext, userAesKey, sender, contract, hashFunc, signingKey, eip191=false, is256bit=false) {

    // Get the bytes of the sender, contract, and function signature
    const senderBytes = toBuffer(sender)
    const contractBytes = toBuffer(contract)
    
    // Convert the plaintext to bytes
    const plaintextBigInt = BigInt(plaintext);
    const bitSize = plaintextBigInt.toString(2).length;

    let ct;

    if (bitSize <= maxPlaintextBitSize/2) {
        const plaintextBytes = Buffer.alloc(block_size); // Allocate a buffer of size 16 bytes
        writeBigUInt128BE(plaintextBytes, plaintextBigInt); // Write the uint128 value to the buffer as big-endian
        // Encrypt the plaintext using AES key
        const {ciphertext, r} = encrypt(userAesKey, plaintextBytes);
        if (is256bit) {
            const zero = BigInt(0);
            const zeroBytes = Buffer.alloc(block_size);
            writeBigUInt128BE(zeroBytes, zero);
            const {ciphertext: ciphertextHigh, r: rHigh} = encrypt(userAesKey, zeroBytes);
            ct = Buffer.concat([ciphertextHigh, rHigh, ciphertext, r]);
        } else {
            ct = Buffer.concat([ciphertext, r]);
        }
    } else if (bitSize <= maxPlaintextBitSize) {
        const plaintextBytes = Buffer.alloc(ctSize); // Allocate a buffer of size 32 bytes
        writeBigUInt256BE(plaintextBytes, plaintextBigInt); // Write the uint256 value to the buffer as big-endian
        
        // Encrypt each part of the plaintext using AES key
        const resultHigh = encrypt(userAesKey, plaintextBytes.slice(0, block_size));
        const resultLow = encrypt(userAesKey, plaintextBytes.slice(block_size));
        
        // Now destructure
        const { ciphertext: ciphertextHigh, r: rHigh } = resultHigh;
        const { ciphertext: ciphertextLow, r: rLow } = resultLow;

        ct = Buffer.concat([ciphertextHigh, rHigh, ciphertextLow, rLow]);
    } else if (bitSize > maxPlaintextBitSize) {
        throw new RangeError("Plaintext size must be 256 bits or smaller.");
    }

    // Sign the message
    const signature = signIT(senderBytes, contractBytes, hashFunc, ct, signingKey, eip191);

    return { ct, signature };
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

/**
 * This function recovers a user's key by decrypting two encrypted key shares with the given private key, 
 * and then XORing the two key shares together.
 *
 * @param {Buffer} privateKey - The private key used to decrypt the key shares.
 * @param {Buffer} encryptedKeyShare0 - The first encrypted key share.
 * @param {Buffer} encryptedKeyShare1 - The second encrypted key share.
 *
 * @returns {Buffer} - The recovered user key.
 */
export function recoverUserKey(privateKey, encryptedKeyShare0, encryptedKeyShare1) {
    const decryptedKeyShare0 = decryptRSA(privateKey, encryptedKeyShare0);
    const decryptedKeyShare1 = decryptRSA(privateKey, encryptedKeyShare1);

    const aesKey = Buffer.alloc(decryptedKeyShare0.length);
    for (let i = 0; i < decryptedKeyShare0.length; i++) {
        aesKey[i] = decryptedKeyShare0[i] ^ decryptedKeyShare1[i];
    }

    return aesKey;
}

export function getFuncSig(functionSig) {
    // Encode the string to a Buffer
    const functionBytes = Buffer.from(functionSig, "utf8");

    // Hash the function signature using Keccak-256
    const hash = ethereumjsUtil.keccak256(functionBytes);

    return hash.subarray(0, 4);
}