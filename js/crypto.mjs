import forge from 'node-forge'
import fs from 'fs';
import crypto from 'crypto';
import ethereumjsUtil from 'ethereumjs-util';
import { hashPersonalMessage, toBuffer } from 'ethereumjs-util';
import pkg from 'elliptic';
import {ethers} from "ethers";
const EC = pkg.ec;

export const BLOCK_SIZE = 16; // AES block size in bytes
export const ADDRESS_SIZE = 20; // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
export const CT_SIZE = 32;
export const KEY_SIZE = 32;
export const HEX_BASE = 16;
export const MAX_PLAINTEXT_BIT_SIZE = 256;
export const SIGNATURE_SIZE = 65; // r (32 bytes) + s (32 bytes) + v (1 byte)
export const EC_PUBLIC_KEY_SIZE = 65; // Uncompressed public key (0x04 + X + Y)
export const BYTES32_SIZE = 32; // size of an EIP-712 bytes32 element (e.g. an encrypt-to-user handle)
export const EIP712_DOMAIN_NAME = "SodaLabs MPC";
export const EIP712_DOMAIN_VERSION = "1";

export function encrypt(key, plaintext) {
    
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintext.length > BLOCK_SIZE) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.");
    }

    // Generate a random value 'r' of the same length as the block size
    const r = forge.random.getBytesSync(BLOCK_SIZE)

    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = encryptNumber(r, key)
    
    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintext_padded = Buffer.concat([Buffer.alloc(BLOCK_SIZE - plaintext.length), plaintext]);

    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }

    const uint8ArrayR = new Uint8Array(r.split('').map(c => c.charCodeAt(0)));

    return { ciphertext, r: Buffer.from(uint8ArrayR) };
}

export function decrypt(key, r, ciphertext, r2=null, ciphertext2=null) {

    if (ciphertext.length !== BLOCK_SIZE) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }

    // Ensure key size is 128 bits (16 bytes)
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits, received " + key.length + " bytes.");
    }

    // Ensure random size is 128 bits (16 bytes)
    if (r.length !== BLOCK_SIZE) {
        throw new RangeError("Random size must be 128 bits, received " + r.length + " bytes.");
    }

    if (r2 !== null) {
        if (r2.length !== BLOCK_SIZE) {
            throw new RangeError("Random2 size must be 128 bits, received " + r2.length + " bytes.");
        }
        if (ciphertext2 === null) {
            throw new RangeError("Ciphertext2 is required.");
        }
    }

    if (ciphertext2 !== null) {
        if (ciphertext2.length !== BLOCK_SIZE) {
            throw new RangeError("Ciphertext2 size must be 128 bits, received " + ciphertext2.length + " bytes.");
        }

        if (r2 === null) {
            throw new RangeError("Random2 is required.");
        }
    }

   // Get the encrypted random value 'r'
    const encryptedR = encryptNumber(r, key)

    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    let plaintext = new Uint8Array(BLOCK_SIZE)

    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i]
    }

    if (r2 !== null && ciphertext2 !== null) {
        // Encrypt the random value 'r2' using AES in ECB mode
        const encryptedR2 = encryptNumber(r2, key)

        // XOR the encrypted random value 'r2' with the ciphertext to obtain the plaintext
        const plaintext2 = Buffer.alloc(encryptedR2.length);
        for (let i = 0; i < encryptedR2.length; i++) {
            plaintext2[i] = encryptedR2[i] ^ ciphertext2[i];
        }

        plaintext = Buffer.concat([plaintext, plaintext2]);
    }

    return plaintext
}

export function loadAesKey(filePath) {
    // Read the hex-encoded contents of the file
    const hexKey = fs.readFileSync(filePath, 'utf8').trim();

    // Decode the hex string to binary
    const key = Buffer.from(hexKey, 'hex');

    // Ensure the key is the correct length
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    return key;
}

export function writeAesKey(filePath, key) {
    // Ensure the key is the correct length
    if (key.length !== BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }

    // Encode the key to hex string
    const hexKey = Buffer.from(key).toString('hex');

    // Write the hex-encoded key to the file
    fs.writeFileSync(filePath, hexKey, 'utf8');
}

export function generateAesKey() {
    // Generate a random 128-bit AES key
    const key = forge.random.getBytesSync(BLOCK_SIZE)

    // Convert the string of bytes to a Uint8Array
    const uint8ArrayKey = new Uint8Array(key.split('').map(c => c.charCodeAt(0)));

    return Buffer.from(uint8ArrayKey);
}

export function generateECDSAPrivateKey(){
    // Create an elliptic curve instance using secp256k1 curve
    const ec = new EC('secp256k1');

    // Generate a key pair
    const keyPair = ec.genKeyPair();

    // Get the raw bytes of the private key
    return keyPair.getPrivate().toArrayLike(Buffer, 'be', 32);

}

export function signIT(sender, addr, ct, key, eip191=false) {
    // Ensure all input sizes are the correct length
    if (sender.length !== ADDRESS_SIZE) {
        throw new RangeError(`Invalid sender address length: ${sender.length} bytes, must be ${ADDRESS_SIZE} bytes`);
    }
    if (addr.length !== ADDRESS_SIZE) {
        throw new RangeError(`Invalid contract address length: ${addr.length} bytes, must be ${ADDRESS_SIZE} bytes`);
    }
    if (ct.length !== CT_SIZE && ct.length !== 2*CT_SIZE) {
        throw new RangeError(`Invalid ct length: ${ct.length} bytes, must be ${CT_SIZE} bytes in case of 128 bits plaintext or less, or ${2*CT_SIZE} bytes in case of 256 bits plaintext or less`);
    }
    // Ensure the key is the correct length
    if (key.length !== KEY_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be ${KEY_SIZE} bytes`);
    }

    // Create the message to be signed by concatenating all inputs
    let message = Buffer.concat([sender, addr, ct]);

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

function buildEIP712Domain(chainId) {
    return {
        name: EIP712_DOMAIN_NAME,
        version: EIP712_DOMAIN_VERSION,
        chainId,
    };
}

function buildEIP712DomainTypes() {
    return {
        EIP712Domain: [
            { name: "name", type: "string" },
            { name: "version", type: "string" },
            { name: "chainId", type: "uint256" },
        ],
    };
}

// chainId defaults to 0 on purpose: onboarding is a bubble-level identity
// operation with no chain in the middle. The signature is verified off-chain by
// bubble (not by a per-chain on-chain verifier), and the onboarded identity is
// reused across every chain, so there is no chain to bind it to. Contrast with
// buildEncryptToUserTypedData, where the handle belongs to a specific chain and
// chainId is therefore required.
export function buildOnboardUserTypedData(rsaPublicKey, address, chainId = 0) {
    return {
        types: {
            ...buildEIP712DomainTypes(),
            OnboardUser: [
                { name: "rsaPublicKey", type: "bytes" },
                { name: "address", type: "address" },
            ],
        },
        primaryType: "OnboardUser",
        domain: buildEIP712Domain(chainId),
        message: {
            rsaPublicKey: ethers.hexlify(rsaPublicKey),
            address: ethers.getAddress(ethers.hexlify(address)),
        },
    };
}

export function buildEncryptToUserTypedData(handles, owner, chainId) {
    const ownerAddress = owner && owner.length > 0
        ? ethers.getAddress(ethers.hexlify(owner))
        : ethers.ZeroAddress;

    return {
        types: {
            ...buildEIP712DomainTypes(),
            EncryptToUser: [
                { name: "handles", type: "bytes32[]" },
                { name: "owner", type: "address" },
            ],
        },
        primaryType: "EncryptToUser",
        domain: buildEIP712Domain(chainId),
        message: {
            handles: handles.map((handle, i) => {
                const hex = ethers.hexlify(handle);
                if (ethers.dataLength(hex) !== BYTES32_SIZE) {
                    throw new Error(`handles[${i}] must be exactly ${BYTES32_SIZE} bytes (bytes32), got ${ethers.dataLength(hex)}`);
                }
                return hex;
            }),
            owner: ownerAddress,
        },
    };
}

export async function signEIP712(typedData, key) {
    const wallet = new ethers.Wallet(ethers.hexlify(key));
    const messageTypes = { [typedData.primaryType]: typedData.types[typedData.primaryType] };
    const signature = await wallet.signTypedData(
        typedData.domain,
        messageTypes,
        typedData.message,
    );
    return Buffer.from(ethers.getBytes(signature));
}

export function recoverAddressFromEIP712Signature(typedData, signature) {
    const messageTypes = { [typedData.primaryType]: typedData.types[typedData.primaryType] };
    return ethers.verifyTypedData(
        typedData.domain,
        messageTypes,
        typedData.message,
        ethers.hexlify(signature),
    );
}

/**
 * Prepares a message by encrypting the given plaintext and constructing the message. This message needs to be signed to create an IT.
 * @param {bigint} plaintext - The plaintext value to be encrypted as a BigInt.
 * @param {string} signerAddress - The address of the signer (Ethereum address).
 * @param {string} aesKey - The AES key used for encryption (32 bytes as a hex string).
 * @param {string} contractAddress - The address of the contract (Ethereum address).
 * @returns {Object} - An object containing the encrypted integer and the message.
 * @throws {TypeError} - Throws if any of the input parameters are of invalid types or have incorrect lengths.
 */
export function prepareMessage(plaintext, signerAddress, aesKey, contractAddress) {
    // Validate signerAddress (Ethereum address)
    if (typeof signerAddress !== "string" || !ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid signer address");
    }

    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length !== 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }

    // Validate contractAddress (Ethereum address)
    if (typeof contractAddress !== "string" || !ethers.isAddress(contractAddress)) {
        throw new TypeError("Invalid contract address");
    }

    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8); // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(plaintext); // Write the uint64 value to the buffer as little-endian

    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encrypt(Buffer.from(aesKey, 'hex'), plaintextBytes);
    const ct = Buffer.concat([ciphertext, r]);

    // Create the packed message
    const message = ethers.solidityPacked(
        ["address", "address", "uint256"],
        [signerAddress, contractAddress, BigInt("0x" + ct.toString("hex"))],
    );

    // Convert the ciphertext to BigInt
    const encryptedInt = BigInt("0x" + ct.toString("hex"));

    return { encryptedInt, message };
}

function writeBigUInt128BE(buffer, value, offset = 0) {
    const hexString = value.toString(HEX_BASE).padStart(CT_SIZE, '0');
    const bytes = Buffer.from(hexString, 'hex');
    bytes.copy(buffer, offset);
}

export function writeBigUInt256BE(buffer, value, offset = 0) {
    const hexString = value.toString(HEX_BASE).padStart(CT_SIZE*2, '0');
    const bytes = Buffer.from(hexString, 'hex');
    if (buffer.length > bytes.length) {
        offset = buffer.length - bytes.length;
    }
    bytes.copy(buffer, offset);
}

export function prepareIT(plaintext, userAesKey, userAddress) {

    // Convert the plaintext to bytes
    const plaintextBigInt = BigInt(plaintext);
    const bitSize = plaintextBigInt.toString(2).length;
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE/2) {
        throw new RangeError("Plaintext size must be 128 bits or smaller. To prepare a 256 bit plaintext, use prepareIT256 instead.");
    }

    const plaintextBytes = Buffer.alloc(BLOCK_SIZE); // Allocate a buffer of size 16 bytes
    writeBigUInt128BE(plaintextBytes, plaintextBigInt); // Write the uint128 value to the buffer as big-endian
    // Encrypt the plaintext using AES key
    const {ciphertext, r} = encrypt(userAesKey, plaintextBytes);
    let ct = Buffer.concat([ciphertext, r]);
    
    // Convert the ciphertext to BigInt
    const ctInt = BigInt('0x' + ct.toString('hex'));

    return { userAddress, ctInt };
}

export function prepareIT256(plaintext, userAesKey, userAddress) {

    // Convert the plaintext to bytes
    const plaintextBigInt = BigInt(plaintext);
    const bitSize = plaintextBigInt.toString(2).length;
    if (bitSize > MAX_PLAINTEXT_BIT_SIZE) {
        throw new RangeError("Plaintext size must be 256 bits or smaller.");
    }

    let ct;

    // In case of 128 bits plaintext, encrypt it as the low part of the ct, and then encrypt the high part of the ct with zeros
    if (bitSize <= MAX_PLAINTEXT_BIT_SIZE/2) {
        const plaintextBytes = Buffer.alloc(BLOCK_SIZE); // Allocate a buffer of size 16 bytes
        writeBigUInt128BE(plaintextBytes, plaintextBigInt); // Write the uint128 value to the buffer as big-endian
        // Encrypt the plaintext using AES key
        const {ciphertext, r} = encrypt(userAesKey, plaintextBytes);

        // Encrypt the high part of the ct with zeros
        const zero = BigInt(0);
        const zeroBytes = Buffer.alloc(BLOCK_SIZE);
        writeBigUInt128BE(zeroBytes, zero);
        const {ciphertext: ciphertextHigh, r: rHigh} = encrypt(userAesKey, zeroBytes);
        ct = Buffer.concat([ciphertextHigh, rHigh, ciphertext, r]);
        
    } else { // bitSize > 128 and bitSize <= 256
        const plaintextBytes = Buffer.alloc(CT_SIZE); // Allocate a buffer of size 32 bytes
        writeBigUInt256BE(plaintextBytes, plaintextBigInt); // Write the uint256 value to the buffer as big-endian
        
        // Encrypt each part of the plaintext using AES key
        const resultHigh = encrypt(userAesKey, plaintextBytes.slice(0, BLOCK_SIZE));
        const resultLow = encrypt(userAesKey, plaintextBytes.slice(BLOCK_SIZE));
        
        // Now destructure
        const { ciphertext: ciphertextHigh, r: rHigh } = resultHigh;
        const { ciphertext: ciphertextLow, r: rLow } = resultLow;

        ct = Buffer.concat([ciphertextHigh, rHigh, ciphertextLow, rLow]);
    } 

    const ciphertextHigh = ct.slice(0, CT_SIZE);
    const ciphertextLow = ct.slice(CT_SIZE);

    // Convert Buffer to uint256 (BigInt) for Solidity compatibility
    const ciphertextHighUint = BigInt('0x' + ciphertextHigh.toString('hex'));
    const ciphertextLowUint = BigInt('0x' + ciphertextLow.toString('hex'));

    return { userAddress, ciphertext: {ciphertextHigh: ciphertextHighUint, ciphertextLow: ciphertextLowUint} };
}

/**
 * Verifies that at least T of the N evaluators signed the message.
 *
 * Each evaluator is run by two parties - an operator (external) instance and a Soda (internal) one - and
 * each signs with its own key. An evaluator has attested a result only once both of its instances have
 * signed it, so `signers` holds two addresses per evaluator: every operator instance first, then every Soda
 * instance, so the final N entries are Soda's, one per evaluator, and within either block entry i belongs to
 * evaluator i % N.
 *
 * That ordering is what says which evaluator a recovered signer belongs to, so a differently ordered list
 * does not fail - it attributes signatures to the wrong evaluators. `getSignersAddresses` returns them in
 * this order.
 *
 * This counts evaluators rather than signatures, which is the whole point: five signatures from five
 * different evaluators' operators plus one Soda signature is six valid signatures and not one evaluator
 * that attested the result in full, so a signature count would accept a result no evaluator stands behind.
 *
 * It mirrors `_verifySignaturesDigest` in GCDecryptionVerifier.sol, the normative statement of the rule.
 * Where the two differ the contract is right: a result the chain accepts and this rejects, or the reverse,
 * is a bug here.
 *
 * The defaults describe a single evaluator, which is what an unreplicated deployment has, and for which this
 * reduces exactly to the previous rule - every signer must have signed.
 *
 * @param {Buffer|Uint8Array} message - The message that was signed.
 * @param {Array} signatures - The signatures to verify, in any order.
 * @param {string[]} signers - Every instance's address, ordered as described above.
 * @param {number} [N=1] - How many evaluators those instances make up.
 * @param {number} [T=1] - How many evaluators must have signed.
 * @returns {boolean} - True if at least T evaluators signed in full, false otherwise.
 */
export function verifySignatures(message, signatures, signers, N = 1, T = 1){
    // A uint read from a contract arrives as a bigint through ethers, and mixing that with a number throws
    // partway through rather than failing validation. Coerce first, then insist on whole numbers: a
    // fractional N can satisfy the divisibility check below and only fail later at new Array(N).
    N = Number(N);
    T = Number(T);
    if (!Number.isInteger(N) || !Number.isInteger(T)) {
        throw new RangeError(`N and T must be integers, got N = ${N}, T = ${T}`);
    }

    if (signers.length === 0) {
        throw new RangeError("Signers must be non-empty");
    }
    // Position is identity here, so a repeated address would leave one of its positions unfillable and that
    // evaluator permanently short of its quota - silently, and inconsistently between languages, since a
    // first-match lookup and a last-wins map disagree about which position an address owns.
    if (new Set(signers).size !== signers.length) {
        throw new RangeError("Signers must not contain duplicate addresses");
    }
    if (N < 1 || signers.length % N !== 0) {
        throw new RangeError(`${signers.length} signers do not divide among ${N} evaluator(s)`);
    }
    // At least two instances per evaluator, which is what setSigners enforces on-chain. Exactly N signers
    // would mean no operator instances at all, and an evaluator with no operators is vacuously complete -
    // so a single Soda signature would satisfy any threshold, T = N included.
    //
    // A single evaluator is exempt because there the same shape is not a shortcut: one evaluator, one
    // signer, and that signer still has to have signed. That is the unreplicated deployment the defaults
    // describe, and rejecting it would break the plain "did this key sign this message" check.
    if (N > 1 && signers.length < 2 * N) {
        throw new RangeError(
            `${signers.length} signers is fewer than two per evaluator for N = ${N}; ` +
            `an evaluator with no operator instance would count as having signed without doing so`);
    }
    if (T < 1 || T > N) {
        throw new RangeError(`T must be in [1, ${N}], got ${T}`);
    }

    // Checksummed once, because position is identity: recoverAddressFromSignature returns a checksummed
    // address, so a signers list in any other casing would match nothing at all.
    // Wrapped rather than passed by reference: map hands the callback (element, index, array), and
    // toChecksumAddress takes an optional EIP-1191 chain id as its second argument, so passing it directly
    // would checksum every address against its own index and match nothing.
    const normalizedSigners = signers.map(signer => ethereumjsUtil.toChecksumAddress(signer));

    // The Soda instances are the last N entries, one per evaluator, so everything before them is an
    // operator instance.
    const sodaOffset = signers.length - N;
    // How many operator instances must sign before an evaluator has spoken. Written out rather than assumed
    // to be one, so a deployment running more instances per evaluator cannot quietly come to mean "any one
    // of them".
    const operatorsPerEvaluator = signers.length / N - 1;

    // Counted rather than flagged: an evaluator with several operators has not spoken until all have.
    const operatorsSigned = new Array(N).fill(0);
    const sodaSigned = new Array(N).fill(false);
    // Which positions have already been counted, so one instance signing twice adds nothing.
    const positionSeen = new Set();

    for (const signature of signatures) {
        const recoveredAddress = recoverAddressFromSignature(message, signature);
        const position = normalizedSigners.indexOf(recoveredAddress);
        // Skipped rather than fatal. An address that is not registered contributes to no evaluator's count,
        // so ignoring it cannot make an unproven result look proven - while rejecting outright would throw
        // away an otherwise sufficient set because one extra signature came along, which is what happens
        // when a key is rotated out between a response being assembled and the signer list being read, or
        // when a caller simply forwards everything it collected. The old rule could fail hard safely
        // because it demanded the exact full set; this one accepts subsets, so it has to accept supersets.
        if (position === -1) {
            console.log("Ignoring signature from " + recoveredAddress + ", which is not a registered signer");
            continue;
        }
        if (positionSeen.has(position)) {
            continue;
        }
        positionSeen.add(position);

        if (position < sodaOffset) {
            operatorsSigned[position % N]++;
        } else {
            sodaSigned[position - sodaOffset] = true;
        }
    }

    // T evaluators must have had every operator sign, and at least one of those same evaluators must also
    // carry its Soda signature. Requiring that Soda signature to come from an evaluator already counted is
    // what ties the two sides together: otherwise the instance attesting the result could belong to an
    // evaluator none of the counted operators ever ran alongside.
    let evaluatorsHeardFrom = 0;
    let countedEvaluatorHasSoda = false;
    for (let evaluator = 0; evaluator < N; evaluator++) {
        if (operatorsSigned[evaluator] === operatorsPerEvaluator) {
            evaluatorsHeardFrom++;
            if (sodaSigned[evaluator]) {
                countedEvaluatorHasSoda = true;
            }
        }
    }
    return evaluatorsHeardFrom >= T && countedEvaluatorHasSoda;
}

/**
 * Recovers the address from the signature.
 * @param {Buffer|Uint8Array} message - The message to be signed.
 * @param {Buffer|Uint8Array} signature - The signature in r||s||v format (65 bytes).
 * @returns {string} - The address recovered from the signature.
 */
export function recoverAddressFromSignature(message, signature) {
    // Validate input types
    if (!(message instanceof Buffer) && !(message instanceof Uint8Array)) {
        throw new TypeError("message must be Buffer or Uint8Array");
    }
    if (message.length === 0) {
        throw new RangeError("message must be non-empty");
    }

    // Validate signature length
    if (!(signature instanceof Buffer) && !(signature instanceof Uint8Array)) {
        throw new TypeError("signature must be Buffer or Uint8Array");
    }
    if (signature.length !== SIGNATURE_SIZE) {
        throw new RangeError(`Invalid signature length: ${signature.length} bytes, must be ${SIGNATURE_SIZE} bytes`);
    }

    // Hash the message
    const messageHash = ethereumjsUtil.keccak256(message);

    // Convert signature components (r, s, v)
    const { rBytes, sBytes, vByte } = extractSignatureComponents(Buffer.from(signature));

    // Convert v from 0-1 to 27-28 for ecrecover
    // vByte is a Buffer, so we need to access the first byte
    const vValue = vByte[0];
    const v = vValue === 0 || vValue === 1 ? vValue + 27 : vValue;

    // Recover the public key from the signature
    const recoveredPublicKey = ethereumjsUtil.ecrecover(messageHash, v, rBytes, sBytes);

    // Get the address from the recovered public key
    const addressBuffer = ethereumjsUtil.pubToAddress(recoveredPublicKey);
    return ethereumjsUtil.toChecksumAddress('0x' + addressBuffer.toString('hex'));
}

/**
 * Extracts the signature components from the signature bytes.
 * This function does not validate the signature bytes, it only extracts the components. 
 * The function expects the signature bytes to be in the correct format (r||s||v).
 * @param {Buffer|Uint8Array} signatureBytes - The signature bytes to extract the components from.
 * @returns {Object} - An object containing the r, s, and v components.
 * @throws {TypeError} - Throws if the signature bytes are of invalid types.
 * @throws {RangeError} - Throws if the signature bytes are empty or have incorrect lengths.
 */
export function extractSignatureComponents(signatureBytes) {
    const rSize = (SIGNATURE_SIZE - 1) / 2;
    const sSize = rSize;
    // Allocate buffers for r, s, and v
    let rBytes = Buffer.alloc(rSize);
    let sBytes = Buffer.alloc(sSize);
    let vByte = Buffer.alloc(1);

    // Copy the corresponding bytes from the signature
    signatureBytes.copy(rBytes, 0, 0, rSize);
    signatureBytes.copy(sBytes, 0, rSize, rSize + sSize);
    signatureBytes.copy(vByte, 0, rSize + sSize);

    // Return the components as an object
    return { rBytes, sBytes, vByte };
}


export function generateRSAKeyPair(){
    // Generate a new RSA key pair
    const rsaKeyPair = forge.pki.rsa.generateKeyPair({bits: 2048})

    // Convert keys to DER format
    const privateKey = forge.asn1.toDer(forge.pki.privateKeyToAsn1(rsaKeyPair.privateKey)).data
    const publicKey = forge.asn1.toDer(forge.pki.publicKeyToAsn1(rsaKeyPair.publicKey)).data

    return {
        privateKey: Buffer.from(encodeString(privateKey)),
        publicKey: Buffer.from(encodeString(publicKey))
    }
}

export function encryptRSA(publicKeyUint8Array, plaintext) {
    // Convert the Uint8Array to a binary string for forge
    const binaryDerString = String.fromCharCode.apply(null, publicKeyUint8Array);

    // Decode the binary DER string into an ASN.1 object
    const asn1PublicKey = forge.asn1.fromDer(binaryDerString);

    // Convert the ASN.1 object to an RSA public key
    const forgePublicKey = forge.pki.publicKeyFromAsn1(asn1PublicKey);

    // Encrypt the plaintext using RSA-OAEP with SHA-256 as the hash function
    const encrypted = forgePublicKey.encrypt(plaintext, 'RSA-OAEP', {
        md: forge.md.sha256.create()  // Use SHA-256 for OAEP padding
    });

    // Convert the encrypted binary string to a Uint8Array
    const encryptedUint8Array = new Uint8Array(forge.util.createBuffer(encrypted, 'raw').bytes().split('').map(c => c.charCodeAt(0)));

    return encryptedUint8Array;
}



export function decryptRSA(privateKeyUint8Array, ciphertext) {
    // Convert privateKey from Uint8Array to PEM format
    const privateKeyPEM = forge.pki.privateKeyToPem(
        forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(privateKeyUint8Array)))
    );

    // Decrypt using RSA-OAEP
    const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

    // If ciphertext is Uint8Array, convert it to a binary string for forge
    let binaryCiphertext;
    if (ciphertext instanceof Uint8Array) {
        binaryCiphertext = String.fromCharCode.apply(null, ciphertext);
    } else if (typeof ciphertext === 'string') {
        // If it's already a hex string, convert hex to bytes
        binaryCiphertext = forge.util.hexToBytes(ciphertext);
    } else {
        throw new Error("Invalid ciphertext format");
    }

    // Decrypt the ciphertext using RSA-OAEP with SHA-256
    const decrypted = rsaPrivateKey.decrypt(binaryCiphertext, 'RSA-OAEP', {
        md: forge.md.sha256.create()
    });

    // Convert the decrypted string to a Uint8Array
    return new Uint8Array(decrypted.split('').map(c => c.charCodeAt(0)));
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
export function reconstructUserKey(privateKey, encryptedKeyShare0, encryptedKeyShare1) {
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


export function encodeString(str) {
    return new Uint8Array([...str.split('').map((char) => parseInt(char.codePointAt(0)?.toString(HEX_BASE), HEX_BASE))])
}


export function encryptNumber(r, key) {
    // Ensure key size is 128 bits (16 bytes)
    if (key.length != BLOCK_SIZE) {
        throw new RangeError("Key size must be 128 bits.")
    }

    // Create a new AES cipher using the provided key
    const cipher = forge.cipher.createCipher('AES-ECB', forge.util.createBuffer(key))

    // Encrypt the random value 'r' using AES in ECB mode
    cipher.start()
    cipher.update(forge.util.createBuffer(r))
    cipher.finish()

    // Get the encrypted random value 'r' as a Buffer and ensure it's exactly 16 bytes
    const encryptedR = encodeString(cipher.output.data).slice(0, BLOCK_SIZE)

    return encryptedR
}