const cryptoOperations = require('./mpcHelper');

// Example usage:
const key = cryptoOperations.generateAndWriteAesKey("key.txt");
console.log("key:", key.toString('hex'));

const plaintextInteger = 100; // Example integer value
const plaintextBuffer = Buffer.alloc(4); // Assuming a 32-bit integer
plaintextBuffer.writeUInt32BE(plaintextInteger);

const { ciphertext, r } = cryptoOperations.encrypt(key, plaintextBuffer);

console.log("Plaintext (integer):", plaintextInteger);
console.log("Ciphertext:", ciphertext.toString('hex'));
console.log("Random value 'r':", r.toString('hex'));

const decryptedBuffer = cryptoOperations.decrypt(key, r, ciphertext);
console.log("decryptedBuffer Size:", decryptedBuffer.length);

const decryptedInteger = decryptedBuffer.readUInt32BE();
console.log("Decrypted message (integer):", decryptedInteger);
