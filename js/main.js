const cryptoOperations = require('./crypto');

// Example usage:

// Generate a key
const key = cryptoOperations.generateAndWriteAesKey("key.txt");
console.log("key:", key.toString('hex'));


const plaintextInteger = 100; // Example integer value
const plaintextBuffer = Buffer.alloc(1); // Assuming a 8-bit integer
plaintextBuffer.writeUInt8(plaintextInteger);

// Encrypt the plaintext
const { ciphertext, r } = cryptoOperations.encrypt(key, plaintextBuffer);

console.log("Plaintext (integer):", plaintextInteger);
console.log("Ciphertext:", ciphertext.toString('hex'));
console.log("Random value 'r':", r.toString('hex'));

// Decrypt the ciphertext
const decryptedBuffer = cryptoOperations.decrypt(key, r, ciphertext);

// Convert the decrypted buffer to an integer
const decryptedInteger = decryptedBuffer.readUInt8();
console.log("Decrypted message (integer):", decryptedInteger);
