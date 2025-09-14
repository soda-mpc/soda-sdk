"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadAesKey = loadAesKey;
exports.writeAesKey = writeAesKey;
const crypto_1 = require("./crypto");
const ethers_1 = require("ethers");
const fs_1 = __importDefault(require("fs"));
function loadAesKey(filePath) {
    // Read the hex-encoded contents of the file
    const hexKey = fs_1.default.readFileSync(filePath, 'utf8').trim();
    // Decode the hex string to binary
    const key = Buffer.from(hexKey.slice(2), 'hex');
    // Ensure the key is the correct length
    if (key.length !== crypto_1.BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }
    return key;
}
function writeAesKey(filePath, key) {
    // Ensure the key is the correct length
    if (key.length !== crypto_1.BLOCK_SIZE) {
        throw new RangeError(`Invalid key length: ${key.length} bytes, must be 16 bytes`);
    }
    // Encode the key to hex string
    const hexKey = ethers_1.ethers.hexlify(key);
    // Write the hex-encoded key to the file
    fs_1.default.writeFileSync(filePath, hexKey, 'utf8');
}
