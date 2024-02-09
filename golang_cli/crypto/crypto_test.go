// crypto_test.go
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encryptDecrypt(t *testing.T, plaintextBytes []byte) []byte {
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	ciphertext, r, err := Encrypt(key, plaintextBytes)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, r, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	return decrypted
}

func TestEncryptDecrypt(t *testing.T) {

	// Create plaintext with the value 100 as a big integer with 128 bits
	plaintextValue := big.NewInt(100)
	plaintextBytes := make([]byte, aes.BlockSize)
	plaintextValue.FillBytes(plaintextBytes)

	decrypted := encryptDecrypt(t, plaintextBytes)

	assert.Equal(t, plaintextBytes, decrypted, "Decrypted message should match the original plaintext")
}

func TestEncryptDecryptWithPadding(t *testing.T) {
	// Create plaintext with the value 100 as a big integer with less than 128 bits
	plaintextValue := big.NewInt(100)
	plaintextBytes := plaintextValue.Bytes()

	decrypted := encryptDecrypt(t, plaintextBytes)
	decryptedValue := new(big.Int).SetBytes(decrypted)

	assert.Equal(t, plaintextValue, decryptedValue, "Decrypted message should match the original plaintext")
}

func TestLoadWriteAESKey(t *testing.T) {
	// Create a temporary file for testing
	tempFile := "temp_key_file.txt"
	defer os.Remove(tempFile)

	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Test WriteAESKey
	err = WriteAESKey(tempFile, key)
	require.NoError(t, err, "WriteAESKey should not return an error")

	// Test LoadAESKey
	loadedKey, err := LoadAESKey(tempFile)
	require.NoError(t, err, "LoadAESKey should not return an error")
	assert.Equal(t, key, loadedKey, "Loaded key should match the original key")
}

func TestGenerateAndWriteAESKey(t *testing.T) {
	// Create a temporary file for testing
	tempFile := "temp_key_file.txt"
	defer os.Remove(tempFile)
	// Test GenerateAESKey and WriteAESKey
	key, err := GenerateAESKey()
	require.NoError(t, err, "GenerateAESKey should not return an error")

	err = WriteAESKey(tempFile, key)
	require.NoError(t, err, "WriteAESKey should not return an error")

	// Verify that the key was written to the file
	loadedKey, err := LoadAESKey(tempFile)
	require.NoError(t, err, "LoadAESKey should not return an error")
	assert.Equal(t, key, loadedKey, "Loaded key should match the generated key")
}

func TestSignature(t *testing.T) {
	// Create plaintext with the value 100 as a big integer with less than 128 bits
	sender := make([]byte, AddressSize)
	_, err := rand.Read(sender)
	addr := make([]byte, AddressSize)
	_, err = rand.Read(addr)
	funcSig := make([]byte, SignatureSize)
	_, err = rand.Read(funcSig)
	nonce := make([]byte, NonceSize)
	_, err = rand.Read(nonce)

	key := make([]byte, KeySize)
	_, err = rand.Read(key)
	require.NoError(t, err, "Failed to generate random key")

	// Create plaintext with the value 100 as a big integer with less than 128 bits
	plaintextValue := big.NewInt(100)
	plaintextBytes := plaintextValue.Bytes()
	ciphertext, r, err := Encrypt(key, plaintextBytes)
	require.NoError(t, err, "Encrypt should not return an error")

	ct := append(ciphertext, r...)

	signature, err := Sign(sender, addr, funcSig, nonce, ct, key)
	require.NoError(t, err, "Sign should not return an error")

	// Create an ECDSA private key from raw bytes
	privateKey, err := crypto.ToECDSA(key)
	require.NoError(t, err, "ToECDSA should not return an error")

	// Verify the signature
	pubKey := privateKey.Public()
	pubKeyECDSA, ok := pubKey.(*ecdsa.PublicKey)
	assert.Equal(t, ok, true, "Error casting public key to ECDSA")

	// Get the bytes from the public key
	pubKeyBytes := crypto.FromECDSAPub(pubKeyECDSA)

	// Verify the signature
	verified := VerifySignature(sender, addr, funcSig, nonce, ct, pubKeyBytes, signature)

	assert.Equal(t, verified, true, "Verify signature should return true")
}

func readSignatureFromFile(path string) ([]byte, error) {
	// Open the file for reading
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}
	defer file.Close() // Make sure to close the file when done

	// Read the contents of the file as a string
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}

	// Convert the hex string to bytes
	hexBytes, err := hex.DecodeString(string(data))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, err
	}

	return hexBytes, nil
}

func TestFixedMsgSignature(t *testing.T) {
	// Create plaintext with the value 100 as a big integer with less than 128 bits
	sender, _ := hex.DecodeString("ee706584bf9a9414997840785b14d157bf315abab2745f60ebe2ba4d9971718181dcdf99154cdfed368256fe1f0fb4bd952296377b70f19817a0511d5a45a28e69a2c0f6cf28e4e7d52f6d966081579d115a22173b91efe5411622df117324d0b23bb13f5dd5f95d72a32aeb559f859179ffa2c84db6a4315af1aab83b03a2b02e7dd9501dd68e7529c9cc8a7140d011b2bf9845a5325a8e2703cae75713a871")
	addr, _ := hex.DecodeString("f2c401492410f9f8842a1b028a88c057f92539c14ca814dc67baad26884b65b3d8491accac662aee08353aed84e00bb856d12e6d816072be64cb87379347ab921e9772b31d47ee70c0bac432366bd669f58a8791a945ddee9a8f2b5d8b8c2a3b891b81d294ddf91bd9176875ce83887dedd6a62e70500bd9017d74dca4f2e284c69cd46ec889ffb9196dbd250e7e0183a2a1502d086baa8e4de2f6c8715cdf3c")
	funcSig, _ := hex.DecodeString("eb7dcb05")
	nonce, _ := hex.DecodeString("0cdab3e6457ec793")
	ct, _ := hex.DecodeString("195c6bbabb9483f5f6d0b95fa5486ebe1ad365fa21bf55f7158b87d560212207")
	key, _ := hex.DecodeString("e96d2e93781c3ee08d98d650c4a9888cc272675dddde76fdedc699871765d7a1")

	// Sign the message
	signature, err := Sign(sender, addr, funcSig, nonce, ct, key)
	require.NoError(t, err, "Sign should not return an error")

	pythonSignature, err := readSignatureFromFile("../../python/pythonSignature.txt")
	require.NoError(t, err, "Read Signature should not return an error")

	err = os.Remove("../../python/pythonSignature.txt")
	require.NoError(t, err, "Delete file should not return an error")

	assert.Equal(t, pythonSignature, signature, "signature should match the python signature")

	jsSignature, err := readSignatureFromFile("../../js/jsSignature.txt")
	require.NoError(t, err, "Read Signature should not return an error")

	err = os.Remove("../../js/jsSignature.txt")
	require.NoError(t, err, "Delete file should not return an error")

	assert.Equal(t, jsSignature, signature, "signature should match the js signature")

	// Create an ECDSA private key from raw bytes
	privateKey, err := crypto.ToECDSA(key)
	require.NoError(t, err, "ToECDSA should not return an error")

	// Verify the signature
	pubKey := privateKey.Public()
	pubKeyECDSA, ok := pubKey.(*ecdsa.PublicKey)
	assert.Equal(t, ok, true, "Error casting public key to ECDSA")

	// Get the bytes from the public key
	pubKeyBytes := crypto.FromECDSAPub(pubKeyECDSA)

	// Verify the signature
	verified := VerifySignature(sender, addr, funcSig, nonce, ct, pubKeyBytes, signature)

	assert.Equal(t, verified, true, "Verify signature should return true")
}

func TestRSAEncryption(t *testing.T) {
	// Generate key pair
	privateKey, publicKey, err := GenerateRSAKeyPair()
	require.NoError(t, err, "Generate RSA key pair should not return an error")

	// Message to encrypt
	plaintext := []byte("hello rsa")

	// Encrypt the plaintext
	cipher, err := EncryptRSA(publicKey, plaintext)
	require.NoError(t, err, "Encrypt should not return an error")

	// Decrypt the ciphertext
	decryptedText, err := DecryptRSA(privateKey, cipher)
	require.NoError(t, err, "Decrypt should not return an error")

	// Verify decrypted plaintext matches original message
	assert.Equal(t, plaintext, decryptedText, "Decrypted plaintext should match original message")
}

func readRSAKeysFromFile(path string) ([]byte, []byte, error) {
	// Open the file for reading
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, nil, err
	}
	defer file.Close() // Make sure to close the file when done

	// Read the contents of the file as a string
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, nil, err
	}

	// Split the data into two hex strings
	hexStrings := bytes.Split(data, []byte("\n"))

	// Convert the hex strings to bytes
	if len(hexStrings) != 2 {
		return nil, nil, fmt.Errorf("Expected two hex strings in the file")
	}

	cipherBytes, err := hex.DecodeString(string(hexStrings[0]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, err
	}

	keyBytes, err := hex.DecodeString(string(hexStrings[1]))
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return nil, nil, err
	}

	return cipherBytes, keyBytes, nil
}

func appendHexToFile(filename string, hexString string) error {
	// Open the file for appending with write permissions
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the hexadecimal string to the file
	// _, err = fmt.Fprintf(file, "%s\n", "")
	_, err = fmt.Fprintf(file, "%s\n", "\n"+hexString)
	if err != nil {
		return err
	}

	return nil
}

func TestRSAEncryptionFixed(t *testing.T) {
	_, pythonKey, err := readRSAKeysFromFile("../../python/pythonRSAEncryption.txt")
	require.NoError(t, err, "Read Signature should not return an error")

	// Message to encrypt
	plaintext := []byte("hello world")

	// Decrypt the ciphertext
	ciphertext, err := EncryptRSA(pythonKey, plaintext)
	require.NoError(t, err, "Encrypt should not return an error")

	appendHexToFile("../../python/pythonRSAEncryption.txt", hex.EncodeToString(ciphertext))

	_, jsKey, err := readRSAKeysFromFile("../../js/jsRSAEncryption.txt")
	require.NoError(t, err, "Read Signature should not return an error")

	// Decrypt the ciphertext
	ciphertext, err = EncryptRSA(jsKey, plaintext)
	require.NoError(t, err, "Encrypt should not return an error")

	appendHexToFile("../../js/jsRSAEncryption.txt", hex.EncodeToString(ciphertext))

}
