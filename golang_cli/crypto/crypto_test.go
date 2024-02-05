// crypto_test.go
package crypto

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
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
	addr := make([]byte, AddressSize)
	funcSig := make([]byte, SignatureSize)
	nonce := make([]byte, NonceSize)

	key := make([]byte, KeySize)
	_, err := rand.Read(key)
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

	// Create the message to be signed by appending all inputs
	message := append(sender, addr...)
	message = append(message, funcSig...)
	message = append(message, nonce...)
	message = append(message, ct...)

	// Hash the concatenated message using Keccak-256
	hash := crypto.Keccak256(message)

	verified := crypto.VerifySignature(pubKeyBytes, hash, signature[:64])

	assert.Equal(t, verified, true, "Verify signature should return true")
}
