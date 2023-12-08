// crypto_test.go
package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Create plaintext with the value 100 as a big integer
	plaintextValue := big.NewInt(100)
	plaintextBytes := make([]byte, aes.BlockSize)
	plaintextValue.FillBytes(plaintextBytes)

	ciphertext, r, err := Encrypt(key, plaintextBytes)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, r, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	assert.Equal(t, plaintextBytes, decrypted, "Decrypted message should match the original plaintext")
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
	// Test GenerateAndWriteAESKey
	key, err := GenerateAndWriteAESKey(tempFile)
	require.NoError(t, err, "GenerateAndWriteAESKey should not return an error")

	// Verify that the key was written to the file
	loadedKey, err := LoadAESKey(tempFile)
	require.NoError(t, err, "LoadAESKey should not return an error")
	assert.Equal(t, key, loadedKey, "Loaded key should match the generated key")
}
