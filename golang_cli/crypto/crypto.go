package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// encrypt generates a random value 'r' and computes AES(k, r) XOR plaintext.
// The function returns the resulting ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher block: %v", err)
	}

	// Generate a random value 'r' of the same length as the block size
	r := make([]byte, aes.BlockSize)

	_, err = rand.Read(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random value 'r': %v", err)
	}

	// Create a temporary buffer to hold the encrypted random value 'r'
	encryptedR := make([]byte, aes.BlockSize)

	// Encrypt the random value 'r' using AES in ECB mode
	block.Encrypt(encryptedR, r)

	// XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
	ciphertext := make([]byte, len(plaintext))
	for i := range encryptedR {
		ciphertext[i] = encryptedR[i] ^ plaintext[i]
	}

	return ciphertext, r, nil
}

func Decrypt(key, r, ct []byte) ([]byte, error) {
	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %v", err)
	}

	// Check that the random value 'r' is exactly 16 bytes
	if len(r) != aes.BlockSize {
		return nil, fmt.Errorf("random value 'r' must be exactly 16 bytes")
	}

	// Check that the ciphertext 'ct' is a multiple of the block size
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext 'ct' must be a multiple of the block size")
	}

	// Create a temporary buffer to hold the encrypted random value 'r'
	encryptedR := make([]byte, aes.BlockSize)

	// Encrypt the random value 'r' using AES in ECB mode
	block.Encrypt(encryptedR, r)

	// XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
	plaintext := make([]byte, len(ct))
	for i := range encryptedR {
		plaintext[i] = encryptedR[i] ^ ct[i]
	}

	return plaintext, nil
}

func LoadAESKey(filePath string) ([]byte, error) {
	// Read the hex-encoded contents of the file
	hexKey, err := os.ReadFile(filePath)
	fmt.Println("hexKey = ", hexKey, len(hexKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// Decode the hex string to binary
	key, err := hex.DecodeString(string(hexKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %v", err)
	}

	// Ensure the key is the correct length (16 bytes for AES-128)
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key length: %d bytes, must be 16 bytes", len(key))
	}

	return key, nil
}

func WriteAESKey(filePath string, key []byte) error {
	// Ensure the key is the correct length (16 bytes for AES-128)
	if len(key) != 16 {
		return fmt.Errorf("invalid key length: %d bytes, must be 16 bytes", len(key))
	}

	// Encode the key to hex string
	hexKey := hex.EncodeToString(key)

	// Write the hex-encoded key to the file
	if err := os.WriteFile(filePath, []byte(hexKey), 0644); err != nil {
		return fmt.Errorf("failed to write key to file: %v", err)
	}

	return nil
}

// writeNetworkAESKey writes an AES key to a file in hex format.
// generateAndWriteAESKey generates a random 128-bit AES key, writes it to a file,
// and returns the key.
func GenerateAndWriteAESKey(fileName string) ([]byte, error) {
	// Generate a random 128-bit AES key
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %v", err)
	}

	// Write the key to the file
	if err := WriteAESKey(fileName, key); err != nil {
		return nil, fmt.Errorf("failed to write key to file: %v", err)
	}

	return key, nil
}
