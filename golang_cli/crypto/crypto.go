package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// PadWithZeros pads the input with zeros to make its length a multiple of blockSize.
func PadWithZeros(input []byte, blockSize int) []byte {
	if len(input)%blockSize == 0 {
		return input
	}
	padding := blockSize - (len(input) % blockSize)
	fmt.Println(padding)
	padText := make([]byte, padding)
	return append(padText, input...)
}

// Encrypt generates a random value 'r' and computes AES(k, r) XOR plaintext.
// The function returns the resulting ciphertext and the generated random value 'r'.
func Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher block: %v", err)
	}

	// Generate a random value 'r' of the same length as the block size
	r := make([]byte, aes.BlockSize)

	// Use crypto/rand for cryptographically secure random number generation
	_, err = rand.Read(r)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate random value 'r': %v", err)
	}

	// Create a temporary buffer to hold the encrypted random value 'r'
	encryptedR := make([]byte, aes.BlockSize)

	// Encrypt the random value 'r' using AES in ECB mode
	block.Encrypt(encryptedR, r)

	// Pad plaintext with zeros if it's not a multiple of the block size
	plaintext = PadWithZeros(plaintext, aes.BlockSize)

	// XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
	ciphertext := make([]byte, len(plaintext))
	for i := range encryptedR {
		ciphertext[i] = encryptedR[i] ^ plaintext[i]
	}

	return ciphertext, r, nil
}

// Decrypt decrypts the ciphertext using the provided key and random value 'r'.
// The function returns the resulting plaintext.
func Decrypt(key, r, ct []byte) ([]byte, error) {
	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AES cipher block: %v", err)
	}

	// Check that the random value 'r' is exactly the block size
	if len(r) != aes.BlockSize {
		return nil, fmt.Errorf("Random value 'r' must be exactly %d bytes", aes.BlockSize)
	}

	// Check that the ciphertext 'ct' is a multiple of the block size
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("Ciphertext 'ct' must be a multiple of the block size")
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

// LoadAESKey reads a hex-encoded AES key from a file.
func LoadAESKey(filePath string) ([]byte, error) {
	// Read the hex-encoded contents of the file
	hexKey, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read key file: %v", err)
	}

	// Decode the hex string to binary
	key, err := hex.DecodeString(string(hexKey))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode hex key: %v", err)
	}

	// Ensure the key is the correct length
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("Invalid key length: %d bytes, must be %d bytes", len(key), aes.BlockSize)
	}

	return key, nil
}

// WriteAESKey writes an AES key to a file in hex format.
func WriteAESKey(filePath string, key []byte) error {
	// Ensure the key is the correct length
	if len(key) != aes.BlockSize {
		return fmt.Errorf("Invalid key length: %d bytes, must be %d bytes", len(key), aes.BlockSize)
	}

	// Encode the key to hex string
	hexKey := hex.EncodeToString(key)

	// Write the hex-encoded key to the file
	if err := os.WriteFile(filePath, []byte(hexKey), 0644); err != nil {
		return fmt.Errorf("Failed to write key to file: %v", err)
	}

	return nil
}

// GenerateAndWriteAESKey generates a random 128-bit AES key, writes it to a file,
// and returns the key.
func GenerateAndWriteAESKey(fileName string) ([]byte, error) {
	// Generate a random 128-bit AES key
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("Failed to generate AES key: %v", err)
	}

	// Write the key to the file
	if err := WriteAESKey(fileName, key); err != nil {
		return nil, fmt.Errorf("Failed to write key to file: %v", err)
	}

	return key, nil
}
