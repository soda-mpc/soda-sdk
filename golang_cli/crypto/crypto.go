package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// PadWithZeros pads the input with zeros to make its length a multiple of blockSize.
func PadWithZeros(input []byte, blockSize int) []byte {
	if len(input)%blockSize == 0 {
		return input
	}
	padding := blockSize - (len(input) % blockSize)

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

// GenerateAESKey generates a random 128-bit AES key and returns the key.
func GenerateAESKey() ([]byte, error) {
	// Generate a random 128-bit AES key
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("Failed to generate AES key: %v", err)
	}

	return key, nil
}

const (
	AddressSize = 20 // 160-bit is the output of the Keccak-256 algorithm on the sender/contract address
	FuncSigSize = 4
	CtSize      = 32
	KeySize     = 32
)

func GenerateECDSAPrivateKey() []byte {
	// Generate a new private key
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		fmt.Println("Error generating private key:", err)
	}
	// Convert the private key to raw bytes
	return ethcrypto.FromECDSA(privateKey)
}

// Sign is a function that signes an hashed message using ECDSA. It takes in six parameters:
// sender: The address of the sender. It should be a byte slice of length AddressSize.
// addr: The contract address. It should be a byte slice of length AddressSize.
// funcSig: The function signature. It should be a byte slice of length FuncSigSize.
// ct: The ciphertext to be signed. It should be a byte slice of length CtSize.
// key: The private key used for signing. It should be a byte slice of length KeySize.
// It first checks if the lengths of these parameters are correct according to predefined constants.
// If any of them are not of the correct length, it returns an error.
// It then concatenates (sender | contract | funcSignature | ct) to create a message.
// This message is then hashed using the Keccak-256 algorithm.
// The function then creates an ECDSA private key from the provided key.
// Finally, it signs the hashed message using the created private key.
// If all steps are successful, it returns the signature and no error.
func SignIT(sender, addr, funcSig, ct, key []byte) ([]byte, error) {
	// Ensure all input sizes are the correct length
	if len(sender) != AddressSize {
		return nil, fmt.Errorf("Invalid sender address length: %d bytes, must be %d bytes", len(sender), AddressSize)
	}
	if len(addr) != AddressSize {
		return nil, fmt.Errorf("Invalid contract address length: %d bytes, must be %d bytes", len(addr), AddressSize)
	}
	if len(funcSig) != FuncSigSize {
		return nil, fmt.Errorf("Invalid signature size: %d bytes, must be %d bytes", len(funcSig), FuncSigSize)
	}
	if len(ct) != CtSize {
		return nil, fmt.Errorf("Invalid ct length: %d bytes, must be %d bytes", len(ct), CtSize)
	}
	// Ensure the key is the correct length
	if len(key) != KeySize {
		return nil, fmt.Errorf("Invalid key length: %d bytes, must be %d bytes", len(key), KeySize)
	}

	// Create the message to be signed by appending all inputs
	message := append(sender, addr...)
	message = append(message, funcSig...)
	message = append(message, ct...)

	return Sign(message, key)
}

// Sign is a function that hashes a message using the Keccak-256 algorithm and then signs the hashed message using ECDSA.
// If all steps are successful, it returns the signature and no error.
func Sign(message, key []byte) ([]byte, error) {

	// Create an ECDSA private key from raw bytes
	privateKey, err := ethcrypto.ToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create ECDSA private key: %v", err)
	}

	// Hash the concatenated message using Keccak-256
	hash := ethcrypto.Keccak256(message)

	// Sign the message
	signature, err := ethcrypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign message: %v", err)
	}

	return signature, nil
}

func VerifyIT(sender, addr, funcSig, ct, signature []byte) bool {

	// Create the message to be signed by appending all inputs
	message := append(sender, addr...)
	message = append(message, funcSig...)
	message = append(message, ct...)

	return RecoverPKAndVerifySignature(message, signature)
}

func RecoverPKAndVerifySignature(message, signature []byte) bool {
	// Hash the concatenated message using Keccak-256
	hash := ethcrypto.Keccak256(message)

	pubkey, err := ethcrypto.Ecrecover(hash, signature)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
	}

	return ethcrypto.VerifySignature(pubkey, hash, signature[:64])
}

// prepareIT prepares the inputs for the verifyIT function
// It takes in the parameters:
// plaintext: The plaintext to encrypt
// userAesKey: Aes key used to encrypt the plaintext
// sender: The address of the sender
// addr: The address of the contract
// funcSig: The signature of the calling function
// signingKey: The private key used for signing
// The function encrypt the plaintext using the userAesKey
// and then signs on the concatination of sender, addr, funcSig, and the ciphertext.
// It returns the ciphertext, signature, and an error if any occurred.
func prepareIT(plaintext, userAesKey, sender, addr, funcSig, signingKey []byte) ([]byte, []byte, error) {
	// Encrypt the plaintext
	ciphertext, r, err := Encrypt(userAesKey, plaintext)
	if err != nil {
		return nil, nil, err
	}
	ct := append(ciphertext, r...)

	// Sign the message
	signature, err := SignIT(sender, addr, funcSig, ct, signingKey)
	if err != nil {
		return nil, nil, err
	}

	return ct, signature, nil
}

func GenerateRSAKeyPair() ([]byte, []byte, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return nil, nil, err
	}

	// Marshal private key to DER format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Println("Error marshaling private key:", err)
		return nil, nil, err
	}

	// Marshal public key to DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error marshaling public key:", err)
		return nil, nil, err
	}

	return privateKeyBytes, publicKeyBytes, nil
}

func EncryptRSA(publicKeyBytes []byte, message []byte) ([]byte, error) {

	// Parse public key from DER format
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return nil, err
	}

	// Type assert parsed key to *rsa.PublicKey
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Error type asserting public key:", err)
		return nil, err
	}
	// Encrypt message using RSA public key with OAEP padding
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, message, nil)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return nil, err
	}

	return ciphertext, nil

}

func DecryptRSA(privateKeyBytes []byte, ciphertext []byte) ([]byte, error) {

	// Parse private key from DER format
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return nil, err
	}

	// Convert parsedKey to *rsa.PrivateKey
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Println("Error: Parsed key is not an RSA private key")
		return nil, fmt.Errorf("parsed key is not an RSA private key")
	}

	// Decrypt message using RSA private key with OAEP padding
	decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, ciphertext, nil)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return nil, err
	}

	return decryptedMessage, nil

}

func GetFuncSig(functionSig string) uint32 {
	// Hash the function signature using Keccak-256 and return the first 4 bytes
	hash := ethcrypto.Keccak256(([]byte)(functionSig))[:4]
	return binary.BigEndian.Uint32(hash)
}
