package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
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
	AddressSize   = 160
	SignatureSize = 4
	NonceSize     = 8
	CtSize        = 32
	KeySize       = 32 // Assuming a 32-byte key size, adjust as needed
	modBits       = 256
)

func Sign(sender, addr, funcSig, nonce, ct, key []byte) ([]byte, error) {
	// Ensure all input sizes are the correct length
	if len(sender) != AddressSize {
		return nil, fmt.Errorf("Invalid sender address length: %d bytes, must be %d bytes", len(sender), AddressSize)
	}
	if len(addr) != AddressSize {
		return nil, fmt.Errorf("Invalid contract address length: %d bytes, must be %d bytes", len(addr), AddressSize)
	}
	if len(funcSig) != SignatureSize {
		return nil, fmt.Errorf("Invalid signature size: %d bytes, must be %d bytes", len(funcSig), SignatureSize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("Invalid nonce length: %d bytes, must be %d bytes", len(nonce), NonceSize)
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
	message = append(message, nonce...)
	message = append(message, ct...)

	// Create an ECDSA private key from raw bytes
	privateKey, err := crypto.ToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create ECDSA private key: %v", err)
	}

	// Hash the concatenated message using Keccak-256
	hash := crypto.Keccak256(message)

	// Sign the message
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign message: %v", err)
	}

	return signature, nil
}

func VerifySignature(sender, addr, funcSig, nonce, ct, pubKeyBytes, signature []byte) bool {

	// Create the message to be signed by appending all inputs
	message := append(sender, addr...)
	message = append(message, funcSig...)
	message = append(message, nonce...)
	message = append(message, ct...)

	// Hash the concatenated message using Keccak-256
	hash := crypto.Keccak256(message)

	return crypto.VerifySignature(pubKeyBytes, hash, signature[:64])
}

func GenerateRSAKeyPair() ([]byte, []byte, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return nil, nil, err
	}

	// Marshal private key to DER format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

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
	// Encrypt message using RSA public key
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, message)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return nil, err
	}

	return ciphertext, nil

}

func DecryptRSA(privateKeyBytes []byte, ciphertext []byte) ([]byte, error) {

	// Parse private key from DER format
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return nil, err
	}

	// Decrypt message using RSA private key
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return nil, err
	}

	return decryptedMessage, nil

}

// KeyPair represents an ElGamal key pair
// type KeyPair struct {
// 	PrivateKey []byte
// 	PublicKey  []byte
// }

// // generateKeyPair generates a key pair for ElGamal encryption over elliptic curves
// func GenerateElGamalKeyPair() (*KeyPair, error) {
// 	// Generate a private key
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Serialize the private key to bytes
// 	privateKeyBytes := privateKey.D.Bytes()

// 	// Serialize the public key to bytes
// 	publicKeyBytes := elliptic.MarshalCompressed(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

// 	keyPair := &KeyPair{
// 		PrivateKey: privateKeyBytes,
// 		PublicKey:  publicKeyBytes,
// 	}

// 	return keyPair, nil
// }

// // ElGamalEncrypt encrypts a plaintext message using ElGamal encryption
// func ElGamalEncrypt(publicKey []byte, plaintext []byte) ([]byte, []byte, error) {
// 	// Deserialize the public key from bytes
// 	curve := elliptic.P256()
// 	x, y := elliptic.UnmarshalCompressed(curve, publicKey)
// 	if x == nil {
// 		return nil, nil, fmt.Errorf("invalid public key")
// 	}
// 	publicKeyEC := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

// 	// Generate a random k
// 	k, err := rand.Int(rand.Reader, curve.Params().N)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	// Compute the ephemeral public key
// 	c1x, c1y := curve.ScalarBaseMult(k.Bytes())
// 	c1 := elliptic.MarshalCompressed(curve, c1x, c1y)

// 	// Compute the shared secret
// 	sharedX, _ := curve.ScalarMult(publicKeyEC.X, publicKeyEC.Y, k.Bytes())

// 	// Encrypt the plaintext
// 	c2 := make([]byte, len(plaintext))
// 	for i, b := range plaintext {
// 		c2[i] = b ^ sharedX.Bytes()[i%len(sharedX.Bytes())]
// 	}

// 	return c1, c2, nil
// }

// // ElGamalDecrypt decrypts a ciphertext using ElGamal decryption
// func ElGamalDecrypt(privateKey []byte, c1 []byte, c2 []byte) ([]byte, error) {
// 	// Deserialize the private key from bytes
// 	curve := elliptic.P256()
// 	d := new(big.Int).SetBytes(privateKey)

// 	// Deserialize c1 to get the ephemeral public key
// 	c1x, c1y := elliptic.UnmarshalCompressed(curve, c1)
// 	if c1x == nil {
// 		return nil, fmt.Errorf("invalid c1")
// 	}

// 	// Compute the shared secret
// 	sharedX, _ := curve.ScalarMult(c1x, c1y, d.Bytes())

// 	// Decrypt the ciphertext
// 	plaintext := make([]byte, len(c2))
// 	for i, b := range c2 {
// 		plaintext[i] = b ^ sharedX.Bytes()[i%len(sharedX.Bytes())]
// 	}

// 	return plaintext, nil
// }
