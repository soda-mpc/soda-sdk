package main

import (
	"crypto/aes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path"

	"golang_cli/crypto" // Import your crypto package
)

func main() {
	helpFlag := flag.Bool("help", false, "Show help message")
	encryptFlag := flag.Bool("encrypt", false, "Encrypt data. Provide a filename and plaintextas an additional argument.")
	decryptFlag := flag.Bool("decrypt", false, "Decrypt data. Provide a filename and two encrypted hex strings as additional arguments.")
	generateKeyFlag := flag.Bool("generate-key", false, "Generate key and save to specified file. Provide a filename.")

	flag.Parse()

	if *helpFlag {
		showHelp()
		return
	}

	if *encryptFlag {
		handleEncryption()
		return
	}

	if *decryptFlag {
		handleDecryption()
		return
	}

	if *generateKeyFlag {
		handleGenerateKey()
		return
	}

	showHelp()
}

func handleEncryption() {
	if flag.NArg() < 1 {
		log.Println("Error: Missing filename or plaintextfor encryption.")
		showHelp()
		return
	}

	fileName := flag.Arg(0)
	key, err := crypto.LoadAESKey(fileName)
	if err != nil {
		log.Printf("Error loading key: %v", err)
		return
	}

	numberToEncrypt := flag.Arg(1)
	data, err := stringToBlock(numberToEncrypt)
	if err != nil {
		log.Printf("Error converting data to bigInteger: %v", err)
		return
	}

	encryptedData, r, err := crypto.Encrypt(key, data)
	if err != nil {
		log.Printf("Error encrypting data: %v", err)
		return
	}

	log.Printf("Encrypting data for key file %s", fileName)

	hexEncryptedData := hex.EncodeToString(encryptedData)
	hexR := hex.EncodeToString(r)
	log.Printf("Encryption: %s", hexEncryptedData)
	log.Printf("Random: %s", hexR)
}

func handleDecryption() {
	if flag.NArg() < 3 {
		log.Println("Error: Missing filename or encrypted hex string.")
		showHelp()
		return
	}

	fileName := flag.Arg(0)
	key, err := crypto.LoadAESKey(fileName)
	if err != nil {
		log.Printf("Error loading key: %v", err)
		return
	}

	hexEnc := flag.Arg(1)
	hexR := flag.Arg(2)

	enc, err := hexToBlockSize(hexEnc)
	if err != nil {
		log.Printf("Error decoding hex of enc: %v", err)
		return
	}

	r, err := hexToBlockSize(hexR)
	if err != nil {
		log.Printf("Error decoding hex of random: %v", err)
		return
	}

	plaintext, err := crypto.Decrypt(key, r, enc)
	if err != nil {
		log.Printf("Error decrypting data: %v", err)
		return
	}

	log.Printf("Decrypting data for key file %s", fileName)

	var result big.Int
	log.Printf("Decryption: %s", result.SetBytes(plaintext))
}

func handleGenerateKey() {
	if flag.NArg() < 1 {
		log.Println("Error: Missing filename.")
		showHelp()
		return
	}

	fileName := flag.Arg(0)

	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Error getting home directory: %v", err)
		return
	}

	filePath := path.Join(home, "Tools", "golang_cli", fileName)

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		log.Printf("Error: File %s already exists. Refusing to overwrite.", filePath)
		return
	}

	key, err := crypto.GenerateAESKey()
	if err != nil {
		log.Printf("Error generating key: %v", err)
		return
	}
	err = crypto.WriteAESKey(filePath, key)
	if err != nil {
		log.Printf("Error generating key: %v", err)
		return
	}

	log.Printf("Generated key and saved to file %s", fileName)
	log.Printf("Key: %x", key)
}

func hexToBlockSize(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode hex: %v", err)
	}

	if len(bytes) != 16 {
		return nil, fmt.Errorf("Invalid key length: %d bytes, must be 16 bytes", len(bytes))
	}
	return bytes, nil
}

func showHelp() {
	fmt.Println("Usage: cli-tool [OPTIONS]")
	fmt.Println("Options:")
	fmt.Println("  --help               	        Show help message")
	fmt.Println("  --encrypt FILE NUMBER            Encrypt data")
	fmt.Println("    Provide a FILE and a NUMBER to encrypt as additional arguments.")
	fmt.Println("  --decrypt FILE ENCRYPTED RANDOM  Decrypt data")
	fmt.Println("    Provide a FILE, an ENCRYPTED hex string, and a hex string for the RANDOM value as additional arguments.")
	fmt.Println("  --generate-key FILE  Generate key and save to specified file")
	os.Exit(1)
}

func stringToBlock(s string) ([]byte, error) {
	var bi big.Int
	_, success := bi.SetString(s, 10)
	if !success {
		return nil, fmt.Errorf("failed to convert string to big.Int")
	}

	// Convert big.Int to bytes and ensure it is exactly 16 bytes
	dataBytes := bi.Bytes()

	if len(dataBytes) > 16 {
		return nil, fmt.Errorf("input string is longer than 16 bytes")
	}

	return bi.FillBytes(make([]byte, aes.BlockSize)), nil
}
