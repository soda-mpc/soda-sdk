package main

import (
	"crypto/aes"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"

	"golang_cli/crypto"
)

func main() {
	// Define command-line flags
	helpFlag := flag.Bool("help", false, "Show help message")
	encryptFlag := flag.Bool("encrypt", false, "Encrypt data. Provide a filename as an additional argument.")
	decryptFlag := flag.Bool("decrypt", false, "Decrypt data. Provide a filename as an additional argument.")
	generateKeyFlag := flag.String("generate-key", "", "Generate key and save to specified file")

	// Parse command-line flags
	flag.Parse()

	// Check if help flag is provided
	if *helpFlag {
		showHelp()
		return
	}

	if *encryptFlag {
		// Check if a filename is provided for encryption
		if flag.NArg() < 1 {
			fmt.Println("Error: Missing filename for encryption.")
			showHelp()
			return
		}

		fileName := flag.Arg(0)

		key, err := crypto.LoadAESKey(fileName)
		if err != nil {
			fmt.Println("Error loading key:", err)
			return
		}

		numberToEncrypt := flag.Arg(1)

		// convert the data to bigInteger
		data, err := stringToBlock(numberToEncrypt)
		if err != nil {
			fmt.Println("Error converting data to bigInteger:", err)
			return
		}

		// Encrypt the data
		encryptedData, r, err := crypto.Encrypt(key, data)
		if err != nil {
			fmt.Println("Error encrypting data:", err)
			return
		}

		// Implement your encryption logic here using data

		fmt.Println("Encrypting data for key file ", fileName)

		hexEncryptedData := hex.EncodeToString(encryptedData)
		hexR := hex.EncodeToString(r)
		fmt.Println("Encryption: ", hexEncryptedData)
		fmt.Println("Random: ", hexR)

		return
	}

	if *decryptFlag {
		// Check if a filename is provided for encryption
		if flag.NArg() < 1 {
			fmt.Println("Error: Missing filename for encryption.")
			showHelp()
			return
		}

		fileName := flag.Arg(0)

		key, err := crypto.LoadAESKey(fileName)
		if err != nil {
			fmt.Println("Error loading key:", err)
			return
		}

		hexEnc := flag.Arg(1)
		hexR := flag.Arg(2)

		// Decode the hex string to binary
		// Ensure the key is the correct length (16 bytes for AES-128)
		enc, err := hexToBlockSize(hexEnc)
		if err != nil {
			fmt.Println("Error decoding hex of enc:", err)
			return
		}
		r, err := hexToBlockSize(hexR)
		if err != nil {
			fmt.Println("Error decoding hex of random:", err)
			return
		}

		plaintext, err := crypto.Decrypt(key, r, enc)
		if err != nil {
			fmt.Println("Error decrypting data:", err)
			return
		}

		// Implement your encryption logic here using data

		fmt.Println("Decrypting data for key file ", fileName)

		var result big.Int

		fmt.Println("Decryption: ", result.SetBytes(plaintext))

		return
	}

	// Check if generate-key flag is provided with a filename
	if *generateKeyFlag != "" {
		fileName := *generateKeyFlag

		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println("no home directory", err)
		}

		filePath := home + "/Tools/golang_cli/"

		// Call the generateAndWriteAESKey function from the crypto package
		key, err := crypto.GenerateAndWriteAESKey(filePath + fileName)
		if err != nil {
			fmt.Println("Error generating key:", err)
			return
		}

		fmt.Printf("Generated key and saved to file %s\n", *generateKeyFlag)
		fmt.Printf("Key: %x\n", key)
		return
	}

	// If no valid flags are provided, show help
	showHelp()
}

func hexToBlockSize(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %v", err)
	}

	if len(bytes) != 16 {
		return nil, fmt.Errorf("invalid key length: %d bytes, must be 16 bytes", len(bytes))
	}
	return bytes, nil
}

func showHelp() {
	fmt.Println("Usage: cli-tool [OPTIONS]")
	fmt.Println("Options:")
	fmt.Println("  --help               Show help message")
	fmt.Println("  --encrypt            Encrypt data")
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
