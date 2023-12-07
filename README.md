# Tools

# CLI Tool for a random AES Encryption and Decryption

This command-line tool provides functionalities for encrypting and decrypting data using AES encryption. It also supports key generation and storage.

## Usage

```bash
cli-tool [OPTIONS]
```

### Options:

- `--help`: Show help message

- `--encrypt`: Encrypt data. Provide a filename as an additional argument.

- `--decrypt`: Decrypt data. Provide a filename and two encrypted hex strings as additional arguments.

- `--generate-key FILE`: Generate key and save to the specified file.

## Examples:

### Encryption:

```bash
cli-tool --encrypt keyfile.txt 1234567890123456
```

### Decryption:

```bash
cli-tool --decrypt keyfile.txt <encrypted-hex-string> <random-hex-string>
```

### Generate Key:

```bash
cli-tool --generate-key mykey.txt
```

## Prerequisites

- Go (Golang) installed on your system.

## Installation

Clone the repository:

```bash
git clone https://github.com/soda-mpc/tools.git
```

Navigate to the project directory:

```bash
cd tools/golang_cli
```

Build the project:

```bash
go build
```
