# Crypto

A command-line utility in **Go** for securely encrypting, decrypting, and looking up cryptocurrency addresses. It supports **single files** and **directories recursively**, with optional extra metadata, and displays results with **friendly emojis and tabular formatting**.

Repository: [https://github.com/chinmay28/crypto](https://github.com/chinmay28/crypto)

---

## Features

- **AES-GCM encryption** with strong key derivation (Scrypt, 32-byte key).
- **Decryption** to recover original files.
- **Lookup** mode to fetch balances for cryptocurrency addresses via a local API.
- Supports:
  - Single file or recursive directories (`-file` / `-dir`)
  - Tab-separated display with optional metadata per address
  - Ignoring comments and extra tokens in files
  - Grand total across multiple files for lookup
- Secure password input (hidden typing)
- Emoji-enhanced output for clarity

---

## Installation

```bash
git clone https://github.com/chinmay28/crypto.git
cd crypto
go build -o crypto main.go
```

This will produce a `crypto` binary.

---

## Usage

```bash
./crypto -mode [encrypt|decrypt|lookup] -file <file> | -dir <directory> [-out <output-directory>]
```

### Arguments

| Flag    | Description                                           |
| ------- | ----------------------------------------------------- |
| `-mode` | Mode of operation: `encrypt`, `decrypt`, or `lookup`. |
| `-file` | Single file to process.                               |
| `-dir`  | Directory to process recursively.                     |
| `-out`  | Output directory (required for encrypt/decrypt).      |

---

## Modes

### 1. Encrypt

Encrypt a file or directory recursively:

```bash
./crypto -mode encrypt -dir ./addresses -out ./encrypted
```

Output files will have `.aes` appended.

### 2. Decrypt

Decrypt a file or directory recursively:

```bash
./crypto -mode decrypt -dir ./encrypted -out ./decrypted
```

Original file names are restored automatically.

### 3. Lookup

Decrypt a file and query balances for addresses using a local API (`http://pi4:3006/api/address/<address>`):

```bash
./crypto -mode lookup -file ./encrypted/addresses.aes
```

Or process an entire directory recursively:

```bash
./crypto -mode lookup -dir ./encrypted
```

**Lookup features:**

- Ignores lines starting with `#` (comments).
- Only considers the first token in a line (before comma) as the address.
- Displays extra tokens as additional columns.
- Prints **total per file** and **grand total across all files**.
- Tab-separated output for readability:

```
✅ wspcdl567712    1842672    5246428
```

---

## Notes

- **Password input** is hidden for security.
- Ensure your local API is running for lookup mode.
- Directory structure is preserved for encrypt/decrypt outputs.

---

## Example Workflow

1. Encrypt addresses:

```bash
./crypto -mode encrypt -dir ./addresses -out ./encrypted
```

2. Decrypt addresses:

```bash
./crypto -mode decrypt -dir ./encrypted -out ./decrypted
```

3. Lookup balances:

```bash
./crypto -mode lookup -dir ./encrypted
```

---

## Dependencies

- [Go](https://golang.org/dl/) >= 1.20
- `golang.org/x/crypto/scrypt`
- `golang.org/x/term`

---

## License

MIT License

