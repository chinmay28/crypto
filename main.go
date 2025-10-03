package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// --- Key derivation using scrypt ---
func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32) // N=32768, r=8, p=1, 32-byte key
}

// --- AES-GCM helpers ---
func encryptFile(inputFile, outFile string, password []byte) error {
	in, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nil, nonce, in, nil)

	// output file = salt || nonce || ciphertext
	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(append(append(salt, nonce...), ciphertext...))
	if err != nil {
		return err
	}

	fmt.Printf("🔒 Encrypted %s -> %s\n", inputFile, outFile)
	return nil
}

func decryptToBytes(inputFile string, password []byte) ([]byte, error) {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}

	if len(data) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	salt := data[:16]
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < 16+aesgcm.NonceSize() {
		return nil, fmt.Errorf("data too short for nonce")
	}

	nonce := data[16 : 16+aesgcm.NonceSize()]
	ciphertext := data[16+aesgcm.NonceSize():]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func decryptFile(inputFile, outFile string, password []byte) error {
	plaintext, err := decryptToBytes(inputFile, password)
	if err != nil {
		return err
	}

	err = os.WriteFile(outFile, plaintext, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("🔓 Decrypted %s -> %s\n", inputFile, outFile)
	return nil
}

// --- Lookup mode ---

type AddrResponse struct {
	ChainStats struct {
		Funded int64 `json:"funded_txo_sum"`
		Spent  int64 `json:"spent_txo_sum"`
	} `json:"chain_stats"`
}

func lookupFile(inputFile string, password []byte) (int64, error) {
	plaintext, err := decryptToBytes(inputFile, password)
	if err != nil {
		return 0, err
	}

	var total int64
	scanner := bufio.NewScanner(bytes.NewReader(plaintext))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		addr := strings.TrimSpace(parts[0])
		extras := parts[1:]

		url := fmt.Sprintf("http://pi4:3006/api/address/%s", addr)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("❌ %s\tERROR: %v\n", addr, err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var ar AddrResponse
		if err := json.Unmarshal(body, &ar); err != nil {
			fmt.Printf("⚠️ %s\tERROR: invalid JSON\n", addr)
			continue
		}

		balance := ar.ChainStats.Funded - ar.ChainStats.Spent
		total += balance

		fmt.Printf("✅ %s\t%d", addr, balance)
		for _, ex := range extras {
			fmt.Printf("\t%s", strings.TrimSpace(ex))
		}
		fmt.Println()
	}

	fmt.Println("------------------------------------------------")
	fmt.Printf("💰 Total for %s:\t%d\n\n", inputFile, total)

	return total, scanner.Err()
}

// --- Helpers for directory walking ---
func processDir(mode, dir, out string, password []byte) error {
	var grandTotal int64
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		switch mode {
		case "encrypt":
			rel, _ := filepath.Rel(dir, path)
			outFile := filepath.Join(out, rel+".aes")
			if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
				return err
			}
			return encryptFile(path, outFile, password)

		case "decrypt":
			rel, _ := filepath.Rel(dir, path)
			base := filepath.Base(path)
			var outFile string
			if filepath.Ext(base) == ".aes" {
				outFile = filepath.Join(out, rel[:len(rel)-4])
			} else {
				outFile = filepath.Join(out, rel+".dec")
			}
			if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
				return err
			}
			return decryptFile(path, outFile, password)

		case "lookup":
			total, err := lookupFile(path, password)
			if err != nil {
				fmt.Printf("❌ Error in %s: %v\n", path, err)
				return nil
			}
			grandTotal += total
		}
		return nil
	})

	if mode == "lookup" && err == nil {
		fmt.Println("===========================================")
		fmt.Printf("🏦 Grand Total Across All Files: %d\n", grandTotal)
		fmt.Println("===========================================")
	}

	return err
}

// --- main ---
func main() {
	mode := flag.String("mode", "", "Mode: encrypt, decrypt, lookup")
	file := flag.String("file", "", "Single file to process")
	dir := flag.String("dir", "", "Directory to process recursively")
	out := flag.String("out", "", "Output directory (required for encrypt/decrypt)")
	flag.Parse()

	if *mode == "" {
		fmt.Println("Usage: crypto -mode [encrypt|decrypt|lookup] -file <file> | -dir <dir> [-out <dir>]")
		os.Exit(1)
	}

	if *mode == "encrypt" || *mode == "decrypt" {
		if *dir == "" {
			fmt.Println("Error: -dir is required for encrypt/decrypt")
			os.Exit(1)
		}
		if *out == "" {
			fmt.Println("Error: -out is required for encrypt/decrypt")
			os.Exit(1)
		}
	}

	if *mode == "lookup" && *dir == "" && *file == "" {
		fmt.Println("Error: -dir or -file required for lookup")
		os.Exit(1)
	}

	fmt.Print("🔑 Enter password: ")
	passBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	var err error
	switch *mode {
	case "encrypt", "decrypt", "lookup":
		if *file != "" {
			switch *mode {
			case "encrypt":
				err = encryptFile(*file, filepath.Join(*out, filepath.Base(*file)+".aes"), passBytes)
			case "decrypt":
				base := filepath.Base(*file)
				var outFile string
				if filepath.Ext(base) == ".aes" {
					outFile = filepath.Join(*out, base[:len(base)-4])
				} else {
					outFile = filepath.Join(*out, base+".dec")
				}
				err = decryptFile(*file, outFile, passBytes)
			case "lookup":
				_, err = lookupFile(*file, passBytes)
			}
		} else if *dir != "" {
			err = processDir(*mode, *dir, *out, passBytes)
		}
	default:
		fmt.Println("Invalid mode. Use encrypt, decrypt, or lookup.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("❌ Error:", err)
		os.Exit(1)
	}
}
