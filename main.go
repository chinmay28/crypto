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
		addr := scanner.Text()
		if addr == "" {
			continue
		}

		url := fmt.Sprintf("http://pi4:3006/api/address/%s", addr)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("❌ %s ERROR: %v\n", addr, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var ar AddrResponse
		if err := json.Unmarshal(body, &ar); err != nil {
			fmt.Printf("⚠️ %s ERROR: invalid JSON\n", addr)
			continue
		}

		balance := ar.ChainStats.Funded - ar.ChainStats.Spent
		total += balance
		fmt.Printf("✅ %s %d\n", addr, balance)
	}
	fmt.Println("-------------------------------------------")
	fmt.Printf("📊 Total for %s: %d\n\n", inputFile, total)

	return total, scanner.Err()
}

// --- main ---
func main() {
	mode := flag.String("mode", "", "Mode: encrypt, decrypt, lookup")
	file := flag.String("file", "", "File to process")
	dir := flag.String("dir", "", "Directory to process (recursive)")
	outDir := flag.String("out", "", "Output directory (required for encrypt/decrypt)")
	flag.Parse()

	if *mode == "" {
		fmt.Println("Usage: crypto -mode [encrypt|decrypt|lookup] -file <file> [-dir <dir>] -out <outdir>")
		os.Exit(1)
	}

	fmt.Print("🔑 Enter password: ")
	passBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	var err error
	switch *mode {
	case "encrypt", "decrypt":
		if *outDir == "" {
			fmt.Println("Error: -out is required for encrypt/decrypt modes")
			os.Exit(1)
		}
		if err := os.MkdirAll(*outDir, 0755); err != nil {
			fmt.Println("Error creating output dir:", err)
			os.Exit(1)
		}

		if *file != "" {
			outFile := filepath.Join(*outDir, filepath.Base(*file)+".aes")
			if *mode == "decrypt" {
				base := filepath.Base(*file)
				if filepath.Ext(base) == ".aes" {
					outFile = filepath.Join(*outDir, base[:len(base)-4])
				} else {
					outFile = filepath.Join(*outDir, base+".dec")
				}
			}
			if *mode == "encrypt" {
				err = encryptFile(*file, outFile, passBytes)
			} else {
				err = decryptFile(*file, outFile, passBytes)
			}
		} else if *dir != "" {
			err = filepath.Walk(*dir, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if info.IsDir() {
					return nil
				}
				outFile := filepath.Join(*outDir, filepath.Base(path)+".aes")
				if *mode == "decrypt" {
					base := filepath.Base(path)
					if filepath.Ext(base) == ".aes" {
						outFile = filepath.Join(*outDir, base[:len(base)-4])
					} else {
						outFile = filepath.Join(*outDir, base+".dec")
					}
				}
				if *mode == "encrypt" {
					return encryptFile(path, outFile, passBytes)
				}
				return decryptFile(path, outFile, passBytes)
			})
		} else {
			fmt.Println("Error: Must provide either -file or -dir for encrypt/decrypt")
			os.Exit(1)
		}

	case "lookup":
		if *file != "" {
			var total int64
			total, err = lookupFile(*file, passBytes)
			if err == nil {
				fmt.Printf("📊 Final Total: %d\n", total)
			}
		} else if *dir != "" {
			var grandTotal int64
			err = filepath.Walk(*dir, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if info.IsDir() {
					return nil
				}
				total, err := lookupFile(path, passBytes)
				if err != nil {
					return err
				}
				grandTotal += total
				return nil
			})
			if err == nil {
				fmt.Println("===========================================")
				fmt.Printf("🏦 Grand Total Across All Files: %d\n", grandTotal)
			        fmt.Println("===========================================")
			}
		} else {
			fmt.Println("Error: Must provide either -file or -dir for lookup")
			os.Exit(1)
		}

	default:
		fmt.Println("Invalid mode. Use encrypt, decrypt, or lookup.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
