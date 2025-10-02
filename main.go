package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// --- AES helpers ---

func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encryptFile(inputFile, password string) error {
	key := deriveKey(password)

	in, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	// PKCS7 padding
	padding := aes.BlockSize - len(in)%aes.BlockSize
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}

	ciphertext := make([]byte, len(in))
	mode.CryptBlocks(ciphertext, in)

	outFile := inputFile + ".aes"
	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(append(iv, ciphertext...))
	if err != nil {
		return err
	}

	fmt.Printf("Encrypted %s -> %s\n", inputFile, outFile)
	return nil
}

func decryptToBytes(inputFile, password string) ([]byte, error) {
	key := deriveKey(password)

	data, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// remove PKCS7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	plaintext = plaintext[:len(plaintext)-padding]

	return plaintext, nil
}

func decryptFile(inputFile, password string) error {
	plaintext, err := decryptToBytes(inputFile, password)
	if err != nil {
		return err
	}

	outFile := filepath.Base(inputFile)
	if filepath.Ext(outFile) == ".aes" {
		outFile = outFile[:len(outFile)-4]
	} else {
		outFile = outFile + ".dec"
	}

	err = os.WriteFile(outFile, plaintext, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted %s -> %s\n", inputFile, outFile)
	return nil
}

// --- Lookup mode ---

type AddrResponse struct {
	ChainStats struct {
		Funded int64 `json:"funded_txo_sum"`
		Spent  int64 `json:"spent_txo_sum"`
	} `json:"chain_stats"`
}

func lookupFile(inputFile, password string) error {
	plaintext, err := decryptToBytes(inputFile, password)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(plaintext))
	for scanner.Scan() {
		addr := scanner.Text()
		if addr == "" {
			continue
		}

		url := fmt.Sprintf("http://pi4:3006/api/address/%s", addr)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("%s ERROR: %v\n", addr, err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var ar AddrResponse
		if err := json.Unmarshal(body, &ar); err != nil {
			fmt.Printf("%s ERROR: invalid JSON\n", addr)
			continue
		}

		balance := ar.ChainStats.Funded - ar.ChainStats.Spent
		fmt.Printf("%s %d\n", addr, balance)
	}

	return scanner.Err()
}

// --- main ---

func main() {
	mode := flag.String("mode", "", "Mode: encrypt, decrypt, lookup")
	file := flag.String("file", "", "File to process")
	password := flag.String("pass", "", "Password")
	flag.Parse()

	if *mode == "" || *file == "" || *password == "" {
		fmt.Println("Usage: crypto -mode [encrypt|decrypt|lookup] -file <file> -pass <password>")
		os.Exit(1)
	}

	var err error
	switch *mode {
	case "encrypt":
		err = encryptFile(*file, *password)
	case "decrypt":
		err = decryptFile(*file, *password)
	case "lookup":
		err = lookupFile(*file, *password)
	default:
		fmt.Println("Invalid mode. Use encrypt, decrypt, or lookup.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
