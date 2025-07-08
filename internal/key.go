package internal

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Key represents metadata and analysis results for a certificate file.
// It holds metadata such as file path, type, size and potential errors during analysis.
type Key struct {
	File  string `json:"file"` // Path to the certificate file
	Type  string `json:"type,omitempty"`
	Size  int    `json:"size,omitempty"`
	Error string `json:"error,omitempty"` // Error represents any error encountered during certificate analysis.
}

// NewKey creates and returns a new Key object by analyzing the provided file for key metadata and errors.
func NewKey(file string) *Key {
	k := &Key{
		File: file,
	}
	err := k.analyze()
	if err != nil {
		k.Error = err.Error()
	}

	return k
}

// analyze reads and parses the key file, determining its type and size, and sets the associated Key metadata.
// Returns an error if the file cannot be read, decoded, or if the key type is unsupported.
func (k *Key) analyze() error {
	data, err := os.ReadFile(k.File)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", k.File, err)
	}

	// Parse all PEM blocks to find the actual key
	var key any
	var parseErr error

	for rest := data; len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		// Skip EC PARAMETERS blocks
		if block.Type == "EC PARAMETERS" {
			rest = remaining
			continue
		}

		// Try to parse the key
		key, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr == nil {
			break
		}

		key, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes) // RSA fallback
		if parseErr == nil {
			break
		}

		key, parseErr = x509.ParseECPrivateKey(block.Bytes) // ECDSA fallback
		if parseErr == nil {
			break
		}

		rest = remaining
	}

	if key == nil {
		return fmt.Errorf("unknown key format or unsupported key type for %s", k.File)
	}

	switch r := key.(type) {
	case *rsa.PrivateKey:
		if r == nil {
			return fmt.Errorf("parsed RSA key is nil for %s", k.File)
		}
		k.Type = "rsa"
		k.Size = r.N.BitLen()
	case *ecdsa.PrivateKey:
		if r == nil {
			return fmt.Errorf("parsed ECDSA key is nil for %s", k.File)
		}
		k.Type = "ecdsa"
		k.Size = r.Curve.Params().BitSize
	case ed25519.PrivateKey:
		k.Type = "ecdsa"
		k.Size = len(r)
	default:
		return fmt.Errorf("unknown key type %v", r)
	}

	return nil
}
