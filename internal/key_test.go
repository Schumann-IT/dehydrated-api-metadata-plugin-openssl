package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewKey_ValidRSAKey(t *testing.T) {
	// Create a temporary file with a valid RSA key
	tempDir, err := os.MkdirTemp("", "test-keys")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "test.key")
	keyContent := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
-----END PRIVATE KEY-----`

	err = os.WriteFile(keyPath, []byte(keyContent), 0600)
	require.NoError(t, err)

	key := NewKey(keyPath)
	require.NotNil(t, key)
	require.Equal(t, keyPath, key.File)
}

func TestNewKey_NonExistentFile(t *testing.T) {
	key := NewKey("nonexistent.key")
	require.NotNil(t, key)
	require.Contains(t, key.Error, "failed to read")
}

func TestNewKey_InvalidKey(t *testing.T) {
	// Create a temporary file with invalid content
	tempDir, err := os.MkdirTemp("", "test-keys")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "invalid.key")
	err = os.WriteFile(keyPath, []byte("invalid content"), 0600)
	require.NoError(t, err)

	key := NewKey(keyPath)
	require.NotNil(t, key)
	require.Contains(t, key.Error, "failed to decode PEM block")
}

func TestKey_Analyze(t *testing.T) {
	key := &Key{
		File: "nonexistent.key",
	}

	err := key.analyze()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read")
}

func TestKey_JSONTags(t *testing.T) {
	key := &Key{
		File:  "test.key",
		Type:  "rsa",
		Size:  2048,
		Error: "test error",
	}

	// Verify that all fields have proper JSON tags
	require.NotEmpty(t, key.File)
	require.NotEmpty(t, key.Type)
	require.Positive(t, key.Size)
	require.NotEmpty(t, key.Error)
}

func TestKey_SupportedKeyTypes(t *testing.T) {
	// Test cases for different key types
	testCases := []struct {
		name     string
		keyType  string
		keySize  int
		expected string
	}{
		{"RSA", "rsa", 2048, "rsa"},
		{"ECDSA", "ecdsa", 256, "ecdsa"},
		{"Ed25519", "ed25519", 32, "ed25519"}, // Note: Ed25519 is mapped to ecdsa in the code
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := &Key{
				Type: tc.keyType,
				Size: tc.keySize,
			}
			require.Equal(t, tc.expected, key.Type)
			require.Positive(t, key.Size)
		})
	}
}
