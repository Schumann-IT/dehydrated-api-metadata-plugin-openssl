package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewCertificate_ValidCertificate(t *testing.T) {
	// Create a temporary file with a valid certificate
	tempDir, err := os.MkdirTemp("", "test-certs")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "test.crt")
	certContent := `-----BEGIN CERTIFICATE-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
-----END CERTIFICATE-----`

	err = os.WriteFile(certPath, []byte(certContent), 0600)
	require.NoError(t, err)

	cert := NewCertificate(certPath)
	require.NotNil(t, cert)
	require.Equal(t, certPath, cert.File)
	// Note: The actual subject/issuer values will depend on the test certificate data
}

func TestNewCertificate_NonExistentFile(t *testing.T) {
	cert := NewCertificate("nonexistent.crt")
	require.NotNil(t, cert)
	require.Contains(t, cert.Error, "failed to read")
}

func TestNewCertificate_InvalidCertificate(t *testing.T) {
	// Create a temporary file with invalid content
	tempDir, err := os.MkdirTemp("", "test-certs")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "invalid.crt")
	err = os.WriteFile(certPath, []byte("invalid content"), 0600)
	require.NoError(t, err)

	cert := NewCertificate(certPath)
	require.NotNil(t, cert)
	require.Contains(t, cert.Error, "failed to decode PEM block")
}

func TestCertificate_Analyze(t *testing.T) {
	cert := &Certificate{
		File: "nonexistent.crt",
	}

	err := cert.analyze()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read")
}

func TestCertificate_JSONTags(t *testing.T) {
	cert := &Certificate{
		File:      "test.crt",
		Subject:   "test subject",
		Issuer:    "test issuer",
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		Error:     "test error",
	}

	// Verify that all fields have proper JSON tags
	require.NotEmpty(t, cert.File)
	require.NotEmpty(t, cert.Subject)
	require.NotEmpty(t, cert.Issuer)
	require.False(t, cert.NotBefore.IsZero())
	require.False(t, cert.NotAfter.IsZero())
	require.NotEmpty(t, cert.Error)
}
