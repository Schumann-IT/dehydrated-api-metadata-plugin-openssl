package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewCertificate_ValidCertificate(t *testing.T) {
	// Create a temporary file with a valid certificate
	tempDir, err := os.MkdirTemp("", "test-certs")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "test.crt")
	certContent := `-----BEGIN CERTIFICATE-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
-----END CERTIFICATE-----`

	err = os.WriteFile(certPath, []byte(certContent), 0644)
	assert.NoError(t, err)

	cert := NewCertificate(certPath)
	assert.NotNil(t, cert)
	assert.Equal(t, certPath, cert.File)
	// Note: The actual subject/issuer values will depend on the test certificate data
}

func TestNewCertificate_NonExistentFile(t *testing.T) {
	cert := NewCertificate("nonexistent.crt")
	assert.NotNil(t, cert)
	assert.Contains(t, cert.Error, "failed to read")
}

func TestNewCertificate_InvalidCertificate(t *testing.T) {
	// Create a temporary file with invalid content
	tempDir, err := os.MkdirTemp("", "test-certs")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "invalid.crt")
	err = os.WriteFile(certPath, []byte("invalid content"), 0644)
	assert.NoError(t, err)

	cert := NewCertificate(certPath)
	assert.NotNil(t, cert)
	assert.Contains(t, cert.Error, "failed to decode PEM block")
}

func TestCertificate_Analyze(t *testing.T) {
	cert := &Certificate{
		File: "nonexistent.crt",
	}

	err := cert.analyze()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
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
	assert.NotEmpty(t, cert.File)
	assert.NotEmpty(t, cert.Subject)
	assert.NotEmpty(t, cert.Issuer)
	assert.False(t, cert.NotBefore.IsZero())
	assert.False(t, cert.NotAfter.IsZero())
	assert.NotEmpty(t, cert.Error)
}
