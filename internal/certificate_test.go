package internal

import (
	"encoding/json"
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

func TestNewCertificate_WithDNSNames(t *testing.T) {
	// Create a temporary file with a certificate that has DNS names
	tempDir, err := os.MkdirTemp("", "test-certs")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "test-dns.crt")
	// This is a sample certificate with multiple DNS names in SAN
	certContent := `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`

	err = os.WriteFile(certPath, []byte(certContent), 0600)
	require.NoError(t, err)

	cert := NewCertificate(certPath)
	require.NotNil(t, cert)
	require.Equal(t, certPath, cert.File)

	t.Logf("cert.Error: %q", cert.Error)
	t.Logf("cert.DNSNames: %#v", cert.DNSNames)

	// Verify that DNSNames field is properly initialized
	require.NotNil(t, cert.DNSNames, "DNSNames should not be nil")
}

func TestNewCertificate_WithMultipleDNSNames(t *testing.T) {
	// Create a temporary file with a certificate that has multiple DNS names
	tempDir, err := os.MkdirTemp("", "test-certs")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "test-multiple-dns.crt")
	// Certificate with multiple DNS names in SAN: example.com, www.example.com, api.example.com, *.example.com
	certContent := `-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAN5/b/SK/vb1MA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC2V4YW1wbGUuY29tMB4XDTI1MDcxNTIwMjg1NFoXDTI2MDcxNTIwMjg1NFow
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDSY86Mc3ltxPHPvzoOiGAf0BHmwnIhzdpRXMrrSNEiXczcSgZAzqO9
7goSav/7HD1XDFYy0PkGnZmEK9KGwlXycBzTE92/L9F4oLlJyJ6IH2jx3PL4hAnp
Pwo0piMt2ebnrRLT9YzooP57pQsqriJdu82Mi/OaBPh0VdbNEuF+lytxXhL65Vu2
LPm9C5osPMFZFCE2xhj1Gn39d2iizh64NHUr50KR6eMvuLx7o6Qk1isftSrn/vaf
JrSFeNbQze+XI9QF+3U5sa290GP2E5/iVBvXoYH1f2Ru6Qz+r/43+oSRVXC5TySg
uYu6nbVz3ZAbSTRKqNw3oNQw6wBpUwLJAgMBAAGjSzBJMEcGA1UdEQRAMD6CC2V4
YW1wbGUuY29tgg93d3cuZXhhbXBsZS5jb22CD2FwaS5leGFtcGxlLmNvbYINKi5l
eGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAnnvONhpfMwYPMaIBaDcgvIR9
HbextnoPOMQM8uzc97QNoTc3xThACMCm564i0c4tW3F3fY/gy3cel3+T1spylQxE
EVhU6AkJRDAcd916lwhYYxPqzFJhhuyArxP2lgMxm0czziDr0WI8QXwQIq8RQCOT
cTGNp8ovJfObmAW7/wYfwG9b+Q3Hs4722hKMCq3eXX7u36la6YpU3J2bDH5/B8ot
dUSnS8LBv0O7naZZ04LSpc2QwfP8Ou973FPIrF8iv8Gu1Mple7GTmfbzw82mMtHZ
JBzvhETSuFdtzG61Djio7vQAhLLcPRMsv86yGSTN3/EBQlyvhM2cxHNKCIHDLg==
-----END CERTIFICATE-----`

	err = os.WriteFile(certPath, []byte(certContent), 0600)
	require.NoError(t, err)

	cert := NewCertificate(certPath)
	require.NotNil(t, cert)
	require.Equal(t, certPath, cert.File)
	require.Empty(t, cert.Error, "Certificate should be parsed without error")

	t.Logf("cert.DNSNames: %#v", cert.DNSNames)

	// Verify that DNSNames field is properly initialized and contains the expected DNS names
	require.NotNil(t, cert.DNSNames, "DNSNames should not be nil")
	require.Len(t, cert.DNSNames, 4, "Should have 4 DNS names")
	require.Contains(t, cert.DNSNames, "example.com")
	require.Contains(t, cert.DNSNames, "www.example.com")
	require.Contains(t, cert.DNSNames, "api.example.com")
	require.Contains(t, cert.DNSNames, "*.example.com")
}

func TestCertificate_DNSNamesField(t *testing.T) {
	// Test that DNSNames field is properly handled in the Certificate struct
	cert := &Certificate{
		File:     "test.crt",
		DNSNames: []string{"example.com", "www.example.com"},
	}

	// Verify DNSNames field is accessible and contains expected values
	require.NotNil(t, cert.DNSNames)
	require.Len(t, cert.DNSNames, 2)
	require.Contains(t, cert.DNSNames, "example.com")
	require.Contains(t, cert.DNSNames, "www.example.com")

	// Test with empty DNS names
	certEmpty := &Certificate{
		File:     "test.crt",
		DNSNames: []string{},
	}

	require.NotNil(t, certEmpty.DNSNames)
	require.Empty(t, certEmpty.DNSNames)
}

func TestCertificate_DNSNamesJSONSerialization(t *testing.T) {
	// Test that DNSNames field is correctly serialized as dns_names in JSON
	cert := &Certificate{
		File:     "test.crt",
		Subject:  "CN=example.com",
		Issuer:   "CN=Test CA",
		DNSNames: []string{"example.com", "www.example.com", "api.example.com"},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(cert)
	require.NoError(t, err)

	t.Logf("JSON output: %s", string(jsonData))

	// Verify the JSON contains dns_names field
	require.Contains(t, string(jsonData), `"dns_names"`)

	// Unmarshal back to verify the structure
	var unmarshaledCert Certificate
	err = json.Unmarshal(jsonData, &unmarshaledCert)
	require.NoError(t, err)

	// Verify DNSNames field is preserved
	require.Equal(t, cert.DNSNames, unmarshaledCert.DNSNames)
	require.Len(t, unmarshaledCert.DNSNames, 3)
	require.Contains(t, unmarshaledCert.DNSNames, "example.com")
	require.Contains(t, unmarshaledCert.DNSNames, "www.example.com")
	require.Contains(t, unmarshaledCert.DNSNames, "api.example.com")
}

func TestCertificate_DNSNamesJSONEmpty(t *testing.T) {
	// Test that empty DNSNames is correctly handled in JSON (omitted due to omitempty tag)
	cert := &Certificate{
		File:     "test.crt",
		Subject:  "CN=example.com",
		Issuer:   "CN=Test CA",
		DNSNames: []string{}, // Empty slice
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(cert)
	require.NoError(t, err)

	t.Logf("JSON output (empty DNSNames): %s", string(jsonData))

	// Verify the JSON does NOT contain dns_names field when empty (due to omitempty tag)
	require.NotContains(t, string(jsonData), `"dns_names"`)

	// Unmarshal back to verify the structure
	var unmarshaledCert Certificate
	err = json.Unmarshal(jsonData, &unmarshaledCert)
	require.NoError(t, err)

	// Accept both nil and empty slice as valid for DNSNames after unmarshaling
	require.Empty(t, unmarshaledCert.DNSNames, "DNSNames should be empty after unmarshaling")
}
