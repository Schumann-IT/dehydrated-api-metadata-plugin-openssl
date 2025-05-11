package internal

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Certificate represents an X.509 certificate.
// It holds metadata such as file path, subject, issuer, validity period, and potential errors during analysis.
type Certificate struct {
	File      string    `json:"file"`                 // Path to the certificate file
	Subject   string    `json:"subject,omitempty"`    // Certificate subject DN
	Issuer    string    `json:"issuer,omitempty"`     // Certificate issuer DN
	NotBefore time.Time `json:"not_before,omitempty"` // Start of validity period
	NotAfter  time.Time `json:"not_after,omitempty"`  // End of validity period
	Error     string    `json:"error,omitempty"`      // Error represents any error encountered during certificate analysis.
}

// NewCertificate creates a new Certificate instance from the provided file path and analyzes its metadata.
func NewCertificate(file string) *Certificate {
	c := &Certificate{
		File: file,
	}
	err := c.analyze()
	if err != nil {
		c.Error = err.Error()
	}

	return c
}

// analyze reads and parses the certificate file, extracting metadata such as subject, issuer, and validity period.
func (c *Certificate) analyze() error {
	b, err := os.ReadFile(c.File)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", c.File, err)
	}

	// Decode the PEM block
	bp, _ := pem.Decode(b)
	if bp == nil {
		return fmt.Errorf("failed to decode PEM block for %s", c.File)
	}
	cert, err := x509.ParseCertificate(bp.Bytes)
	if err != nil {
		return err
	}

	c.Subject = cert.Subject.String()
	c.Issuer = cert.Issuer.String()
	c.NotBefore = cert.NotBefore
	c.NotAfter = cert.NotAfter

	return nil
}
