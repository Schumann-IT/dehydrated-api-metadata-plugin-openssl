package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/schumann-it/dehydrated-api-go/plugin/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestOpensslPlugin_Initialize(t *testing.T) {
	plugin := &OpensslPlugin{
		logger: hclog.NewNullLogger(),
		config: proto.NewPluginConfig(),
	}

	config := make(map[string]*structpb.Value)
	req := &proto.InitializeRequest{
		Config: config,
	}

	resp, err := plugin.Initialize(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestOpensslPlugin_GetMetadata_NonExistentDirectory(t *testing.T) {
	plugin := &OpensslPlugin{
		logger: hclog.NewNullLogger(),
		config: proto.NewPluginConfig(),
	}

	req := &proto.GetMetadataRequest{
		DomainEntry: &proto.DomainEntry{
			Domain: "nonexistent.example.com",
		},
		DehydratedConfig: &proto.DehydratedConfig{
			CertDir: "/tmp",
		},
	}

	resp, err := plugin.GetMetadata(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Check for error in metadata
	assert.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error, "domain directory does not exist")
}

func TestOpensslPlugin_GetMetadata_ValidDirectory(t *testing.T) {
	// Create a temporary directory with test certificates
	tempDir, err := os.MkdirTemp("", "test-certs")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test certificate files
	certFiles := map[string]string{
		"privkey.pem":   "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END PRIVATE KEY-----\n",
		"cert.pem":      "-----BEGIN CERTIFICATE-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END CERTIFICATE-----\n",
		"chain.pem":     "-----BEGIN CERTIFICATE-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END CERTIFICATE-----\n",
		"fullchain.pem": "-----BEGIN CERTIFICATE-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END CERTIFICATE-----\n",
	}

	for filename, content := range certFiles {
		err := os.WriteFile(filepath.Join(tempDir, filename), []byte(content), 0644)
		assert.NoError(t, err)
	}

	plugin := &OpensslPlugin{
		logger: hclog.NewNullLogger(),
		config: proto.NewPluginConfig(),
	}

	req := &proto.GetMetadataRequest{
		DomainEntry: &proto.DomainEntry{
			Domain: "test.example.com",
		},
		DehydratedConfig: &proto.DehydratedConfig{
			CertDir: tempDir,
		},
	}

	resp, err := plugin.GetMetadata(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	// Note: The actual metadata content will depend on the test certificate data
}

func TestToMap(t *testing.T) {
	type testStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	input := testStruct{
		Name:  "test",
		Value: 42,
	}

	result, err := toMap(input)
	assert.NoError(t, err)
	assert.Equal(t, "test", result["name"])
	assert.Equal(t, float64(42), result["value"]) // JSON numbers are float64
}
