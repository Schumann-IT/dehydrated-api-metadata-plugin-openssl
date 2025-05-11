package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/schumann-it/dehydrated-api-metadata-plugin-openssl/internal"

	"github.com/hashicorp/go-hclog"
	"github.com/schumann-it/dehydrated-api-go/plugin/proto"
	"github.com/schumann-it/dehydrated-api-go/plugin/server"
)

// OpensslPlugin is a simple plugin implementation
type OpensslPlugin struct {
	proto.UnimplementedPluginServer
	logger hclog.Logger
	config *proto.PluginConfig
}

// Initialize implements the plugin.Plugin interface
func (p *OpensslPlugin) Initialize(_ context.Context, req *proto.InitializeRequest) (*proto.InitializeResponse, error) {
	p.logger.Debug("Initialize called")
	p.config.FromProto(req.Config)
	return &proto.InitializeResponse{}, nil
}

// GetMetadata implements the plugin.Plugin interface
func (p *OpensslPlugin) GetMetadata(_ context.Context, req *proto.GetMetadataRequest) (*proto.GetMetadataResponse, error) {
	p.logger.Debug("GetMetadata called")

	// Create a new Metadata for the response
	metadata := proto.NewMetadata()

	// Get domain directory
	dir := req.GetDomainEntry().GetDomain()
	if req.GetDomainEntry().GetAlias() != "" {
		dir = req.GetDomainEntry().GetAlias()
	}
	domainDir := filepath.Join(req.DehydratedConfig.CertDir, dir)

	// Check if the domain directory exists
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		metadata.SetError(fmt.Sprintf("domain directory does not exist: %s", domainDir))
		return metadata.ToGetMetadataResponse()
	}

	// Process certificate files
	certFiles := map[string]string{
		"key":       "privkey.pem",
		"cert":      "cert.pem",
		"chain":     "chain.pem",
		"fullchain": "fullchain.pem",
	}

	var errs []string
	for metadataKey, filename := range certFiles {
		filePath := filepath.Join(domainDir, filename)
		var value interface{}
		var err error

		switch metadataKey {
		case "key":
			key := internal.NewKey(filePath)
			value, err = toMap(key)
		default:
			cert := internal.NewCertificate(filePath)
			value, err = toMap(cert)
		}

		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to process %s: %v", filename, err))
			continue
		}

		metadata.Set(metadataKey, value)
	}

	// Add errors to metadata if any occurred
	if len(errs) > 0 {
		metadata.SetError(strings.Join(errs, "; "))
	}

	return metadata.ToGetMetadataResponse()
}

// Close implements the plugin.Plugin interface
func (p *OpensslPlugin) Close(_ context.Context, _ *proto.CloseRequest) (*proto.CloseResponse, error) {
	p.logger.Debug("Close called")
	return &proto.CloseResponse{}, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "openssl-plugin",
		Level:  hclog.Trace,
		Output: os.Stdout,
	})

	plugin := &OpensslPlugin{
		logger: logger,
		config: proto.NewPluginConfig(),
	}

	server.NewPluginServer(plugin).Serve()
}

// toMap converts a struct to a map[string]interface{} using JSON marshaling
func toMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return result, nil
}
