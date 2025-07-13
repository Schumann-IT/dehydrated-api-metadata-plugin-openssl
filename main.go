package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/schumann-it/dehydrated-api-metadata-plugin-openssl/internal"

	"github.com/hashicorp/go-hclog"
	"github.com/schumann-it/dehydrated-api-go/plugin/proto"
	"github.com/schumann-it/dehydrated-api-go/plugin/server"
)

var (
	// These variables are set by GoReleaser during build
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// OpensslPlugin is a simple plugin implementation
type OpensslPlugin struct {
	proto.UnimplementedPluginServer
	logger hclog.Logger
	config *proto.PluginConfig
}

// Initialize implements the plugin.Plugin interface
func (p *OpensslPlugin) Initialize(_ context.Context, req *proto.InitializeRequest) (*proto.InitializeResponse, error) {
	p.config.FromProto(req.Config)

	if logLevel, err := p.config.GetString("logLevel"); err == nil {
		p.logger.SetLevel(hclog.LevelFromString(logLevel))
	}

	p.logger.Debug("Initialize called")

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
		p.logger.Warn("domain directory does not exist", "domainDir", domainDir)
		metadata.Set("error", fmt.Sprintf("domain directory does not exist: %s", domainDir))
		return metadata.ToGetMetadataResponse()
	}

	// Process certificate files
	certFiles := map[string]string{
		"key":       "privkey.pem",
		"cert":      "cert.pem",
		"chain":     "chain.pem",
		"fullchain": "fullchain.pem",
	}

	for metadataKey, filename := range certFiles {
		filePath := filepath.Join(domainDir, filename)
		var value any

		switch metadataKey {
		case "key":
			value = internal.NewKey(filePath)
		default:
			value = internal.NewCertificate(filePath)
		}

		_ = metadata.SetMap(metadataKey, value)
	}

	return metadata.ToGetMetadataResponse()
}

// Close implements the plugin.Plugin interface
func (p *OpensslPlugin) Close(_ context.Context, _ *proto.CloseRequest) (*proto.CloseResponse, error) {
	p.logger.Debug("Close called")
	return &proto.CloseResponse{}, nil
}

func main() {
	// Parse command line flags
	versionFlag := flag.Bool("version", false, "Print version information")
	flag.Parse()

	// Handle version flag
	if *versionFlag {
		printVersionInfoAndExit()
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "openssl-plugin",
		Level:      hclog.Trace,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	plugin := &OpensslPlugin{
		logger: logger,
		config: proto.NewPluginConfig(),
	}

	server.NewPluginServer(plugin).Serve()
}

// printVersionInfoAndExit prints the version information as a formatted string and exists the program
func printVersionInfoAndExit() {
	fmt.Printf("Version: %s\nCommit: %s\nBuild Time: %s\n", Version, Commit, BuildTime)
	os.Exit(0)
}
