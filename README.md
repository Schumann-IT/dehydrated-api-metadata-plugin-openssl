# Dehydrated API Metadata Plugin for OpenSSL

A plugin for the Dehydrated API that provides metadata extraction and analysis capabilities for SSL/TLS certificates and private keys using OpenSSL.

## Overview

This plugin extends the Dehydrated API functionality by providing detailed metadata about SSL/TLS certificates and private keys. It analyzes certificate files and private keys to extract important information such as:

- Certificate metadata (subject, issuer, validity periods)
- Private key information (type, size)
- Certificate chain analysis
- Version information and build details

## Features

- **Certificate file analysis**: Extracts metadata from various certificate files:
  - Private keys (`privkey.pem`)
  - Certificates (`cert.pem`)
  - Certificate chains (`chain.pem`)
  - Full certificate chains (`fullchain.pem`)
- **Multiple key type support**: Supports various key types:
  - RSA (with bit size detection)
  - ECDSA (with curve information)
  - Ed25519
- **Comprehensive metadata**: Provides detailed certificate information:
  - Subject DN (Distinguished Name)
  - Issuer DN (Distinguished Name)
  - Validity periods (not before/after dates)
  - Key type and size
- **Error handling**: Comprehensive error handling and reporting for invalid or corrupted files
- **Version tracking**: Built-in version information with GoReleaser integration
- **Integration ready**: Implements the Dehydrated API plugin interface for seamless integration

## Requirements

- Go 1.24 or later
- OpenSSL (for certificate and key analysis)
- Dehydrated API Go client
- Network access to certificate directories

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/schumann-it/dehydrated-api-metadata-plugin-openssl.git
   cd dehydrated-api-metadata-plugin-openssl
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Build the plugin:
   ```bash
   go build -o openssl-plugin .
   ```

### From Releases

Download the latest release for your platform from the [Releases page](https://github.com/schumann-it/dehydrated-api-metadata-plugin-openssl/releases).

## Configuration

The plugin works with the standard Dehydrated certificate directory structure. No additional configuration is required beyond the standard Dehydrated API configuration.

### Certificate Directory Structure

The plugin expects certificates to be organized in the following structure:
```
/path/to/certificates/
├── example.com/
│   ├── privkey.pem
│   ├── cert.pem
│   ├── chain.pem
│   └── fullchain.pem
└── another-domain.com/
    ├── privkey.pem
    ├── cert.pem
    ├── chain.pem
    └── fullchain.pem
```

## Usage

### Version Information

Check the plugin version and build information:
```bash
./openssl-plugin -version
```

Example output:
```
Version: v1.0.0
Commit: a1b2c3d
Build Time: 2024-03-21T12:34:56Z
```

### Plugin Interface

The plugin implements the Dehydrated API plugin interface and provides the following functionality:

#### Plugin Methods

1. **Initialize**: Sets up the plugin with configuration
2. **GetMetadata**: Analyzes certificate files and returns metadata
3. **Close**: Handles plugin cleanup and resource release

#### Certificate Processing

The plugin processes the following files in each domain directory:
- `privkey.pem`: Private key file (analyzes type, size, format)
- `cert.pem`: Certificate file (analyzes subject, issuer, validity)
- `chain.pem`: Certificate chain file (analyzes intermediate certificates)
- `fullchain.pem`: Full certificate chain file (analyzes complete chain)

#### Example Usage

```go
// Initialize the plugin
plugin := &OpensslPlugin{}
err := plugin.Initialize(config)
if err != nil {
    log.Fatal(err)
}

// Get metadata for a domain
metadata, err := plugin.GetMetadata(domainEntry, dehydratedConfig)
if err != nil {
    log.Fatal(err)
}

// Process the metadata
for key, value := range metadata {
    fmt.Printf("%s: %v\n", key, value)
}
```

## Testing

### Unit Tests

Run unit tests:
```bash
make test
# or
go test -v ./...
```

### Test Coverage

The test suite includes:
- Plugin interface testing
- Certificate file analysis testing
- Private key analysis testing
- Error handling testing
- Version flag testing

### Running Tests with Race Detection

```bash
go test -v -race ./...
```

### Test Structure

```
.
├── main_test.go              # Main plugin tests
├── internal/
│   ├── certificate_test.go   # Certificate analysis tests
│   └── key_test.go          # Private key analysis tests
```

## Development

### Project Structure

```
.
├── main.go                    # Main plugin implementation
├── main_test.go              # Main package tests
├── internal/                 # Internal package
│   ├── certificate.go        # Certificate analysis
│   ├── certificate_test.go   # Certificate tests
│   ├── key.go               # Private key analysis
│   └── key_test.go          # Key tests
├── .github/workflows/       # CI/CD workflows
│   ├── ci.yml              # Continuous integration
│   └── release.yml         # Release automation
├── .golangci.yml           # Linting configuration
├── .goreleaser.yml         # Release configuration
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
├── Makefile                # Build automation
├── LICENSE                 # MIT License
└── README.md              # This file
```

### Building

Use the provided Makefile for common tasks:

```bash
# Build the plugin
make build

# Run tests
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Show all available targets
make help
```

### Building for Different Platforms

The project uses GoReleaser for building releases across multiple platforms:

```bash
# Build for current platform
go build

# Build for all platforms (requires GoReleaser)
goreleaser build --snapshot --clean
```

### Linting

The project uses golangci-lint for code quality checks:

```bash
golangci-lint run
```

## CI/CD

The project includes automated CI/CD workflows:

### Continuous Integration

- **Triggers**: Runs on every push and pull request
- **Go Version**: Tests against Go 1.24
- **Checks**:
  - Unit tests with race detection
  - Linting with golangci-lint
  - Code quality standards enforcement

### Release Automation

- **Triggers**: Automatically creates releases when tags are pushed
- **Builds**: Multi-platform support
  - Linux (amd64, arm64)
  - macOS (amd64, arm64)
  - Windows (amd64)
- **Artifacts**: Creates GitHub releases with binaries and checksums

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go coding standards and conventions
- Write tests for new functionality
- Ensure all tests pass before submitting PRs
- Run linting before submitting PRs
- Update documentation as needed
- Use conventional commit messages

## Author

Jan Schumann

## Support

For issues and questions:

- Create an issue on [GitHub](https://github.com/schumann-it/dehydrated-api-metadata-plugin-openssl/issues)
- Check the existing issues for similar problems
- Review the test examples for usage patterns

## Related Projects

- [Dehydrated API](https://github.com/schumann-it/dehydrated-api-go) - The core API
- [Netscaler Plugin](https://github.com/Schumann-IT/dehydrated-api-metadata-plugin-netscaler) - Similar plugin for Netscaler integration 