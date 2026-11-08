package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"errors"
)

// BuildServerTLSConfig creates a strict mTLS configuration for the Gateway HTTP server.
// It enforces ICP-Brasil client certificate verification at the transport layer.
func BuildServerTLSConfig(caCertPath string) (*tls.Config , error) {

	// Read the public Root CA certificate (ca.crt) from disk.
	// The server never touches ca.key; it only needs ca.crt's public key
	// to verify signatures on incoming client certificates (client.crt).
	caCertBytes , err := os.ReadFile(caCertPath) 
	if err != nil {
		return nil , fmt.Errorf("failed to read Root CA certificate from %s: %w",caCertPath , err)
	}

	caCertPool := x509.NewCertPool() 
	if ok := caCertPool.AppendCertsFromPEM(caCertBytes); !ok {
		return nil, errors.New("failed to parse and append Root CA certificate to x509 pool")
	}

	// Return the strict mTLS configuration.
	// RequireAndVerifyClientCert automatically checks:
	// - Signature chain against caCertPool (ca.crt)
	// - Certificate expiration window (NotBefore / NotAfter)
	// - Proof-of-possession of client.key via TLS CertificateVerify
	return &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}