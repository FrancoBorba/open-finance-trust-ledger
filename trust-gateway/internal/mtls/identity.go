package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
)

// Official ASN.1 Object Identifiers (OIDs) defined in Open Finance Brasil Certificate Standards (Chain V10)
var (
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	oidUID                    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
)

type ClientIdentity struct {
	CommonName             string `json:"commonName"`
	SerialNumberCNPJ       string `json:"serialNumberCnpj"`
	OrganizationIdentifier string `json:"organizationIdentifier"`
	SoftwareStatementUID   string `json:"softwareStatementUid"`
	ThumbprintS256         string `json:"x5t#S256"`
}

// ComputeCertThumbprintS256 calculates the RFC 8705 Section 3.1 certificate thumbprint (x5t#S256).
// It computes the SHA-256 hash over the DER-encoded certificate bytes and encodes it in raw Base64URL.
func ComputerCertThumbprintS256(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func ExtractClientIdentity(cert *x509.Certificate) ClientIdentity {

	identity := ClientIdentity{
		CommonName: cert.Subject.CommonName ,
		SerialNumberCNPJ: cert.Subject.SerialNumber,
		ThumbprintS256: ComputerCertThumbprintS256(cert),
	}

	// Standard Go x509.Certificate parses CommonName and SerialNumber automatically,
	// but custom Open Finance OIDs (2.5.4.97 and 0.9.2342...) must be read from Subject.Names.
	for _, attr := range cert.Subject.Names {
		if attr.Type.Equal(oidOrganizationIdentifier) {
			if val, ok := attr.Value.(string); ok {
				identity.OrganizationIdentifier = val
			}
		} else if attr.Type.Equal(oidUID) {
			if val, ok := attr.Value.(string); ok {
				identity.SoftwareStatementUID = val
			}
		}
	}

	return identity
}