package util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/google/uuid"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func ExportPKCS12(
	clientKeyBytes []byte, 
	clientCertBytes []byte, 
	caCerts []*x509.Certificate, 
	password string,
) ([]byte, error) {
	// Decode private key
	privateKey, err := x509.ParsePKCS1PrivateKey(clientKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %v", err)
	}

	// Create PKCS#12 archive
	p12Bytes, err := pkcs12.Modern.Encode(privateKey, clientCert, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#12 archive: %v", err)
	}

	return p12Bytes, nil
}

func Generate(daysValid int, password string) ([]byte, error) {
	caPEM, caKey, caCerts := static.ca, static.caKey, static.caCerts

	key, err := GenKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create client.key: %v", err)
	}

	csr, err := GenCSR(key, x509.CertificateRequest{
		Subject: pkix.Name{
			Country: []string{"US"},
			Organization: []string{"scone"},
			OrganizationalUnit: []string{"dev"},
			Locality: []string{"Texas"},
			Province: []string{"Frisco"},
			StreetAddress: []string{"13270 Mossvine Dr"},
			PostalCode: []string{"75035"},
			CommonName: uuid.NewString(),
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create client.csr: %v", err)
	}

	crt, err := SignCSR(csr, caPEM, caKey, daysValid)
	
	if err != nil {
		return nil, fmt.Errorf("failed to create client.crt: %v", err)
	}

	p12, err := ExportPKCS12(key.N.Bytes(), crt, caCerts, password)
	
	if err != nil {
		return nil, fmt.Errorf("failed to create client.p12: %v", err)
	}

	return p12, nil
}