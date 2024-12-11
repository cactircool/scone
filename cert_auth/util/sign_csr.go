package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func readCACertificate(path string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM: %v", err)
	}

	// b, err := x509.DecryptPEMBlock(block, []byte("password"))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to decrypt CA certificate PEM: %v", err)
	// }

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	return caCert, nil
}

func readCAPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %v", err)
	}

	// Try parsing as PKCS8
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	der, err := x509.DecryptPEMBlock(block, []byte("password"))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CA private key PEM: %v", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key PEM: %v", err)
	}
	return privateKey, nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	return serialNumber, nil
}

func signCSR(csrBytes []byte, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, error) {
	// Decode the CSR
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR")
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	// Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %v", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 365 days
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(
		rand.Reader, 
		template, 
		caCert, 
		csr.PublicKey, 
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return certPEM, nil
}

func Sign(key *rsa.PrivateKey) ([]byte, error) {
	csrBytes, err := GenCSR(key)
	if err != nil {
		return nil, fmt.Errorf("failed generating csr: %v", err)
	}

	caCert, err := readCACertificate("/Users/arjun/Dump/scone/cert_auth/certs/radius/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("failed reading ca cert: %v", err)
	}

	caKey, err := readCAPrivateKey("/Users/arjun/Dump/scone/cert_auth/certs/radius/ca.key")
	if err != nil {
		return nil, fmt.Errorf("failed reading ca key: %v", err)
	}

	signedCert, err := signCSR(csrBytes, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("error signing CSR: %v", err)
	}

	return signedCert, nil
}