package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	// "encoding/pem"
)

func GenCSR(privateKey *rsa.PrivateKey, subjectInfo x509.CertificateRequest) ([]byte, error) {
	csrTemplate := &x509.CertificateRequest{
		Subject:  subjectInfo.Subject,
		DNSNames: subjectInfo.DNSNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}

	return csrBytes, nil

	// pemCSR := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "CERTIFICATE REQUEST",
	// 	Bytes: csrBytes,
	// })

	// return pemCSR, nil
}