package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"math/big"
	"net/http"
	"time"

	"github.com/joho/godotenv"
	"software.sslmate.com/src/go-pkcs12"
)

/**
 * All you have to do now is create an endpoint that takes a common name, a start time, an end time
 * and creates a certificate from that information that is signed by the root ca of the radius server
 *
 * This data should be returned in the response as a string, not as a download
 */

// CertificateAuthority holds the CA certificates and keys
type CertificateAuthority struct {
	RootCert         *x509.Certificate
	RootKey          *rsa.PrivateKey
	IntermediateCert *x509.Certificate
	IntermediateKey  *rsa.PrivateKey
}

// Load root CA certificate from DER file
func loadRootCACertificate(certPath string) (*x509.Certificate, error) {
	// Read the DER file
	derBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate file: %v", err)
	}

	// Parse the certificate
	rootCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing CA certificate: %v", err)
	}

	return rootCert, nil
}

// Load root CA private key from PEM file
func loadRootCAPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	// Read the PEM file
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading CA private key file: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	return privateKey, nil
}

// Initialize the Certificate Authority from environment configuration
func NewCertificateAuthority() (*CertificateAuthority, error) {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file, using system environment")
	}

	// Get certificate directory from environment
	certDir := os.Getenv("RADIUS_CERTS_DIR")
	if certDir == "" {
		return nil, fmt.Errorf("RADIUS_CERTS_DIR environment variable not set")
	}

	// Construct full paths
	rootCertPath := filepath.Join(certDir, "ca.der")
	rootKeyPath := filepath.Join(certDir, "ca.key")

	// Load root CA certificate
	rootCert, err := loadRootCACertificate(rootCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA certificate: %v", err)
	}

	// Load root CA private key
	rootKey, err := loadRootCAPrivateKey(rootKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA private key: %v", err)
	}

	// Generate Intermediate CA (you might want to load this from files too)
	intermediateCert, intermediateKey, err := generateIntermediateCA(rootCert, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate CA: %v", err)
	}

	return &CertificateAuthority{
		RootCert:         rootCert,
		RootKey:          rootKey,
		IntermediateCert: intermediateCert,
		IntermediateKey:  intermediateKey,
	}, nil
}

// Generate intermediate CA (similar to previous implementation)
func generateIntermediateCA(rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key for intermediate CA
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create intermediate CA template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	intermediateTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Intermediate CA"},
			CommonName:   "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0), // Valid for 5 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}

	// Create intermediate CA certificate signed by root CA
	intermediateCert, err := x509.CreateCertificate(
		rand.Reader, 
		intermediateTemplate, 
		rootCert, 
		&intermediateKey.PublicKey, 
		rootKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// Parse the created certificate
	parsedIntermediateCert, err := x509.ParseCertificate(intermediateCert)
	if err != nil {
		return nil, nil, err
	}

	return parsedIntermediateCert, intermediateKey, nil
}

// Generate a new end-entity certificate (similar to previous implementation)
func (ca *CertificateAuthority) GenerateCertificate(commonName string, start time.Time, end time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key for end entity
	entityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create end entity certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	entityTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"scone"},
			CommonName:   commonName,
		},
		NotBefore:             start,
		NotAfter:              end, 
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Create end entity certificate signed by intermediate CA
	entityCert, err := x509.CreateCertificate(
		rand.Reader, 
		entityTemplate, 
		ca.IntermediateCert, 
		&entityKey.PublicKey, 
		ca.IntermediateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// Parse the created certificate
	parsedEntityCert, err := x509.ParseCertificate(entityCert)
	if err != nil {
		return nil, nil, err
	}

	return parsedEntityCert, entityKey, nil
}

// Create a P12 file in memory (similar to previous implementation)
func (ca *CertificateAuthority) CreateP12(
	cert *x509.Certificate, 
	privateKey *rsa.PrivateKey, 
	password string,
) ([]byte, error) {
	// Create certificate chain
	caCerts := []*x509.Certificate{ca.IntermediateCert, ca.RootCert}

	// Convert to PKCS#12 format
	p12Data, err := pkcs12.Modern.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		return nil, err
	}

	return p12Data, nil
}

// Web server handler to generate and serve P12 certificate
func (ca *CertificateAuthority) HandleCertificateRequest(w http.ResponseWriter, r *http.Request) {
	// Extract common name from query parameter or use default
    type RadiusRequest struct {
        CommonName string `json:"cn"`
        Start string `json:"start"`
        End string `json:"end"`
    }

    body := []RadiusRequest{}
    bytes, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = json.Unmarshal(bytes, &body)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer r.Body.Close()

    certs := [][]byte{}
    for _, req := range body {
        commonName := req.CommonName
        if req.CommonName == "" {
            http.Error(w, "Invalid common name", http.StatusBadRequest)
            return
        }

        startStr := req.Start
        if startStr == "" {
            http.Error(w, "No start time provided", http.StatusBadRequest)
            return
        }

        start, err := time.Parse("2006-01-02T15:04:05-0700", startStr)
        if err != nil {
            http.Error(w, "Invalid start time", http.StatusBadRequest)
            return
        }

        endStr := req.End
        if endStr == "" {
            http.Error(w, "No end time provided", http.StatusBadRequest)
            return
        }

        end, err := time.Parse("2006-01-02T15:04:05-0700", endStr)
        if err != nil {
            http.Error(w, "Invalid end time", http.StatusBadRequest)
            return
        }

        // Generate new certificate
        cert, privateKey, err := ca.GenerateCertificate(commonName, start, end)
        if err != nil {
            http.Error(w, "Failed to generate certificate", http.StatusInternalServerError)
            log.Printf("Certificate generation error: %v", err)
            return
        }

        // Create P12 file
        password := "whatever" // In practice, generate a unique password per request
        p12Data, err := ca.CreateP12(cert, privateKey, password)
        if err != nil {
            http.Error(w, "Failed to create P12 file", http.StatusInternalServerError)
            log.Printf("P12 file creation error: %v", err)
            return
        }

        certs = append(certs, p12Data)
    }

	// Set response headers
	w.Header().Set("Content-Type", "text/json")
	// w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.p12\"", commonName))
	
	// Write P12 file to response
    certsJson, err := json.Marshal(certs)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
	w.Write(certsJson)
}

func main() {
    err := godotenv.Load("../.env")
    if err != nil {
        log.Fatal(err)
    }

    ca, err := NewCertificateAuthority()
	if err != nil {
		log.Fatalf("Failed to initialize Certificate Authority: %v", err)
	}

    // Create a multiplexer (router)
    mux := http.NewServeMux()
    mux.HandleFunc("POST /", ca.HandleCertificateRequest)

    // TLS configuration
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
        PreferServerCipherSuites: true,
    }

    // Create server with timeouts
    server := &http.Server{
        Addr:         ":8443",
        Handler:      mux,
        TLSConfig:    tlsConfig,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    log.Println("Starting secure server on :8443")
    
    // Start server with TLS
    err = server.ListenAndServeTLS("certs/server-cert.pem", "certs/server-key.pem")
    if err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}