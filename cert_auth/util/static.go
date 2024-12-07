package util

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

type StaticType struct {
	ca []byte
	caKey []byte
	caCerts []*x509.Certificate
}

var static StaticType = StaticType{
	nil,
	nil,
	nil,
}

func SetCA(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("Couldn't read ca.pem file!")
	}

	block, _ := pem.Decode(file)
	if block == nil {
		log.Fatal("Couldn't decode ca.pem file!")
	}
	bytes := block.Bytes

	if x509.IsEncryptedPEMBlock(block) {
		bytes, err = x509.DecryptPEMBlock(block, []byte("password"))
		if err != nil {
			log.Fatal("Couldn't decrypt pem block")
		}
	}

	static.ca = bytes
}

func SetCAKey(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("Couldn't read ca.key file!")
	}

	block, _ := pem.Decode(file)
	if block == nil {
		log.Fatal("Couldn't decode ca.key file!")
	}
	bytes := block.Bytes

	bytes, err = x509.DecryptPEMBlock(block, []byte("password"))
	fmt.Println("Attempted decryption")
	if err != nil {
		log.Fatal("Couldn't decrypt pem block")
	}

	static.caKey = bytes
}

func SetCACerts(path string) {
	// file, err := os.ReadFile(path)
	// if err != nil {
	// 	log.Fatal("couldn't read ca.pem file!")
	// }

	// var caCerts []*x509.Certificate
	// var pemBlock *pem.Block
	// pemBlock, _ = pem.Decode(file)

	// bytes := pemBlock.Bytes
	// if x509.IsEncryptedPEMBlock(pemBlock) {
	// 	bytes, err = x509.DecryptPEMBlock(pemBlock, []byte("password"))
	// 	if err != nil {
	// 		log.Fatal("Couldn't decrypt pem block")
	// 	}
	// }

	// for pemBlock != nil {
	// 	if pemBlock.Type == "CERTIFICATE" {
	// 		caCert, err := x509.ParseCertificate(bytes)
	// 		if err != nil {
	// 			log.Fatalf("failed to parse CA certificate: %v", err)
	// 		}
	// 		caCerts = append(caCerts, caCert)
	// 	}
		
	// 	// Move to next block
	// 	file = file[len(pemBlock.Bytes):]
	// 	pemBlock, _ = pem.Decode(file)
	// 	bytes = pemBlock.Bytes

	// 	if x509.IsEncryptedPEMBlock(pemBlock) {
	// 		bytes, err = x509.DecryptPEMBlock(pemBlock, []byte("password"))
	// 		if err != nil {
	// 			log.Fatal("Couldn't decrypt pem block")
	// 		}
	// 	}
	// }

	static.caCerts = []*x509.Certificate{}
}