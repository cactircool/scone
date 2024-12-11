package util

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func GenKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %v", err)
	}
	return key, nil
}