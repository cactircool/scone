package util

import (
	"crypto/rand"
	"crypto/rsa"
)

func GenKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}