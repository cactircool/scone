package endpoints

import (
	"ca/util"
	"crypto/x509"
	"net/http"
)

func Create(w http.ResponseWriter, r *http.Request) {
	key, cert, err := util.Create()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(append(x509.MarshalPKCS1PrivateKey(key), cert...))
}