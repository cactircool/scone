package endpoints

import (
	"ca/util"
	"net/http"
)

func Create(w http.ResponseWriter, r *http.Request) {
	bytes, err := util.Generate(365, "whatever")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}