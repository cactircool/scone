package main

import (
	"ca/endpoints"
	// "ca/util"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

func get(key string) string {
	return os.Getenv(key);
}

func initialize() {
	casList := strings.Split(get("RADIUS_CA_FILE"), ":")
	cas := make(map[string]string)
	for _, item := range casList {
		a := strings.Split(item, ".")
		cas[a[len(a) - 1]] = item
	}

	// util.SetCA(cas["pem"])
	// util.SetCACerts(cas["pem"])
	// util.SetCAKey(cas["key"])
}

func generateEndpoints() {
	http.HandleFunc("GET /", endpoints.Root)
	http.HandleFunc("GET /create", endpoints.Create)
}

func main() {
	err := godotenv.Load(".env");
	if err != nil {
		log.Fatal("Error loading environment variables from the .env file. Please create a file called .env in the server directory with the relevant variables defined.");
	}

	port := 8443

	initialize()
	generateEndpoints()

	fmt.Printf("Server started at port %d\n", port)
	err = http.ListenAndServeTLS(fmt.Sprintf(":%d", port), get("HTTPS_CERT"), get("HTTPS_KEY"), nil);
	log.Fatal(err)
}