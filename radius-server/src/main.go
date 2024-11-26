package main

import (
    "crypto/tls"
    "fmt"
    "log"
    "net/http"
    "time"
)

/**
 * All you have to do now is create an endpoint that takes a common name, a start time, an end time
 * and creates a certificate from that information that is signed by the root ca of the radius server
 * 
 * This data should be returned in the response as a string, not as a download
 */
func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, secure world!")
}

func main() {
    // Create a multiplexer (router)
    mux := http.NewServeMux()
    mux.HandleFunc("/", helloHandler)

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
    err := server.ListenAndServeTLS("certs/server-cert.pem", "certs/server-key.pem")
    if err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}