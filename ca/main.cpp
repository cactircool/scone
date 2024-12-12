#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <thread>
#include <fstream>
#include <unordered_set>

#include "SSLConfig.hpp"
#include "Request.hpp"

X509 *ca;
EVP_PKEY *caKey;

void initOpenSSLThreadSafety();

void handleClient(int client, SSL_CTX *ctx);

void loadEnv(const char *filepath);

// Use RSA_free to free this resource
RSA *generateClientKey();

// Use X509_REQ_free to free this resource
X509_REQ *generateCSR(RSA *key, char *commonName);

// Use X509_free to free this resource
X509 *getCA(const char *filename);

// Use EVP_PKEY_free to free this resource
EVP_PKEY *getCAKey(const char *filename, const char *password, X509 *ca);

// Use X509_free to free this resource
X509 *signCertificate(X509_REQ *req, X509 *ca, EVP_PKEY *caKey, long notBefore, long notAfter);

char *certToString(X509 *cert);

int main() {
    loadEnv("../.env");

    const std::string CERT_FILE = getenv("HTTPS_SERVER_CRT");
    const std::string KEY_FILE = getenv("HTTPS_SERVER_KEY");
    const std::string PASSPHRASE = getenv("HTTPS_CERTS_PASSPHRASE");

    const std::string CA_FILE = getenv("RADIUS_CA_PEM");
    const std::string CA_KEY = getenv("RADIUS_CA_KEY");

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    initOpenSSLThreadSafety();

    SSLConfig config(
            CERT_FILE,
            KEY_FILE,
            PASSPHRASE
    );

    ca = getCA(CA_FILE.c_str());
    caKey = getCAKey(CA_KEY.c_str(), PASSPHRASE.c_str(), ca);

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return 1;
    }

    // Set up socket address
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket
    if (bind(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        close(sockfd);
        return 1;
    }

    // Listen for connections
    if (listen(sockfd, 10) == -1) {
        std::cerr << "Listen failed: " << strerror(errno) << std::endl;
        close(sockfd);
        return 1;
    }

    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context" << std::endl;
        close(sockfd);
        return 1;
    }

    if (!config.configureSSLContext(ctx)) {
        std::cerr << "SSL config failed" << std::endl;
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    std::vector<std::thread> threads;
    while (true) {
        int client = accept(sockfd, nullptr, nullptr);
        if (client == -1)
            continue;
        threads.emplace_back(handleClient, client, ctx);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    X509_free(ca);
    EVP_PKEY_free(caKey);

    for (auto &thread : threads)
        if (thread.joinable()) thread.join();

    return 0;
}

char *certToString(X509 *cert) {
    BIO *bio = BIO_new(BIO_s_mem());

    // Write the certificate to the memory BIO
    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        return nullptr;
    }

    // Get the length of the buffer
    long len = BIO_get_mem_data(bio, NULL);

    // Allocate memory for the string (add 1 for null terminator)
    char *cert_str = static_cast<char *>(malloc(len + 1));
    if (!cert_str) {
        BIO_free(bio);
        return nullptr;
    }

    // Read the data from BIO into the string
    BIO_read(bio, cert_str, len);
    cert_str[len] = '\0';  // Null-terminate the string

    // Free the BIO
    BIO_free(bio);
    return cert_str;
}

void loadEnv(const char *filepath) {
    std::ifstream file(filepath);
    if (!file.is_open())
        return;

    for (std::string line; std::getline(file, line);) {
        // Parse key-value pair
        std::string key = line.substr(0, line.find('='));
        std::string value = line.substr(line.find('=') + 1);

        bool ignoreDollar = false;
        if (value.front() == value.back() && (value.front() == '"' || value.front() == '\'')) {
            ignoreDollar = value.front() == '\'';
            value.pop_back();
            value.erase(0, 1);
        }

        if (!ignoreDollar) {
            for (size_t start = 0, index = value.find('$', start); index != std::string::npos; start = index + 1, index = value.find('$', start)) {
                if (!std::isalpha(value[index + 1]) && value[index + 1] != '_')
                    continue;
                size_t i = index + 1;
                for (; std::isalnum(value[i]) || value[i] == '_'; ++i);
                std::string var = value.substr(index + 1, (i - index - 1));
                value = value.substr(0, index) + getenv(var.c_str()) + value.substr(i);
            }
        }

        // Set environment variable
        if (!key.empty())
            setenv(key.c_str(), value.c_str(), 1);
    }
    file.close();
}

void handleClient(int client, SSL_CTX *ctx) {
    // Create SSL connection
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Failed to create SSL connection" << std::endl;
        SSL_CTX_free(ctx);
        close(client);
        return;
    }

    // Attach SSL to socket
    if (!SSL_set_fd(ssl, client)) {
        std::cerr << "SSL_set_fd failed" << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(client);
        return;
    }

    // Perform SSL handshake
    int ssl_accept_result = SSL_accept(ssl);
    if (ssl_accept_result != 1) {
        SSL_free(ssl);
        close(client);
        return;
    }

    // Read client request
    char buffer[1024] = {0};
    int bytes_read = SSL_read(ssl, buffer, 1023);
    if (bytes_read <= 0) {
        std::cerr << "Read failed" << std::endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    Request req(buffer, 1024);

    // Verify it's a GET request
    if (req.method() != Request::PUT) {
        std::cerr << "Expected PUT request" << std::endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    // Prepare and send response
    std::string res = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

    auto getLong = [](JSON::Value &data, size_t index) {
        return std::get<long long>(std::get<JSON::Primitive>(JSON::List(*std::get<JSON *>(data))[index]));
    };

    auto getString = [](JSON::Value &data, size_t index) {
        return std::get<std::string>(std::get<JSON::Primitive>(JSON::List(*std::get<JSON *>(data))[index]));
    };

    for (auto &data : JSON::List(req.body())) {
        RSA *clientKey = generateClientKey();
        std::string commonName = getString(data, 0);
        X509_REQ *csr = generateCSR(clientKey, commonName.data());
        X509 *cert = signCertificate(csr, ca, caKey, getLong(data, 1), getLong(data, 2)); // 0, 60 * 60 * 24 * 365

        res.append(certToString(cert)).push_back(',');

        RSA_free(clientKey);
        X509_REQ_free(csr);
        X509_free(cert);
    }

    int bytes_written = SSL_write(ssl, res.c_str(), res.size());
    if (bytes_written <= 0) {
        std::cerr << "Write failed" << std::endl;
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
}

void initOpenSSLThreadSafety() {
    static std::mutex* locks = nullptr;
    if (!locks) {
        locks = new std::mutex[CRYPTO_num_locks()];
        CRYPTO_set_locking_callback([](int mode, int n, const char*, int) {
            if (mode & CRYPTO_LOCK) {
                locks[n].lock();
            } else {
                locks[n].unlock();
            }
        })
    }
}

RSA *generateClientKey() {
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);

    RSA *rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, 2048, bne, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        BN_free(bne);
        return nullptr;
    }

    BN_free(bne);
    return rsa;
}

X509_REQ *generateCSR(RSA *key, char *commonName) {
    if (!key) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Create x509 request
    X509_REQ *req = X509_REQ_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, key);
    X509_REQ_set_pubkey(req, pkey);

    // Set subject name
    X509_NAME *name = X509_REQ_get_subject_name(req);

    std::pair<const char *, char *> fields[] = {
            { "C", const_cast<char *>("US") },
            { "CN", commonName },
    };

    for (auto &field : fields)
        X509_NAME_add_entry_by_txt(name, field.first, MBSTRING_ASC, (unsigned char *)field.second, -1, -1, 0);

    // Sign the request
    if (X509_REQ_sign(req, pkey, EVP_sha256()) == 0) {
        ERR_print_errors_fp(stderr);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    EVP_PKEY_free(pkey);
    return req;
}

X509 *getCA(const char *filename) {
    FILE *caf = fopen(filename, "rb");
    if (!caf) {
        perror("Error opening CA certificate");
        return nullptr;
    }

    X509 *ca_cert = PEM_read_X509(caf, nullptr, nullptr, nullptr);
    fclose(caf);
    return ca_cert;
}

EVP_PKEY *getCAKey(const char *filename, const char *password, X509 *ca) {
    FILE *cakeyf = fopen(filename, "rb");
    if (!cakeyf) {
        X509_free(ca);
        perror("Error opening CA key");
        return nullptr;
    }

    EVP_PKEY *ca_key = PEM_read_PrivateKey(cakeyf, nullptr, [](char *buf, int size, int rwflag, void *userdata) -> int {
        auto *passphrase = static_cast<const char *>(userdata);
        if (rwflag == 0) {
            size_t len = strlen(passphrase);
            if (len > (size_t)size)
                len = size;
            memcpy(buf, passphrase, len);
            buf[len] = '\0';
            return len;
        }
        return 0;
    }, (void *) password);
    fclose(cakeyf);
    return ca_key;
}

X509 *signCertificate(X509_REQ *req, X509 *ca, EVP_PKEY *caKey, long notBefore, long notAfter) {
    X509 *cert = X509_new();
    X509_set_version(cert, 2);

    // Serial number
    ASN1_INTEGER *sno = ASN1_INTEGER_new();
    ASN1_INTEGER_set(sno, 1); // Simple serial number
    X509_set_serialNumber(cert, sno);

    X509_set_issuer_name(cert, X509_get_subject_name(ca));
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));

    X509_gmtime_adj(X509_get_notBefore(cert), notBefore);
    X509_gmtime_adj(X509_get_notAfter(cert), notAfter);

    X509_set_pubkey(cert, X509_REQ_get_pubkey(req));

    // Sign the certificate
    if (X509_sign(cert, caKey, EVP_sha256()) == 0) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        X509_REQ_free(req);
        return nullptr;
    }

    return cert;
}