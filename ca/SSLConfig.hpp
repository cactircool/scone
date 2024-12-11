//
// Created by Arjun Krishnan on 12/9/24.
//

#ifndef CA_SSLCONFIG_HPP
#define CA_SSLCONFIG_HPP

#include <string>
#include <openssl/ssl.h>

class SSLConfig {
public:
    SSLConfig(const std::string& cert_path,
              const std::string& key_path,
              const std::string& passphrase = "");

    static int passphraseCallback(char *buf, int size, int rwflag, void *userdata);

    bool configureSSLContext(SSL_CTX* ctx);

private:
    int handlePassphrase(char *buf, int size, int rwflag);

    std::string m_cert_path;
    std::string m_key_path;
    std::string m_passphrase;
};


#endif //CA_SSLCONFIG_HPP
