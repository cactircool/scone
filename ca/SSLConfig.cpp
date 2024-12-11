//
// Created by Arjun Krishnan on 12/9/24.
//

#include "SSLConfig.hpp"
#include <iostream>

SSLConfig::SSLConfig(const std::string &cert_path, const std::string &key_path, const std::string &passphrase) : m_cert_path(cert_path),
                                                                                                                 m_key_path(key_path),
                                                                                                                 m_passphrase(passphrase) {}

int SSLConfig::passphraseCallback(char *buf, int size, int rwflag, void *userdata) {
    SSLConfig* config = static_cast<SSLConfig*>(userdata);
    return config->handlePassphrase(buf, size, rwflag);
}

bool SSLConfig::configureSSLContext(SSL_CTX *ctx) {
    // Set passphrase callback if needed
    if (!m_passphrase.empty()) {
        SSL_CTX_set_default_passwd_cb(ctx, passphraseCallback);
        SSL_CTX_set_default_passwd_cb_userdata(ctx, this);
    }

    // Load certificate chain
    if (SSL_CTX_use_certificate_chain_file(ctx, m_cert_path.c_str()) != 1) {
        std::cerr << "Failed to load certificate chain" << std::endl;
        return false;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, m_key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cerr << "Failed to load private key" << std::endl;
        return false;
    }

    return true;
}

int SSLConfig::handlePassphrase(char *buf, int size, int rwflag) {
    // Encryption not supported
    if (rwflag == 1) {
        std::cerr << "Encryption not supported" << std::endl;
        return -1;
    }

    // Check passphrase length
    size_t passphrase_len = m_passphrase.length();
    if (passphrase_len > static_cast<size_t>(size)) {
        std::cerr << "Passphrase too long" << std::endl;
        return -1;
    }

    // Copy passphrase
    strncpy(buf, m_passphrase.c_str(), size);
    return passphrase_len;
}