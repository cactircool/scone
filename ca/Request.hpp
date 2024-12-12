//
// Created by Arjun Krishnan on 12/10/24.
//

#ifndef CA_REQUEST_HPP
#define CA_REQUEST_HPP

#include <unordered_map>
#include <string>
#include <cstring>
#include "JSON.hpp"

class Request {
public:
    using Headers = std::unordered_map<std::string, std::string>;

    enum Method {
        GET,
        PUT,
        POST,
        DELETE,
    };

private:
    Method m_method;
    char *m_path;
    char *m_httpVersion;

    Headers m_headers;
    JSON *m_body;

public:
    Request(const char *req, size_t size);

    const std::string &header(const std::string &key) const { return m_headers.at(key); }
    std::string &header(const std::string &key) { return m_headers.at(key); }

    const Headers &headers() const { return m_headers; }
    Headers &headers() { return m_headers; }

    const Method &method() const { return m_method; }
    const std::string &path() const { return m_path; }
    const std::string &version() const { return m_httpVersion; }
    const JSON &body() const { return *m_body; }
};


#endif //CA_REQUEST_HPP
