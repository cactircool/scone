//
// Created by Arjun Krishnan on 12/10/24.
//

#include "Request.hpp"

Request::Request(const char *req, size_t size) {
    size_t i = 0;
    if (strncmp(req, "PUT", 3) == 0) {
        m_method = PUT;
        i = 3;
    }
    else if (strncmp(req, "POST", 4) == 0) {
        m_method = POST;
        i = 4;
    }
    else if (strncmp(req, "GET", 3) == 0) {
        m_method = GET;
        i = 3;
    }
    else if (strncmp(req, "DELETE", 6) == 0) {
        m_method = DELETE;
        i = 6;
    }

    ++i;
    {
        size_t diff = i;
        for (; req[i] != ' '; ++i);
        diff = i - diff;
        m_path = new char[diff];
        memcpy(m_path, &req[i - diff], diff);
    }
    ++i;
    {
        size_t start = i;
        bool read = false;
        for (; req[i] != '\r'; ++i) {
            if (req[i] == '/') {
                read = true;
                start = i + 1;
                continue;
            }
        }
        size_t diff = i - start;
        m_httpVersion = new char[diff];
        memcpy(m_httpVersion, &req[i - diff], diff);
    }
    i += 2;

    {
        std::string key;
        std::string value;
        bool toKey = true;
        for (; i < size; ++i) {
            if (req[i] == '\r') {
                if (key.empty() || value.empty())
                    break;

                m_headers.insert({key, value});
                ++i;
                toKey = true;
                key.clear();
                value.clear();
                continue;
            }

            if (req[i] == ':') {
                toKey = false;
                ++i;
                continue;
            }
            if (toKey)
                key.push_back(req[i]);
            else
                value.push_back(req[i]);
        }
    }
    ++i;

    if (m_method != GET) {
        for (; std::isspace(req[i]); ++i);
        m_body = JSON::generate(&req[i]);
    } else
        m_body = nullptr;
}