//
// Created by Arjun Krishnan on 12/10/24.
//

#include "JSON.hpp"
#include <cstdio>
#include <clocale>

JSON::operator long double() const {
    if (!defaultValue.has_value() || !std::holds_alternative<long double>(*defaultValue))
        throw std::runtime_error("Could not convert JSON data to a double type");
    return std::get<long double>(*defaultValue);
}

JSON::operator long long() const {
    if (!defaultValue.has_value() || !std::holds_alternative<long long>(*defaultValue))
        throw std::runtime_error("Could not convert JSON data to an int type");
    return std::get<long long>(*defaultValue);
}

JSON::operator std::string() const {
    if (!defaultValue.has_value() || !std::holds_alternative<std::string>(*defaultValue))
        throw std::runtime_error("Could not convert JSON data to a string type");
    return std::get<std::string>(*defaultValue);
}

JSON::operator nullptr_t() const {
    if (!defaultValue.has_value() || !std::holds_alternative<nullptr_t>(*defaultValue))
        throw std::runtime_error("Could not convert JSON data to the null type");
    return std::get<nullptr_t>(*defaultValue);
}

JSON::operator Object() const {
    if (!std::holds_alternative<Object>(json))
        throw std::runtime_error("Could not convert JSON data to an object");
    return std::get<Object>(json);
}

JSON::operator List() const {
    if (!std::holds_alternative<List>(json))
        throw std::runtime_error("Could not convert JSON data to a list");
    return std::get<List>(json);
}

const JSON::Value &JSON::operator[](const std::string &key) const {
    if (!std::holds_alternative<Object>(json))
        throw std::runtime_error("Could not using strings as keys for JSON data. This is either a list or a primitive value.");
    return std::get<Object>(json).at(key);
}

JSON::Value &JSON::operator[](const std::string &key) {
    if (!std::holds_alternative<Object>(json))
        throw std::runtime_error("Could not using strings as keys for JSON data. This is either a list or a primitive value.");
    return std::get<Object>(json).at(key);
}

const JSON::Value &JSON::operator[](const size_t &index) const {
    if (!std::holds_alternative<List>(json))
        throw std::runtime_error("Could not using integers as indexes for JSON data. This is either an object or a primitive value.");
    return std::get<List>(json).at(index);
}

JSON::Value &JSON::operator[](const size_t &index) {
    if (!std::holds_alternative<List>(json))
        throw std::runtime_error("Could not using integers as indexes for JSON data. This is either an object or a primitive value.");
    return std::get<List>(json).at(index);
}

JSON::Primitive JSON::parsePrimitive(const std::string &json, size_t &i) {
    if (std::isdigit(json[i])) {
        long long result = 0;
        unsigned long long pow10 = 1;
        long double dResult = 0;
        bool dot = false;
        for (; std::isdigit(json[i]) || (json[i] == '.' && !dot); ++i, ++i) {
            if (json[i] == '.') {
                dot = true;
                continue;
            }

            if (!dot) {
                result *= 10;
                result += json[i] - '0';
            } else {
                pow10 *= 10;
                dResult += ((json[i] - '0') / static_cast<long double>(pow10));
            }
        }

        if (dot)
            return result + dResult;
        return result;
    } else if (strncmp(&json[i], "null", 4) == 0) {
        i += 4;
        return nullptr;
    } if (json[i] == '\'' || json[i] == '"') {
        bool slash = false;
        std::string buf;
        auto start = json[i];
        ++i;
        for (; json[i] != 0; ++i) {
            if (slash && json[i] != '\\') slash = false;
            if (json[i] == '\\') slash = !slash;
            if (!slash && json[i] == start) {
                ++i;
                break;
            }
            if (!slash)
                buf.push_back(json[i]);
        }
        return buf;
    }
    throw std::runtime_error("Invalid JSON primitive value: " + std::string(&json[i]));
}

std::string JSON::parseKeyAndInc(const std::string &json, size_t &i) {
    if (json[i] != '"' && json[i] != '\'' && !std::isalpha(json[i]) && json[i] != '_')
        throw std::runtime_error("Invalid key: " + json);
    if (json[i] == '"' || json[i] == '\'') {
        bool slash = false;
        std::string buf;
        auto start = json[i];
        ++i;
        for (; json[i] != 0; ++i) {
            if (slash && json[i] != '\\') slash = false;
            if (json[i] == '\\') slash = !slash;
            if (!slash && json[i] == start) {
                ++i;
                break;
            }
            if (!slash)
                buf.push_back(json[i]);
        }
        return buf;
    }

    std::string buf;
    ++i;
    for (; std::isalnum(json[i]) || json[i] == '_'; ++i)
        buf.push_back(json[i]);
    return buf;
}

JSON::Value JSON::parseValueAndInc(const std::string &json, size_t &i) {
    for (; std::isspace(json[i]); ++i);

    if (json[i] == '[' || json[i] == '{') {
        int count = 1;
        size_t start = i;
        for (; count != 0; ++i)
            count += (json[i] == '{' || json[i] == '[') ? 1 : (json[i] == '}' || json[i] == ']') ? -1 : 0;
        return JSON::generate(json, start);
    }
    if (json[i] == '"' || json[i] == '\'') {
        bool slash = false;
        std::string buf;
        auto start = json[i];
        ++i;
        for (; json[i] != 0; ++i) {
            if (slash && json[i] != '\\') slash = false;
            if (json[i] == '\\') slash = !slash;
            if (!slash && json[i] == start)
                break;
            if (!slash)
                buf.push_back(json[i]);
        }
        return buf;
    }
    return parsePrimitive(json, i);
}

JSON *JSON::generate(const std::string &json, size_t &i) {
    JSON *obj{nullptr};
    for (; std::isspace(json[i]); ++i);
    if (json[i] == '{') {
        obj = new JSON(Object());
        int count = 1;
        for (size_t i = 1; i < json.size(); ++i) {
            char &c = const_cast<char &>(json[i]);
            if (std::isspace(c) || c == ',') continue;

            count += (c == '{' || c == '[') ? 1 : (c == '}' || c == ']') ? -1 : 0;
            if (count == 0) break;

            auto key = parseKeyAndInc(json, i);
            ++i;
            auto value = parseValueAndInc(json, i);
            std::get<Object>(obj->json).insert({ key, value });
        }
        return obj;
    }
    else if (json[i] == '[') {
        obj = new JSON(List());
        int count = 1;
        size_t start = i + 1;
        size_t j = start;
        for (; j < json.size(); ++j) {
            for (; std::isspace(json[start]); ++start, ++j);

            if (json[j] == ',' && count == 1) {
                ++start;
                continue;
            }

            char &c = const_cast<char &>(json[j]);
            count += (c == '{' || c == '[') ? 1 : (c == '}' || c == ']') ? -1 : 0;

            if (count == 0)
                break;

            if (json[start] == '{' || json[start] == '[') {
                std::get<List>(obj->json).emplace_back(generate(json, j));
                --count;
            } else
                std::get<List>(obj->json).emplace_back(parsePrimitive(json, j));
            start = j + 1;
        }
        i = j;
        return obj;
    }

    for (; std::isspace(json[i]); ++i);
    obj = new JSON(parsePrimitive(json, i));
    return obj;
}

JSON *JSON::generate(const std::string &json) {
    size_t i = 0;
    return JSON::generate(json, i);
}