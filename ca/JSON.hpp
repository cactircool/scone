//
// Created by Arjun Krishnan on 12/10/24.
//

#ifndef CA_JSON_HPP
#define CA_JSON_HPP

#include <unordered_map>
#include <variant>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>
#include <cstring>

class JSON {
public:
    using Primitive = std::variant<long long, long double, std::string, nullptr_t>;
    using Value = std::variant<Primitive, JSON *>;
    using Object = std::unordered_map<std::string, Value>;
    using List = std::vector<Value>;
    using JSON_t = std::variant<Object, List>;

private:
    std::optional<Primitive> defaultValue;
    JSON_t json;

    explicit JSON(const Primitive &value) : defaultValue(value) {}
    explicit JSON(const JSON_t &json) : json(json) {}

    static Primitive parsePrimitive(const std::string &json, size_t &i);
    static std::string parseKeyAndInc(const std::string &json, size_t &i);
    static Value parseValueAndInc(const std::string &json, size_t &i);

    static JSON *generate(const std::string &json, size_t &i);

public:
    static JSON *generate(const std::string &json);

    const Value &operator[](const std::string &key) const;
    Value &operator[](const std::string &key);

    const Value &operator[](const size_t &index) const;
    Value &operator[](const size_t &index);

    operator long long() const;
    operator long double() const;
    operator std::string() const;
    operator nullptr_t() const;

    operator Object() const;
    operator List() const;
};


#endif //CA_JSON_HPP
