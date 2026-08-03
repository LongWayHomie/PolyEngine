#pragma once
// json.h — minimal JSON parser/writer for our own data files (settings, profiles, history).
// Zero external dependencies. Values: object, array, string, number, bool, null.
// Port of the System.Text.Json usage in the C# version (write-indented for profiles/settings,
// compact lines for history JSONL).
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <optional>

namespace peg {

class JsonValue;
using JsonPtr = std::shared_ptr<JsonValue>;

enum class JsonType { Null, Bool, Number, String, Array, Object };

class JsonValue {
public:
    JsonType type = JsonType::Null;
    bool b = false;
    double num = 0.0;
    std::string str;
    std::vector<JsonPtr> arr;
    std::vector<std::pair<std::string, JsonPtr>> obj; // insertion-ordered

    static JsonPtr makeNull() { return std::make_shared<JsonValue>(); }
    static JsonPtr makeBool(bool v) { auto p = std::make_shared<JsonValue>(); p->type = JsonType::Bool; p->b = v; return p; }
    static JsonPtr makeNumber(double v) { auto p = std::make_shared<JsonValue>(); p->type = JsonType::Number; p->num = v; return p; }
    static JsonPtr makeString(std::string v) { auto p = std::make_shared<JsonValue>(); p->type = JsonType::String; p->str = std::move(v); return p; }
    static JsonPtr makeArray() { auto p = std::make_shared<JsonValue>(); p->type = JsonType::Array; return p; }
    static JsonPtr makeObject() { auto p = std::make_shared<JsonValue>(); p->type = JsonType::Object; return p; }

    // Object access (nullptr when missing or wrong type).
    JsonValue* get(const std::string& key) {
        if (type != JsonType::Object) return nullptr;
        for (auto& [k, v] : obj) if (k == key) return v.get();
        return nullptr;
    }
    const JsonValue* get(const std::string& key) const {
        if (type != JsonType::Object) return nullptr;
        for (const auto& [k, v] : obj) if (k == key) return v.get();
        return nullptr;
    }
    void set(const std::string& key, JsonPtr value) {
        for (auto& [k, v] : obj) if (k == key) { v = std::move(value); return; }
        obj.emplace_back(key, std::move(value));
    }

    std::string asString(const std::string& fallback = {}) const {
        if (type == JsonType::String) return str;
        if (type == JsonType::Number) return std::to_string(static_cast<long long>(num));
        if (type == JsonType::Bool) return b ? "true" : "false";
        return fallback;
    }
    bool asBool(bool fallback = false) const { return type == JsonType::Bool ? b : fallback; }
    double asNumber(double fallback = 0.0) const { return type == JsonType::Number ? num : fallback; }
};

// Parse a JSON document. Returns nullptr on syntax error (tolerant: callers skip malformed files).
JsonPtr jsonParse(const std::string& text);

// Serialize. indent < 0 → compact (history JSONL); otherwise pretty with the given indent width.
std::string jsonSerialize(const JsonValue& value, int indent = -1);

} // namespace peg
