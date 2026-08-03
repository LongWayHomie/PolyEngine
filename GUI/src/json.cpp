#include "json.h"
#include <cctype>
#include <cmath>

namespace peg {
namespace {

struct Parser {
    const std::string& s;
    size_t i = 0;

    void skipWs() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++; }

    bool peek(char c) const { return i < s.size() && s[i] == c; }

    JsonPtr parseValue() {
        skipWs();
        if (i >= s.size()) return nullptr;
        char c = s[i];
        switch (c) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': return JsonValue::makeString(parseString());
            case 't': if (s.compare(i, 4, "true") == 0) { i += 4; return JsonValue::makeBool(true); } return nullptr;
            case 'f': if (s.compare(i, 5, "false") == 0) { i += 5; return JsonValue::makeBool(false); } return nullptr;
            case 'n': if (s.compare(i, 4, "null") == 0) { i += 4; return JsonValue::makeNull(); } return nullptr;
            default: {
                if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
                return nullptr;
            }
        }
    }

    std::string parseString() {
        // caller guarantees s[i] == '"'
        i++;
        std::string out;
        while (i < s.size() && s[i] != '"') {
            if (s[i] == '\\' && i + 1 < s.size()) {
                char e = s[i + 1];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        // \uXXXX — handle BMP only; surrogate pairs decoded.
                        if (i + 6 <= s.size()) {
                            auto hex = [&](size_t at) -> int {
                                char h = s[at];
                                if (h >= '0' && h <= '9') return h - '0';
                                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                                return -1;
                            };
                            int hi = hex(i + 2), h1 = hex(i + 3), h2 = hex(i + 4), h3 = hex(i + 5);
                            if (hi >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
                                unsigned cp = (unsigned)((hi << 12) | (h1 << 8) | (h2 << 4) | h3);
                                if (cp >= 0xD800 && cp <= 0xDBFF && i + 12 <= s.size() &&
                                    s[i + 6] == '\\' && s[i + 7] == 'u') {
                                    int l0 = hex(i + 8), l1 = hex(i + 9), l2 = hex(i + 10), l3 = hex(i + 11);
                                    if (l0 >= 0 && l1 >= 0 && l2 >= 0 && l3 >= 0) {
                                        unsigned low = (unsigned)((l0 << 12) | (l1 << 8) | (l2 << 4) | l3);
                                        if (low >= 0xDC00 && low <= 0xDFFF) {
                                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                            i += 6; // consume the low surrogate \uXXXX too
                                        }
                                    }
                                }
                                // UTF-8 encode
                                if (cp < 0x80) out += (char)cp;
                                else if (cp < 0x800) {
                                    out += (char)(0xC0 | (cp >> 6));
                                    out += (char)(0x80 | (cp & 0x3F));
                                } else if (cp < 0x10000) {
                                    out += (char)(0xE0 | (cp >> 12));
                                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                                    out += (char)(0x80 | (cp & 0x3F));
                                } else {
                                    out += (char)(0xF0 | (cp >> 18));
                                    out += (char)(0x80 | ((cp >> 12) & 0x3F));
                                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                                    out += (char)(0x80 | (cp & 0x3F));
                                }
                                i += 4; // skip the 4 hex digits (loop adds 2 for "\u")
                                break;
                            }
                        }
                        out += '?'; // malformed escape — tolerate
                        break;
                    }
                    default: out += e; break;
                }
                i += 2;
            } else {
                out += s[i++];
            }
        }
        if (i < s.size()) i++; // closing quote
        return out;
    }

    JsonPtr parseNumber() {
        size_t start = i;
        if (peek('-')) i++;
        while (i < s.size() && (std::isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-')) i++;
        std::string tok = s.substr(start, i - start);
        try {
            return JsonValue::makeNumber(std::stod(tok));
        } catch (...) {
            return JsonValue::makeNull();
        }
    }

    JsonPtr parseObject() {
        i++; // '{'
        auto obj = JsonValue::makeObject();
        skipWs();
        if (peek('}')) { i++; return obj; }
        while (true) {
            skipWs();
            if (i >= s.size() || s[i] != '"') return nullptr;
            std::string key = parseString();
            skipWs();
            if (i >= s.size() || s[i] != ':') return nullptr;
            i++;
            auto val = parseValue();
            if (!val) return nullptr;
            obj->set(key, val);
            skipWs();
            if (peek(',')) { i++; continue; }
            if (peek('}')) { i++; break; }
            return nullptr;
        }
        return obj;
    }

    JsonPtr parseArray() {
        i++; // '['
        auto arr = JsonValue::makeArray();
        skipWs();
        if (peek(']')) { i++; return arr; }
        while (true) {
            auto val = parseValue();
            if (!val) return nullptr;
            arr->arr.push_back(val);
            skipWs();
            if (peek(',')) { i++; continue; }
            if (peek(']')) { i++; break; }
            return nullptr;
        }
        return arr;
    }
};

std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

void serialize(const JsonValue& v, int indent, int depth, std::string& out) {
    switch (v.type) {
        case JsonType::Null: out += "null"; break;
        case JsonType::Bool: out += v.b ? "true" : "false"; break;
        case JsonType::Number: {
            if (v.num == std::floor(v.num) && std::abs(v.num) < 1e15) {
                char buf[32];
                snprintf(buf, sizeof buf, "%lld", (long long)v.num);
                out += buf;
            } else {
                char buf[64];
                snprintf(buf, sizeof buf, "%.9g", v.num);
                out += buf;
            }
            break;
        }
        case JsonType::String: out += '"' + escape(v.str) + '"'; break;
        case JsonType::Array: {
            if (v.arr.empty()) { out += "[]"; break; }
            out += '[';
            bool first = true;
            for (const auto& e : v.arr) {
                if (!first) out += ',';
                first = false;
                if (indent >= 0) { out += '\n'; out.append((size_t)(depth + 1) * indent, ' '); }
                serialize(*e, indent, depth + 1, out);
            }
            if (indent >= 0) { out += '\n'; out.append((size_t)depth * indent, ' '); }
            out += ']';
            break;
        }
        case JsonType::Object: {
            if (v.obj.empty()) { out += "{}"; break; }
            out += '{';
            bool first = true;
            for (const auto& [k, val] : v.obj) {
                if (!first) out += ',';
                first = false;
                if (indent >= 0) { out += '\n'; out.append((size_t)(depth + 1) * indent, ' '); }
                out += '"' + escape(k) + '"' + ':';
                if (indent >= 0) out += ' ';
                serialize(*val, indent, depth + 1, out);
            }
            if (indent >= 0) { out += '\n'; out.append((size_t)depth * indent, ' '); }
            out += '}';
            break;
        }
    }
}

} // namespace

JsonPtr jsonParse(const std::string& text) {
    Parser p{text};
    auto v = p.parseValue();
    if (!v) return nullptr;
    p.skipWs();
    return p.i == p.s.size() ? v : nullptr; // trailing garbage → invalid
}

std::string jsonSerialize(const JsonValue& value, int indent) {
    std::string out;
    serialize(value, indent, 0, out);
    return out;
}

} // namespace peg
