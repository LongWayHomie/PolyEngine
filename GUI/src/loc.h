#pragma once
// loc.h — UI string tables (English primary, Polish secondary) — port of Loc/Strings.
#include <string>
#include <map>

namespace peg {

class Loc {
public:
    static Loc& instance();

    void setLanguage(const std::string& lang);
    const std::string& language() const { return language_; }

    // "Key" lookup; falls back to English, then to the key itself.
    const std::string& operator[](const std::string& key) const;

    // "{0}"-style single-argument format (covers every {0} usage in the UI).
    std::string format(const std::string& key, const std::string& arg0) const;

private:
    Loc() = default;
    std::string language_ = "en";
    const std::map<std::string, std::string>* table_ = nullptr;
    void rebuild();
};

} // namespace peg
