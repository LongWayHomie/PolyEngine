#pragma once
// test.h — minimal test harness (no external deps).
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace test {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

inline int& failures() {
    static int n = 0;
    return n;
}

inline int& assertions() {
    static int n = 0;
    return n;
}

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline void fail(const char* file, int line, const std::string& msg) {
    failures()++;
    std::printf("    FAIL %s:%d — %s\n", file, line, msg.c_str());
}

inline void pass() { assertions()++; }

inline int runAll(const char* filter = nullptr) {
    int ran = 0;
    for (const auto& t : registry()) {
        if (filter && t.name.find(filter) == std::string::npos)
            continue;
        int before = failures();
        std::printf("[ RUN  ] %s\n", t.name.c_str());
        t.fn();
        if (failures() == before)
            std::printf("[  OK  ] %s\n", t.name.c_str());
        else
            std::printf("[FAILED] %s\n", t.name.c_str());
        ran++;
    }
    std::printf("\n%d tests, %d assertions, %d failures\n", ran, assertions(), failures());
    return failures() == 0 ? 0 : 1;
}

} // namespace test

#define TEST_SUITE(name) \
    static void test_##name(); \
    static test::Registrar reg_##name(#name, test_##name); \
    static void test_##name()

#define CHECK(cond) \
    do { \
        if (cond) { test::pass(); } \
        else { test::fail(__FILE__, __LINE__, "CHECK(" #cond ")"); } \
    } while (0)

#define CHECK_EQ(a, b) \
    do { \
        auto va = (a); auto vb = (b); \
        if (va == vb) { test::pass(); } \
        else { test::fail(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ")"); } \
    } while (0)
