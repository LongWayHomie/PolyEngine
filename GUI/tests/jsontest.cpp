#include "services.h"
#include "json.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
using namespace peg;

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_dbg_history";
    std::filesystem::remove_all(tmp);
    BuildHistoryStore store(tmp.wstring());
    HistoryEntry e1;
    e1.timestampUnixMs = 1000;
    e1.commandLine = "a.exe b.exe";
    e1.success = true;
    e1.sha256 = "ABC";
    e1.outputSizeBytes = 1234;
    store.append(e1);
    auto entries = store.loadAll();
    printf("loaded=%zu\n", entries.size());
    std::filesystem::remove_all(tmp);
    return 0;
}
