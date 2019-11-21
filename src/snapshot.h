// Copyright (c) 2019 RomanceCoin developers
#ifndef ROMANCE_SNAPSHOT_H
#define ROMANCE_SNAPSHOT_H

#include <util.h>
// #include <amount.h>
// #include <utilstrencodings.h>
#include <primitives/transaction.h>
// #include <support/httplib.h>
// #include <support/csv.h>
// #include <core_io.h>
// #include <random>

struct SnapshotEntry {
    CScript script;
    CAmount amount;
};

struct SnapshotProvider {
    std::string address;
    std::string path;
    int port;
};

CScript ReadScriptSnapshot(const std::string& s);
bool FetchSnapshot(fs::path &path, SnapshotProvider provider);
std::vector<SnapshotEntry> LoadSnapshot(fs::path &path);
std::vector<SnapshotEntry> InitSnapshot(const std::string fileName, std::vector<SnapshotProvider> providers);

#endif // ROMANCE_SNAPSHOT_H
