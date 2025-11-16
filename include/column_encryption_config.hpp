#pragma once
#include <unordered_map>
#include <string>

namespace parquet_encryption {

struct ColumnEncryptionConfig {
    // Key per column:
    std::unordered_map<std::string, std::string> column_keys;

    // Footer encryption key:
    std::string footer_key = "";

    // Algorithm selector
    bool use_gcm = true;

    bool IsColumnEncrypted(const std::string &column) const {
        return column_keys.find(column) != column_keys.end();
    }

    std::string GetKey(const std::string &column) const {
        auto it = column_keys.find(column);
        if (it != column_keys.end()) return it->second;
        return "";
    }
};

} // namespace parquet_encryption
