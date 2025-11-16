#pragma once
#include "parquet_encryption_mode.hpp"
#include <string>
#include <unordered_map>

namespace parquet_encryption {

struct ParquetEncryptionConfig {
    EncryptionMode mode = EncryptionMode::AES_GCM;

    std::string encryption_key = "default_key_123456";

    std::string master_key = "MASTER_KEY_ABC123";

    std::unordered_map<std::string, std::string> column_keys = {
        {"col1", "COL1_KEY_ABC"},
        {"col2", "COL2_KEY_DEF"}
    };

    bool use_kms = false;
    std::string kms_key_id = "dummy_kms_key";
};

} // namespace parquet_encryption
