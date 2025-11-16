#pragma once
#include <vector>
#include <cstdint> 
#include <string>
#include <utility>

namespace parquet_encryption {

class KMS {
public:
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> GenerateDataKey(const std::string &kms_key_id);
    std::vector<uint8_t> DecryptDataKey(const std::vector<uint8_t> &encrypted_key, const std::string &kms_key_id);
};

} // namespace parquet_encryption
