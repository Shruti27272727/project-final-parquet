#pragma once
#include <vector>
#include <cstdint> 
#include <string>

namespace parquet_encryption {

// AES placeholder
std::vector<uint8_t> aes_encrypt(
    const std::vector<uint8_t> &plain,
    const std::string &key,
    bool use_gcm
);

std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t> &encrypted,
    const std::string &key,
    bool use_gcm
);

// Hex conversion
std::string BytesToHex(const std::vector<uint8_t> &data);
std::vector<uint8_t> HexToBytes(const std::string &hex);

} // namespace parquet_encryption
