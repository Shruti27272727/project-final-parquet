#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace parquet_encryption {

// ---------------------------------------------------------------------------
// Utility: Throw if condition fails
// ---------------------------------------------------------------------------
void assert_or_throw(bool condition, const std::string &msg);

// ---------------------------------------------------------------------------
// AES Encrypt / Decrypt (GCM or CTR)
// NOTE: Real implementation is in crypto_utils.cpp
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Validate AES key length
// Acceptable: 16, 24, 32 bytes
// ---------------------------------------------------------------------------
void validate_aes_key(const std::string &key);

// ---------------------------------------------------------------------------
// Convert bytes → hex
// ---------------------------------------------------------------------------
std::string BytesToHex(const std::vector<uint8_t> &data);

// ---------------------------------------------------------------------------
// Convert hex → bytes
// ---------------------------------------------------------------------------
std::vector<uint8_t> HexToBytes(const std::string &hex);

} // namespace parquet_encryption
