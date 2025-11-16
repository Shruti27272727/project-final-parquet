// src/crypto_utils.cpp
#include "crypto_utils.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace parquet_encryption {

// ---------------- Dummy AES (XOR placeholder) ----------------
std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t> &plain,
                                 const std::string &key,
                                 bool use_gcm) {
    if (key.empty()) throw std::runtime_error("Encryption key is empty");

    std::vector<uint8_t> out = plain;
    for (size_t i = 0; i < out.size(); i++) {
        out[i] ^= static_cast<uint8_t>(key[i % key.size()]); // simple XOR encryption
    }
    return out;
}

std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t> &encrypted,
                                 const std::string &key,
                                 bool use_gcm) {
    if (key.empty()) throw std::runtime_error("Decryption key is empty");

    std::vector<uint8_t> out = encrypted;
    for (size_t i = 0; i < out.size(); i++) {
        out[i] ^= static_cast<uint8_t>(key[i % key.size()]); // XOR decrypt
    }
    return out;
}

// ---------------- Hex conversion ----------------
std::string BytesToHex(const std::vector<uint8_t> &data) {
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

std::vector<uint8_t> HexToBytes(const std::string &hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("Invalid hex string");
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

} // namespace parquet_encryption
