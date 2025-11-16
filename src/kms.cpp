#include "kms.hpp"
#include <iostream>
#include "crypto_utils.hpp"

namespace parquet_encryption {

// Generate a data key: plaintext used for encryption, encrypted stored in footer
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> KMS::GenerateDataKey(const std::string &kms_key_id) {
    // Generate a dummy random 16-byte key for plaintext
    std::vector<uint8_t> plaintext(16);
    for (size_t i = 0; i < 16; ++i) plaintext[i] = static_cast<uint8_t>(i + 1);

    // Simulate "KMS encryption" by just XORing with 0xAA (for demo)
    std::vector<uint8_t> encrypted(16);
    for (size_t i = 0; i < 16; ++i) encrypted[i] = plaintext[i] ^ 0xAA;

    std::cout << "[KMS] Generated plaintext key: " << BytesToHex(plaintext) << "\n";
    std::cout << "[KMS] Encrypted key for footer: " << BytesToHex(encrypted) << "\n";

    return {plaintext, encrypted}; // plaintext first, encrypted second
}

// Decrypt a KMS key: return the original plaintext used for encryption
std::vector<uint8_t> KMS::DecryptDataKey(const std::vector<uint8_t> &encrypted_key, const std::string &kms_key_id) {
    std::vector<uint8_t> decrypted(16);
    for (size_t i = 0; i < 16; ++i) decrypted[i] = encrypted_key[i] ^ 0xAA;

    std::cout << "[KMS] Decrypted key: " << BytesToHex(decrypted) << "\n";
    return decrypted;
}

} // namespace parquet_encryption
