// src/crypto_utils.cpp
#include "crypto_utils.hpp"

#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <vector>
#include <cstring>

namespace parquet_encryption {

// AES-GCM params
static constexpr size_t GCM_IV_LEN = 12;   // 96-bit recommended
static constexpr size_t GCM_TAG_LEN = 16;  // 128-bit tag

// ---------------- random helper (MbedTLS CTR-DRBG) ----------------
static void mbedtls_random_init(mbedtls_entropy_context &entropy, mbedtls_ctr_drbg_context &ctr_drbg) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "parquet_encryption_rng";
    int rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
    if (rc != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error("mbedtls_ctr_drbg_seed failed");
    }
}

// Fill a vector with cryptographically secure random bytes
static std::vector<uint8_t> random_bytes(size_t n) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_random_init(entropy, ctr_drbg);

    std::vector<uint8_t> out(n);
    int rc = mbedtls_ctr_drbg_random(&ctr_drbg, out.data(), static_cast<size_t>(n));
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (rc != 0) throw std::runtime_error("Failed to generate random bytes (mbedtls)");
    return out;
}

// ---------------- AES-GCM encrypt/decrypt using MbedTLS ----------------
std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t> &plain,
                                 const std::string &key,
                                 bool use_gcm) {
    if (!use_gcm) throw std::runtime_error("aes_encrypt: only AES-GCM supported in this implementation");

    if (key.empty()) throw std::runtime_error("Encryption key is empty");
    std::vector<uint8_t> key_bytes(key.begin(), key.end());
    if (!(key_bytes.size() == 16 || key_bytes.size() == 24 || key_bytes.size() == 32))
        throw std::runtime_error("Encryption key length must be 16/24/32 bytes");

    // Generate IV
    std::vector<uint8_t> iv = random_bytes(GCM_IV_LEN);

    // Prepare output: IV || ciphertext || tag
    std::vector<uint8_t> out;
    out.reserve(GCM_IV_LEN + plain.size() + GCM_TAG_LEN);
    out.insert(out.end(), iv.begin(), iv.end());

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_bytes.data(), static_cast<unsigned int>(key_bytes.size() * 8));
    if (rc != 0) {
        mbedtls_gcm_free(&gcm);
        throw std::runtime_error("mbedtls_gcm_setkey failed");
    }

    std::vector<uint8_t> ciphertext(plain.size());
    std::vector<uint8_t> tag(GCM_TAG_LEN);

    rc = mbedtls_gcm_crypt_and_tag(&gcm,
                                   MBEDTLS_GCM_ENCRYPT,
                                   plain.size(),
                                   iv.data(), iv.size(),
                                   nullptr, 0,                // no additional authenticated data (AAD)
                                   plain.data(), ciphertext.data(),
                                   tag.size(), tag.data());
    mbedtls_gcm_free(&gcm);

    if (rc != 0) {
        throw std::runtime_error("mbedtls_gcm_crypt_and_tag failed");
    }

    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t> &encrypted,
                                 const std::string &key,
                                 bool use_gcm) {
    if (!use_gcm) throw std::runtime_error("aes_decrypt: only AES-GCM supported in this implementation");
    if (encrypted.size() < GCM_IV_LEN + GCM_TAG_LEN) throw std::runtime_error("Encrypted blob too small");

    if (key.empty()) throw std::runtime_error("Decryption key is empty");
    std::vector<uint8_t> key_bytes(key.begin(), key.end());
    if (!(key_bytes.size() == 16 || key_bytes.size() == 24 || key_bytes.size() == 32))
        throw std::runtime_error("Decryption key length must be 16/24/32 bytes");

    // Parse IV, ciphertext, tag
    const uint8_t *p = encrypted.data();
    std::vector<uint8_t> iv(p, p + GCM_IV_LEN);
    const size_t ciphertext_len = encrypted.size() - GCM_IV_LEN - GCM_TAG_LEN;
    const uint8_t *ciphertext_ptr = p + GCM_IV_LEN;
    const uint8_t *tag_ptr = p + GCM_IV_LEN + ciphertext_len;

    std::vector<uint8_t> plaintext(ciphertext_len);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_bytes.data(), static_cast<unsigned int>(key_bytes.size() * 8));
    if (rc != 0) {
        mbedtls_gcm_free(&gcm);
        throw std::runtime_error("mbedtls_gcm_setkey failed");
    }

    rc = mbedtls_gcm_auth_decrypt(&gcm,
                                 ciphertext_len,
                                 iv.data(), iv.size(),
                                 nullptr, 0, // no AAD
                                 tag_ptr, GCM_TAG_LEN,
                                 ciphertext_ptr, plaintext.data());
    mbedtls_gcm_free(&gcm);

    if (rc != 0) {
        throw std::runtime_error("AES-GCM authentication failed (tag mismatch or corrupt data)");
    }

    return plaintext;
}

// ---------------- Hex conversion ----------------
std::string BytesToHex(const std::vector<uint8_t> &data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
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
