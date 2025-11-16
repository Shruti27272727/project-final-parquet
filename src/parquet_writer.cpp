// src/parquet_writer.cpp
#include "parquet_writer.hpp"
#include "crypto_utils.hpp"
#include "kms.hpp"

#include <fstream>
#include <set>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>

using json = nlohmann::json;

namespace parquet_encryption {

// Maximum characters to display in console (do not truncate actual data)
constexpr size_t MAX_DISPLAY_LENGTH = 100;

static bool IsValidAesKeyLength(const std::vector<uint8_t> &key) {
    return key.size() == 16 || key.size() == 24 || key.size() == 32;
}

void write_parquet_file(const std::string &filename,
                        const ParquetEncryptionConfig &config,
                        const std::vector<Row> &rows) {

    std::cout << "\n=== PARQUET WRITER START ===\n";
    std::cout << "Output File: " << filename << "\n";
    std::cout << "Encryption Mode: "
              << (config.mode == EncryptionMode::AES_GCM ? "AES-GCM" :
                  config.mode == EncryptionMode::AES_CTR ? "AES-CTR" : "NONE")
              << "\n";
    std::cout << "KMS Enabled: " << (config.use_kms ? "YES" : "NO") << "\n";

    if (rows.empty()) {
        std::cerr << "No rows to write.\n";
        return;
    }

    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        std::cerr << "ERROR: Cannot open output file.\n";
        return;
    }

    KMS kms;
    json footer;
    footer["row_count"] = rows.size();
    footer["columns"] = json::object();

    // Collect all column names dynamically
    std::set<std::string> all_columns;
    for (const auto &row : rows)
        for (const auto &[col_name, _] : row.columns)
            all_columns.insert(col_name);

    // Write each column
    for (const auto &col_name : all_columns) {
        std::stringstream ss;

        // Ensure every row has a value line for this column
        for (size_t r = 0; r < rows.size(); ++r) {
            std::string value = "";
            auto it = rows[r].columns.find(col_name);
            if (it != rows[r].columns.end()) {
                value = it->second;
            }
            ss << col_name << ": " << value << "\n";
        }

        std::string col_plain_str = ss.str();
        std::vector<uint8_t> col_plain(col_plain_str.begin(), col_plain_str.end());

        // ===== Robust Key Selection (Column-key -> KMS -> Fallback) =====
        std::vector<uint8_t> resolved_key;
        std::string key_type = "none";

        // 1) Try column-specific key (if provided)
        if (config.column_keys.find(col_name) != config.column_keys.end()) {
            std::vector<uint8_t> candidate = HexToBytes(config.column_keys.at(col_name));
            if (IsValidAesKeyLength(candidate)) {
                resolved_key = std::move(candidate);
                key_type = "column-specific key";
            } else {
                std::cerr << "WARNING: Column-specific key for [" << col_name << "] has invalid length ("
                          << candidate.size() << " bytes). Falling back to KMS/fallback.\n";
            }
        }

        // 2) If not resolved, try KMS (if enabled)
        if (resolved_key.empty() && config.use_kms) {
            // If footer already has an encrypted key for this column (re-run or pre-seeded), use it
            if (footer["columns"].contains(col_name) && footer["columns"][col_name].contains("kms_encrypted_key")) {
                std::vector<uint8_t> encrypted_blob = HexToBytes(footer["columns"][col_name]["kms_encrypted_key"]);
                std::vector<uint8_t> decrypted = kms.DecryptDataKey(encrypted_blob, config.kms_key_id);
                if (IsValidAesKeyLength(decrypted)) {
                    resolved_key = std::move(decrypted);
                    key_type = "KMS key (from footer)";
                } else {
                    std::cerr << "WARNING: KMS-decrypted key (from footer) for [" << col_name << "] invalid length ("
                              << decrypted.size() << " bytes). Will try to generate new KMS key or fallback.\n";
                }
            }

            // If still not resolved, generate a fresh data key via KMS and store encrypted blob in footer
            if (resolved_key.empty()) {
                auto [plaintext, encrypted_blob] = kms.GenerateDataKey(config.kms_key_id);
                if (IsValidAesKeyLength(plaintext)) {
                    resolved_key = plaintext;
                    footer["columns"][col_name]["kms_encrypted_key"] = BytesToHex(encrypted_blob);
                    key_type = "KMS key (generated)";
                    std::cout << "[KMS] Generated encrypted key for column: " << col_name << "\n";
                } else {
                    std::cerr << "WARNING: KMS generated key for [" << col_name << "] invalid length ("
                              << plaintext.size() << " bytes). Falling back to configured master key.\n";
                }
            }
        }

        // 3) Fallback to config.encryption_key (master/fallback)
        if (resolved_key.empty()) {
            std::vector<uint8_t> candidate = HexToBytes(config.encryption_key);
            if (IsValidAesKeyLength(candidate)) {
                resolved_key = std::move(candidate);
                key_type = "fallback key";
            } else {
                std::cerr << "ERROR: fallback encryption key has invalid length (" << candidate.size()
                          << " bytes). Cannot encrypt column [" << col_name << "].\n";
                // Write plain column (for dev/testing). In production prefer failing closed.
                std::cerr << "Writing plaintext column [" << col_name << "] due to missing valid encryption key.\n";
                size_t col_offset_plain = static_cast<size_t>(out.tellp());
                out.write(reinterpret_cast<char*>(col_plain.data()), static_cast<std::streamsize>(col_plain.size()));
                footer["columns"][col_name]["offset"] = col_offset_plain;
                footer["columns"][col_name]["size"] = col_plain.size();
                footer["columns"][col_name]["mode"] = "PLAINTEXT";
                footer["columns"][col_name]["key_type"] = "none";
                // continue to next column
                continue;
            }
        }

        // Record key type in footer for debugging/inspection (DO NOT store plaintext keys)
        footer["columns"][col_name]["key_type"] = key_type;

        std::cout << "Column [" << col_name << "] will be encrypted using: " << key_type << "\n";

        // Encrypt column
        std::string col_key_str(resolved_key.begin(), resolved_key.end());
        bool use_gcm = (config.mode == EncryptionMode::AES_GCM);
        std::vector<uint8_t> col_enc = aes_encrypt(col_plain, col_key_str, use_gcm);

        // parse IV/tag for footer metadata (iv/tag are embedded in col_enc per our AES helpers)
        if (use_gcm) {
            // format: [12-byte IV][ciphertext][16-byte TAG]
            const size_t IV_LEN = 12;
            const size_t TAG_LEN = 16;
            if (col_enc.size() >= IV_LEN + TAG_LEN) {
                std::vector<uint8_t> iv(col_enc.begin(), col_enc.begin() + IV_LEN);
                std::vector<uint8_t> tag(col_enc.end() - TAG_LEN, col_enc.end());
                std::vector<uint8_t> ciphertext(col_enc.begin() + IV_LEN, col_enc.end() - TAG_LEN);

                size_t col_offset = static_cast<size_t>(out.tellp());
                // write full blob as stored (IV + ciphertext + TAG)
                out.write(reinterpret_cast<char*>(col_enc.data()), static_cast<std::streamsize>(col_enc.size()));

                footer["columns"][col_name]["offset"] = col_offset;
                footer["columns"][col_name]["size"] = col_enc.size();
                footer["columns"][col_name]["mode"] = "AES_GCM";
                footer["columns"][col_name]["iv"] = BytesToHex(iv);
                footer["columns"][col_name]["tag"] = BytesToHex(tag);
                footer["columns"][col_name]["cipher_size"] = ciphertext.size();
            } else {
                // fallback: write as-is but mark error
                size_t col_offset = static_cast<size_t>(out.tellp());
                out.write(reinterpret_cast<char*>(col_enc.data()), static_cast<std::streamsize>(col_enc.size()));
                footer["columns"][col_name]["offset"] = col_offset;
                footer["columns"][col_name]["size"] = col_enc.size();
                footer["columns"][col_name]["mode"] = "AES_GCM";
                footer["columns"][col_name]["iv"] = "";
                footer["columns"][col_name]["tag"] = "";
                footer["columns"][col_name]["cipher_size"] = 0;
                std::cerr << "WARNING: Encrypted blob for column [" << col_name << "] too small to parse IV/TAG.\n";
            }
        } else {
            // AES-CTR format: [16-byte IV][ciphertext]
            const size_t IV_LEN = 16;
            if (col_enc.size() >= IV_LEN) {
                std::vector<uint8_t> iv(col_enc.begin(), col_enc.begin() + IV_LEN);
                std::vector<uint8_t> ciphertext(col_enc.begin() + IV_LEN, col_enc.end());

                size_t col_offset = static_cast<size_t>(out.tellp());
                out.write(reinterpret_cast<char*>(col_enc.data()), static_cast<std::streamsize>(col_enc.size()));

                footer["columns"][col_name]["offset"] = col_offset;
                footer["columns"][col_name]["size"] = col_enc.size();
                footer["columns"][col_name]["mode"] = "AES_CTR";
                footer["columns"][col_name]["iv"] = BytesToHex(iv);
                footer["columns"][col_name]["cipher_size"] = ciphertext.size();
            } else {
                size_t col_offset = static_cast<size_t>(out.tellp());
                out.write(reinterpret_cast<char*>(col_enc.data()), static_cast<std::streamsize>(col_enc.size()));
                footer["columns"][col_name]["offset"] = col_offset;
                footer["columns"][col_name]["size"] = col_enc.size();
                footer["columns"][col_name]["mode"] = "AES_CTR";
                footer["columns"][col_name]["iv"] = "";
                footer["columns"][col_name]["cipher_size"] = 0;
                std::cerr << "WARNING: Encrypted CTR blob for column [" << col_name << "] too small to parse IV.\n";
            }
        }

        // Optional: print sample for console
        if (!rows.empty()) {
            std::string first_val = rows[0].columns.count(col_name) ? rows[0].columns.at(col_name) : "";
            if (first_val.size() > MAX_DISPLAY_LENGTH)
                first_val = first_val.substr(0, MAX_DISPLAY_LENGTH) + "...";
            std::cout << "  Sample value: " << first_val << "\n";
        }
    }

    // Serialize and encrypt footer
    std::string footer_str = footer.dump();
    std::vector<uint8_t> footer_plain(footer_str.begin(), footer_str.end());
    std::vector<uint8_t> master_key_bytes = HexToBytes(config.master_key);
    std::string master_key_str(master_key_bytes.begin(), master_key_bytes.end());
    std::vector<uint8_t> footer_encrypted = aes_encrypt(footer_plain, master_key_str, true);

    out.write(reinterpret_cast<char*>(footer_encrypted.data()), static_cast<std::streamsize>(footer_encrypted.size()));

    // Write footer length
    uint64_t footer_len = static_cast<uint64_t>(footer_encrypted.size());
    out.write(reinterpret_cast<char*>(&footer_len), sizeof(uint64_t));

    out.close();
    std::cout << "=== PARQUET WRITE COMPLETE ===\n";
}

} // namespace parquet_encryption
