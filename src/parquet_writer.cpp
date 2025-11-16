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

using json = nlohmann::json;

namespace parquet_encryption {

// Maximum characters to display in console (do not truncate actual data)
constexpr size_t MAX_DISPLAY_LENGTH = 100;

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

        // ===== Robust Key Selection =====
        std::vector<uint8_t> col_key;
        std::string key_type;

        // 1️⃣ Column-specific key
        if (config.column_keys.find(col_name) != config.column_keys.end()) {
            col_key = HexToBytes(config.column_keys.at(col_name));
            key_type = "column-specific key";
        }
        // 2️⃣ KMS key
        else if (config.use_kms) {
            // Generate new KMS key if not present
            if (!footer["columns"].contains(col_name) || !footer["columns"][col_name].contains("kms_encrypted_key")) {
                auto [plaintext, encrypted] = kms.GenerateDataKey(config.kms_key_id);
                col_key = plaintext;
                footer["columns"][col_name]["kms_encrypted_key"] = BytesToHex(encrypted);
            } else {
                col_key = kms.DecryptDataKey(HexToBytes(footer["columns"][col_name]["kms_encrypted_key"]), config.kms_key_id);
            }
            key_type = "KMS key";
        }
        // 3️⃣ Fallback key
        else {
            col_key = HexToBytes(config.encryption_key);
            key_type = "fallback key";
        }

        std::cout << "Column [" << col_name << "] uses " << key_type << ".\n";

        // Encrypt column
        std::string col_key_str(col_key.begin(), col_key.end());
        bool use_gcm = (config.mode == EncryptionMode::AES_GCM);
        std::vector<uint8_t> col_enc = aes_encrypt(col_plain, col_key_str, use_gcm);

        // Save offset, size, and mode
        size_t col_offset = out.tellp();
        out.write(reinterpret_cast<char*>(col_enc.data()), col_enc.size());
        footer["columns"][col_name]["offset"] = col_offset;
        footer["columns"][col_name]["size"] = col_enc.size();
        footer["columns"][col_name]["mode"] = (config.mode == EncryptionMode::AES_GCM ? "AES_GCM" : "AES_CTR");

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

    out.write(reinterpret_cast<char*>(footer_encrypted.data()), footer_encrypted.size());

    // Write footer length
    uint64_t footer_len = footer_encrypted.size();
    out.write(reinterpret_cast<char*>(&footer_len), sizeof(uint64_t));

    out.close();
    std::cout << "=== PARQUET WRITE COMPLETE ===\n";
}

} // namespace parquet_encryption
