// src/parquet_reader.cpp
#include "parquet_reader.hpp"
#include "crypto_utils.hpp"
#include "kms.hpp"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>
#include <map>
#include <set>
#include <sstream>

using json = nlohmann::json;

namespace parquet_encryption {

constexpr size_t MAX_DISPLAY_LENGTH = 100;

std::map<std::string, std::vector<std::string>> read_parquet_file(
    const std::string &filename,
    const ParquetEncryptionConfig &config,
    const std::set<std::string> &requested_columns)
{
    std::cout << "\n=== PARQUET READER START ===\n";
    std::cout << "Input File: " << filename << "\n";

    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        std::cerr << "ERROR: Unable to open file.\n";
        return {};
    }

    // ---- Compute file size ----
    in.seekg(0, std::ios::end);
    std::streampos file_size_pos = in.tellg();
    std::streamoff file_size = static_cast<std::streamoff>(file_size_pos);

    in.seekg(0);
    if (file_size < static_cast<std::streamoff>(sizeof(uint64_t))) {
        std::cerr << "ERROR: Invalid file.\n";
        return {};
    }

    // ---- Read footer length ----
    in.seekg(file_size - static_cast<std::streamoff>(sizeof(uint64_t)));

    uint64_t footer_len = 0;
    in.read(reinterpret_cast<char*>(&footer_len), sizeof(uint64_t));

    if (footer_len == 0 || footer_len > static_cast<uint64_t>(file_size)) {
        std::cerr << "ERROR: Corrupted footer length.\n";
        return {};
    }

    // ---- Read encrypted footer ----
    std::streamoff footer_start =
        file_size - static_cast<std::streamoff>(sizeof(uint64_t)) - static_cast<std::streamoff>(footer_len);

    in.seekg(footer_start);

    std::vector<uint8_t> encrypted_footer(footer_len);
    in.read(reinterpret_cast<char*>(encrypted_footer.data()), footer_len);

    // ---- Read entire file for column extraction ----
    in.seekg(0);
    std::vector<uint8_t> file_data(file_size);
    in.read(reinterpret_cast<char*>(file_data.data()), file_size);
    in.close();

    // ---- Decrypt footer ----
    std::vector<uint8_t> master_key_bytes = HexToBytes(config.master_key);
    std::string master_key_str(master_key_bytes.begin(), master_key_bytes.end());

    std::vector<uint8_t> footer_plain =
        aes_decrypt(encrypted_footer, master_key_str, true);

    json footer = json::parse(std::string(footer_plain.begin(), footer_plain.end()));

    size_t row_count = footer["row_count"];
    std::cout << "Footer metadata loaded. Rows = " << row_count << "\n";

    // ---- Initialization ----
    KMS kms;
    std::map<std::string, std::vector<std::string>> column_values;
    std::vector<std::string> column_order;

    // ---- Process each column ----
    for (auto &[col_name, col_meta] : footer["columns"].items()) {
        column_order.push_back(col_name);

        bool should_decrypt =
            requested_columns.empty() ||
            requested_columns.count(col_name) != 0;

        // Skip unrequested columns
        if (!should_decrypt) {
            std::cout << "Skipping column [" << col_name << "] — not requested.\n";
            column_values[col_name] = std::vector<std::string>(row_count, "[ENCRYPTED]");
            continue;
        }

        // Metadata
        size_t offset = col_meta["offset"];
        size_t size = col_meta["size"];
        bool use_gcm = (col_meta["mode"] == "AES_GCM");

        if (offset + size > file_data.size()) {
            std::cerr << "ERROR: Column bounds invalid for [" << col_name << "]\n";
            column_values[col_name] = std::vector<std::string>(row_count, "[ERROR]");
            continue;
        }

        std::vector<uint8_t> col_enc(
            file_data.begin() + offset,
            file_data.begin() + offset + size
        );

        // ---- Key Selection ----
        std::vector<uint8_t> col_key;
        std::string key_type;

        if (config.column_keys.count(col_name)) {
            col_key = HexToBytes(config.column_keys.at(col_name));
            key_type = "column-specific key";
        }
        else if (config.use_kms && col_meta.contains("kms_encrypted_key")) {
            col_key = kms.DecryptDataKey(
                HexToBytes(col_meta["kms_encrypted_key"]),
                config.kms_key_id
            );
            key_type = "KMS key";

            if (col_key.empty()) {
                std::cerr << "ERROR: Failed decrypting KMS key for [" << col_name << "]\n";
                column_values[col_name] = std::vector<std::string>(row_count, "[ERROR]");
                continue;
            }
        }
        else {
            col_key = HexToBytes(config.encryption_key);
            key_type = "fallback key";
        }

        std::cout << "Column [" << col_name << "] decrypted using " << key_type << ".\n";

        // ---- Decrypt column ----
        std::string col_key_str(col_key.begin(), col_key.end());
        std::vector<uint8_t> col_plain =
            aes_decrypt(col_enc, col_key_str, use_gcm);

        // ---- Parse values ----
        std::vector<std::string> values;
        std::istringstream ss(std::string(col_plain.begin(), col_plain.end()));

        std::string line;
        while (std::getline(ss, line)) {
            size_t p = line.find(": ");
            values.push_back(p != std::string::npos ? line.substr(p + 2) : "");
        }

        // Pad missing rows
        while (values.size() < row_count)
            values.push_back("");

        column_values[col_name] = values;
    }

    // ---- Print reconstructed table ----
    std::cout << "\n=== PARQUET DATA ===\n";
    for (size_t i = 0; i < row_count; i++) {
        std::cout << "Row " << i + 1 << ":\n";
        for (const auto &col_name : column_order) {
            const std::string &v = column_values[col_name][i];

            if (v.size() > MAX_DISPLAY_LENGTH)
                std::cout << "  " << col_name << " = "
                          << v.substr(0, MAX_DISPLAY_LENGTH)
                          << "... [" << v.size() << " chars]\n";
            else
                std::cout << "  " << col_name << " = " << v << "\n";
        }
    }

    std::cout << "\n=== PARQUET READER COMPLETE ===\n";
    return column_values;
}

} // namespace parquet_encryption
