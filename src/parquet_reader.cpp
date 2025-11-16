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

constexpr size_t MAX_DISPLAY_LENGTH = 100; // display truncation only

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

    // Determine file size
    in.seekg(0, std::ios::end);
    std::streampos file_size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (file_size < static_cast<std::streampos>(sizeof(uint64_t))) {
        std::cerr << "ERROR: File too small.\n";
        return {};
    }

    // Read footer length
    in.seekg(file_size - static_cast<std::streampos>(sizeof(uint64_t)));
    uint64_t footer_len;
    in.read(reinterpret_cast<char*>(&footer_len), sizeof(uint64_t));
    if (footer_len == 0 || footer_len > static_cast<uint64_t>(file_size)) {
        std::cerr << "ERROR: Invalid footer length.\n";
        return {};
    }

    size_t footer_start = static_cast<size_t>(
        static_cast<uint64_t>(file_size) - sizeof(uint64_t) - footer_len
    );

    in.seekg(static_cast<std::streampos>(footer_start));
    std::vector<uint8_t> encrypted_footer(footer_len);
    in.read(reinterpret_cast<char*>(encrypted_footer.data()), footer_len);

    // Read full file for column data
    std::vector<uint8_t> file_data(static_cast<size_t>(file_size));
    in.seekg(0);
    in.read(reinterpret_cast<char*>(file_data.data()), static_cast<std::streamsize>(file_size));
    in.close();

    // Decrypt footer using master key
    std::vector<uint8_t> master_key_bytes = HexToBytes(config.master_key);
    std::string master_key_str(master_key_bytes.begin(), master_key_bytes.end());
    std::vector<uint8_t> footer_plain = aes_decrypt(encrypted_footer, master_key_str, true);

    json footer = json::parse(std::string(footer_plain.begin(), footer_plain.end()));
    size_t row_count = footer["row_count"];
    std::cout << "Footer metadata parsed. Row count = " << row_count << "\n";

    KMS kms;
    std::map<std::string, std::vector<std::string>> column_values;
    std::vector<std::string> column_order;

    // Process each column
    for (auto &[col_name, col_meta] : footer["columns"].items()) {
        column_order.push_back(col_name);

        bool decrypt_column_flag = requested_columns.empty() || requested_columns.count(col_name) > 0;
        if (!decrypt_column_flag) {
            std::cout << "Column [" << col_name << "] skipped (not requested).\n";
            column_values[col_name] = std::vector<std::string>(row_count, "[ENCRYPTED]");
            continue;
        }

        size_t offset = static_cast<size_t>(col_meta["offset"]);
        size_t size = col_meta["size"];
        bool use_gcm = (col_meta["mode"] == "AES_GCM");

        if (offset + size > file_data.size()) {
            std::cerr << "ERROR: Column data out of bounds.\n";
            column_values[col_name] = std::vector<std::string>(row_count, "[ERROR]");
            continue;
        }

        std::vector<uint8_t> col_enc(file_data.begin() + offset, file_data.begin() + offset + size);

        // ===== Robust Key Selection =====
        std::vector<uint8_t> col_key;
        std::string key_type;

        // 1️⃣ Column-specific key has highest priority
        if (config.column_keys.find(col_name) != config.column_keys.end()) {
            col_key = HexToBytes(config.column_keys.at(col_name));
            key_type = "column-specific key";
        }
        // 2️⃣ KMS key (if enabled and available)
        else if (config.use_kms && col_meta.contains("kms_encrypted_key")) {
            col_key = kms.DecryptDataKey(HexToBytes(col_meta["kms_encrypted_key"]), config.kms_key_id);
            key_type = "KMS key";

            if (col_key.empty()) {
                std::cerr << "ERROR: Failed to decrypt KMS key for column [" << col_name << "]\n";
                column_values[col_name] = std::vector<std::string>(row_count, "[ERROR]");
                continue;
            }
        }
        // 3️⃣ Fallback key (master key)
        else {
            col_key = HexToBytes(config.encryption_key);
            key_type = "fallback key";
        }

        std::cout << "Column [" << col_name << "] decrypted using " << key_type << ".\n";

        std::string col_key_str(col_key.begin(), col_key.end());
        std::vector<uint8_t> col_plain = aes_decrypt(col_enc, col_key_str, use_gcm);

        // Parse column data into row values
        std::string data_str(col_plain.begin(), col_plain.end());
        std::istringstream ss(data_str);
        std::string line;
        std::vector<std::string> values;
        while (std::getline(ss, line)) {
            size_t pos = line.find(": ");
            std::string value = (pos != std::string::npos) ? line.substr(pos + 2) : "";
            values.push_back(value);
        }

        while (values.size() < row_count)
            values.push_back("");

        column_values[col_name] = std::move(values);
    }

    // Print row-wise data (truncated)
    std::cout << "\n=== PARQUET DATA ===\n";
    for (size_t i = 0; i < row_count; i++) {
        std::cout << "Row " << i + 1 << ":\n";
        for (const auto &col_name : column_order) {
            std::string value = column_values[col_name][i];
            if (value.size() > MAX_DISPLAY_LENGTH)
                std::cout << "  " << col_name << " = " << value.substr(0, MAX_DISPLAY_LENGTH) << "... [" << value.size() << " chars]\n";
            else
                std::cout << "  " << col_name << " = " << value << "\n";
        }
    }

    std::cout << "\n=== PARQUET READER COMPLETE ===\n\n";
    return column_values;
}

} // namespace parquet_encryption
