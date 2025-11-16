// src/main.cpp
#include "parquet_writer.hpp"
#include "parquet_reader.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>

using namespace parquet_encryption;

// Maximum characters to display for very long values
constexpr size_t MAX_DISPLAY_LENGTH = 100;

// Utility function to create a Row dynamically
Row create_row(const std::map<std::string, std::string>& cols) {
    Row row;
    row.columns = cols;
    return row;
}

// Function to print all rows neatly
void print_rows(const std::vector<Row>& rows) {
    std::set<std::string> all_columns;
    for (const auto& row : rows) {
        for (const auto& [col_name, _] : row.columns) {
            all_columns.insert(col_name);
        }
    }

    std::cout << "\n=== ROW DATA ===\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        std::cout << "Row " << i + 1 << ":\n";
        for (const auto& col_name : all_columns) {
            auto it = rows[i].columns.find(col_name);
            std::string value = (it != rows[i].columns.end()) ? it->second : "";

            if (value.size() > MAX_DISPLAY_LENGTH) {
                std::cout << "  " << col_name << " = "
                          << value.substr(0, MAX_DISPLAY_LENGTH) << "... [" 
                          << value.size() << " chars]\n";
            } else {
                std::cout << "  " << col_name << " = " << value << "\n";
            }
        }
    }
}

// Function to perform a decryption test and return decrypted column values
std::map<std::string, std::vector<std::string>> run_decryption_test(
    const std::string& test_name,
    const std::string& filename,
    const ParquetEncryptionConfig& config,
    const std::set<std::string>& requested_columns)
{
    std::cout << "\n=== DECRYPTION TEST: " << test_name << " ===\n";
    return read_parquet_file(filename, config, requested_columns);
}

// Function to validate selective decryption
void validate_decryption(const std::string& test_name,
                         const std::map<std::string, std::vector<std::string>>& decrypted_data,
                         const std::set<std::string>& requested_columns,
                         const std::vector<Row>& original_rows)
{
    std::cout << "\n=== VALIDATION TEST: " << test_name << " ===\n";
    bool valid = true;

    for (size_t i = 0; i < original_rows.size(); ++i) {
        for (const auto& [col_name, orig_val] : original_rows[i].columns) {
            auto it = decrypted_data.find(col_name);
            std::string value = (it != decrypted_data.end() && i < it->second.size()) ? it->second[i] : "[ENCRYPTED]";

            if (requested_columns.count(col_name)) {
                // Should be decrypted
                if (value != orig_val) {
                    std::cout << "ERROR: Column [" << col_name << "] row " << i+1 
                              << " expected decrypted value: " << (orig_val.size() > MAX_DISPLAY_LENGTH ? orig_val.substr(0, MAX_DISPLAY_LENGTH) + "..." : orig_val)
                              << ", but got: " << (value.size() > MAX_DISPLAY_LENGTH ? value.substr(0, MAX_DISPLAY_LENGTH) + "..." : value) << "\n";
                    valid = false;
                }
            } else {
                // Should remain encrypted
                if (value != "[ENCRYPTED]") {
                    std::cout << "ERROR: Column [" << col_name << "] row " << i+1 
                              << " should remain [ENCRYPTED], but got: " << (value.size() > MAX_DISPLAY_LENGTH ? value.substr(0, MAX_DISPLAY_LENGTH) + "..." : value) << "\n";
                    valid = false;
                }
            }
        }
    }

    if (valid)
        std::cout << "Validation passed ✅\n";
    else
        std::cout << "Validation failed ❌\n";
}

int main(int argc, char** argv) {
    // === Parquet encryption configuration ===
    ParquetEncryptionConfig config;
    config.mode = EncryptionMode::AES_GCM;
    config.use_kms = true;
    config.kms_key_id = "example-kms-id";
    config.master_key = "0123456789ABCDEF0123456789ABCDEF";
    config.encryption_key = "00112233445566778899AABBCCDDEEFF"; // fallback key

    // Column-specific keys
    config.column_keys.clear();
    config.column_keys["Name"] = "00112233445566778899AABBCCDDEEFF";
    config.column_keys["Salary"] = "FFEEDDCCBBAA99887766554433221100";
    config.column_keys["Department"] = "A1B2C3D4E5F60718293A4B5C6D7E8F90";

    // === Prepare rows dynamically ===
    std::vector<Row> rows;
    rows.push_back(create_row({{"Name","Shruti"}, {"Salary","90000"}, {"Department","IT"}}));
    rows.push_back(create_row({{"Name","Alex"}, {"Salary","75000"}}));
    rows.push_back(create_row({{"Name","John"}, {"Salary","80000"}, {"Department","Finance"}, {"Location","NY"}}));
    rows.push_back(create_row({{"Name","Emma"}, {"Location","CA"}}));

    std::string huge_string(5000, 'X'); 
    rows.push_back(create_row({{"Name", huge_string}, {"Salary","1234567890"}, {"Department","Engineering"}}));
    rows.push_back(create_row({})); // empty row

    // === Write Parquet file ===
    std::string filename = "test_kms.parquet";
    std::cout << "\n=== WRITING PARQUET FILE ===\n";
    write_parquet_file(filename, config, rows);

    // === Run multiple decryption tests and validate ===
    auto full_data = run_decryption_test("Full Decryption (All Columns)", filename, config, {"Name", "Salary", "Department", "Location"});
    validate_decryption("Full Decryption (All Columns)", full_data, {"Name", "Salary", "Department", "Location"}, rows);

    auto sel1_data = run_decryption_test("Selective Decryption 1 (Salary + Department)", filename, config, {"Salary", "Department"});
    validate_decryption("Selective Decryption 1 (Salary + Department)", sel1_data, {"Salary", "Department"}, rows);

    auto sel2_data = run_decryption_test("Selective Decryption 2 (Location Only)", filename, config, {"Location"});
    validate_decryption("Selective Decryption 2 (Location Only)", sel2_data, {"Location"}, rows);

    auto sel3_data = run_decryption_test("Selective Decryption 3 (Name Only)", filename, config, {"Name"});
    validate_decryption("Selective Decryption 3 (Name Only)", sel3_data, {"Name"}, rows);

    // === Print original rows dynamically ===
    print_rows(rows);

    std::cout << "\n=== PROCESS COMPLETE ===\n";
    return 0;
}
