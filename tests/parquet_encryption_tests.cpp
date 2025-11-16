#include "../include/parquet_writer.hpp"
#include "../include/parquet_reader.hpp"
#include "../include/parquet_encryption_config.hpp"
#include "../include/parquet_encryption_mode.hpp"
#include <string>
#include <filesystem>
#include <iostream>

int main() {

    // Debug: Print working directory
    std::cout << "Current Working Directory: "
              << std::filesystem::current_path()
              << std::endl;

    parquet_encryption::ParquetEncryptionConfig config;
    config.mode = parquet_encryption::EncryptionMode::AES_GCM;

    std::string test_file = "C:\\Users\\powar\\Desktop\\project_final_parquet\\test.parquet";

    parquet_encryption::write_parquet_file(test_file, config);
    parquet_encryption::read_parquet_file(test_file, config);

    return 0;
}
