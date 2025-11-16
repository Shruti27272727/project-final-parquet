#include "../include/parquet_writer.hpp"
#include "../include/parquet_reader.hpp"
#include "../include/parquet_encryption_config.hpp"
#include "../include/parquet_encryption_mode.hpp"
#include <string>

int main() {
    parquet_encryption::ParquetEncryptionConfig config;
    config.mode = parquet_encryption::EncryptionMode::AES_GCM;

    std::string test_file = "test.parquet";

    parquet_encryption::write_parquet_file(test_file, config);
    parquet_encryption::read_parquet_file(test_file, config);

    return 0;
}
