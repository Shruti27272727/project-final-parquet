#pragma once

#include "parquet_encryption_config.hpp"
#include "parquet_encryption_mode.hpp"
#include <string>
#include <vector>
#include <map>

namespace parquet_encryption {

    // Row struct supporting dynamic columns
    // Each row can have any number of columns identified by name
    struct Row {
        std::map<std::string, std::string> columns; // column name -> value
    };

    // Writes a Parquet file with the specified encryption configuration
    void write_parquet_file(const std::string &filename,
                            const ParquetEncryptionConfig &config,
                            const std::vector<Row> &rows);

    // Reads a Parquet file and prints decrypted content based on configuration
    void read_parquet_file(const std::string &filename,
                           const ParquetEncryptionConfig &config);

} // namespace parquet_encryption
