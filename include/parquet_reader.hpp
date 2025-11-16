#pragma once
#include <string>
#include <set>
#include <map>
#include <vector>
#include "parquet_encryption_config.hpp"

namespace parquet_encryption {

// Updated declaration to return column values
std::map<std::string, std::vector<std::string>> read_parquet_file(
    const std::string &filename,
    const ParquetEncryptionConfig &config,
    const std::set<std::string> &requested_columns);

} // namespace parquet_encryption
