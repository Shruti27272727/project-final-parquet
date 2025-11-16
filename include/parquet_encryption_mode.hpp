#pragma once

namespace parquet_encryption {

// Supported encryption modes for Parquet files.
// NONE    → No encryption
// AES_CTR → AES Counter Mode
// AES_GCM → AES Galois/Counter Mode (authenticated encryption)
enum class EncryptionMode {
    NONE,
    AES_CTR,
    AES_GCM
};

} // namespace parquet_encryption
