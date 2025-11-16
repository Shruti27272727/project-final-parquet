"# project-final-parquet" 
# Parquet Modular (Column-Level) Encryption

## Overview

This project implements **column-level AES-GCM encryption for Parquet files**, with optional KMS integration for key management. It allows selective encryption and decryption of sensitive columns while leaving non-sensitive data unencrypted.

**Key Features:**

* AES-GCM column-level encryption
* KMS-managed keys for secure key handling
* Full and selective column decryption
* Validation of encrypted/decrypted data

---

## Installation & Build

1. Clone the repository:

```
git clone <your-repo-url>
cd project_final_parquet
```

2. Build the project (Windows PowerShell example):

```powershell
cd build\Release
.\parquet_encryption.exe --skip-pro-check
```

> The executable will generate a Parquet file (`test_kms.parquet`) and perform encryption/decryption tests.

---

## Usage Examples

### Full Decryption

```powershell
Input File: test_kms.parquet
All columns decrypted:
Department = IT, Location = NY, Name = Shruti, Salary = 90000
```

### Selective Decryption

Decrypt only Salary and Department:

```powershell
Column [Department] decrypted
Column [Salary] decrypted
Column [Location] = [ENCRYPTED]
Column [Name] = [ENCRYPTED]
```

### KMS Key Integration

* Column `Location` encrypted using a KMS key.
* Keys are securely generated and used during decryption.

---

## Project Structure

```
project_final_parquet/
├─ build/Release/            # Compiled executable
├─ include/                  # Header files
├─ src/                      # Source files
└─ README.md
```

---

## Status

✅ Core encryption and decryption functionality complete

✅ Full and selective column decryption validated

✅ KMS key integration verified

---

## Future Improvements

* Handle null/missing values in encrypted columns
* Optimize for large datasets
* Role-based access for decryption
* Column masking for partially sensitive data
* CLI usability enhancements

---

## License

This project is licensed under the MIT License.
