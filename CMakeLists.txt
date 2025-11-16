cmake_minimum_required(VERSION 3.10)
project(parquet_encryption)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------
# Compiler warnings
# ---------------------------------------------------------
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# ---------------------------------------------------------
# Directory structure
# ---------------------------------------------------------
include_directories(
    include
    third_party
)

# ---------------------------------------------------------
# Find MbedTLS (via vcpkg)
# ---------------------------------------------------------
find_package(MbedTLS CONFIG REQUIRED)

message(STATUS "MbedTLS Found: YES")
message(STATUS "Using mbedtls include dir: ${MbedTLS_INCLUDE_DIRS}")

# ---------------------------------------------------------
# Executable and source files
# ---------------------------------------------------------
add_executable(parquet_encryption
    src/main.cpp
    src/parquet_writer.cpp
    src/parquet_reader.cpp
    src/crypto_utils.cpp
    src/kms.cpp
)

# ---------------------------------------------------------
# Link required libs
# ---------------------------------------------------------
target_link_libraries(parquet_encryption
    PRIVATE
        MbedTLS::mbedtls
        MbedTLS::mbedcrypto
        MbedTLS::mbedx509
)

# ---------------------------------------------------------
# Output folders for Windows builds
# ---------------------------------------------------------
set_target_properties(parquet_encryption PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE   ${CMAKE_BINARY_DIR}/Release
    RUNTIME_OUTPUT_DIRECTORY_DEBUG     ${CMAKE_BINARY_DIR}/Debug
)

# ---------------------------------------------------------
# Fix for Windows UTF-8 console output (optional but useful)
# ---------------------------------------------------------
if(MSVC)
    target_compile_options(parquet_encryption PRIVATE /utf-8)
endif()
