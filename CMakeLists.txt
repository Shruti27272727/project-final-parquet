cmake_minimum_required(VERSION 3.10)
project(parquet_encryption)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable warnings
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Include directories
include_directories(
    include
    third_party    # If you put nlohmann/json.hpp here
)

# Source files
add_executable(parquet_encryption
    src/main.cpp
    src/parquet_writer.cpp
    src/parquet_reader.cpp
    src/crypto_utils.cpp
    src/kms.cpp
)

# Link any required libraries here (if you have crypto or system libs)
# target_link_libraries(parquet_encryption <lib_name>)
