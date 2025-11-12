cmake_minimum_required(VERSION 3.10)
project(rdma-example C)

# === Basic configuration ===
set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

# Compiler & optimization flags
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Ofast -ffast-math -funroll-loops -Wall -Wextra")

# === RDMA libraries ===
find_library(IBVERBS_LIBRARY ibverbs HINTS /home/atr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu)
find_library(RDMACM_LIBRARY rdmacm HINTS /home/atr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu)

# === OpenSSL (for SHA-256) ===
find_package(OpenSSL REQUIRED)

# === Include directories ===
# /usr/include is implicit for gcc, but we add it explicitly for safety
include_directories(
    ${PROJECT_SOURCE_DIR}
    /usr/include
    /home/atr/local/include
)

# === Executables ===
add_executable(rdma_client
    ${PROJECT_SOURCE_DIR}/rdma_common.c
    ${PROJECT_SOURCE_DIR}/rdma_client.c
)

# === Link libraries ===
target_link_libraries(rdma_client
    PRIVATE
    pthread
    ${IBVERBS_LIBRARY}
    ${RDMACM_LIBRARY}
    OpenSSL::Crypto
)

# === Print summary ===
message(STATUS "IBVERBS library: ${IBVERBS_LIBRARY}")
message(STATUS "RDMACM  library: ${RDMACM_LIBRARY}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libs: ${OPENSSL_LIBRARIES}")
