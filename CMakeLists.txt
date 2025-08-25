cmake_minimum_required(VERSION 3.20)
project(IntrDet VERSION 1.0.0 LANGUAGES CXX)

# Set C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -O3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Boost REQUIRED COMPONENTS system asio)
find_package(Threads REQUIRED)

# Find libpcap
pkg_check_modules(PCAP REQUIRED libpcap)

# Find ONNX Runtime
find_package(ONNXRuntime QUIET)
if(NOT ONNXRuntime_FOUND)
    message(WARNING "ONNX Runtime not found. ML inference will be disabled.")
    set(ENABLE_ML_INFERENCE OFF)
else()
    set(ENABLE_ML_INFERENCE ON)
endif()

# Find GoogleTest
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    message(WARNING "GoogleTest not found. Tests will be disabled.")
    set(ENABLE_TESTS OFF)
else()
    set(ENABLE_TESTS ON)
endif()

# Find Google Benchmark
find_package(benchmark QUIET)
if(NOT benchmark_FOUND)
    message(WARNING "Google Benchmark not found. Benchmarks will be disabled.")
    set(ENABLE_BENCHMARKS OFF)
else()
    set(ENABLE_BENCHMARKS ON)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${PCAP_INCLUDE_DIRS})

# Add subdirectories
add_subdirectory(src)
if(ENABLE_TESTS)
    add_subdirectory(tests)
endif()
if(ENABLE_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# Install configuration
install(TARGETS IntrDet
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Install headers
install(DIRECTORY include/ DESTINATION include)

