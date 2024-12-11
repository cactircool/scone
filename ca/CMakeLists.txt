cmake_minimum_required(VERSION 3.29)
project(ca)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

#add_compile_options(-O3)

# Add executable
add_executable(ca main.cpp
        SSLConfig.cpp
        SSLConfig.hpp
        Request.cpp
        Request.hpp
        JSON.cpp
        JSON.hpp)

# Link OpenSSL libraries
target_link_libraries(ca
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Include OpenSSL headers
target_include_directories(ca PRIVATE ${OPENSSL_INCLUDE_DIR})