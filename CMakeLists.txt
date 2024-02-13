cmake_minimum_required(VERSION 3.10)
# Set the project name
project (bitaddress)
find_package(OpenSSL REQUIRED)
# Add the source files to a library
add_library(bitaddress STATIC GenerateMnemonic.cpp ProcessAddress.cpp)
# Specify the include directories
target_include_directories(bitaddress PUBLIC include)
target_link_libraries(bitaddress OpenSSL::SSL OpenSSL::Crypto)