cmake_minimum_required(VERSION 3.23)
project(aes_crypt)

set(CMAKE_CXX_STANDARD 14)
add_executable(aes_crypt main.cpp base64.cpp aes.cpp)
