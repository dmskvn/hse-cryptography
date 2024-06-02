cmake_minimum_required(VERSION 3.5)

project(moskvin_aes LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(moskvin_aes main_aes.cpp aes.cpp)
add_executable(moskvin_rsa main_rsa.cpp rsa.cpp)
