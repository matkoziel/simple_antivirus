cmake_minimum_required(VERSION 3.21)
project(simple_antivirus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)


link_libraries(crypto)
link_libraries(crypto++)
#target_link_libraries(crypto++ STATIC)
#find_package(crypto++ REQUIRED)
#target_link_libraries(${simple_antivirus} crypto++)

add_executable(simple_antivirus src/file_management.cpp headers/file_management.h src/crypto_functions.cpp headers/crypto_functions.h src/main.cpp headers/main.h)
