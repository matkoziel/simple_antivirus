cmake_minimum_required(VERSION 3.21)
project(Antywirus_Mateusz_Koziel)

set(CMAKE_CXX_STANDARD 17)

link_libraries(crypto)
link_libraries(crypto++)

add_executable(Antywirus_Mateusz_Koziel src/file_management.cpp headers/file_management.h src/crypto_functions.cpp headers/crypto_functions.h src/main.cpp)
