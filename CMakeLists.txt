cmake_minimum_required(VERSION 3.21)
project(Antywirus_Mateusz_Koziel)

set(CMAKE_CXX_STANDARD 17)

link_libraries(crypto)

add_executable(Antywirus_Mateusz_Koziel file_management.cpp file_management.h crypto_functions.cpp crypto_functions.h main.cpp)
