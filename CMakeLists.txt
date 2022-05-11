cmake_minimum_required(VERSION 3.16)
project(simple_antivirus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
find_package (Threads REQUIRED)
find_package(cpprestsdk REQUIRED)
find_package(CURL REQUIRED)
include_directories( ${CURL_INCLUDE_DIRS} )
link_directories( ${CURL_LIBRARIES} )
add_executable(simple_antivirus src/file_functions.cpp headers/file_functions.h src/crypto_functions.cpp headers/crypto_functions.h src/main.cpp headers/main.h src/scan.cpp headers/scan.h src/data_functions.cpp headers/data_functions.h src/monitor.cpp headers/monitor.h libs/safe_queue.h src/virustotal_api.cpp headers/virustotal_api.h)
#add_executable(simple_antivirus src/file_functions.cpp headers/file_functions.h src/crypto_functions.cpp headers/crypto_functions.h src/main.cpp headers/main.h src/scan.cpp headers/scan.h src/data_functions.cpp headers/data_functions.h src/monitor.cpp headers/monitor.h libs/safe_queue.h)
target_link_libraries(simple_antivirus ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(simple_antivirus ${CMAKE_SOURCE_DIR}/libs/libcrypto++.a)
target_link_libraries(simple_antivirus cpprestsdk::cpprest)
target_link_libraries(simple_antivirus curl)



