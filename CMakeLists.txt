cmake_minimum_required(VERSION 3.16)
project(simple_antivirus)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
find_package (Threads REQUIRED)
find_package(cpprestsdk REQUIRED)
add_executable(simple_antivirus src/file_functions.cpp headers/file_functions.h src/crypto_functions.cpp headers/crypto_functions.h src/main.cpp headers/main.h src/scan.cpp headers/scan.h src/data_functions.cpp headers/data_functions.h src/monitor.cpp headers/monitor.h libs/safe_queue.h src/virustotal_api.cpp headers/virustotal_api.h)
target_link_libraries(simple_antivirus ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(simple_antivirus ${CMAKE_SOURCE_DIR}/libs/libcrypto++.a)
target_link_libraries(simple_antivirus cpprestsdk::cpprest)
#add_custom_target(setcap ALL
#        WORKING_DIRECTORY ${OUTPUT_DIR}
#        COMMAND ${CMAKE_COMMAND} -E 'sudo setcap CAP_DAC_READ_SEARCH,CAP_DAC_OVERRIDE' ${}<simple_antivirus>)
#add_dependencies(setcap ${simple_antivirus})
SET(SUDO_COMMAND sudo)
add_custom_command(TARGET simple_antivirus POST_BUILD
        COMMAND ${SUDO_COMMAND} setcap CAP_DAC_OVERRIDE+ep simple_antivirus
        WORKING_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})

