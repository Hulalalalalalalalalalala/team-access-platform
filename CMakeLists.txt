cmake_minimum_required(VERSION 3.20)
project(sealmark VERSION 0.1.0 LANGUAGES CXX)

add_executable(sealmark src/main.cpp)
target_compile_features(sealmark PRIVATE cxx_std_20)
set_target_properties(sealmark PROPERTIES CXX_EXTENSIONS OFF)

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(sealmark PRIVATE OpenSSL::Crypto)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)
    target_link_libraries(sealmark PRIVATE PkgConfig::OPENSSL)
endif()

enable_testing()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(
        NAME digest
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_digest.py
    )
    set_tests_properties(
        digest
        PROPERTIES
            ENVIRONMENT "SEALMARK_BIN=$<TARGET_FILE:sealmark>"
    )
    add_test(
        NAME verify-digest
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_verify_digest.py
    )
    set_tests_properties(
        verify-digest
        PROPERTIES
            ENVIRONMENT "SEALMARK_BIN=$<TARGET_FILE:sealmark>"
    )
endif()
