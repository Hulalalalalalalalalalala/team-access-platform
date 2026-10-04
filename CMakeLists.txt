cmake_minimum_required(VERSION 3.20)
project(sealmark VERSION 0.1.0 LANGUAGES CXX C)

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
    set(SEALMARK_TEST_ENV "SEALMARK_BIN=$<TARGET_FILE:sealmark>")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # LD_PRELOAD helper used by the tests to simulate a read(2) failure
        # partway through an otherwise healthy regular file.
        add_library(sealmark_read_fault_injector MODULE tests/read_fault_injector.c)
        set_target_properties(sealmark_read_fault_injector PROPERTIES PREFIX "")
        target_link_libraries(sealmark_read_fault_injector PRIVATE ${CMAKE_DL_LIBS})
        list(APPEND SEALMARK_TEST_ENV
             "SEALMARK_FAULT_LIB=$<TARGET_FILE:sealmark_read_fault_injector>")
    endif()
    add_test(
        NAME digest
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_digest.py
    )
    set_tests_properties(
        digest
        PROPERTIES
        ENVIRONMENT "${SEALMARK_TEST_ENV}"
    )
    add_test(
        NAME verify-digest
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_verify_digest.py
    )
    set_tests_properties(
        verify-digest
        PROPERTIES
        ENVIRONMENT "${SEALMARK_TEST_ENV}"
    )
endif()
