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

# Regression tests are opt-in: the default build only needs a C++20 compiler
# and OpenSSL, and does not look for Python, cryptography, or a C compiler.
# Configure with -DBUILD_TESTING=ON to also build the test helper libraries
# and register the test suite; missing test prerequisites then fail the
# configure step with an explicit message instead of surfacing at test time.
option(BUILD_TESTING "Build the regression tests and their helper libraries" OFF)
if(NOT BUILD_TESTING)
    return()
endif()

enable_testing()

# Deterministic mid-read failure injection (Linux only): a small LD_PRELOAD
# library that makes read() fail with EIO part-way through one chosen regular
# file, so the "opened fine, then a read failed after partial data" path can
# be exercised without root, FUSE, or relying on coincidental file changes.
# Its location is handed to the Python tests through SEALMARK_READFAIL_PRELOAD;
# when unset (non-Linux) the corresponding tests skip themselves.
#
# A second preload (SEALMARK_TOCTOU_PRELOAD) makes the path-based status
# calls lie -- reporting one chosen FIFO as a regular file -- while leaving
# open() untouched, so the "file type is decided on the object actually
# opened, not on a separate stat of the path" rule can be tested without a
# real check/open race.
#
# A third preload (SEALMARK_EINTR_PRELOAD) injects transient EINTR results
# (optionally combined with short reads and a later genuine EIO) into reads
# of one chosen regular file, so the "an interrupted read is retried and the
# digest still covers the complete file" rule can be tested deterministically.
# It also writes a counters report so tests can prove the staged conditions
# actually occurred.
set(SEALMARK_TEST_ENV "SEALMARK_BIN=$<TARGET_FILE:sealmark>")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # The preload helpers are C, so a working C compiler is a hard test
    # prerequisite on Linux; fail at configure time with a clear message
    # rather than letting enable_language() emit its generic error.
    include(CheckLanguage)
    check_language(C)
    if(NOT CMAKE_C_COMPILER)
        message(
            FATAL_ERROR
            "BUILD_TESTING is ON but no C compiler was found, which is needed "
            "to build the Linux test helper libraries (readfail/eintr/toctou "
            "preloads). Install a C compiler, or reconfigure with "
            "-DBUILD_TESTING=OFF to build just the sealmark program."
        )
    endif()
    enable_language(C)
    add_library(sealmark_readfail_preload MODULE tests/readfail_preload.c)
    set_target_properties(
        sealmark_readfail_preload
        PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        PREFIX ""
        C_STANDARD 11
    )
    target_link_libraries(sealmark_readfail_preload PRIVATE ${CMAKE_DL_LIBS})

    add_library(sealmark_eintr_preload MODULE tests/eintr_preload.c)
    set_target_properties(
        sealmark_eintr_preload
        PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        PREFIX ""
        C_STANDARD 11
    )
    target_link_libraries(sealmark_eintr_preload PRIVATE ${CMAKE_DL_LIBS})

    add_library(sealmark_toctou_preload MODULE tests/toctou_preload.c)
    set_target_properties(
        sealmark_toctou_preload
        PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        PREFIX ""
        C_STANDARD 11
    )
    target_link_libraries(sealmark_toctou_preload PRIVATE ${CMAKE_DL_LIBS})

    list(
        APPEND SEALMARK_TEST_ENV
        "SEALMARK_READFAIL_PRELOAD=$<TARGET_FILE:sealmark_readfail_preload>"
        "SEALMARK_TOCTOU_PRELOAD=$<TARGET_FILE:sealmark_toctou_preload>"
        "SEALMARK_EINTR_PRELOAD=$<TARGET_FILE:sealmark_eintr_preload>"
    )
endif()

# With tests enabled, Python is a hard prerequisite: silently skipping the
# registered tests when no interpreter is found would hide regressions.
find_package(Python3 COMPONENTS Interpreter)
if(NOT Python3_Interpreter_FOUND)
    message(
        FATAL_ERROR
        "BUILD_TESTING is ON but no Python 3 interpreter was found, which is "
        "needed to run the regression tests. Install Python 3 (or point "
        "Python3_EXECUTABLE at one), or reconfigure with -DBUILD_TESTING=OFF "
        "to build just the sealmark program."
    )
endif()

# The key-id tests recompute fingerprints with the cryptography package, so
# verify it is importable by the interpreter selected above -- checking any
# other Python environment would not prove the tests can run.
execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import cryptography"
    RESULT_VARIABLE SEALMARK_CRYPTOGRAPHY_RESULT
    OUTPUT_QUIET
    ERROR_QUIET
)
if(NOT SEALMARK_CRYPTOGRAPHY_RESULT EQUAL 0)
    message(
        FATAL_ERROR
        "BUILD_TESTING is ON but the 'cryptography' package is not importable "
        "by the selected Python interpreter (${Python3_EXECUTABLE}), which is "
        "needed by the key-id regression tests. Install it for that "
        "interpreter (e.g. ${Python3_EXECUTABLE} -m pip install cryptography), "
        "or reconfigure with -DBUILD_TESTING=OFF to build just the sealmark "
        "program."
    )
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
add_test(
    NAME key-id
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_key_id.py
)
set_tests_properties(
    key-id
    PROPERTIES
    ENVIRONMENT "${SEALMARK_TEST_ENV}"
)
