cmake_minimum_required(VERSION 3.20)
project(sealmark VERSION 0.1.0 LANGUAGES CXX)

# Building the sealmark program never requires anything beyond a C++20
# compiler and the OpenSSL development files below. The regression tests and
# their auxiliary content (a Python interpreter plus the Python cryptography
# package, and on Linux three small C LD_PRELOAD fault injectors) are prepared
# only when tests are explicitly enabled.
option(BUILD_TESTING "Build the regression tests and their helper libraries" OFF)

add_executable(sealmark src/main.cpp)
target_compile_features(sealmark PRIVATE cxx_std_20)
set_target_properties(sealmark PROPERTIES CXX_EXTENSIONS OFF)

# OpenSSL (libcrypto) is a hard requirement of the program itself; the lookup
# order and the OPENSSL_ROOT_DIR / PKG_CONFIG_PATH hints are unchanged, and a
# missing OpenSSL still fails configuration even with tests disabled.
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(sealmark PRIVATE OpenSSL::Crypto)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)
    target_link_libraries(sealmark PRIVATE PkgConfig::OPENSSL)
endif()

# Always generate the CTest description: with testing off it registers no
# tests at all, and turning BUILD_TESTING back OFF in a previously enabled
# build directory drops the previously registered tests instead of leaving
# stale entries behind. enable_testing() does not look for Python or C.
enable_testing()

if(BUILD_TESTING)
    # The regression suites are Python scripts. The interpreter selected here
    # is the only one involved in testing: it is used both for the
    # cryptography import check below and as the interpreter ctest launches
    # the suites with, so an installation in some other Python environment
    # cannot satisfy the check by accident. Choose it explicitly with
    # -DPython3_EXECUTABLE=/path/to/python3 if needed.
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    # cryptography is imported by tests/test_key_id.py; check it with the
    # configured interpreter itself at configure time, so a missing package
    # fails here (with a way to keep building the program) rather than as an
    # ImportError when the tests are run later.
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -c "import cryptography"
        RESULT_VARIABLE SEALMARK_CRYPTOGRAPHY_RESULT
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(NOT SEALMARK_CRYPTOGRAPHY_RESULT EQUAL 0)
        message(FATAL_ERROR
            "BUILD_TESTING=ON requires the Python 'cryptography' package, "
            "but it cannot be imported by the configured interpreter "
            "${Python3_EXECUTABLE}. Install it into that interpreter (for "
            "example: \"${Python3_EXECUTABLE}\" -m pip install "
            "cryptography), point -DPython3_EXECUTABLE at an interpreter "
            "that already has it, or reconfigure without -DBUILD_TESTING=ON "
            "(or with -DBUILD_TESTING=OFF) to build only the sealmark "
            "program without the regression tests.")
    endif()

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
        # On Linux the read-error/read-interruption/file-type checks need the
        # three C preload libraries, so a working C compiler is required for
        # the tests at configure time. CheckLanguage locates one without
        # aborting configuration; a missing compiler (or an explicitly
        # configured one that does not exist) is then reported here, with the
        # option to leave the tests off, instead of as a bare compiler error.
        include(CheckLanguage)
        check_language(C)
        if(NOT CMAKE_C_COMPILER OR NOT EXISTS "${CMAKE_C_COMPILER}")
            message(FATAL_ERROR
                "BUILD_TESTING=ON on Linux requires a C compiler to build "
                "the test fault-injection helper libraries "
                "(tests/readfail_preload.c, tests/eintr_preload.c and "
                "tests/toctou_preload.c), but no usable C compiler was "
                "found. Install one (for example gcc), point "
                "-DCMAKE_C_COMPILER at it, or reconfigure without "
                "-DBUILD_TESTING=ON (or with -DBUILD_TESTING=OFF) to build "
                "only the sealmark program.")
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
endif()
