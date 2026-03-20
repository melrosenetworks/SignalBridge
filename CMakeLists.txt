cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds pollute the repository. Use a build directory:\n"
        "  mkdir -p build && cd build && cmake .. && cmake --build .")
endif()

project(SignalBridge VERSION 1.0.0 LANGUAGES CXX)

# 3GPP Release 17 — normative target for S1AP/NGAP/NAS (see docs/3GPP_RELEASE.md).

option(SIGNALBRIDGE_USE_ASN1C_NAS
    "Use asn1c-backed NAS IMSI discovery entry point (see docs/ASN1C_NAS.md). ON by default; delegates to manual until Rel-17 NAS is wired. OFF: link manual collector only."
    ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find dependencies
# yaml-cpp: prefer CONFIG (Homebrew, vcpkg). Ubuntu/Debian libyaml-cpp-dev often ships no usable
# yaml-cpp::yaml-cpp target (or a half-broken config); then define IMPORTED yaml-cpp::yaml-cpp ourselves.
# Clear cached NOTFOUND from earlier configures so find_* can succeed after apt install.
find_package(yaml-cpp CONFIG QUIET)
if(NOT TARGET yaml-cpp::yaml-cpp)
    unset(YAML_CPP_INCLUDE_DIR CACHE)
    unset(YAML_CPP_LIBRARY CACHE)
    # Debian/Ubuntu: libyaml-cpp-dev installs yaml-cpp.pc — use it when CMake config / find_* miss (minimal images, odd multiarch).
    find_package(PkgConfig QUIET)
    set(_signalbridge_yaml_from_pkg FALSE)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(SB_YAML_CPP QUIET IMPORTED_TARGET GLOBAL yaml-cpp)
        if(TARGET PkgConfig::SB_YAML_CPP)
            add_library(yaml-cpp::yaml-cpp ALIAS PkgConfig::SB_YAML_CPP)
            set(_signalbridge_yaml_from_pkg TRUE)
        endif()
        # Some toolchains/CMake combos skip IMPORTED_TARGET; use classic .pc variables + find_library.
        if(NOT _signalbridge_yaml_from_pkg)
            pkg_check_modules(SB_YAML_LEGACY QUIET yaml-cpp)
            if(SB_YAML_LEGACY_FOUND)
                find_library(_sb_yaml_pc_lib NAMES yaml-cpp yaml-cpp0.7 yaml-cpp0.6
                    PATHS ${SB_YAML_LEGACY_LIBRARY_DIRS}
                    /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
                    /usr/lib/aarch64-linux-gnu /lib/aarch64-linux-gnu
                    /usr/lib /usr/local/lib)
                if(_sb_yaml_pc_lib AND SB_YAML_LEGACY_INCLUDE_DIRS)
                    add_library(yaml-cpp::yaml-cpp UNKNOWN IMPORTED GLOBAL)
                    set_target_properties(yaml-cpp::yaml-cpp PROPERTIES
                        IMPORTED_LOCATION "${_sb_yaml_pc_lib}"
                        INTERFACE_INCLUDE_DIRECTORIES "${SB_YAML_LEGACY_INCLUDE_DIRS}")
                    set(_signalbridge_yaml_from_pkg TRUE)
                endif()
            endif()
        endif()
    endif()
    if(NOT _signalbridge_yaml_from_pkg)
        find_path(YAML_CPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h
            PATHS /usr/include /usr/local/include /opt/homebrew/include)
        set(_sb_yaml_lib_paths
            /usr/lib/x86_64-linux-gnu
            /lib/x86_64-linux-gnu
            /usr/lib/aarch64-linux-gnu
            /lib/aarch64-linux-gnu
            /usr/lib/riscv64-linux-gnu
            /lib/riscv64-linux-gnu
            /usr/lib
            /usr/local/lib
            /opt/homebrew/lib)
        if(CMAKE_LIBRARY_ARCHITECTURE)
            list(PREPEND _sb_yaml_lib_paths
                "/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
                "/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
        endif()
        find_library(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cpp0.7 yaml-cpp0.6
            PATHS ${_sb_yaml_lib_paths})
        if(NOT YAML_CPP_LIBRARY)
            find_library(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cpp0.7 yaml-cpp0.6)
        endif()
        if(NOT YAML_CPP_INCLUDE_DIR)
            find_path(YAML_CPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h)
        endif()
        # Last resort: explicit paths (some images / cross roots confuse find_library).
        if(NOT YAML_CPP_LIBRARY)
            set(_sb_yaml_so_dirs)
            if(CMAKE_LIBRARY_ARCHITECTURE)
                list(APPEND _sb_yaml_so_dirs
                    "${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
                    "${CMAKE_SYSROOT}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
            endif()
            list(APPEND _sb_yaml_so_dirs
                "${CMAKE_SYSROOT}/usr/lib/x86_64-linux-gnu"
                "${CMAKE_SYSROOT}/lib/x86_64-linux-gnu"
                "${CMAKE_SYSROOT}/usr/lib/aarch64-linux-gnu"
                "${CMAKE_SYSROOT}/lib/aarch64-linux-gnu"
                "${CMAKE_SYSROOT}/usr/lib"
                "${CMAKE_SYSROOT}/usr/local/lib")
            foreach(_yb_dir IN LISTS _sb_yaml_so_dirs)
                foreach(_yb_name IN ITEMS libyaml-cpp.so libyaml-cpp.so.0.7)
                    set(_yb_cand "${_yb_dir}/${_yb_name}")
                    if(EXISTS "${_yb_cand}")
                        set(YAML_CPP_LIBRARY "${_yb_cand}")
                        break()
                    endif()
                endforeach()
                if(YAML_CPP_LIBRARY)
                    break()
                endif()
            endforeach()
        endif()
        if(NOT YAML_CPP_INCLUDE_DIR AND EXISTS "${CMAKE_SYSROOT}/usr/include/yaml-cpp/yaml.h")
            set(YAML_CPP_INCLUDE_DIR "${CMAKE_SYSROOT}/usr/include")
        endif()
        if(NOT YAML_CPP_INCLUDE_DIR OR NOT YAML_CPP_LIBRARY)
            message(FATAL_ERROR
                "yaml-cpp not found. Debian/Ubuntu: sudo apt-get install -y libyaml-cpp-dev pkg-config "
                "(verify: pkg-config --exists yaml-cpp && ls /usr/include/yaml-cpp/yaml.h). "
                "macOS: brew install yaml-cpp. If deps are OK: git pull origin main (your clone may predate CMake fixes), "
                "then rm -rf build && cmake -S . -B build.")
        endif()
        add_library(yaml-cpp::yaml-cpp UNKNOWN IMPORTED GLOBAL)
        set_target_properties(yaml-cpp::yaml-cpp PROPERTIES
            IMPORTED_LOCATION "${YAML_CPP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${YAML_CPP_INCLUDE_DIR}")
    endif()
endif()
if(NOT TARGET yaml-cpp::yaml-cpp)
    message(FATAL_ERROR "Internal error: yaml-cpp::yaml-cpp target missing after discovery.")
endif()
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
include(FetchContent)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)
find_library(PCAP_LIBRARY NAMES pcap
    PATHS /opt/homebrew/lib /opt/homebrew/Cellar/libpcap/*/lib /usr/local/lib /usr/lib)
find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h
    PATHS /opt/homebrew/include /opt/homebrew/Cellar/libpcap/*/include /usr/local/include /usr/include)
if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap required. Install: brew install libpcap (macOS) or apt-get install libpcap-dev (Linux)")
endif()

# S1-SEE parser sources: optional vendored third_party/s1see (e.g. publish/ mirror), else sibling ../S1-SEE
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/s1see/src/s1ap_parser.cpp")
    set(_s1see_default "${CMAKE_CURRENT_SOURCE_DIR}/third_party/s1see")
else()
    set(_s1see_default "${CMAKE_CURRENT_SOURCE_DIR}/../S1-SEE")
endif()
set(S1_SEE_DIR "${_s1see_default}" CACHE PATH
    "Path to S1-SEE parser sources (s1ap_parser, nas_parser, pcap_reader)")
if(NOT EXISTS "${S1_SEE_DIR}/src/s1ap_parser.cpp")
    message(FATAL_ERROR
        "S1-SEE parser sources not found at ${S1_SEE_DIR}.\n"
        "  Clone https://github.com/melrosenetworks/S1-SEE next to this repository, or pass "
        "-DS1_SEE_DIR=/path/to/S1-SEE\n"
        "  For the self-contained public mirror under publish/, run scripts/sync_to_publish.sh")
endif()

# Build parsers from S1-SEE (s1ap_parser, nas_parser, pcap_reader) - no protobuf/gRPC
add_library(signalbridge_s1see_parsers STATIC
    ${S1_SEE_DIR}/src/s1ap_parser.cpp
    ${S1_SEE_DIR}/src/nas_parser.cpp
    ${S1_SEE_DIR}/src/utils/pcap_reader.cc
)
target_include_directories(signalbridge_s1see_parsers PUBLIC
    ${S1_SEE_DIR}/include
    ${S1_SEE_DIR}/src
)
target_compile_definitions(signalbridge_s1see_parsers PRIVATE HAVE_PCAP)
target_include_directories(signalbridge_s1see_parsers PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(signalbridge_s1see_parsers PUBLIC ${PCAP_LIBRARY})

# SignalBridge library (pipeline, I/O, config, metrics, ngap_parser, nas_5gs_parser)
set(SIGNALBRIDGE_LIB_SOURCES
    src/ngap_parser.cc
    src/nas_5gs_parser.cc
    src/nas_identity_manual.cc
    src/pipeline/frame_extractor.cc
    src/pipeline/procedure_filter.cc
    src/pipeline/protocol_filter.cc
    src/pipeline/ip_filter.cc
    src/pipeline/anonymiser.cc
    src/pipeline/pipeline.cc
    src/io/pcap_io.cc
    src/io/async_pcap_output.cc
    src/io/tcp_io.cc
    src/io/http_stream_output.cc
    src/io/udp_output.cc
    src/io/tcp_output.cc
    src/config/config_loader.cc
    src/metrics/metrics.cc
    src/metrics/metrics_server.cc
)

if(SIGNALBRIDGE_USE_ASN1C_NAS)
    list(APPEND SIGNALBRIDGE_LIB_SOURCES src/nas_identity_asn1c.cc)
endif()

add_library(signalbridge_lib STATIC ${SIGNALBRIDGE_LIB_SOURCES})

if(SIGNALBRIDGE_USE_ASN1C_NAS)
    target_compile_definitions(signalbridge_lib PUBLIC SIGNALBRIDGE_USE_ASN1C_NAS)
endif()

target_compile_definitions(signalbridge_lib PRIVATE HAVE_PCAP)
target_include_directories(signalbridge_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${S1_SEE_DIR}/include
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(signalbridge_lib PUBLIC
    signalbridge_s1see_parsers
    yaml-cpp::yaml-cpp
    CURL::libcurl
    ZLIB::ZLIB
    OpenSSL::SSL
    nlohmann_json::nlohmann_json
    Threads::Threads
    ${PCAP_LIBRARY}
)

# Main binary
add_executable(signalbridge
    apps/signalbridge.cc
)

target_link_libraries(signalbridge signalbridge_lib)

# Install
install(TARGETS signalbridge RUNTIME DESTINATION bin)
install(DIRECTORY config/ DESTINATION etc/signalbridge FILES_MATCHING PATTERN "*.yaml" PATTERN "*.yml")

# Unit tests and bench target (omitted in public mirror — no test/ tree; enable by cloning full repo)
if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test")
    enable_testing()
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(signalbridge_tests
        test/unit/config_loader_test.cc
        test/unit/procedure_filter_test.cc
        test/unit/protocol_filter_test.cc
        test/unit/ip_filter_test.cc
        test/unit/pipeline_test.cc
        test/unit/http_url_test.cc
        test/unit/udp_output_test.cc
        test/unit/tcp_output_test.cc
        test/unit/anonymiser_test.cc
        test/unit/frame_extractor_test.cc
        test/unit/pcap_io_test.cc
        test/unit/tcp_io_test.cc
        test/unit/metrics_test.cc
        test/unit/ngap_parser_test.cc
    )
    target_include_directories(signalbridge_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${S1_SEE_DIR}/include
    )
    target_link_libraries(signalbridge_tests PRIVATE
        signalbridge_lib
        GTest::gtest_main
    )
    add_test(NAME signalbridge_tests COMMAND signalbridge_tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    # Benchmark: 9 input/output combinations (File/Stdin/TCP × PCAP/PCAPNG/HTTP)
    add_custom_target(bench
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test/bench_output.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Benchmark 9 I/O combinations (2 runs each; PCAP path from script search or arg)"
        USES_TERMINAL
    )
endif()
