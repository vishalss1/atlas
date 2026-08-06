cmake_minimum_required(VERSION 3.21)

project(atlas VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC compiler flags
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc)
    add_compile_options($<$<CONFIG:Debug>:/Zi>)
    add_compile_options($<$<CONFIG:Release>:/O2>)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)

include(FetchContent)

# 1. nlohmann_json
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(
        json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(json)
endif()

# 2. fmt
find_package(fmt CONFIG QUIET)
if(NOT fmt_FOUND)
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 10.2.1
    )
    FetchContent_MakeAvailable(fmt)
endif()

# 3. spdlog (Use external fmt 10.2.1 for MSVC compatibility)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
find_package(spdlog CONFIG QUIET)
if(NOT spdlog_FOUND)
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.14.1
    )
    FetchContent_MakeAvailable(spdlog)
endif()

# 4. GoogleTest
find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# Subsystem Targets
# Header-only interface target for packet definitions
add_library(atlas_packet INTERFACE)
target_include_directories(atlas_packet INTERFACE src include)
target_link_libraries(atlas_packet INTERFACE fmt::fmt)

add_library(atlas_config STATIC
    src/config/config.hpp
    src/config/config.cpp
)
target_include_directories(atlas_config PUBLIC src include)
target_link_libraries(atlas_config PUBLIC atlas_packet nlohmann_json::nlohmann_json spdlog::spdlog)

add_library(atlas_ethernet STATIC
    src/ethernet/ethernet.hpp
    src/ethernet/ethernet.cpp
)
target_include_directories(atlas_ethernet PUBLIC src include)
target_link_libraries(atlas_ethernet PUBLIC atlas_packet)

add_library(atlas_ipv4 STATIC
    src/ipv4/ipv4.hpp
    src/ipv4/ipv4.cpp
)
target_include_directories(atlas_ipv4 PUBLIC src include)
target_link_libraries(atlas_ipv4 PUBLIC atlas_packet)

add_library(atlas_interfaces STATIC
    src/interfaces/interface.hpp
    src/interfaces/interface.cpp
    src/interfaces/manager.hpp
    src/interfaces/manager.cpp
)
target_include_directories(atlas_interfaces PUBLIC src include)
target_link_libraries(atlas_interfaces PUBLIC atlas_packet)

# Main Executable Target
add_executable(atlas src/main.cpp)
target_link_libraries(atlas PRIVATE
    atlas_packet
    atlas_config
    atlas_ethernet
    atlas_ipv4
    atlas_interfaces
    spdlog::spdlog
)

# Unit Tests Target
enable_testing()

add_executable(atlas_tests
    tests/unit/test_config.cpp
    tests/unit/test_ethernet.cpp
    tests/unit/test_ipv4.cpp
)
target_link_libraries(atlas_tests PRIVATE
    atlas_packet
    atlas_config
    atlas_ethernet
    atlas_ipv4
    atlas_interfaces
    gtest
    gtest_main
)

include(GoogleTest)
gtest_discover_tests(atlas_tests)
