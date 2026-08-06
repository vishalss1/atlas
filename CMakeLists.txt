cmake_minimum_required(VERSION 3.21)

project(atlas VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC compiler flags
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc /FS)
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
    include/atlas/config/config.hpp
    src/config/config.cpp
)
target_include_directories(atlas_config PUBLIC include src)
target_link_libraries(atlas_config PUBLIC atlas_packet nlohmann_json::nlohmann_json spdlog::spdlog)

add_library(atlas_ethernet STATIC
    include/atlas/ethernet/ethernet.hpp
    src/ethernet/ethernet.cpp
)
target_include_directories(atlas_ethernet PUBLIC include src)
target_link_libraries(atlas_ethernet PUBLIC atlas_packet)

add_library(atlas_ipv4 STATIC
    include/atlas/ipv4/ipv4.hpp
    src/ipv4/ipv4.cpp
)
target_include_directories(atlas_ipv4 PUBLIC include src)
target_link_libraries(atlas_ipv4 PUBLIC atlas_packet)

add_library(atlas_interfaces STATIC
    include/atlas/interfaces/interface.hpp
    src/interfaces/interface.cpp
    include/atlas/interfaces/manager.hpp
    src/interfaces/manager.cpp
)
target_include_directories(atlas_interfaces PUBLIC include src)
target_link_libraries(atlas_interfaces PUBLIC atlas_packet)

add_library(atlas_routing STATIC
    include/atlas/routing/routing.hpp
    src/routing/routing.cpp
)
target_include_directories(atlas_routing PUBLIC include src)
target_link_libraries(atlas_routing PUBLIC atlas_packet)

add_library(atlas_arp STATIC
    include/atlas/arp/cache.hpp
    src/arp/cache.cpp
    include/atlas/arp/arp.hpp
    src/arp/arp.cpp
)
target_include_directories(atlas_arp PUBLIC include src)
target_link_libraries(atlas_arp PUBLIC atlas_packet atlas_ethernet atlas_interfaces)

add_library(atlas_firewall STATIC
    include/atlas/firewall/firewall.hpp
    src/firewall/firewall.cpp
)
target_include_directories(atlas_firewall PUBLIC include src)
target_link_libraries(atlas_firewall PUBLIC atlas_packet)

add_library(atlas_nat STATIC
    include/atlas/nat/nat.hpp
    src/nat/nat.cpp
)
target_include_directories(atlas_nat PUBLIC include src)
target_link_libraries(atlas_nat PUBLIC atlas_packet atlas_ipv4 spdlog::spdlog)

add_library(atlas_forwarding STATIC
    include/atlas/forwarding/forwarding.hpp
    src/forwarding/forwarding.cpp
)
target_include_directories(atlas_forwarding PUBLIC include src)
target_link_libraries(atlas_forwarding PUBLIC atlas_packet atlas_ethernet atlas_ipv4 atlas_routing atlas_arp atlas_interfaces atlas_firewall atlas_nat spdlog::spdlog)

# Main Executable Target
add_executable(atlas src/main.cpp)
target_link_libraries(atlas PRIVATE
    atlas_packet
    atlas_config
    atlas_ethernet
    atlas_ipv4
    atlas_interfaces
    atlas_routing
    atlas_arp
    atlas_firewall
    atlas_nat
    atlas_forwarding
    spdlog::spdlog
)

# Unit Tests Target
enable_testing()

add_executable(atlas_tests
    tests/unit/test_config.cpp
    tests/unit/test_ethernet.cpp
    tests/unit/test_ipv4.cpp
    tests/unit/test_routing.cpp
    tests/unit/test_arp.cpp
    tests/unit/test_firewall.cpp
    tests/unit/test_nat.cpp
    tests/unit/test_forwarding.cpp
)
target_link_libraries(atlas_tests PRIVATE
    atlas_packet
    atlas_config
    atlas_ethernet
    atlas_ipv4
    atlas_interfaces
    atlas_routing
    atlas_arp
    atlas_firewall
    atlas_nat
    atlas_forwarding
    gtest
    gtest_main
)

include(GoogleTest)
gtest_discover_tests(atlas_tests)

