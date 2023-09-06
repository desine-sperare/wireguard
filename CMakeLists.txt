cmake_minimum_required(VERSION 3.5.0)
project(wireguard VERSION 1.0.0 LANGUAGES CXX)

set(SOURCE_LIB ./src/wireguard.cpp)



include_directories(./libs/wg_utils/include)
include_directories(./libs/ipv4/include)
include_directories(./libs/uuid/include)
include_directories(./libs/json/single_include/nlohmann)
include_directories(./libs/wg_utils/libs/time/include)
include_directories(./include)

add_subdirectory(libs/wg_utils)
add_subdirectory(libs/ipv4)
add_subdirectory(libs/uuid)

add_library(wireguard ${SOURCE_LIB})
#add_library(json ./libs/json/single_include/nlohmann/json.hpp)

target_link_libraries(wireguard wg_utils)
target_link_libraries(wireguard ipv4)
target_link_libraries(wireguard time)
#target_link_libraries(wireguard json)
target_link_libraries(wireguard uuid)
