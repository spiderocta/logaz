cmake_minimum_required(VERSION 3.25)

project(logaz
        VERSION 1.0.0
        LANGUAGES CXX       
        DESCRIPTION "log file analyzer")

set(CMAKE_CXX_STANDARD         17)
set(CMAKE_C_STANDARD_REQUIRED  ON)
set(CMAKE_CXX_FEATURES         OFF)

set(TARGET_NAME logaz)

add_executable(${TARGET_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/logaz.cpp
)
