cmake_minimum_required(VERSION 3.20)
project(sealmark VERSION 0.1.0 LANGUAGES CXX)

add_executable(sealmark src/main.cpp)
target_compile_features(sealmark PRIVATE cxx_std_20)
set_target_properties(sealmark PROPERTIES CXX_EXTENSIONS OFF)
