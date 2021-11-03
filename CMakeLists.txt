# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.20)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(
  bindssl
  VERSION 0.0.1
  LANGUAGES CXX
)

include(FetchContent)

# Dependencies
FetchContent_Declare(
    spdlog
    URL https://github.com/gabime/spdlog/archive/eb3220622e73a4889eee355ffa37972b3cac3df5.zip
)

FetchContent_Declare(
    CLI11
    URL https://github.com/CLIUtils/CLI11/archive/70f8072f9dd2292fd0b9f9e5f58e279f60483ed3.zip
)

# Artifact definition
add_library(
  ${PROJECT_NAME}
    
  inc/bind_ssl.h
  inc/certificate_binding.h
  inc/endpoint.h
  inc/guid.h
  inc/hash.h
  inc/platform.h
  inc/primitives.h
  inc/result.h

  src/bind_ssl.cc
  src/guid.cc
  src/certificate_binding.cc
)

# set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 17)

FetchContent_MakeAvailable(spdlog)
FetchContent_MakeAvailable(cli11)

target_link_libraries(
  ${PROJECT_NAME}
  httpapi
  Ws2_32
  CLI11::CLI11
  spdlog::spdlog
)

target_include_directories(
  ${PROJECT_NAME} PUBLIC inc
)

# sub projects
# add_subdirectory(app)
# add_subdirectory(test)