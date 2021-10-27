# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# set(SPDLOG_WCHAR_SUPPORT ON)

project ("spdlog")
project ("ensure_ssl_binding")

# Include sub-projects.
add_subdirectory ("spdlog")
add_subdirectory ("ensure_ssl_binding")
