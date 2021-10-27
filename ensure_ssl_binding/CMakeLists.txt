# CMakeList.txt : CMake project for ensure_ssl_binding, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (
    ensure_ssl_binding
    "ensure_ssl_binding.cpp"
    "ensure_ssl_binding.h"
    "CertificateBinding.cpp"
    "platform.cpp"
    "query_binding.cpp"
    "set_binding.cpp"
    "strconv.cpp")

add_dependencies(ensure_ssl_binding spdlog)

target_compile_features(ensure_ssl_binding PUBLIC cxx_std_17)
target_link_libraries(ensure_ssl_binding httpapi Ws2_32 spdlog::spdlog)