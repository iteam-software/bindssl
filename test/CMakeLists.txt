# CMakeList.txt : CMake project for ensure_ssl_binding, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.20)

project(
  bindssl_test
  LANGUAGES CXX
)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)

# Add source to this project's executable.
add_executable (
  ${PROJECT_NAME}
  src/strconv_test.cc
)

add_dependencies(${PROJECT_NAME} bindssl)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_link_libraries(${PROJECT_NAME} gtest_main bindssl)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})
