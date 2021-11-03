cmake_minimum_required (VERSION 3.20)

project(
  bindssl_app
  LANGUAGES CXX
)

add_executable(
  ${PROJECT_NAME}
  src/main.cc
)

add_dependencies(${PROJECT_NAME} bindssl)

set_target_properties(
  ${PROJECT_NAME} PROPERTIES CXX_STANDARD 17 OUTPUT_NAME "bindssl")

target_link_libraries(${PROJECT_NAME} bindssl)
