project(quickstack)
cmake_minimum_required(VERSION 3.1)
include(CPack)

find_package(PkgConfig)

set(CMAKE_CXX_STANDARD 11)
set(SOURCE quickstack.cc)

pkg_check_modules(ELF REQUIRED libelf)

find_library(BFD_LIBRARY bfd REQUIRED)
find_path(BFD_INCLUDE_DIR bfd.h REQUIRED)

find_package(ZLIB REQUIRED)

include_directories(${BFD_INCLUDE_DIR} ${ZLIB_INCLUDE_DIRS})
add_executable(quickstack ${SOURCE})
target_link_libraries(quickstack ZLIB::ZLIB ${ELF_LIBRARIES} ${BFD_LIBRARY})

install(TARGETS quickstack DESTINATION bin)

