project(quickstack)
cmake_minimum_required(VERSION 2.6)
include(CPack)

set(SOURCE quickstack.cc)
set(BINUTILS_LIB_DIR /usr/binutils/lib /usr/binutils/lib64)

find_library(BINUTILS_LIB NAMES bfd
  PATHS ${BINUTILS_LIB_DIR})
find_library(BINUTILS_ELF_LIB NAMES elf
  PATHS ${BINUTILS_LIB_DIR})
find_library(BINUTILS_IBERTY_LIB NAMES iberty
  PATHS ${BINUTILS_LIB_DIR})

find_path(BINUTILS_INCLUDE_DIR  bfd.h
  /usr/binutils/include)
include_directories(${BINUTILS_INCLUDE_DIR})

add_executable(quickstack ${SOURCE})
target_link_libraries(quickstack
  z ${BINUTILS_LIB} ${BINUTILS_ELF_LIB} ${BINUTILS_IBERTY_LIB})

install(TARGETS quickstack DESTINATION bin)

