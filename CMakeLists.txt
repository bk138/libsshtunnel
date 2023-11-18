# Simple C library to let your networking app connect to a host running behind a SSH server.
#
# Copyright (c) Christian Beier <info@christianbeier.net>
#
# SPDX-License-Identifier: BSD-3-Clause
#
cmake_minimum_required(VERSION 3.10)
project(libsshtunnel C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_GENERATOR MATCHES "Unix Makefiles|Ninja")
# some LSP servers expect compile_commands.json in the project root
add_custom_target(
    libsshtunnel-copy-compile-commands ALL
    ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif(CMAKE_GENERATOR MATCHES "Unix Makefiles|Ninja")

#
# Dependencies
#
find_package(LibSSH2 REQUIRED)

#
# Sources
#
set(SOURCE_FILES
    src/libsshtunnel.c
)

set(HEADER_FILES
    include/libsshtunnel.h
)

#
# Build config
#
if(UNIX)
    add_definitions(-DUNIX)
endif(UNIX)

if(WIN32)
    add_definitions(-DWIN32)
    set(WS_LIBRARY ws2_32)
endif(WIN32)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${LIBSSH2_INCLUDE_DIR})
add_library(sshtunnel ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(sshtunnel PRIVATE ${LIBSSH2_LIBRARY} ${WS_LIBRARY})


#
# Install
#
# Install built targets
install(TARGETS sshtunnel
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
)

# Install headers
install(FILES ${HEADER_FILES} DESTINATION include)
