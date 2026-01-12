#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
# - Try to find the libssh2 library
# Once done this will define
#
# Libssh2_FOUND - system has the libssh2 library
# Libssh2_INCLUDE_DIR - the libssh2 include directory
# Libssh2_LIBRARY - the libssh2 library name

find_path(Libssh2_INCLUDE_DIR libssh2.h)

find_library(Libssh2_LIBRARIES NAMES ssh2 libssh2)

if(Libssh2_INCLUDE_DIR)
  file(STRINGS "${Libssh2_INCLUDE_DIR}/libssh2.h" libssh2_version_str REGEX "^#define[\t ]+LIBSSH2_VERSION[\t ]+\"(.*)\"")
  string(REGEX REPLACE "^.*\"([^\"]+)\"" "\\1"  Libssh2_VERSION "${libssh2_version_str}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libssh2
    REQUIRED_VARS Libssh2_LIBRARIES Libssh2_INCLUDE_DIR
    VERSION_VAR Libssh2_VERSION)

mark_as_advanced(Libssh2_INCLUDE_DIR Libssh2_LIBRARIES)
