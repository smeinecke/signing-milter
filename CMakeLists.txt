#
#  signing-milter - CMakeLists.txt
#  Copyright (C) 2010-2024  Andreas Schulze
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; only version 2 of the License is applicable.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Debian 10 (buster) ships CMake 3.13.4; 3.10 keeps us compatible
# with older backports while still providing modern targets.
cmake_minimum_required(VERSION 3.10)

project(signing-milter
    LANGUAGES C
    DESCRIPTION "Sign email via the milter protocol"
)

include(GNUInstallDirs)
include(FindPkgConfig)
include(CheckStructHasMember)

# ----------------------------------------------------------------------
# Version string -- derived from git tags so it is not stale on build.
# ----------------------------------------------------------------------
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()
if(NOT GIT_VERSION)
    set(GIT_VERSION "unknown")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(STR_PROGVERSION "${GIT_VERSION}-debug")
else()
    set(STR_PROGVERSION "${GIT_VERSION}")
endif()

# config.h generates the NDEBUG define, so avoid duplicating it
# from the default CMake build-type flags.
foreach(_flag_var
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL
        CMAKE_C_FLAGS_RELWITHDEBINFO)
    if(${_flag_var} MATCHES "-DNDEBUG")
        string(REGEX REPLACE "-DNDEBUG" "" ${_flag_var} "${${_flag_var}}")
    endif()
endforeach()

# ----------------------------------------------------------------------
# Options
# ----------------------------------------------------------------------
option(ENABLE_DMALLOC "Enable dmalloc memory debugging" OFF)
option(WITH_SYSTEMD  "Install the systemd service unit" ON)
option(WITH_CRON     "Install cron daily/hourly scripts" ON)
option(WITH_SUPERVISE "Install the daemontools supervise symlink" OFF)
option(WITH_EXAMPLES "Install the example /etc/signing-milter directory" ON)
option(WITH_REDIS    "Enable Redis-backed dynamic certificate lookup" ON)
option(WITH_REDIS_SSL "Enable Redis TLS (rediss://) support" ON)

# ----------------------------------------------------------------------
# Required dependencies
# ----------------------------------------------------------------------
pkg_check_modules(LIBCDB REQUIRED libcdb)
pkg_check_modules(OPENSSL REQUIRED openssl)

find_path(LIBMILTER_INCLUDE_DIR libmilter/mfapi.h)
find_library(LIBMILTER_LIBRARY NAMES milter
    PATHS /usr/lib /usr/lib64
          /usr/lib/x86_64-linux-gnu
          /usr/lib/aarch64-linux-gnu
)
if(NOT LIBMILTER_INCLUDE_DIR OR NOT LIBMILTER_LIBRARY)
    message(FATAL_ERROR "libmilter (mfapi.h / -lmilter) not found")
endif()

find_package(Threads REQUIRED)

# ----------------------------------------------------------------------
# Optional Redis client (hiredis) and TLS support (hiredis_ssl)
# ----------------------------------------------------------------------
if(WITH_REDIS)
    pkg_check_modules(HIREDIS hiredis)
    if(NOT HIREDIS_FOUND)
        message(FATAL_ERROR
            "WITH_REDIS is ON but hiredis was not found. "
            "Install libhiredis-dev or set -DWITH_REDIS=OFF")
    endif()
    if(WITH_REDIS_SSL)
        pkg_check_modules(HIREDIS_SSL hiredis_ssl)
        if(HIREDIS_SSL_FOUND)
            message(STATUS "hiredis_ssl found; rediss:// TLS support enabled")
        else()
            message(WARNING "hiredis_ssl not found; rediss:// TLS support disabled")
        endif()
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${HIREDIS_INCLUDE_DIRS})
    check_struct_has_member(redisReader maxelements hiredis/read.h
                            HAVE_REDISREADER_MAXELEMENTS)
    unset(CMAKE_REQUIRED_INCLUDES)
endif()

# ----------------------------------------------------------------------
# Optional dmalloc
# ----------------------------------------------------------------------
if(ENABLE_DMALLOC)
    find_path(DMALLOC_INCLUDE_DIR dmalloc.h)
    find_library(DMALLOC_LIBRARY NAMES dmalloc)
    if(NOT DMALLOC_INCLUDE_DIR OR NOT DMALLOC_LIBRARY)
        message(FATAL_ERROR "dmalloc requested but not found")
    endif()
endif()

# ----------------------------------------------------------------------
# Source files and executable are defined in src/CMakeLists.txt
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# config.h
# ----------------------------------------------------------------------
# Release / RelWithDebInfo / MinSizeRel and the Debian default
# CMAKE_BUILD_TYPE=None all keep NDEBUG defined.  Only a plain Debug
# build turns NDEBUG off so the version string gets the "-debug" suffix.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(NDEBUG "")
else()
    set(NDEBUG 1)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
    @ONLY
)

# ----------------------------------------------------------------------
# Executable
# ----------------------------------------------------------------------
add_subdirectory(src)

# ----------------------------------------------------------------------
# Unit tests (cmocka)
# ----------------------------------------------------------------------
enable_testing()

pkg_check_modules(CMOCKA cmocka)
if(CMOCKA_FOUND)
    add_subdirectory(tests/unit)
else()
    message(STATUS "cmocka not found; unit tests will not be built")
endif()

# ----------------------------------------------------------------------
# Custom check target
# ----------------------------------------------------------------------
add_custom_target(check
    COMMAND sh -c "cd ${CMAKE_CURRENT_SOURCE_DIR} && egrep -r 'strcpy|strcat|strtok|sprintf' src/*.c src/utils/*.c src/ctxdata/*.c && echo 'unsafe function used' || true"
    COMMENT "Checking for unsafe C functions"
    VERBATIM
)

# ----------------------------------------------------------------------
# Install paths
# ----------------------------------------------------------------------
if(CMAKE_INSTALL_PREFIX STREQUAL "/usr")
    # For system packages config/state must be outside /usr even when
    # a DESTDIR is used.
    set(SIGNING_MILTER_SYSCONFDIR "/etc")
    set(SIGNING_MILTER_LOCALSTATEDIR "/var")
else()
    # Keep local relocatable installs under the prefix.
    set(SIGNING_MILTER_SYSCONFDIR "${CMAKE_INSTALL_SYSCONFDIR}")
    set(SIGNING_MILTER_LOCALSTATEDIR "${CMAKE_INSTALL_LOCALSTATEDIR}")
endif()

set(SYSTEMD_UNIT_DIR "lib/systemd/system")

# Binary and man page
install(TARGETS signing-milter DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES docs/signing-milter.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)

# Default config file
install(FILES debian/signing-milter.default
    DESTINATION ${SIGNING_MILTER_SYSCONFDIR}/default
    RENAME signing-milter
)

# Run script used by the service and the supervise symlink
install(PROGRAMS run_signing-milter
    DESTINATION ${CMAKE_INSTALL_DATADIR}/signing-milter
)

# Cron scripts
if(WITH_CRON)
    install(PROGRAMS debian/signing-milter.cron.daily
        DESTINATION ${SIGNING_MILTER_SYSCONFDIR}/cron.daily
        RENAME signing-milter
    )
    install(PROGRAMS debian/signing-milter.cron.hourly
        DESTINATION ${SIGNING_MILTER_SYSCONFDIR}/cron.hourly
        RENAME signing-milter
    )
endif()

# systemd service
if(WITH_SYSTEMD)
    install(FILES debian/signing-milter.service
        DESTINATION ${SYSTEMD_UNIT_DIR}
    )
endif()

# Example /etc/signing-milter directory (signingtable, Makefile, certs)
if(WITH_EXAMPLES)
    install(DIRECTORY debian/etc/signing-milter
        DESTINATION ${SIGNING_MILTER_SYSCONFDIR}
    )
endif()

# Legacy daemontools supervise symlink
if(WITH_SUPERVISE)
    install(DIRECTORY
        DESTINATION ${SIGNING_MILTER_LOCALSTATEDIR}/lib/supervise/signing-milter
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        ../../../../usr/share/signing-milter/run_signing-milter
        ${SIGNING_MILTER_LOCALSTATEDIR}/lib/supervise/signing-milter/run
    )")
endif()
