#
#  signing-milter - src/CMakeLists.txt
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

# ----------------------------------------------------------------------
# Source files
# ----------------------------------------------------------------------
set(MAIN_SOURCES
    main.c
    callbacks.c
    stats.c
)

set(CTXDATA_SOURCES
    ctxdata/cleanup.c
    ctxdata/create.c
    ctxdata/free.c
    ctxdata/setup.c
)

set(UTILS_SOURCES
    utils/address.c
    utils/append2buffer.c
    utils/auth_signing.c
    utils/bio2file.c
    utils/break_after_semicolon.c
    utils/delete_marked_headers.c
    utils/dict_cdb.c
    utils/dump_mailflags.c
    utils/dump_pkcs7flags.c
    utils/get_num_semicolons.c
    utils/hdrdup.c
    utils/headerchain2signingbuffer.c
    utils/is_already_signed.c
    utils/is_multipart_mime.c
    utils/linkedlist.c
    utils/load_pem.c
    utils/logmsg.c
    utils/lowercase.c
    utils/node.c
    utils/redis.c
    utils/separate_header.c
    utils/usage.c
    utils/validate_pem_permissions.c
)

# ----------------------------------------------------------------------
# Executable
# ----------------------------------------------------------------------
add_executable(signing-milter
    ${MAIN_SOURCES}
    ${CTXDATA_SOURCES}
    ${UTILS_SOURCES}
)

set_target_properties(signing-milter PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

target_include_directories(signing-milter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/ctxdata
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_BINARY_DIR}
    ${LIBCDB_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${LIBMILTER_INCLUDE_DIR}
)

target_compile_options(signing-milter PRIVATE
    ${LIBCDB_CFLAGS_OTHER}
    ${OPENSSL_CFLAGS_OTHER}
)

if(WITH_REDIS)
    target_include_directories(signing-milter PRIVATE ${HIREDIS_INCLUDE_DIRS})
    target_compile_options(signing-milter PRIVATE ${HIREDIS_CFLAGS_OTHER})
    target_link_libraries(signing-milter PRIVATE ${HIREDIS_LIBRARIES})
    if(WITH_REDIS_SSL AND HIREDIS_SSL_FOUND)
        target_include_directories(signing-milter PRIVATE ${HIREDIS_SSL_INCLUDE_DIRS})
        target_compile_options(signing-milter PRIVATE ${HIREDIS_SSL_CFLAGS_OTHER})
        target_link_libraries(signing-milter PRIVATE ${HIREDIS_SSL_LIBRARIES})
        target_compile_definitions(signing-milter PRIVATE WITH_REDIS_SSL)
    endif()
endif()

if(ENABLE_DMALLOC)
    target_compile_definitions(signing-milter PRIVATE DMALLOC)
    target_include_directories(signing-milter PRIVATE ${DMALLOC_INCLUDE_DIR})
    target_link_libraries(signing-milter PRIVATE ${DMALLOC_LIBRARY})
endif()

target_link_libraries(signing-milter PRIVATE
    ${LIBCDB_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${LIBMILTER_LIBRARY}
    Threads::Threads
)
