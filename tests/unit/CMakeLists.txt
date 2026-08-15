# signing-milter - tests/unit/CMakeLists.txt

pkg_check_modules(CMOCKA REQUIRED cmocka)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/utils
    ${CMAKE_SOURCE_DIR}/src/ctxdata
    ${CMAKE_BINARY_DIR}
    ${CMOCKA_INCLUDE_DIRS}
)

if(WITH_REDIS)
    include_directories(${HIREDIS_INCLUDE_DIRS})
    if(WITH_REDIS_SSL AND HIREDIS_SSL_FOUND)
        include_directories(${HIREDIS_SSL_INCLUDE_DIRS})
    endif()
endif()

add_library(test_stubs OBJECT test_stubs.c)

# Helper to build a unit test against the source files it exercises.
function(add_unit_test TEST_NAME)
    set(SOURCES)
    foreach(SRC ${ARGN})
        if(IS_ABSOLUTE "${SRC}")
            list(APPEND SOURCES "${SRC}")
        else()
            list(APPEND SOURCES "${CMAKE_SOURCE_DIR}/${SRC}")
        endif()
    endforeach()

    add_executable(${TEST_NAME}
        ${TEST_NAME}.c
        ${SOURCES}
        $<TARGET_OBJECTS:test_stubs>
    )

    target_compile_options(${TEST_NAME} PRIVATE
        ${CMOCKA_CFLAGS_OTHER}
    )

    set(TEST_LINK_LIBRARIES
        ${CMOCKA_LIBRARIES}
        ${LIBCDB_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${LIBMILTER_LIBRARY}
        Threads::Threads
    )
    if(WITH_REDIS)
        list(APPEND TEST_LINK_LIBRARIES ${HIREDIS_LIBRARIES})
        if(WITH_REDIS_SSL AND HIREDIS_SSL_FOUND)
            list(APPEND TEST_LINK_LIBRARIES ${HIREDIS_SSL_LIBRARIES})
            target_compile_definitions(${TEST_NAME} PRIVATE WITH_REDIS_SSL)
        endif()
    endif()

    target_link_libraries(${TEST_NAME} PRIVATE ${TEST_LINK_LIBRARIES})

    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

add_unit_test(test_address                     src/utils/address.c)
add_unit_test(test_lowercase                   src/utils/lowercase.c)
add_unit_test(test_get_num_semicolons          src/utils/get_num_semicolons.c)
add_unit_test(test_is_multipart_mime           src/utils/is_multipart_mime.c)
add_unit_test(test_is_already_signed           src/utils/is_already_signed.c src/utils/lowercase.c)
add_unit_test(test_break_after_semicolon       src/utils/break_after_semicolon.c src/utils/get_num_semicolons.c)
add_unit_test(test_separate_header             src/utils/separate_header.c)
add_unit_test(test_append2buffer               src/utils/append2buffer.c)
add_unit_test(test_ctxdata                     src/ctxdata/create.c src/ctxdata/free.c src/ctxdata/cleanup.c)
add_unit_test(test_dict_cdb                    src/utils/dict_cdb.c src/utils/address.c src/utils/lowercase.c)
add_unit_test(test_auth_signing                src/utils/auth_signing.c src/utils/dict_cdb.c src/utils/address.c src/utils/redis.c src/utils/lowercase.c)
if(WITH_REDIS)
    add_unit_test(test_redis                       src/utils/redis.c src/utils/address.c src/utils/lowercase.c)
endif()
add_unit_test(test_validate_pem_permissions    src/utils/validate_pem_permissions.c)
