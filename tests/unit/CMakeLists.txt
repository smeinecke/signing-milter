# signing-milter - tests/unit/CMakeLists.txt

pkg_check_modules(CMOCKA REQUIRED cmocka)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/utils
    ${CMAKE_SOURCE_DIR}/src/ctxdata
    ${CMAKE_BINARY_DIR}
    ${CMOCKA_INCLUDE_DIRS}
)

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

    target_link_libraries(${TEST_NAME} PRIVATE
        ${CMOCKA_LIBRARIES}
        ${LIBCDB_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${LIBMILTER_LIBRARY}
        Threads::Threads
    )

    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

add_unit_test(test_lowercase                   src/utils/lowercase.c)
add_unit_test(test_get_num_semicolons          src/utils/get_num_semicolons.c)
add_unit_test(test_is_multipart_mime           src/utils/is_multipart_mime.c)
add_unit_test(test_is_already_signed           src/utils/is_already_signed.c src/utils/lowercase.c)
add_unit_test(test_break_after_semicolon       src/utils/break_after_semicolon.c src/utils/get_num_semicolons.c)
add_unit_test(test_separate_header             src/utils/separate_header.c)
add_unit_test(test_append2buffer               src/utils/append2buffer.c)
add_unit_test(test_ctxdata                     src/ctxdata/create.c src/ctxdata/free.c src/ctxdata/cleanup.c)
add_unit_test(test_dict_cdb                    src/utils/dict_cdb.c src/utils/lowercase.c)
add_unit_test(test_validate_pem_permissions    src/utils/validate_pem_permissions.c)
