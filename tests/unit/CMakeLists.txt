# signing-milter - tests/unit/CMakeLists.txt

pkg_check_modules(CMOCKA REQUIRED cmocka)

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_SOURCE_DIR}/ctxdata
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

add_unit_test(test_lowercase                   utils/lowercase.c)
add_unit_test(test_get_num_semicolons          utils/get_num_semicolons.c)
add_unit_test(test_is_multipart_mime           utils/is_multipart_mime.c)
add_unit_test(test_is_already_signed           utils/is_already_signed.c)
add_unit_test(test_break_after_semicolon       utils/break_after_semicolon.c utils/get_num_semicolons.c)
add_unit_test(test_separate_header             utils/separate_header.c)
add_unit_test(test_append2buffer               utils/append2buffer.c)
add_unit_test(test_ctxdata                     ctxdata/create.c ctxdata/free.c ctxdata/cleanup.c)
add_unit_test(test_dict_cdb                    utils/dict_cdb.c utils/lowercase.c)
