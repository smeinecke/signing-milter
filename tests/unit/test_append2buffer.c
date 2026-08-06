/*
 * signing-milter - tests/unit/test_append2buffer.c
 * Unit tests for utils/append2buffer.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "append2buffer.h"

static void test_append_to_empty(void** state) {
    (void) state;
    unsigned char* buf = NULL;
    size_t size = 0;

    assert_int_equal(append2buffer(&buf, &size, "hello", 5), 0);
    assert_int_equal(size, 5);
    assert_memory_equal(buf, "hello", 5);
    free(buf);
}

static void test_append_to_existing(void** state) {
    (void) state;
    unsigned char* buf = malloc(5);
    memcpy(buf, "hello", 5);
    size_t size = 5;

    assert_int_equal(append2buffer(&buf, &size, " world", 6), 0);
    assert_int_equal(size, 11);
    assert_memory_equal(buf, "hello world", 11);
    free(buf);
}

static void test_append_binary(void** state) {
    (void) state;
    unsigned char* buf = NULL;
    size_t size = 0;
    unsigned char data[] = { 0x00, 0x01, 0x02, 0x00, 0xff };

    assert_int_equal(append2buffer(&buf, &size, (char*) data, sizeof(data)), 0);
    assert_int_equal(size, sizeof(data));
    assert_memory_equal(buf, data, sizeof(data));
    free(buf);
}

static void test_append_zero_bytes(void** state) {
    (void) state;
    unsigned char* buf = malloc(5);
    memcpy(buf, "hello", 5);
    size_t size = 5;

    assert_int_equal(append2buffer(&buf, &size, "", 0), 0);
    assert_int_equal(size, 5);
    assert_memory_equal(buf, "hello", 5);
    free(buf);
}

static void test_append_overflow(void** state) {
    (void) state;
    unsigned char* buf = malloc(5);
    memcpy(buf, "hello", 5);
    size_t size = SIZE_MAX - 1;

    assert_int_equal(append2buffer(&buf, &size, "!!", 2), 1);
    assert_int_equal(size, SIZE_MAX - 1);
    assert_memory_equal(buf, "hello", 5);
    free(buf);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_append_to_empty),
        cmocka_unit_test(test_append_to_existing),
        cmocka_unit_test(test_append_binary),
        cmocka_unit_test(test_append_zero_bytes),
        cmocka_unit_test(test_append_overflow),
    };
    return cmocka_run_group_tests_name("append2buffer", tests, NULL, NULL);
}
