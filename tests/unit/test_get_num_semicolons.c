/*
 * signing-milter - tests/unit/test_get_num_semicolons.c
 * Unit tests for utils/get_num_semicolons.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "get_num_semicolons.h"

static void test_zero(void** state) {
    (void) state;
    assert_int_equal(get_num_semicolons("text/plain"), 0);
}

static void test_one(void** state) {
    (void) state;
    assert_int_equal(get_num_semicolons("text/plain; charset=utf-8"), 1);
}

static void test_multiple(void** state) {
    (void) state;
    assert_int_equal(get_num_semicolons("a;b;c;d"), 3);
}

static void test_null(void** state) {
    (void) state;
    assert_int_equal(get_num_semicolons(NULL), -1);
}

static void test_empty(void** state) {
    (void) state;
    assert_int_equal(get_num_semicolons(""), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_zero),
        cmocka_unit_test(test_one),
        cmocka_unit_test(test_multiple),
        cmocka_unit_test(test_null),
        cmocka_unit_test(test_empty),
    };
    return cmocka_run_group_tests_name("get_num_semicolons", tests, NULL, NULL);
}
