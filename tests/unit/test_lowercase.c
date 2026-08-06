/*
 * signing-milter - tests/unit/test_lowercase.c
 * Unit tests for utils/lowercase.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <string.h>

#include "lowercase.h"

static void test_lowercase_uppercase(void** state) {
    (void) state;
    char buf[] = "HELLO";
    assert_string_equal(lowercase(buf), "hello");
    assert_string_equal(buf, "hello");
}

static void test_lowercase_mixed(void** state) {
    (void) state;
    char buf[] = "HeLLo";
    assert_string_equal(lowercase(buf), "hello");
}

static void test_lowercase_no_change(void** state) {
    (void) state;
    char buf[] = "hello";
    assert_string_equal(lowercase(buf), "hello");
}

static void test_lowercase_non_alpha(void** state) {
    (void) state;
    char buf[] = "123 ABC!";
    assert_string_equal(lowercase(buf), "123 abc!");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lowercase_uppercase),
        cmocka_unit_test(test_lowercase_mixed),
        cmocka_unit_test(test_lowercase_no_change),
        cmocka_unit_test(test_lowercase_non_alpha),
    };
    return cmocka_run_group_tests_name("lowercase", tests, NULL, NULL);
}
