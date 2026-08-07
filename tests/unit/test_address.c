/*
 * signing-milter - tests/unit/test_address.c
 * Unit tests for utils/address.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <string.h>

#include "address.h"

static void test_normalize_address_safe_basic(void** state) {
    (void) state;
    char out[256];

    assert_int_equal(normalize_address_safe("<Sender@EXAMPLE.COM>", out, sizeof(out)), 1);
    assert_string_equal(out, "sender@example.com");

    assert_int_equal(normalize_address_safe("sender@EXAMPLE.COM", out, sizeof(out)), 1);
    assert_string_equal(out, "sender@example.com");

    assert_int_equal(normalize_address_safe("<>", out, sizeof(out)), 1);
    assert_string_equal(out, "<>");

    assert_int_equal(normalize_address_safe("", out, sizeof(out)), 1);
    assert_string_equal(out, "<>");
}

static void test_normalize_address_safe_empty_sender(void** state) {
    (void) state;
    char out[256];

    assert_int_equal(normalize_address_safe("<>", out, sizeof(out)), 1);
    assert_string_equal(out, "<>");

    assert_int_equal(normalize_address_safe("", out, sizeof(out)), 1);
    assert_string_equal(out, "<>");
}

static void test_normalize_address_safe_oversize(void** state) {
    (void) state;
    char out[16];

    assert_int_equal(normalize_address_safe("<verylongaddress@example.com>", out, sizeof(out)), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_normalize_address_safe_basic),
        cmocka_unit_test(test_normalize_address_safe_empty_sender),
        cmocka_unit_test(test_normalize_address_safe_oversize),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
