/*
 * signing-milter - tests/unit/test_separate_header.c
 * Unit tests for utils/separate_header.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "separate_header.h"

static void test_basic(void** state) {
    (void) state;
    char line[] = "Content-Type: text/plain\r\n";
    char* headerf = NULL;
    char* headerv = separate_header(line, &headerf);

    assert_non_null(headerv);
    assert_string_equal(headerf, "Content-Type");
    assert_string_equal(headerv, "text/plain");
    free(headerv);
}

static void test_with_leading_space(void** state) {
    (void) state;
    char line[] = "Content-Type:  text/plain\r\n";
    char* headerf = NULL;
    char* headerv = separate_header(line, &headerf);

    assert_non_null(headerv);
    assert_string_equal(headerf, "Content-Type");
    assert_string_equal(headerv, "text/plain");
    free(headerv);
}

static void test_lf_only(void** state) {
    (void) state;
    char line[] = "Subject: Hello\n";
    char* headerf = NULL;
    char* headerv = separate_header(line, &headerf);

    assert_non_null(headerv);
    assert_string_equal(headerf, "Subject");
    assert_string_equal(headerv, "Hello");
    free(headerv);
}

static void test_empty_line(void** state) {
    (void) state;
    char* headerf = NULL;
    assert_ptr_equal(separate_header(NULL, &headerf), NULL);
    assert_ptr_equal(separate_header("", &headerf), NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic),
        cmocka_unit_test(test_with_leading_space),
        cmocka_unit_test(test_lf_only),
        cmocka_unit_test(test_empty_line),
    };
    return cmocka_run_group_tests_name("separate_header", tests, NULL, NULL);
}
