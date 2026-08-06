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
    char empty[] = "";
    char* headerf = NULL;
    assert_ptr_equal(separate_header(NULL, &headerf), NULL);
    assert_ptr_equal(separate_header(empty, &headerf), NULL);
}

static void test_no_colon(void** state) {
    (void) state;
    char line[] = "No colon here";
    char* headerf = NULL;
    assert_ptr_equal(separate_header(line, &headerf), NULL);
}

static void test_only_colon(void** state) {
    (void) state;
    char line[] = "X:";
    char* headerf = NULL;
    char* headerv = separate_header(line, &headerf);

    assert_non_null(headerv);
    assert_string_equal(headerf, "X");
    assert_string_equal(headerv, "");
    free(headerv);
}

static void test_overlong_no_terminator(void** state) {
    (void) state;
    char line[MAXHEADERLEN + 32];
    memset(line, 'A', sizeof(line));
    line[0] = 'X';
    line[1] = ':';
    line[sizeof(line) - 1] = '\0';

    char* headerf = NULL;
    char* headerv = separate_header(line, &headerf);

    assert_non_null(headerv);
    assert_string_equal(headerf, "X");
    assert_int_equal(strlen(headerv), MAXHEADERLEN - 1);
    assert_int_equal(headerv[0], 'A');
    free(headerv);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic),
        cmocka_unit_test(test_with_leading_space),
        cmocka_unit_test(test_lf_only),
        cmocka_unit_test(test_empty_line),
        cmocka_unit_test(test_no_colon),
        cmocka_unit_test(test_only_colon),
        cmocka_unit_test(test_overlong_no_terminator),
    };
    return cmocka_run_group_tests_name("separate_header", tests, NULL, NULL);
}
