/*
 * signing-milter - tests/unit/test_break_after_semicolon.c
 * Unit tests for utils/break_after_semicolon.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "break_after_semicolon.h"

static void test_no_semicolon_pre(void** state) {
    (void) state;
    char* s = strdup("text/plain");
    char* result = break_after_semicolon(s, PHASE_PRE_SIGN);
    assert_string_equal(result, "text/plain");
    assert_ptr_equal(result, s);
    free(result);
}

static void test_no_semicolon_post(void** state) {
    (void) state;
    char* s = strdup("text/plain");
    char* result = break_after_semicolon(s, PHASE_POST_SIGN);
    assert_string_equal(result, "text/plain");
    free(result);
}

static void test_one_semicolon_pre(void** state) {
    (void) state;
    char* s = strdup("text/plain; charset=\"utf-8\"");
    char* result = break_after_semicolon(s, PHASE_PRE_SIGN);
    assert_string_equal(result, "text/plain;\r\n charset=\"utf-8\"");
    free(result);
}

static void test_one_semicolon_post(void** state) {
    (void) state;
    char* s = strdup("text/plain; charset=\"utf-8\"");
    char* result = break_after_semicolon(s, PHASE_POST_SIGN);
    assert_string_equal(result, "text/plain;\n charset=\"utf-8\"");
    free(result);
}

static void test_multiple_semicolons(void** state) {
    (void) state;
    char* s = strdup("text/plain; charset=\"utf-8\"; name=\"foo\"");
    char* result = break_after_semicolon(s, PHASE_PRE_SIGN);
    assert_string_equal(result, "text/plain;\r\n charset=\"utf-8\";\r\n name=\"foo\"");
    free(result);
}

static void test_null_string(void** state) {
    (void) state;
    assert_ptr_equal(break_after_semicolon(NULL, PHASE_PRE_SIGN), NULL);
}

static void test_missing_space(void** state) {
    (void) state;
    char* s = strdup("text/plain;boundary=foo");
    char* result = break_after_semicolon(s, PHASE_PRE_SIGN);
    assert_string_equal(result, "text/plain;\r\n boundary=foo");
    free(result);
}

static void test_trailing_semicolon(void** state) {
    (void) state;
    char* s = strdup("text/plain;");
    char* result = break_after_semicolon(s, PHASE_POST_SIGN);
    assert_string_equal(result, "text/plain;\n ");
    free(result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_no_semicolon_pre),
        cmocka_unit_test(test_no_semicolon_post),
        cmocka_unit_test(test_one_semicolon_pre),
        cmocka_unit_test(test_one_semicolon_post),
        cmocka_unit_test(test_multiple_semicolons),
        cmocka_unit_test(test_null_string),
        cmocka_unit_test(test_missing_space),
        cmocka_unit_test(test_trailing_semicolon),
    };
    return cmocka_run_group_tests_name("break_after_semicolon", tests, NULL, NULL);
}
