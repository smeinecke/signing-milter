/*
 * signing-milter - tests/unit/test_is_multipart_mime.c
 * Unit tests for utils/is_multipart_mime.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "is_multipart_mime.h"

static void test_multipart_mixed(void** state) {
    (void) state;
    assert_int_equal(is_multipart_mime("content-type", "multipart/mixed; boundary=foo"), 1);
}

static void test_multipart_alternative(void** state) {
    (void) state;
    assert_int_equal(is_multipart_mime("Content-Type", "multipart/alternative"), 1);
}

static void test_not_content_type(void** state) {
    (void) state;
    assert_int_equal(is_multipart_mime("subject", "multipart/mixed"), 0);
}

static void test_not_multipart(void** state) {
    (void) state;
    assert_int_equal(is_multipart_mime("content-type", "text/plain"), 0);
}

static void test_signed_is_not_multipart(void** state) {
    (void) state;
    assert_int_equal(is_multipart_mime("content-type", "multipart/signed; protocol=\"application/pkcs7-signature\""), 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_multipart_mixed),
        cmocka_unit_test(test_multipart_alternative),
        cmocka_unit_test(test_not_content_type),
        cmocka_unit_test(test_not_multipart),
        cmocka_unit_test(test_signed_is_not_multipart),
    };
    return cmocka_run_group_tests_name("is_multipart_mime", tests, NULL, NULL);
}
