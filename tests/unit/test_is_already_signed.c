/*
 * signing-milter - tests/unit/test_is_already_signed.c
 * Unit tests for utils/is_already_signed.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "is_already_signed.h"

static void test_already_signed_pkcs7(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("content-type",
        "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha256"), 1);
}

static void test_not_signed_content_type(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("content-type", "text/plain"), 0);
}

static void test_wrong_protocol(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("content-type",
        "multipart/signed; protocol=\"application/pkcs7-mime\""), 0);
}

static void test_not_content_type(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("subject", "multipart/signed; pkcs7-signature"), 0);
}

static void test_missing_pkcs7_signature(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("content-type", "multipart/signed; protocol=\"application/pkcs7-signature\""), 1);
    assert_int_equal(is_already_signed("content-type", "multipart/signed"), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_already_signed_pkcs7),
        cmocka_unit_test(test_not_signed_content_type),
        cmocka_unit_test(test_wrong_protocol),
        cmocka_unit_test(test_not_content_type),
        cmocka_unit_test(test_missing_pkcs7_signature),
    };
    return cmocka_run_group_tests_name("is_already_signed", tests, NULL, NULL);
}
