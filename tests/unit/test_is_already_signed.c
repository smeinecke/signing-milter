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

static void test_already_signed_mixed_case(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("Content-Type",
        "Multipart/Signed; Protocol=\"application/PKCS7-Signature\"; micalg=sha256"), 1);
    assert_int_equal(is_already_signed("CONTENT-TYPE",
        "MULTIPART/SIGNED; PROTOCOL=\"APPLICATION/PKCS7-SIGNATURE\""), 1);
}

static void test_folded_whitespace(void** state) {
    (void) state;
    /* RFC 822/2822 folded header: CRLF followed by WSP must not loop */
    assert_int_equal(is_already_signed("content-type",
        "multipart/signed;\r\n protocol=\"application/pkcs7-signature\"; micalg=sha256"), 1);
    assert_int_equal(is_already_signed("content-type",
        "multipart/signed;\r\n boundary=\"foo\""), 0);
}

static void test_embedded_substring(void** state) {
    (void) state;
    assert_int_equal(is_already_signed("content-type",
        "text/plain; comment=\"multipart/signed; protocol=application/pkcs7-signature\""), 0);
    assert_int_equal(is_already_signed("content-type",
        "multipart/signed; boundary=\"application/pkcs7-signature\""), 0);
    assert_int_equal(is_already_signed("content-type",
        "multipart/mixed; boundary=\"multipart/signed; protocol=application/pkcs7-signature\""), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_already_signed_pkcs7),
        cmocka_unit_test(test_not_signed_content_type),
        cmocka_unit_test(test_wrong_protocol),
        cmocka_unit_test(test_not_content_type),
        cmocka_unit_test(test_missing_pkcs7_signature),
        cmocka_unit_test(test_already_signed_mixed_case),
        cmocka_unit_test(test_folded_whitespace),
        cmocka_unit_test(test_embedded_substring),
    };
    return cmocka_run_group_tests_name("is_already_signed", tests, NULL, NULL);
}
