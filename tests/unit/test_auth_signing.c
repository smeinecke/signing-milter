/*
 * signing-milter - tests/unit/test_auth_signing.c
 * Unit tests for auth_signing_authorized() and the CDB multi-value lookup.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <cdb.h>

#include "auth_signing.h"
#include "address.h"
#include "dict_cdb.h"

static int create_auth_cdb(const char* path, ...) {

    int             fd;
    struct cdb_make cdbm;
    const char*     key;
    const char*     val;
    va_list         ap;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;

    if (cdb_make_start(&cdbm, fd) != 0) {
        close(fd);
        return -1;
    }

    va_start(ap, path);
    while ((key = va_arg(ap, const char*)) != NULL) {
        val = va_arg(ap, const char*);
        if (val == NULL)
            break;
        if (cdb_make_add(&cdbm, key, strlen(key), val, strlen(val)) != 0) {
            va_end(ap);
            cdb_make_finish(&cdbm);
            close(fd);
            return -1;
        }
    }
    va_end(ap);

    if (cdb_make_finish(&cdbm) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void test_no_auth_table_is_authorized(void** state) {

    (void) state;

    opt_auth_signing_table = NULL;
    opt_redis_auth_signing_table = 0;

    assert_int_equal(auth_signing_authorized("alice@example.org", "sender@example.com"), 1);
    assert_int_equal(auth_signing_authorized(NULL, "sender@example.com"), 1);
}

static void test_authorized_single_signer(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";

    assert_true(create_auth_cdb(path,
                                "alice", "sender@example.com",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    assert_int_equal(auth_signing_authorized("alice", "sender@example.com"), 1);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_multiple_signers_per_auth_identity(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";

    assert_true(create_auth_cdb(path,
                                "alice", "sender@example.com",
                                "alice", "sales@example.org",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    assert_int_equal(auth_signing_authorized("alice", "sender@example.com"), 1);
    assert_int_equal(auth_signing_authorized("alice", "sales@example.org"), 1);
    assert_int_equal(auth_signing_authorized("alice", "other@example.org"), 0);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_auth_identity_is_case_sensitive(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";

    assert_true(create_auth_cdb(path,
                                "alice", "sender@example.com",
                                "ALICE", "other@example.com",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    /* SASL login names are opaque and must be matched case-sensitively. */
    assert_int_equal(auth_signing_authorized("alice", "sender@example.com"), 1);
    assert_int_equal(auth_signing_authorized("ALICE", "other@example.com"), 1);
    assert_int_equal(auth_signing_authorized("ALICE", "sender@example.com"), 0);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_signer_address_is_normalized(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";

    assert_true(create_auth_cdb(path,
                                "bob", "<Sender@Example.COM>",
                                "case", "Sender@EXAMPLE.COM, sales@example.org",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    /* signer identities are normalized (lower case, <> stripped) */
    assert_int_equal(auth_signing_authorized("bob", "sender@example.com"), 1);
    assert_int_equal(auth_signing_authorized("bob", "<SENDER@EXAMPLE.COM>"), 1);
    assert_int_equal(auth_signing_authorized("case", "<sender@example.com>"), 1);
    assert_int_equal(auth_signing_authorized("case", "SALES@EXAMPLE.ORG"), 1);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_unauthorized_auth_identity(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";

    assert_true(create_auth_cdb(path,
                                "alice", "sender@example.com",
                                "bob", "other@example.com",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    /* bob is only authorized for other@example.com, not sender@example.com */
    assert_int_equal(auth_signing_authorized("bob", "sender@example.com"), 0);
    /* mallory is not present at all */
    assert_int_equal(auth_signing_authorized("mallory", "sender@example.com"), 0);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_missing_auth_identity_is_denied(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";

    assert_true(create_auth_cdb(path,
                                "alice", "sender@example.com",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    assert_int_equal(auth_signing_authorized(NULL, "sender@example.com"), 0);
    assert_int_equal(auth_signing_authorized("", "sender@example.com"), 0);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_oversized_identity_fails_closed(void** state) {

    (void) state;
    char path[] = "/tmp/signing-milter-test-auth-XXXXXX";
    char long_signer[1024];
    size_t i;

    for (i = 0; i < sizeof(long_signer) - 1; i++)
        long_signer[i] = 'a';
    long_signer[i] = '\0';

    assert_true(create_auth_cdb(path,
                                "alice", "sender@example.com",
                                NULL) == 0);

    opt_auth_signing_table = path;
    opt_redis_auth_signing_table = 0;
    dict_open(path, &dict_auth_signingtable);

    /* a signer that does not fit into the normalization buffer must fail closed */
    assert_int_equal(auth_signing_authorized("alice", long_signer), -1);

    dict_close(&dict_auth_signingtable);
    unlink(path);
}

static void test_normalize_address(void** state) {

    (void) state;
    char out[128];

    normalize_address("<Alice@Example.ORG>", out, sizeof(out));
    assert_string_equal(out, "alice@example.org");

    normalize_address("BOB@EXAMPLE.COM", out, sizeof(out));
    assert_string_equal(out, "bob@example.com");

    normalize_address("<>", out, sizeof(out));
    assert_string_equal(out, "<>");

    memset(out, 0, sizeof(out));
    normalize_address("", out, sizeof(out));
    assert_string_equal(out, "<>");
}

static void test_normalize_address_safe(void** state) {

    (void) state;
    char out[128];
    int  rc;

    rc = normalize_address_safe("<Alice@Example.ORG>", out, sizeof(out));
    assert_true(rc);
    assert_string_equal(out, "alice@example.org");

    rc = normalize_address_safe("BOB@EXAMPLE.COM", out, sizeof(out));
    assert_true(rc);
    assert_string_equal(out, "bob@example.com");

    rc = normalize_address_safe("<>", out, sizeof(out));
    assert_true(rc);
    assert_string_equal(out, "<>");

    rc = normalize_address_safe("", out, sizeof(out));
    assert_true(rc);
    assert_string_equal(out, "<>");

    /* an overlong identity must fail closed */
    {
        char long_addr[1024];
        size_t i;
        for (i = 0; i < sizeof(long_addr) - 1; i++)
            long_addr[i] = 'a';
        long_addr[i] = '\0';

        memset(out, 0, sizeof(out));
        rc = normalize_address_safe(long_addr, out, sizeof(out));
        assert_true(!rc);
        assert_string_equal(out, "");
    }
}

int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_no_auth_table_is_authorized),
        cmocka_unit_test(test_authorized_single_signer),
        cmocka_unit_test(test_multiple_signers_per_auth_identity),
        cmocka_unit_test(test_auth_identity_is_case_sensitive),
        cmocka_unit_test(test_signer_address_is_normalized),
        cmocka_unit_test(test_unauthorized_auth_identity),
        cmocka_unit_test(test_missing_auth_identity_is_denied),
        cmocka_unit_test(test_oversized_identity_fails_closed),
        cmocka_unit_test(test_normalize_address),
        cmocka_unit_test(test_normalize_address_safe),
    };

    return cmocka_run_group_tests_name("auth_signing", tests, NULL, NULL);
}
