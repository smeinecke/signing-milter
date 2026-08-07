/*
 * signing-milter - tests/unit/test_redis.c
 * Unit tests for Redis URI parsing and TLS option validation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <string.h>

#include "redis.h"

extern const char* opt_redis_uri;

static void test_plain_ipv6_uri(void** state) {
    (void) state;
    opt_redis_uri = "redis://[::1]:6379/0";
    assert_int_equal(redis_global_init(), 0);
    redis_global_cleanup();
}

static void test_plaintext_tls_params_rejected(void** state) {
    (void) state;
    opt_redis_uri = "redis://127.0.0.1:6379/0?verify=peer";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    opt_redis_uri = "redis://127.0.0.1:6379/0?cacert=/tmp/ca.pem";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    opt_redis_uri = "redis://127.0.0.1:6379/0?cert=/tmp/c.pem&key=/tmp/k.pem";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    opt_redis_uri = "redis://127.0.0.1:6379/0?sni=redis.example";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    opt_redis_uri = "redis://127.0.0.1:6379/0?verify_name=redis.example";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();
}

static void test_malformed_ipv6_rejected(void** state) {
    (void) state;
    /* missing closing bracket */
    opt_redis_uri = "rediss://[::1:6380/0?verify=none";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    /* junk after closing bracket before port */
    opt_redis_uri = "rediss://[::1]abc:6380/0?verify=none";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    /* non-numeric port */
    opt_redis_uri = "rediss://[::1]:abc/0?verify=none";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();
}

static void test_invalid_port_rejected(void** state) {
    (void) state;
    opt_redis_uri = "rediss://127.0.0.1:99999/0?verify=none";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();
}

static void test_cert_key_mismatch_rejected(void** state) {
    (void) state;
    /* cert without key */
    opt_redis_uri = "rediss://127.0.0.1:6380/0?cert=/tmp/client.pem";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    /* key without cert */
    opt_redis_uri = "rediss://127.0.0.1:6380/0?key=/tmp/client.key";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();
}

#ifdef WITH_REDIS_SSL
static void test_tls_ipv6_uri_verify_none(void** state) {
    (void) state;
    opt_redis_uri = "rediss://[2001:db8::1]:6380/0?verify=none";
    assert_int_equal(redis_global_init(), 0);
    redis_global_cleanup();
}

static void test_invalid_verify_mode_rejected(void** state) {
    (void) state;
    opt_redis_uri = "rediss://127.0.0.1:6380/0?verify=fail";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();

    opt_redis_uri = "rediss://127.0.0.1:6380/0?verify=strict";
    assert_int_equal(redis_global_init(), -1);
    redis_global_cleanup();
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_plain_ipv6_uri),
        cmocka_unit_test(test_plaintext_tls_params_rejected),
        cmocka_unit_test(test_malformed_ipv6_rejected),
        cmocka_unit_test(test_invalid_port_rejected),
        cmocka_unit_test(test_cert_key_mismatch_rejected),
#ifdef WITH_REDIS_SSL
        cmocka_unit_test(test_tls_ipv6_uri_verify_none),
        cmocka_unit_test(test_invalid_verify_mode_rejected),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
