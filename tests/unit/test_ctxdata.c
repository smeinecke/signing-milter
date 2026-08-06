/*
 * signing-milter - tests/unit/test_ctxdata.c
 * Unit tests for ctxdata create/free/cleanup
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "ctxdata.h"

static void test_create_and_free(void** state) {
    (void) state;
    CTXDATA* ctx = ctxdata_create();

    assert_non_null(ctx);
    assert_null(ctx->pemfilename);
    assert_null(ctx->headerchain);
    assert_null(ctx->data2sign);

    ctxdata_free(ctx);
}

static void test_cleanup_fresh(void** state) {
    (void) state;
    CTXDATA* ctx = ctxdata_create();

    assert_non_null(ctx);
    ctxdata_cleanup(ctx);
    ctxdata_free(ctx);
}

static void test_cleanup_with_buffer(void** state) {
    (void) state;
    CTXDATA* ctx = ctxdata_create();

    assert_non_null(ctx);
    ctx->buffer = malloc(32);
    assert_non_null(ctx->buffer);
    ctx->buffer_len = 32;

    ctxdata_cleanup(ctx);
    assert_null(ctx->buffer);
    ctxdata_free(ctx);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_and_free),
        cmocka_unit_test(test_cleanup_fresh),
        cmocka_unit_test(test_cleanup_with_buffer),
    };
    return cmocka_run_group_tests_name("ctxdata", tests, NULL, NULL);
}
