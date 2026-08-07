/*
 * signing-milter - tests/unit/test_dict_cdb.c
 * Unit tests for utils/dict_cdb.c
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

#include "dict_cdb.h"

static void test_open_lookup_close(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-cdb-XXXXXX";
    int fd = mkstemp(path);

    assert_true(fd >= 0);

    struct cdb_make cdbm;
    assert_int_equal(cdb_make_start(&cdbm, fd), 0);
    assert_int_equal(cdb_make_add(&cdbm, "sender@example.com", 18,
                                  "/etc/signing-milter/test.pem", 28), 0);
    assert_int_equal(cdb_make_add(&cdbm, "recipient@example.com", 21,
                                  "/etc/signing-milter/other.pem", 29), 0);
    assert_int_equal(cdb_make_finish(&cdbm), 0);
    close(fd);

    DICT dict;
    memset(&dict, 0, sizeof(dict));
    dict.name = "test";
    dict.flags = DICT_FLAG_TRY0NULL;

    dict_open(path, &dict);

    char result[DICT_BUFFER_LEN];
    int rc;

    rc = dict_lookup(&dict, "<sender@example.com>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "/etc/signing-milter/test.pem");

    rc = dict_lookup(&dict, "<recipient@example.com>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "/etc/signing-milter/other.pem");

    rc = dict_lookup(&dict, "<unknown@example.com>", result, sizeof(result));
    assert_int_equal(rc, 0);
    assert_string_equal(result, "");

    dict_close(&dict);
    unlink(path);
}

static void test_lookup_lowercase(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-cdb-XXXXXX";
    int fd = mkstemp(path);

    assert_true(fd >= 0);

    struct cdb_make cdbm;
    assert_int_equal(cdb_make_start(&cdbm, fd), 0);
    assert_int_equal(cdb_make_add(&cdbm, "sender@example.com", 18,
                                  "/etc/signing-milter/test.pem", 28), 0);
    assert_int_equal(cdb_make_finish(&cdbm), 0);
    close(fd);

    DICT dict;
    memset(&dict, 0, sizeof(dict));
    dict.name = "test";
    dict.flags = DICT_FLAG_TRY0NULL;

    dict_open(path, &dict);

    char result[DICT_BUFFER_LEN];
    int rc;

    rc = dict_lookup(&dict, "<SENDER@EXAMPLE.COM>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "/etc/signing-milter/test.pem");

    dict_close(&dict);
    unlink(path);
}

static void test_dict_reload(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-cdb-XXXXXX";
    char path2[] = "/tmp/signing-milter-test-cdb-2-XXXXXX";
    int fd;
    int fd2;
    struct cdb_make cdbm;
    struct cdb_make cdbm2;
    DICT dict;
    char result[DICT_BUFFER_LEN];
    int rc;

    fd = mkstemp(path);
    assert_true(fd >= 0);

    assert_int_equal(cdb_make_start(&cdbm, fd), 0);
    assert_int_equal(cdb_make_add(&cdbm, "a", 1, "1", 1), 0);
    assert_int_equal(cdb_make_finish(&cdbm), 0);
    close(fd);

    memset(&dict, 0, sizeof(dict));
    dict.name = "test";
    dict.flags = DICT_FLAG_TRY0NULL;

    dict_open(path, &dict);

    rc = dict_lookup(&dict, "<a>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "1");

    fd2 = mkstemp(path2);
    assert_true(fd2 >= 0);

    assert_int_equal(cdb_make_start(&cdbm2, fd2), 0);
    assert_int_equal(cdb_make_add(&cdbm2, "a", 1, "2", 1), 0);
    assert_int_equal(cdb_make_finish(&cdbm2), 0);
    close(fd2);

    assert_int_equal(rename(path2, path), 0);
    dict_reload(&dict);

    rc = dict_lookup(&dict, "<a>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "2");

    dict_close(&dict);
    unlink(path);
}

static void test_lookup_short_and_malformed(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-cdb-3-XXXXXX";
    int fd = mkstemp(path);

    assert_true(fd >= 0);

    struct cdb_make cdbm;
    assert_int_equal(cdb_make_start(&cdbm, fd), 0);
    assert_int_equal(cdb_make_add(&cdbm, "a", 1, "1", 1), 0);
    assert_int_equal(cdb_make_add(&cdbm, "<>", 2, "empty", 5), 0);
    assert_int_equal(cdb_make_finish(&cdbm), 0);
    close(fd);

    DICT dict;
    memset(&dict, 0, sizeof(dict));
    dict.name = "test";
    dict.flags = DICT_FLAG_TRY0NULL;

    dict_open(path, &dict);

    char result[DICT_BUFFER_LEN];
    int rc;

    /* well-formed bracketed address */
    rc = dict_lookup(&dict, "<a>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "1");

    /* empty sender */
    rc = dict_lookup(&dict, "<>", result, sizeof(result));
    assert_int_equal(rc, 1);
    assert_string_equal(result, "empty");

    /* too short or malformed: must not underflow */
    rc = dict_lookup(&dict, "<", result, sizeof(result));
    assert_int_equal(rc, 0);
    assert_string_equal(result, "");

    rc = dict_lookup(&dict, "<a", result, sizeof(result));
    assert_int_equal(rc, 0);
    assert_string_equal(result, "");

    rc = dict_lookup(&dict, "<abc", result, sizeof(result));
    assert_int_equal(rc, 0);
    assert_string_equal(result, "");

    rc = dict_lookup(&dict, "abc>", result, sizeof(result));
    assert_int_equal(rc, 0);
    assert_string_equal(result, "");

    rc = dict_lookup(&dict, "<unknown@example.com>", result, sizeof(result));
    assert_int_equal(rc, 0);
    assert_string_equal(result, "");

    dict_close(&dict);
    unlink(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_open_lookup_close),
        cmocka_unit_test(test_lookup_lowercase),
        cmocka_unit_test(test_lookup_short_and_malformed),
        cmocka_unit_test(test_dict_reload),
    };
    return cmocka_run_group_tests_name("dict_cdb", tests, NULL, NULL);
}
