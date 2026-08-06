/*
 * signing-milter - tests/unit/test_dict_cdb.c
 * Unit tests for utils/dict_cdb.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
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

    const char* result = dict_lookup(&dict, "<sender@example.com>");
    assert_string_equal(result, "/etc/signing-milter/test.pem");

    result = dict_lookup(&dict, "<recipient@example.com>");
    assert_string_equal(result, "/etc/signing-milter/other.pem");

    result = dict_lookup(&dict, "<unknown@example.com>");
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

    const char* result = dict_lookup(&dict, "<SENDER@EXAMPLE.COM>");
    assert_string_equal(result, "/etc/signing-milter/test.pem");

    dict_close(&dict);
    unlink(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_open_lookup_close),
        cmocka_unit_test(test_lookup_lowercase),
    };
    return cmocka_run_group_tests_name("dict_cdb", tests, NULL, NULL);
}
