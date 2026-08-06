/*
 * signing-milter - tests/unit/test_validate_pem_permissions.c
 * Unit tests for utils/validate_pem_permissions.c
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"

static void test_valid_file(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-pem-XXXXXX";
    int fd = mkstemp(path);

    assert_true(fd >= 0);
    assert_int_equal(fchmod(fd, 0400), 0);
    close(fd);

    int vfd = validate_pem_permissions(path);
    assert_true(vfd >= 0);
    if (vfd >= 0)
        close(vfd);
    unlink(path);
}

static void test_missing_file(void** state) {
    (void) state;
    assert_int_equal(validate_pem_permissions("/tmp/signing-milter-test-pem-does-not-exist"), -1);
}

static void test_symlink_rejected(void** state) {
    (void) state;
    char target[] = "/tmp/signing-milter-test-pem-target-XXXXXX";
    char link[] = "/tmp/signing-milter-test-pem-link-XXXXXX";
    int fd = mkstemp(target);

    assert_true(fd >= 0);
    assert_int_equal(fchmod(fd, 0400), 0);
    close(fd);

    /* link must not exist, so use a path we own and can delete */
    (void) unlink(link);
    assert_int_equal(symlink(target, link), 0);

    assert_int_equal(validate_pem_permissions(link), -1);

    unlink(link);
    unlink(target);
}

static void test_other_readable_rejected(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-pem-XXXXXX";
    int fd = mkstemp(path);

    assert_true(fd >= 0);
    assert_int_equal(fchmod(fd, 0644), 0);
    close(fd);

    assert_int_equal(validate_pem_permissions(path), -1);
    unlink(path);
}

static void test_owner_writable_rejected(void** state) {
    (void) state;
    char path[] = "/tmp/signing-milter-test-pem-XXXXXX";
    int fd = mkstemp(path);

    assert_true(fd >= 0);
    assert_int_equal(fchmod(fd, 0600), 0);
    close(fd);

    assert_int_equal(validate_pem_permissions(path), -1);
    unlink(path);
}

static void test_optional_missing(void** state) {
    (void) state;
    /* open_and_validate_pem with optional=1 must return -1 but not log an error */
    assert_int_equal(open_and_validate_pem("/tmp/signing-milter-test-pem-does-not-exist", 1), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_file),
        cmocka_unit_test(test_missing_file),
        cmocka_unit_test(test_symlink_rejected),
        cmocka_unit_test(test_other_readable_rejected),
        cmocka_unit_test(test_owner_writable_rejected),
        cmocka_unit_test(test_optional_missing),
    };
    return cmocka_run_group_tests_name("validate_pem_permissions", tests, NULL, NULL);
}
