/*
 * signing-milter - tests/unit/test_stubs.c
 * Stubs for globals and logging so individual source files can be unit-tested
 * without linking the full executable.
 */

#include <stdarg.h>
#include <stdlib.h>

#include "signing-milter.h"
#include "utils.h"

/* Global log settings used by logmsg() in the source files under test. */
int opt_loglevel = LOG_NOTICE;
int opt_logdest  = LOG_DEST_STDOUT;

/* Redis configuration globals referenced by redis.c. */
const char* opt_redis_uri = NULL;
const char* opt_redis_prefix = "signing-milter:";
const char* opt_redis_passphrase = NULL;
char*       opt_redis_username = NULL;
char*       opt_redis_password = NULL;

/* Global dictionaries referenced by dict_cdb.c. */
struct DICT dict_signingtable = {
    "signingtable",
    DICT_FLAG_TRY0NULL,
    0,
    0,
    CDB_STATIC_INIT,
    NULL,
    NULL
};

struct DICT dict_modetable = {
    "modetable",
    DICT_FLAG_TRY0NULL,
    0,
    0,
    CDB_STATIC_INIT,
    NULL,
    NULL
};

/* Silent logmsg() for unit tests. */
void deletechain(NODE* node) {
    (void) node;
}

void logmsg(int priority, const char* fmt, ...) {
    (void) priority;
    (void) fmt;
    /* no-op: unit tests must not depend on syslog or stdout. */
}
