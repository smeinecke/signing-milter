#ifndef _DICT_CDB_H_INCLUDED_
#define _DICT_CDB_H_INCLUDED_

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

/*
 * Look up an authenticated identity in a CDB table and check whether it is
 * permitted to use the given signer identity.  Multiple records with the same
 * key are enumerated; a single record may contain a comma/whitespace-separated
 * list of permitted signer identities.  All lookups are case-insensitive and
 * strip surrounding angle brackets.
 *
 * Returns 1 if authorized, 0 if not, -1 on CDB read error.
 */
extern int dict_auth_signing_lookup(DICT* dict, const char* auth_raw, const char* signer_raw);

#endif
