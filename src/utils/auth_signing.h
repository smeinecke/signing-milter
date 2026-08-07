#ifndef _AUTH_SIGNING_H_INCLUDED_
#define _AUTH_SIGNING_H_INCLUDED_

#include "../signing-milter.h"

/*
 * Path to the optional CDB auth-signing table.
 * When set, the authenticated SMTP identity must be authorized for the
 * selected signing identity before the message is signed.
 */
extern const char* opt_auth_signing_table;

/*
 * Enable the optional Redis-backed auth-signing table.
 * Requires a Redis URI configured with -r and uses the configured -P prefix
 * under the "auth:" sub-namespace.
 */
extern int opt_redis_auth_signing_table;

/* Global CDB auth-signing table, opened when -a is set. */
extern struct DICT dict_auth_signingtable;

/*
 * Check whether auth_identity is authorized to use signer_identity.
 *
 * Returns:
 *   1  - authorized (or no auth table configured)
 *   0  - not authorized
 *  -1  - lookup error (fails closed)
 */
extern int auth_signing_authorized(const char* auth_identity, const char* signer_identity);

#endif
