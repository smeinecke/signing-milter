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

/*
 * Require an authenticated SMTP/SASL identity.
 * When set (-A), or when an explicit auth-signing backend (-a/-R) is
 * configured, the milter only signs messages for authenticated identities.
 */
extern int opt_require_auth;

/* Global CDB auth-signing table, opened when -a is set. */
extern struct DICT dict_auth_signingtable;

/*
 * Maximum length of a Common Name extracted for certificate fallback
 * authorization (plus one byte for the terminating NUL).
 */
#define AUTH_CERT_CN_MAX_LEN 256

/*
 * Return 1 if an explicit auth-signing backend (CDB or Redis) is configured.
 */
extern int auth_signing_has_explicit_backend(void);

/*
 * Return 1 if the current configuration requires an authenticated SMTP/SASL
 * identity.  This is true when -A is set, or when an explicit auth-signing
 * backend (-a or -R) is configured.
 */
extern int auth_signing_required(void);

/*
 * Check whether auth_identity (opaque SASL principal) is authorized to use
 * signer_identity (RFC 5321 address).
 *
 * If an explicit auth-signing backend is configured (-a or -R), it is
 * authoritative and signer_cert is ignored.
 *
 * If no explicit backend is configured, certificate-CN fallback authorization
 * is used: signer_cert must be a valid certificate with exactly one subject
 * Common Name that matches auth_identity exactly (case-sensitive, opaque byte
 * comparison).  A NULL or unusable certificate results in denial.
 *
 * The signer identity is normalized internally; auth_identity is matched
 * case-sensitively.
 *
 * Returns:
 *   1  - authorized
 *   0  - not authorized
 *  -1  - lookup, parsing, or normalization error (fails closed)
 */
extern int auth_signing_authorized(const char* auth_identity, const char* signer_identity, const X509* signer_cert);

#endif
