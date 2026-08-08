#include "auth_signing.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "dict_cdb.h"
#include "logmsg.h"
#include "redis.h"

const char* opt_auth_signing_table = NULL;
int         opt_redis_auth_signing_table = 0;

struct DICT dict_auth_signingtable = {
    "authsigningtable",  /* name       */
    DICT_FLAG_TRY0NULL,  /* flags      */
    -1,                  /* stat_fd    */
    0,                   /* mtime      */
    CDB_STATIC_INIT,     /* cdb        */
    NULL,                /* buffer     */
    NULL                 /* cdb_path   */
};

int auth_signing_authorized(const char* auth_identity, const char* signer_identity) {

    char signer_norm[DICT_BUFFER_LEN];
    int  rc;

    /*
     * Signing is a privileged operation and must be bound to a trustworthy
     * authenticated principal.  Without an authorization table, no signer is
     * permitted (CWE-862).
     */
    if (opt_auth_signing_table == NULL && !opt_redis_auth_signing_table)
        return 0;

    if (auth_identity == NULL || *auth_identity == '\0' ||
        signer_identity == NULL || *signer_identity == '\0')
        return 0;

    /*
     * The authenticated identity is an opaque SASL principal: do not normalize
     * it.  The signer identity is an RFC 5321 address and is normalized
     * (lowercase, strip angle brackets).  Fail closed on overflow.
     */
    if (!normalize_address_safe(signer_identity, signer_norm, sizeof(signer_norm))) {
        logmsg(LOG_ERR, "auth_signing_authorized: signer identity too long or invalid: '%s'",
               signer_identity);
        return -1;
    }

    if (signer_norm[0] == '\0' || strcmp(signer_norm, "<>") == 0)
        return 0;

    if (opt_auth_signing_table != NULL) {
        rc = dict_reload(&dict_auth_signingtable);
        if (rc < 0) {
            logmsg(LOG_ERR, "auth_signing_authorized: auth table reload failed");
            return -1;
        }

        rc = dict_auth_signing_lookup(&dict_auth_signingtable, auth_identity, signer_norm);
        if (rc == 1)
            logmsg(LOG_DEBUG, "authenticated identity '%s' is authorized for signer '%s'",
                   auth_identity, signer_norm);
        else if (rc == 0)
            logmsg(LOG_INFO, "authenticated identity '%s' is not authorized for signer '%s'",
                   auth_identity, signer_norm);
        return rc;
    }

    if (opt_redis_auth_signing_table) {
        rc = redis_auth_signing_lookup(auth_identity, signer_norm);
        if (rc == 1)
            logmsg(LOG_DEBUG, "authenticated identity '%s' is authorized for signer '%s' (redis)",
                   auth_identity, signer_norm);
        else if (rc == 0)
            logmsg(LOG_INFO, "authenticated identity '%s' is not authorized for signer '%s' (redis)",
                   auth_identity, signer_norm);
        return rc;
    }

    return 0;
}
