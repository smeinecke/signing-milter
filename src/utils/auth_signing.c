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
    NULL,                /* result     */
    0,                   /* result_len */
    NULL                 /* cdb_path   */
};

int auth_signing_authorized(const char* auth_identity, const char* signer_identity) {

    char auth_norm[DICT_BUFFER_LEN];
    char signer_norm[DICT_BUFFER_LEN];
    int  rc;

    /*
     * If no authorization table is configured, signing is not restricted.
     */
    if (opt_auth_signing_table == NULL && !opt_redis_auth_signing_table)
        return 1;

    if (auth_identity == NULL || *auth_identity == '\0' ||
        signer_identity == NULL || *signer_identity == '\0')
        return 0;

    normalize_address(auth_identity, auth_norm, sizeof(auth_norm));
    normalize_address(signer_identity, signer_norm, sizeof(signer_norm));

    if (auth_norm[0] == '\0' || strcmp(auth_norm, "<>") == 0 ||
        signer_norm[0] == '\0' || strcmp(signer_norm, "<>") == 0)
        return 0;

    if (opt_auth_signing_table != NULL) {
        dict_reload(&dict_auth_signingtable);
        rc = dict_auth_signing_lookup(&dict_auth_signingtable, auth_norm, signer_norm);
        if (rc == 1)
            logmsg(LOG_DEBUG, "authenticated identity '%s' is authorized for signer '%s'",
                   auth_norm, signer_norm);
        else if (rc == 0)
            logmsg(LOG_INFO, "authenticated identity '%s' is not authorized for signer '%s'",
                   auth_norm, signer_norm);
        return rc;
    }

    if (opt_redis_auth_signing_table) {
        rc = redis_auth_signing_lookup(auth_norm, signer_norm);
        if (rc == 1)
            logmsg(LOG_DEBUG, "authenticated identity '%s' is authorized for signer '%s' (redis)",
                   auth_norm, signer_norm);
        else if (rc == 0)
            logmsg(LOG_INFO, "authenticated identity '%s' is not authorized for signer '%s' (redis)",
                   auth_norm, signer_norm);
        return rc;
    }

    return 0;
}
