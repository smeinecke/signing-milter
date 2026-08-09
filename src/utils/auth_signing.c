#include "auth_signing.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/asn1.h>

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

int auth_signing_has_explicit_backend(void) {
    return (opt_auth_signing_table != NULL || opt_redis_auth_signing_table);
}

/*
 * Extract the subject Common Name from a certificate.  The extraction fails
 * unless the subject contains exactly one CN attribute, the CN can be
 * converted to a safe UTF-8 string, it does not contain an embedded NUL, and
 * it fits into the caller's buffer.  The returned CN is a NUL-terminated
 * opaque string.
 *
 * Returns 1 on success, -1 on any parsing error or malformed CN.
 */
static int extract_subject_cn(const X509* cert, char* out, size_t out_len) {

    X509_NAME*        subject;
    int               idx;
    int               last = -1;
    int               count = 0;
    X509_NAME_ENTRY*  entry;
    ASN1_STRING*      asn1;
    unsigned char*    utf8 = NULL;
    int               len;
    int               rc = -1;

    if (cert == NULL || out == NULL || out_len == 0)
        return -1;

    subject = X509_get_subject_name((X509*) cert);
    if (subject == NULL)
        return -1;

    /* Require exactly one CN.  More or less is ambiguous. */
    for (;;) {
        idx = X509_NAME_get_index_by_NID(subject, NID_commonName, last);
        if (idx < 0)
            break;
        last = idx;
        count++;
        if (count > 1) {
            logmsg(LOG_INFO, "auth_signing: certificate has multiple Common Name attributes");
            return -1;
        }
    }

    if (count != 1) {
        logmsg(LOG_INFO, "auth_signing: certificate has no Common Name attribute");
        return -1;
    }

    idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0)
        return -1;

    entry = X509_NAME_get_entry(subject, idx);
    if (entry == NULL)
        return -1;

    asn1 = X509_NAME_ENTRY_get_data(entry);
    if (asn1 == NULL)
        return -1;

    len = ASN1_STRING_to_UTF8(&utf8, asn1);
    if (len < 0) {
        logmsg(LOG_INFO, "auth_signing: cannot decode certificate Common Name");
        return -1;
    }

    if ((size_t) len >= out_len) {
        logmsg(LOG_INFO, "auth_signing: certificate Common Name is too long");
        goto out;
    }

    if (memchr(utf8, '\0', (size_t) len) != NULL) {
        logmsg(LOG_INFO, "auth_signing: certificate Common Name contains embedded NUL");
        goto out;
    }

    memcpy(out, utf8, (size_t) len);
    out[len] = '\0';
    rc = 1;

out:
    if (utf8 != NULL)
        OPENSSL_free(utf8);
    return rc;
}

/*
 * Certificate-CN fallback authorization.  The certificate must contain
 * exactly one subject CN and it must match auth_identity exactly.
 */
static int auth_signing_cert_authorized(const char* auth_identity, const X509* cert) {

    char cn[AUTH_CERT_CN_MAX_LEN];

    if (auth_identity == NULL || *auth_identity == '\0')
        return 0;

    if (cert == NULL)
        return 0;

    if (extract_subject_cn(cert, cn, sizeof(cn)) != 1)
        return -1;

    if (strcmp(auth_identity, cn) != 0) {
        logmsg(LOG_INFO, "auth_signing: certificate CN '%s' does not match authenticated identity '%s'",
               cn, auth_identity);
        return 0;
    }

    logmsg(LOG_DEBUG, "auth_signing: certificate CN '%s' matches authenticated identity '%s'",
           cn, auth_identity);
    return 1;
}

int auth_signing_authorized(const char* auth_identity, const char* signer_identity, const X509* signer_cert) {

    char signer_norm[DICT_BUFFER_LEN];
    int  rc;

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

    /*
     * No explicit auth-signing backend is configured.  Fall back to
     * certificate-CN authorization.  signer_cert must have been resolved
     * before the private key is loaded.
     */
    return auth_signing_cert_authorized(auth_identity, signer_cert);
}
