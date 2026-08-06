#include "setup.h"

#include <unistd.h>

int ctxdata_setup(CTXDATA* ctxdata, const char* pemfilename) {

    int   pemfd = -1;
    int   chainfd = -1;
    char* chainfilename = NULL;
    const char* suffix;
    size_t len;
    size_t prefix_len;
    size_t chainfilename_len;

    assert(ctxdata != NULL);
    assert(pemfilename != NULL);

    if ((pemfd = validate_pem_permissions(pemfilename)) < 0)
        return(1);

    if ((ctxdata->pemfilename = strdup(pemfilename)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup: malloc for ctxdata.pemfilename failed: %m", strerror(errno));
        close(pemfd);
        return(2);
    }

    if ((ctxdata->cert = load_pem_cert(pemfd)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup: loading certificate %s failed", ctxdata->pemfilename);
        close(pemfd);
        return(3);
    }

    if (lseek(pemfd, 0, SEEK_SET) < 0) {
        logmsg(LOG_ERR, "error: ctxdata_setup: lseek on %s failed: %m", ctxdata->pemfilename, strerror(errno));
        close(pemfd);
        return(4);
    }

    if ((ctxdata->key = load_pem_key(pemfd, NULL)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup: loading key %s failed", ctxdata->pemfilename);
        close(pemfd);
        return(4);
    }

    close(pemfd);

    ctxdata->pkcs7flags = PKCS7_DETACHED | PKCS7_NOOLDMIMETYPE | PKCS7_STREAM | PKCS7_CRLFEOL;

    ctxdata->buffer_len = MAXHEADERLEN;
    if ((ctxdata->buffer = malloc(ctxdata->buffer_len)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup: allocation of %i byte (MAXHEADERLEN) for header failed", MAXHEADERLEN);
        return(5);
    }

    /*
     * Only load chain certificates if the file name ends with "cert+key.pem".
     * The chain file name is the same prefix with "chain.pem" appended.
     */
    len = strlen(ctxdata->pemfilename);
    if (len < 12 ||
        (suffix = strstr(ctxdata->pemfilename, "cert+key.pem")) == NULL ||
        suffix != ctxdata->pemfilename + len - 12) {
        logmsg(LOG_DEBUG, "info: certificate file not named /path/to/foo-cert+key.pem, including chaincerts disabled");
        return(0);
    }

    prefix_len = len - 12;
    chainfilename_len = prefix_len + 9 + 1;

    if ((chainfilename = malloc(chainfilename_len)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup: malloc for chainfilename failed: %m", strerror(errno));
        return(6);
    }

    snprintf(chainfilename, chainfilename_len, "%.*schain.pem", (int) prefix_len, ctxdata->pemfilename);

    if ((chainfd = open_and_validate_pem(chainfilename, 1)) >= 0) {
        ctxdata->chain = load_pem_chain(chainfd);
        close(chainfd);
        logmsg(LOG_INFO, "info: %schaincerts loaded from %s", ctxdata->chain != NULL ? "" : "no ", chainfilename);
    } else {
        logmsg(LOG_INFO, "info: no chaincerts loaded from %s", chainfilename);
    }

    free(chainfilename);

    return(0);
}

int ctxdata_setup_from_redis(CTXDATA* ctxdata, const char* redis_key, char* pem, size_t pem_len, char* chain, size_t chain_len, const char* passphrase) {

    X509*           cert = NULL;
    EVP_PKEY*       key = NULL;
    STACK_OF(X509)* chainstack = NULL;
    int             rc = 0;

    assert(ctxdata != NULL);
    assert(redis_key != NULL);
    assert(pem != NULL);
    assert(pem_len > 0);

    cert = load_pem_cert_mem(pem, pem_len);
    if (cert == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_redis: loading certificate for %s failed", redis_key);
        rc = 3;
        goto cleanup;
    }

    key = load_pem_key_mem(pem, pem_len, passphrase);
    if (key == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_redis: loading key for %s failed", redis_key);
        rc = 4;
        goto cleanup;
    }

    if (chain != NULL && chain_len > 0) {
        chainstack = load_pem_chain_mem(chain, chain_len);
        logmsg(LOG_INFO, "info: %schaincerts loaded from redis for %s",
               chainstack != NULL ? "" : "no ", redis_key);
    } else {
        logmsg(LOG_INFO, "info: no chaincerts from redis for %s", redis_key);
    }

    if ((ctxdata->pemfilename = strdup(redis_key)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_redis: malloc for ctxdata.pemfilename failed: %s", strerror(errno));
        rc = 2;
        goto cleanup;
    }

    ctxdata->cert = cert;
    ctxdata->key = key;
    ctxdata->chain = chainstack;
    cert = NULL;
    key = NULL;
    chainstack = NULL;

    ctxdata->pkcs7flags = PKCS7_DETACHED | PKCS7_NOOLDMIMETYPE | PKCS7_STREAM | PKCS7_CRLFEOL;

    ctxdata->buffer_len = MAXHEADERLEN;
    if ((ctxdata->buffer = malloc(ctxdata->buffer_len)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_redis: allocation of %i byte (MAXHEADERLEN) for header failed", MAXHEADERLEN);
        rc = 5;
        goto cleanup;
    }

cleanup:
    if (cert != NULL)
        X509_free(cert);
    if (key != NULL)
        EVP_PKEY_free(key);
    if (chainstack != NULL)
        sk_X509_pop_free(chainstack, X509_free);
    free(pem);
    free(chain);

    return rc;
}
