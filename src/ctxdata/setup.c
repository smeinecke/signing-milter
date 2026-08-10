#include "setup.h"

#include <unistd.h>

int ctxdata_setup(CTXDATA* ctxdata, const char* pemfilename) {

    int pemfd;

    assert(ctxdata != NULL);
    assert(pemfilename != NULL);

    if ((pemfd = validate_pem_permissions(pemfilename)) < 0)
        return(1);

    return ctxdata_setup_from_fd(ctxdata, pemfilename, pemfd);
}

int ctxdata_setup_from_fd(CTXDATA* ctxdata, const char* pemfilename, int pemfd) {

    int            chainfd = -1;
    char*          chainfilename = NULL;
    const char*    suffix;
    size_t         len;
    size_t         prefix_len;
    size_t         chainfilename_len;

    X509*          cert = NULL;
    EVP_PKEY*      key = NULL;
    STACK_OF(X509)* chain = NULL;
    char*          pemcopy = NULL;
    unsigned char* buffer = NULL;

    assert(ctxdata != NULL);
    assert(pemfilename != NULL);
    assert(pemfd >= 0);

    if ((pemcopy = strdup(pemfilename)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: malloc for ctxdata.pemfilename failed: %m", strerror(errno));
        close(pemfd);
        return(2);
    }

    if (lseek(pemfd, 0, SEEK_SET) < 0) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: lseek on %s failed: %m", pemcopy, strerror(errno));
        close(pemfd);
        free(pemcopy);
        return(4);
    }

    if ((cert = load_pem_cert(pemfd)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: loading certificate %s failed", pemcopy);
        close(pemfd);
        free(pemcopy);
        return(3);
    }

    if (lseek(pemfd, 0, SEEK_SET) < 0) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: lseek on %s failed: %m", pemcopy, strerror(errno));
        close(pemfd);
        X509_free(cert);
        free(pemcopy);
        return(4);
    }

    if ((key = load_pem_key(pemfd, NULL)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: loading key %s failed", pemcopy);
        close(pemfd);
        X509_free(cert);
        free(pemcopy);
        return(4);
    }

    if (X509_check_private_key(cert, key) == 0) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: certificate and private key in %s do not match", pemcopy);
        close(pemfd);
        X509_free(cert);
        EVP_PKEY_free(key);
        free(pemcopy);
        return(7);
    }

    close(pemfd);
    pemfd = -1;

    if ((buffer = malloc(MAXHEADERLEN)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: allocation of %i byte (MAXHEADERLEN) for header failed", MAXHEADERLEN);
        X509_free(cert);
        EVP_PKEY_free(key);
        free(pemcopy);
        return(5);
    }

    /*
     * Only load chain certificates if the file name ends with "cert+key.pem".
     * The chain file name is the same prefix with "chain.pem" appended.
     */
    len = strlen(pemcopy);
    if (len >= 12 &&
        (suffix = strstr(pemcopy, "cert+key.pem")) != NULL &&
        suffix == pemcopy + len - 12) {

        prefix_len = len - 12;
        chainfilename_len = prefix_len + 9 + 1;

        if ((chainfilename = malloc(chainfilename_len)) == NULL) {
            logmsg(LOG_ERR, "error: ctxdata_setup_from_fd: malloc for chainfilename failed: %m", strerror(errno));
            free(buffer);
            X509_free(cert);
            EVP_PKEY_free(key);
            free(pemcopy);
            return(6);
        }

        snprintf(chainfilename, chainfilename_len, "%.*schain.pem", (int) prefix_len, pemcopy);

        if ((chainfd = open_and_validate_pem(chainfilename, 1)) >= 0) {
            chain = load_pem_chain(chainfd);
            close(chainfd);
            logmsg(LOG_INFO, "info: %schaincerts loaded from %s", chain != NULL ? "" : "no ", chainfilename);
        } else {
            logmsg(LOG_INFO, "info: no chaincerts loaded from %s", chainfilename);
        }

        free(chainfilename);
    } else {
        logmsg(LOG_DEBUG, "info: certificate file not named /path/to/foo-cert+key.pem, including chaincerts disabled");
    }

    /*
     * Any previously-loaded envelope signing material is replaced only after
     * the new signer identity has been fully loaded.  This keeps a rejected or
     * unusable X-Signer from suppressing an already-authorized envelope signer
     * (CWE-807).
     */
    ctxdata_reset_cert(ctxdata);

    /* transfer ownership only when everything else succeeded */
    ctxdata->pemfilename = pemcopy;
    ctxdata->cert = cert;
    ctxdata->key = key;
    ctxdata->chain = chain;
    ctxdata->buffer = buffer;
    ctxdata->buffer_len = MAXHEADERLEN;
    ctxdata->pkcs7flags = PKCS7_DETACHED | PKCS7_NOOLDMIMETYPE | PKCS7_STREAM | PKCS7_CRLFEOL;

    return(0);
}

int ctxdata_setup_from_redis(CTXDATA* ctxdata, const char* redis_key, char* pem, size_t pem_len, char* chain, size_t chain_len, const char* passphrase) {

    X509*           cert = NULL;
    EVP_PKEY*       key = NULL;
    STACK_OF(X509)* chainstack = NULL;
    char*           pemcopy = NULL;
    unsigned char*  buffer = NULL;
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

    if ((pemcopy = strdup(redis_key)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_redis: malloc for ctxdata.pemfilename failed: %s", strerror(errno));
        rc = 2;
        goto cleanup;
    }

    if ((buffer = malloc(MAXHEADERLEN)) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_setup_from_redis: allocation of %i byte (MAXHEADERLEN) for header failed", MAXHEADERLEN);
        rc = 5;
        goto cleanup;
    }

    /*
     * Any previously-loaded envelope signing material is replaced only after
     * the new signer identity has been fully loaded.  This keeps a rejected or
     * unusable X-Signer from suppressing an already-authorized envelope signer
     * (CWE-807).
     */
    ctxdata_reset_cert(ctxdata);

    /* transfer ownership only when all allocations succeeded */
    ctxdata->pemfilename = pemcopy;
    pemcopy = NULL;
    ctxdata->cert = cert;
    cert = NULL;
    ctxdata->key = key;
    key = NULL;
    ctxdata->chain = chainstack;
    chainstack = NULL;
    ctxdata->buffer = buffer;
    buffer = NULL;
    ctxdata->buffer_len = MAXHEADERLEN;
    ctxdata->pkcs7flags = PKCS7_DETACHED | PKCS7_NOOLDMIMETYPE | PKCS7_STREAM | PKCS7_CRLFEOL;

cleanup:
    if (cert != NULL)
        X509_free(cert);
    if (key != NULL)
        EVP_PKEY_free(key);
    if (chainstack != NULL)
        sk_X509_pop_free(chainstack, X509_free);
    free(pemcopy);
    free(buffer);
    free(pem);
    free(chain);

    return rc;
}
