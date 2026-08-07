#include "cleanup.h"

void ctxdata_reset_cert(CTXDATA* ctxdata) {

    assert(ctxdata != NULL);

    if (ctxdata->pemfilename != NULL) {
        free(ctxdata->pemfilename);
        ctxdata->pemfilename = NULL;
    }

    if (ctxdata->cert != NULL) {
        X509_free(ctxdata->cert);
        ctxdata->cert = NULL;
    }

    if (ctxdata->key != NULL) {
        EVP_PKEY_free(ctxdata->key);
        ctxdata->key = NULL;
    }

    if (ctxdata->chain != NULL) {
        sk_X509_pop_free(ctxdata->chain, X509_free);
        ctxdata->chain = NULL;
    }

    if (ctxdata->buffer != NULL) {
        free(ctxdata->buffer);
        ctxdata->buffer = NULL;
    }
}

void ctxdata_cleanup(CTXDATA* ctxdata) {

    assert(ctxdata != NULL);

    if (ctxdata->auth_identity != NULL) {
        free(ctxdata->auth_identity);
        ctxdata->auth_identity = NULL;
    }

    if (ctxdata->pemfilename != NULL)
        free(ctxdata->pemfilename);

    if (ctxdata->headerchain != NULL)
        deletechain(ctxdata->headerchain);

    if (ctxdata->data2sign != NULL)
        free(ctxdata->data2sign);

    if (ctxdata->cert != NULL)
        X509_free(ctxdata->cert);

    if (ctxdata->key != NULL)
        EVP_PKEY_free(ctxdata->key);

    if (ctxdata->chain != NULL)
        sk_X509_pop_free(ctxdata->chain, X509_free);

    if (ctxdata->inbio != NULL)
        BIO_free_all(ctxdata->inbio);

    if (ctxdata->outbio != NULL)
        BIO_free_all(ctxdata->outbio);

    if (ctxdata->pkcs7 != NULL)
        PKCS7_free(ctxdata->pkcs7);

    if (ctxdata->buffer != NULL)
        free(ctxdata->buffer);

    /* memset zero */
    bzero(ctxdata, sizeof(CTXDATA));
}
