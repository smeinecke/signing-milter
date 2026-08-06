#include "cleanup.h"

void ctxdata_cleanup(CTXDATA* ctxdata) {

    assert(ctxdata != NULL);

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
