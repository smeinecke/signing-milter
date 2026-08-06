#include "headerchain2signingbuffer.h"

int headerchain2signingbuffer(SMFICTX* ctx, CTXDATA* ctxdata) {

    NODE*          n;

    if ((ctxdata->mailflags & MF_TYPE_MIME) == 0) {

        /* simplest case:
         * plain text, body is implicitly 7-bit ASCII
         * the header chain is empty because there are no MIME headers
         */
        ctxdata->pkcs7flags |= PKCS7_TEXT;
    }
    else {

        ctxdata->pkcs7flags |= PKCS7_BINARY;

        /*
         * some kind of MIME mail
         * there MUST be headers
         */
        assert(ctxdata->headerchain != NULL);

        /*
         * if there are MIME headers, write them into inBIO
         * so that they are co-signed.
         * ( however, do not copy the MIME-Version: 1.0 into the body )
         */
        n = ctxdata->headerchain;
        while (n != NULL) {
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), n->headerf, strlen(n->headerf));
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), ": ", 2);
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), n->headerv, strlen(n->headerv));
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), "\r\n", 2);
            n = n->next;
        }
        /*
         * and another empty line as separator between MIME header and body
         */
        append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), "\r\n", 2);
    }

    return(0);
}
