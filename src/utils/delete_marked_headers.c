#include "delete_marked_headers.h"

int delete_marked_headers(SMFICTX* ctx, CTXDATA* ctxdata) {

    if ((ctxdata->mailflags & MF_TYPE_MIME) == 0) {

        /* simplest case:
         * plain text, body is implicitly 7-bit ASCII
         * the header chain is empty because there are no MIME headers
         */
        assert(ctxdata->headerchain == NULL);
    }
    else {

        NODE* n;

        /*
         * any MIME mail: there MUST be headers
         */
        assert(ctxdata->headerchain != NULL);

        n = ctxdata->headerchain;
        while (n != NULL) {
            if (smfi_chgheader(ctx, n->headerf, 1, NULL) != MI_SUCCESS) {
                logmsg(LOG_ERR, "%s: error: delete_marked_headers: delete_header %s failed", ctxdata->queueid, n->headerf);
                return (1); /* wird in der aufrufenden Funktion zu SMFIS_TEMPFAIL */
            }
            n = n->next;
        }
    }

    return(0);
}

