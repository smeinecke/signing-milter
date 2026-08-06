#include "create.h"

CTXDATA* ctxdata_create(void) {

    CTXDATA* ctxdata;

    if ((ctxdata = malloc(sizeof(CTXDATA))) == NULL) {
        logmsg(LOG_ERR, "error: ctxdata_create: malloc for ctxdata failed: %m", strerror(errno));
        return(NULL);
    }

    /* memset zero */
    bzero(ctxdata, sizeof(CTXDATA));
    return(ctxdata);
}
