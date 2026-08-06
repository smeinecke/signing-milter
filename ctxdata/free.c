#include "free.h"

void ctxdata_free(CTXDATA* ctxdata) {

    assert(ctxdata != NULL);

    free(ctxdata);
}
