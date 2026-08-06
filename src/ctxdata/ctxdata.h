#ifndef _CTXDATA_H_INCLUDED_
#define _CTXDATA_H_INCLUDED_

#include <openssl/ssl.h>

#include "../signing-milter.h"

extern void ctxdata_cleanup(CTXDATA* ctxdata);
extern CTXDATA* ctxdata_create(void);
extern void ctxdata_free(CTXDATA* ctxdata);
extern int ctxdata_setup(CTXDATA* ctxdata, const char* pemfilename);

#endif
