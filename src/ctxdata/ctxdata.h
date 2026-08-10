#ifndef _CTXDATA_H_INCLUDED_
#define _CTXDATA_H_INCLUDED_

#include <openssl/ssl.h>

#include "../signing-milter.h"

extern void ctxdata_cleanup(CTXDATA* ctxdata);
extern void ctxdata_reset_cert(CTXDATA* ctxdata);
extern CTXDATA* ctxdata_create(void);
extern void ctxdata_free(CTXDATA* ctxdata);
extern int ctxdata_setup(CTXDATA* ctxdata, const char* pemfilename);
extern int ctxdata_setup_from_fd(CTXDATA* ctxdata, const char* pemfilename, int pemfd);
extern int ctxdata_setup_from_redis(CTXDATA* ctxdata, const char* redis_key, char* pem, size_t pem_len, char* chain, size_t chain_len, const char* passphrase);

#endif
