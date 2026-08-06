#ifndef _CALLBACKS_H_INCLUDED_
#define _CALLBACKS_H_INCLUDED_

#include <assert.h>
#include <libmilter/mfapi.h>
#include <openssl/pkcs7.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>

#include "signing-milter.h"

#include "stats.h"
#include "ctxdata/ctxdata.h"
#include "utils/utils.h"

extern struct smfiDesc callbacks;

sfsistat callback_envfrom(SMFICTX* ctx, char** argv);
sfsistat callback_envrcpt(SMFICTX* ctx, char** argv);
sfsistat callback_header(SMFICTX* ctx, char* headerf, char* headerv);
sfsistat callback_eoh(SMFICTX *ctx);
sfsistat callback_body(SMFICTX* ctx, unsigned char *bodyp, size_t len);
sfsistat callback_eom(SMFICTX* ctx);
sfsistat callback_abort(SMFICTX* ctx);
sfsistat callback_close(SMFICTX* ctx);

#endif
