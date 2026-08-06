#include "dump_pkcs7flags.h"

void dump_pkcs7flags(int flags) {
    (void) flags;

#ifndef NDEBUG
    /* 14 flags, the longest is 20 characters -> buffer 20x20 bytes */
    char* buf;

    /*
     * return if LOGLEVEL is not set to LOG_DEBUG
     */
    if (opt_loglevel < LOG_DEBUG)
        return;

    if ((buf = malloc(4096)) == NULL) {
        logmsg(LOG_ERR, "dump_pkcs7flags: malloc failed");
        return;
    }

    bzero(buf, 4096);

    if (flags & PKCS7_TEXT) {
	strcat(buf, "PKCS7_TEXT | ");
    }
    if (flags & PKCS7_NOCERTS) {
	strcat(buf, "PKCS7_NOCERTS | ");
    }
    if (flags & PKCS7_NOSIGS) {
	strcat(buf, "PKCS7_NOSIGS | ");
    }
    if (flags & PKCS7_NOCHAIN) {
	strcat(buf, "PKCS7_NOCHAIN | ");
    }
    if (flags & PKCS7_NOINTERN) {
	strcat(buf, "PKCS7_NOINTERN | ");
    }
    if (flags & PKCS7_NOVERIFY) {
	strcat(buf, "PKCS7_NOVERIFY | ");
    }
    if (flags & PKCS7_DETACHED) {
	strcat(buf, "PKCS7_DETACHED | ");
    }
    if (flags & PKCS7_BINARY) {
	strcat(buf, "PKCS7_BINARY | ");
    }
    if (flags & PKCS7_NOATTR) {
	strcat(buf, "PKCS7_NOATTR | ");
    }
    if (flags & PKCS7_NOSMIMECAP) {
	strcat(buf, "PKCS7_NOSMIMECAP | ");
    }
    if (flags & PKCS7_NOOLDMIMETYPE) {
	strcat(buf, "PKCS7_NOOLDMIMETYPE | ");
    }
    if (flags & PKCS7_CRLFEOL) {
	strcat(buf, "PKCS7_CRLFEOL | ");
    }
    if (flags & PKCS7_STREAM) {
	strcat(buf, "PKCS7_STREAM | ");
    }
    if (flags & PKCS7_NOCRL) {
	strcat(buf, "PKCS7_NOCRL | ");
    }
    strcat(buf, "0");

    logmsg(LOG_DEBUG, "dump_pkcs7flags: %s", buf);

    free(buf);
#endif
}
