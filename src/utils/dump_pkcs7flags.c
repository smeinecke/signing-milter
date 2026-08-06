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

    char* p = buf;
    size_t left = 4096;
    int n;

    p[0] = '\0';

    if (flags & PKCS7_TEXT) {
        n = snprintf(p, left, "PKCS7_TEXT | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOCERTS) {
        n = snprintf(p, left, "PKCS7_NOCERTS | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOSIGS) {
        n = snprintf(p, left, "PKCS7_NOSIGS | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOCHAIN) {
        n = snprintf(p, left, "PKCS7_NOCHAIN | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOINTERN) {
        n = snprintf(p, left, "PKCS7_NOINTERN | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOVERIFY) {
        n = snprintf(p, left, "PKCS7_NOVERIFY | "); p += n; left -= n;
    }
    if (flags & PKCS7_DETACHED) {
        n = snprintf(p, left, "PKCS7_DETACHED | "); p += n; left -= n;
    }
    if (flags & PKCS7_BINARY) {
        n = snprintf(p, left, "PKCS7_BINARY | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOATTR) {
        n = snprintf(p, left, "PKCS7_NOATTR | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOSMIMECAP) {
        n = snprintf(p, left, "PKCS7_NOSMIMECAP | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOOLDMIMETYPE) {
        n = snprintf(p, left, "PKCS7_NOOLDMIMETYPE | "); p += n; left -= n;
    }
    if (flags & PKCS7_CRLFEOL) {
        n = snprintf(p, left, "PKCS7_CRLFEOL | "); p += n; left -= n;
    }
    if (flags & PKCS7_STREAM) {
        n = snprintf(p, left, "PKCS7_STREAM | "); p += n; left -= n;
    }
    if (flags & PKCS7_NOCRL) {
        n = snprintf(p, left, "PKCS7_NOCRL | "); p += n; left -= n;
    }
    snprintf(p, left, "0");

    logmsg(LOG_DEBUG, "dump_pkcs7flags: %s", buf);

    free(buf);
#endif
}
