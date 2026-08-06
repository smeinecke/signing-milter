#include "dump_mailflags.h"

void dump_mailflags(int flags) {
    (void) flags;

#ifndef NDEBUG
    /* 5 flags, the longest is 20 characters -> buffer 20x20 bytes */
    char* buf;

    /*
     * return if LOGLEVEL is not set to LOG_DEBUG
     */
    if (opt_loglevel < LOG_DEBUG)
        return;

    if ((buf = malloc(4096)) == NULL) {
        logmsg(LOG_ERR, "dump_mailflags: malloc failed");
        return;
    }

    char* p = buf;
    size_t left = 4096;
    int n;

    p[0] = '\0';

    if (flags & MF_TYPE_MIME) {
        n = snprintf(p, left, "MF_TYPE_MIME | "); p += n; left -= n;
    }
    if (flags & MF_TYPE_MULTIPART) {
        n = snprintf(p, left, "MF_TYPE_MULTIPART | "); p += n; left -= n;
    }
    if (flags & MF_SIGNMODE_OPAQUE) {
        n = snprintf(p, left, "MF_SIGNMODE_OPAQUE | "); p += n; left -= n;
    }
    if (flags & MF_SIGNER_FROM_HEADER) {
        n = snprintf(p, left, "MF_SIGNER_FROM_HEADER | "); p += n; left -= n;
    }
    if (flags & MF_MIME_VERSION_DEFAULT) {
        n = snprintf(p, left, "MF_MIME_VERSION_DEFAULT | "); p += n; left -= n;
    }
    snprintf(p, left, "0");

    logmsg(LOG_DEBUG, "dump_mailflags: %s", buf);

    free(buf);
#endif
}
