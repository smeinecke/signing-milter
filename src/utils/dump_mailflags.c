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

    bzero(buf, 4096);

    if (flags & MF_TYPE_MIME) {
	strcat(buf, "MF_TYPE_MIME | ");
    }
    if (flags & MF_TYPE_MULTIPART) {
	strcat(buf, "MF_TYPE_MULTIPART | ");
    }
    if (flags & MF_SIGNMODE_OPAQUE) {
	strcat(buf, "MF_SIGNMODE_OPAQUE | ");
    }
    if (flags & MF_SIGNER_FROM_HEADER) {
	strcat(buf, "MF_SIGNER_FROM_HEADER | ");
    }
    if (flags & MF_MIME_VERSION_DEFAULT) {
	strcat(buf, "MF_MIME_VERSION_DEFAULT | ");
    }
    strcat(buf, "0");

    logmsg(LOG_DEBUG, "dump_mailflags: %s", buf);

    free(buf);
#endif
}
