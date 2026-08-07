#include "bio2file.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int queueid_is_safe(const char* queueid) {
    const char* p;

    if (queueid == NULL || *queueid == '\0')
        return 0;

    for (p = queueid; *p != '\0'; p++) {
        unsigned char c = (unsigned char) *p;
        /*
         * Allow only characters that are safe in a file name and commonly
         * found in MTA queue IDs.  Reject any path separator or shell
         * metacharacter.
         */
        if (isalnum(c) || c == '.' || c == '-' || c == '_')
            continue;
        return 0;
    }

    return 1;
}

int bio2file(BIO *b, const char* dir, const char* prefix, const char* queueid) {

    BIO*     biofile;
    BUF_MEM* pp;
    char*    bio_filename;
    size_t   filename_len;
    int      fd;

    assert(dir != NULL);
    assert(prefix != NULL);
    assert(queueid != NULL);

    if (!queueid_is_safe(queueid)) {
        logmsg(LOG_ERR, "bio2file: refusing to write keep file for unsafe queue id");
        return(1);
    }

    filename_len = strlen(dir) + strlen(prefix) + strlen(queueid) + 3;
    if ((bio_filename = malloc(filename_len)) == NULL) {
        logmsg(LOG_ERR, "bio2file: malloc for bio_filename failed: %m", strerror(errno));
        return(1);
    }

    snprintf(bio_filename, filename_len, "%s/%s-%s", dir, prefix, queueid);

    if (BIO_get_mem_ptr(b, &pp) <= 0 || pp == NULL) {
        logmsg(LOG_ERR, "bio2file: BIO_get_mem_ptr failed");
        free(bio_filename);
        return(2);
    }

    fd = open(bio_filename,
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
              0600);
    if (fd < 0) {
        logmsg(LOG_ERR, "bio2file: open %s failed: %m", bio_filename, strerror(errno));
        free(bio_filename);
        return(2);
    }

    if ((biofile = BIO_new_fd(fd, BIO_CLOSE)) == NULL) {
        logmsg(LOG_ERR, "bio2file: BIO_new_fd failed");
        close(fd);
        free(bio_filename);
        return(2);
    }

    size_t written = 0;
    while (written < pp->length) {
        size_t remaining = pp->length - written;
        int chunk = (remaining > INT_MAX) ? INT_MAX : (int) remaining;
        int n = BIO_write(biofile, (const char*) pp->data + written, chunk);
        if (n <= 0) {
            logmsg(LOG_ERR, "bio2file: BIO_write failed");
            BIO_free(biofile);
            free(bio_filename);
            return(2);
        }
        written += (size_t) n;
    }

    BIO_free(biofile);
    free(bio_filename);

    return(0);
}
