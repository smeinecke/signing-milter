#include "bio2file.h"

#include <limits.h>

int bio2file(BIO *b, const char* dir, const char* prefix, const char* queueid) {

    BIO*     biofile;
    BUF_MEM* pp;
    char*    bio_filename;
    size_t   filename_len;

    assert(dir != NULL);
    assert(prefix != NULL);
    assert(queueid != NULL);

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

    if ((biofile = BIO_new_file(bio_filename, "w")) == NULL) {
        logmsg(LOG_ERR, "bio2file: BIO_new_file failed");
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
