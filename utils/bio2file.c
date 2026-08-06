#include "bio2file.h"

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

    if (BIO_write(biofile, pp->data, (int) pp->length) != (int) pp->length) {
        logmsg(LOG_ERR, "bio2file: BIO_write failed");
        BIO_free(biofile);
        free(bio_filename);
        return(2);
    }

    BIO_free(biofile);
    free(bio_filename);

    return(0);
}
