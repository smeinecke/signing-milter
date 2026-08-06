#include "bio2file.h"

int bio2file(BIO *b, const char* dir, const char* prefix, const char* queueid) {

    BIO*     biofile;
    BUF_MEM* pp;
    char*    bio_filename;

    assert(dir != NULL);
    assert(prefix != NULL);
    assert(queueid != NULL);

    if ((bio_filename = malloc(strlen(dir) + strlen(prefix) + strlen(queueid + 1) + 100)) == NULL) {
        logmsg(LOG_ERR, "bio2file: malloc for bio_filename failed: %m", strerror(errno));
        return(1);
    }

    sprintf(bio_filename, "%s/%s-%s", dir, prefix, queueid);

    BIO_get_mem_ptr(b, &pp);

    biofile = BIO_new_file(bio_filename, "w");
    if (!biofile) {
        logmsg(LOG_ERR, "bio2file: BIO_new_file failed");
        BIO_free_all(biofile);
        BUF_MEM_free(pp);
        return(2);
    }

    BIO_write(biofile, pp->data, pp->length);

    BIO_free(biofile);
    free(bio_filename);

    return(0);
}
