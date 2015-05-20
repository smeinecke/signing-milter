/*
 * signing-milter - utils/bio2file.c
 * Copyright (C) 2010-2013  Andreas Schulze
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Authors:
 *   Andreas Schulze <signing-milter at andreasschulze.de>
 *
 */

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
