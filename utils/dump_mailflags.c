/*
 * signing-milter - utils/dump_mailflags.c
 * Copyright (C) 2010,2011  Andreas Schulze
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

#include "dump_mailflags.h"

void dump_mailflags(int flags) {

#ifndef NDEBUG
    /* 5 Flags, das längste 20 Zeichen -> Puffer 20x20 Byte */
    char* buf;

    /*
     * Rüchsprung, falls LOGLEVEL nicht auf LOG_DEBUG steht
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
    strcat(buf, "0");

    logmsg(LOG_DEBUG, "dump_mailflags: %s", buf);

    free(buf);
#endif
}
