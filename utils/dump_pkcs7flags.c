/*
 * signing-milter - utils/dump_pkcs7flags.c
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

#include "dump_pkcs7flags.h"

void dump_pkcs7flags(int flags) {

#ifndef NDEBUG
    /* 14 Flags, das längste 20 Zeichen -> Puffer 20x20 Byte */
    char* buf;

    /*
     * Rüchsprung, falls LOGLEVEL nicht auf LOG_DEBUG steht
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
