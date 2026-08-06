/*
 * signing-milter - utils/headerchain2signingbuffer.c
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

#include "headerchain2signingbuffer.h"

int headerchain2signingbuffer(SMFICTX* ctx, CTXDATA* ctxdata) {

    NODE*          n;

    if ((ctxdata->mailflags & MF_TYPE_MIME) == 0) {

        /* simplest case:
         * plain text, body is implicitly 7-bit ASCII
         * the header chain is empty because there are no MIME headers
         */
        ctxdata->pkcs7flags |= PKCS7_TEXT;
    }
    else {

        ctxdata->pkcs7flags |= PKCS7_BINARY;

        /*
         * some kind of MIME mail
         * there MUST be headers
         */
        assert(ctxdata->headerchain != NULL);

        /*
         * if there are MIME headers, write them into inBIO
         * so that they are co-signed.
         * ( however, do not copy the MIME-Version: 1.0 into the body )
         */
        n = ctxdata->headerchain;
        while (n != NULL) {
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), n->headerf, strlen(n->headerf));
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), ": ", 2);
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), n->headerv, strlen(n->headerv));
            append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), "\r\n", 2);
            n = n->next;
        }
        /*
         * and another empty line as separator between MIME header and body
         */
        append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), "\r\n", 2);
    }

    return(0);
}
