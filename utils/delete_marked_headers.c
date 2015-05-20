/*
 * signing-milter - utils/delete_marked_header.c
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

#include "delete_marked_headers.h"

int delete_marked_headers(SMFICTX* ctx, CTXDATA* ctxdata) {

    if ((ctxdata->mailflags & MF_TYPE_MIME) == 0) {

        /* einfachster Fall:
         * plain text, Body ist implizit 7bit Ascii
         * die Headerchain ist leer, da es keine MIME-Header gibt
         */
        assert(ctxdata->headerchain == NULL);
    }
    else {

        NODE* n;

        /*
         * irgendwelche MIME-Mail es MUSS Header geben
         */
        assert(ctxdata->headerchain != NULL);

        n = ctxdata->headerchain;
        while (n != NULL) {
            if (smfi_chgheader(ctx, n->headerf, 1, NULL) != MI_SUCCESS) {
                logmsg(LOG_ERR, "%s: error: delete_marked_headers: delete_header %s failed", ctxdata->queueid, n->headerf);
                return (1); /* wird in der aufrufenden Funktion zu SMFIS_TEMPFAIL */
            }
            n = n->next;
        }
    }

    return(0);
}

