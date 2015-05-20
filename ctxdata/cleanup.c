/*
 * signing-milter - ctxdata/cleanup.c
 * Copyright (C) 2010-2012  Andreas Schulze
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

#include "cleanup.h"

void ctxdata_cleanup(CTXDATA* ctxdata) {

    assert(ctxdata != NULL);

    if (ctxdata->pemfilename != NULL)
        free(ctxdata->pemfilename);

    if (ctxdata->headerchain != NULL)
        deletechain(ctxdata->headerchain);

    if (ctxdata->data2sign != NULL)
        free(ctxdata->data2sign);

    if (ctxdata->cert != NULL)
        X509_free(ctxdata->cert);

    if (ctxdata->key != NULL)
        EVP_PKEY_free(ctxdata->key);

    if (ctxdata->chain != NULL)
        sk_X509_pop_free(ctxdata->chain, X509_free);

    if (ctxdata->inbio != NULL)
        BIO_free_all(ctxdata->inbio);

    if (ctxdata->outbio != NULL)
        BIO_free_all(ctxdata->outbio);

    if (ctxdata->pkcs7 != NULL)
        PKCS7_free(ctxdata->pkcs7);

    if (ctxdata->buffer != NULL)
        free(ctxdata->buffer);

    /* memset zero */
    bzero(ctxdata, sizeof(CTXDATA));
}
