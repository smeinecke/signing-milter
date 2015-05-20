/*
 * signing-milter - utils/load_pem.c
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

#include "load_pem.h"

/* 
 * laed eine X509 Zertifikat aus der PEM-Datei "file"
 */
X509* load_pem_cert(const char* file) {

    BIO*  bio  = NULL;
    X509* cert = NULL;

    if ((bio=BIO_new(BIO_s_file())) == NULL) {
        logmsg(LOG_ERR, "load_pem_cert: BIO_new() failed");
        goto end;
    }

    if (BIO_read_filename(bio,file) <= 0) {
        logmsg(LOG_ERR, "load_pem_cert: BIO_read_filename(%s) failed", file);
        goto end;
    }

    if ((cert=PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
        logmsg(LOG_ERR, "load_pem_cert: PEM_read_bio_X509() failed, file=%s", file);
        goto end;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    return (cert);
}

EVP_PKEY* load_pem_key(const char* file, const char* pass) {

    BIO*      bio  = NULL;
    EVP_PKEY* pkey = NULL;

    if ((bio=BIO_new(BIO_s_file())) == NULL) {
        logmsg(LOG_ERR, "load_pem_key: BIO_new() failed");
        goto end;
    }

    if (BIO_read_filename(bio,file) <= 0) {
        logmsg(LOG_ERR, "load_pem_key: BIO_read_filename(%s) failed", file);
        goto end;
    }

    if ((pkey=PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*) pass)) == NULL) {
        logmsg(LOG_ERR, "load_pem_key: PEM_read_bio_PrivateKey() failed, file=%s", file);
        goto end;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    return(pkey);
}

STACK_OF(X509)* load_pem_chain(const char* file) {

    BIO*                 bio   = NULL;
    STACK_OF(X509_INFO)* sk    = NULL;
    STACK_OF(X509)*      stack = NULL;
    X509_INFO*           xi;
    int                  num;
    int                  numcerts;

    if((bio=BIO_new_file(file, "r")) == NULL) {
        logmsg(LOG_INFO, "load_pem_chain: BIO_new_file(%s) failed", file);
        goto end;
    }

    if((sk=PEM_X509_INFO_read_bio(bio,NULL,NULL,NULL)) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain: PEM_X509_INFO_read_bio(%s) failed", file);
        goto end;
    }

    if((stack = sk_X509_new_null()) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain: sk_X509_new_null() == NULL, file=%s", file);
        goto end;
    }

    num = sk_X509_INFO_num(sk);
    if (num < 0) {
        logmsg(LOG_ERR, "load_pem_chain: sk_X509_INFO_num returned %i (which is < 0)", num);
        sk_X509_free(stack);
        stack = NULL;
        goto end;
    }

    logmsg(LOG_INFO, "info: load_pem_chain: sk_X509_INFO_num returned %i, file=%s", num, file);
    while (sk_X509_INFO_num(sk)) {
        xi=sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack,xi->x509);
            xi->x509=NULL;
        }
        X509_INFO_free(xi);
    }

    numcerts = sk_X509_num(stack);
    if(numcerts == 0) {
        sk_X509_free(stack);
        stack = NULL;
    }
    logmsg(LOG_INFO, "info: loaded %i certificate%s from %s", numcerts, numcerts != 1 ? "s" : "", file);

end:
    if (bio != NULL)
        BIO_free(bio);

    if (sk != NULL)
        sk_X509_INFO_free(sk);

    return (stack);
}
