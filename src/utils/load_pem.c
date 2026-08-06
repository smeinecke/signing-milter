#include "load_pem.h"

/*
 * load an X509 certificate from an open PEM file descriptor
 */
X509* load_pem_cert(int fd) {

    BIO*  bio  = NULL;
    X509* cert = NULL;

    if ((bio = BIO_new_fd(fd, BIO_NOCLOSE)) == NULL) {
        logmsg(LOG_ERR, "load_pem_cert: BIO_new_fd() failed");
        goto end;
    }

    if ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
        logmsg(LOG_ERR, "load_pem_cert: PEM_read_bio_X509() failed");
        goto end;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    return (cert);
}

EVP_PKEY* load_pem_key(int fd, char* pass) {

    BIO*      bio  = NULL;
    EVP_PKEY* pkey = NULL;

    if ((bio = BIO_new_fd(fd, BIO_NOCLOSE)) == NULL) {
        logmsg(LOG_ERR, "load_pem_key: BIO_new_fd() failed");
        goto end;
    }

    if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*) pass)) == NULL) {
        logmsg(LOG_ERR, "load_pem_key: PEM_read_bio_PrivateKey() failed");
        goto end;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    return(pkey);
}

STACK_OF(X509)* load_pem_chain(int fd) {

    BIO*                 bio   = NULL;
    STACK_OF(X509_INFO)* sk    = NULL;
    STACK_OF(X509)*      stack = NULL;
    X509_INFO*           xi;
    int                  num;
    int                  numcerts;

    if ((bio = BIO_new_fd(fd, BIO_NOCLOSE)) == NULL) {
        logmsg(LOG_INFO, "load_pem_chain: BIO_new_fd() failed");
        goto end;
    }

    if ((sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL)) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain: PEM_X509_INFO_read_bio() failed");
        goto end;
    }

    if ((stack = sk_X509_new_null()) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain: sk_X509_new_null() == NULL");
        goto end;
    }

    num = sk_X509_INFO_num(sk);
    if (num < 0) {
        logmsg(LOG_ERR, "load_pem_chain: sk_X509_INFO_num returned %i (which is < 0)", num);
        sk_X509_free(stack);
        stack = NULL;
        goto end;
    }

    logmsg(LOG_INFO, "info: load_pem_chain: sk_X509_INFO_num returned %i", num);
    while (sk_X509_INFO_num(sk)) {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack, xi->x509);
            xi->x509 = NULL;
        }
        X509_INFO_free(xi);
    }

    numcerts = sk_X509_num(stack);
    if (numcerts == 0) {
        sk_X509_free(stack);
        stack = NULL;
    }
    logmsg(LOG_INFO, "info: loaded %i certificate%s", numcerts, numcerts != 1 ? "s" : "");

end:
    if (bio != NULL)
        BIO_free(bio);

    if (sk != NULL)
        sk_X509_INFO_free(sk);

    return (stack);
}

X509* load_pem_cert_mem(const char* data, size_t len) {
    BIO*  bio  = NULL;
    X509* cert = NULL;

    if ((bio = BIO_new_mem_buf((void*) data, (int) len)) == NULL) {
        logmsg(LOG_ERR, "load_pem_cert_mem: BIO_new_mem_buf() failed");
        goto end;
    }

    if ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
        logmsg(LOG_ERR, "load_pem_cert_mem: PEM_read_bio_X509() failed");
        goto end;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    return (cert);
}

EVP_PKEY* load_pem_key_mem(const char* data, size_t len, const char* pass) {
    BIO*      bio  = NULL;
    EVP_PKEY* pkey = NULL;

    if ((bio = BIO_new_mem_buf((void*) data, (int) len)) == NULL) {
        logmsg(LOG_ERR, "load_pem_key_mem: BIO_new_mem_buf() failed");
        goto end;
    }

    if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*) pass)) == NULL) {
        logmsg(LOG_ERR, "load_pem_key_mem: PEM_read_bio_PrivateKey() failed");
        goto end;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    return (pkey);
}

STACK_OF(X509)* load_pem_chain_mem(const char* data, size_t len) {
    BIO*                 bio   = NULL;
    STACK_OF(X509_INFO)* sk    = NULL;
    STACK_OF(X509)*      stack = NULL;
    X509_INFO*           xi;
    int                  num;
    int                  numcerts;

    if ((bio = BIO_new_mem_buf((void*) data, (int) len)) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain_mem: BIO_new_mem_buf() failed");
        goto end;
    }

    if ((sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL)) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain_mem: PEM_X509_INFO_read_bio() failed");
        goto end;
    }

    if ((stack = sk_X509_new_null()) == NULL) {
        logmsg(LOG_ERR, "load_pem_chain_mem: sk_X509_new_null() == NULL");
        goto end;
    }

    num = sk_X509_INFO_num(sk);
    if (num < 0) {
        logmsg(LOG_ERR, "load_pem_chain_mem: sk_X509_INFO_num returned %i (which is < 0)", num);
        sk_X509_free(stack);
        stack = NULL;
        goto end;
    }

    while (sk_X509_INFO_num(sk)) {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack, xi->x509);
            xi->x509 = NULL;
        }
        X509_INFO_free(xi);
    }

    numcerts = sk_X509_num(stack);
    if (numcerts == 0) {
        sk_X509_free(stack);
        stack = NULL;
    }

end:
    if (bio != NULL)
        BIO_free(bio);

    if (sk != NULL)
        sk_X509_INFO_free(sk);

    return (stack);
}
