#ifndef _SIGNING_MILTER_H_INCLUDED_
#define _SIGNING_MILTER_H_INCLUDED_

#include <cdb.h>
#include <openssl/x509.h>
#include "config.h"

extern char STR_PROGNAME[];

/*
 * Name of the header added by -x cmdline switch
 */
extern char HEADERNAME_XHEADER[];

/*
 * Name of the header used as signeraddress
 * if opt_signerfromheader is enabled
 */
extern char HEADERNAME_SIGNER[];

/*
 * Name of the header used to signal the
 * desire to not sign a particular message
 */
extern char HEADERNAME_SKIP_SIGNING[];

/* buffer for caching one header */
#define MAXHEADERLEN 4096

/* ======= CDB ======================= */
/* usual size of memory allocated for dict.buffer */
#define DICT_BUFFER_LEN 512

typedef struct DICT {
    const char*    name;
    int            flags;
    int            stat_fd;
    time_t         mtime;
    struct cdb     cdb;
    char*          buffer;
    char*          result;
    unsigned       result_len;
    char*          cdb_path;
} DICT;

#define DICT_FLAG_TRY0NULL      (1<<2)  /* do not append 0 to key/value */
#define DICT_FLAG_TRY1NULL      (1<<3)  /* append 0 to key/value */

/* ======= NODES ======================= */
/*
 * - pointer to the next node
 * - type of the node
 */
struct node_t {
    struct node_t* next;
    char*          headerf;
    char*          headerv;
};
#define NODE struct node_t

/* ======= CALLBACK ================== */
struct ctxdata {
    char*           pemfilename;
    NODE*           headerchain;
    unsigned char*  data2sign;
    size_t          data2sign_len;
    X509*           cert;
    EVP_PKEY*       key;
    STACK_OF(X509)* chain;
    BIO*            inbio;
    BIO*            outbio;
    PKCS7*          pkcs7;
    int             pkcs7flags;
    int             mailflags;
    char*           buffer;
    size_t          buffer_len;
    const char*     queueid;
    int             first_bodychunk_seen;
    const char*     keepdir;
    char*           auth_identity;
};
#define CTXDATA struct ctxdata

/* values for ctxdata.mailflags */
#define MF_TYPE_MIME                   (1<<0)
#define MF_TYPE_MULTIPART              (1<<1)
#define MF_SIGNMODE_OPAQUE             (1<<2)
#define MF_SIGNER_FROM_HEADER          (1<<3)
#define MF_SKIP_SIGNING                (1<<4)
#define MF_MIME_VERSION_DEFAULT        (1<<5)

/*
 * global variables
 * can be changed by command-line parameters
 */
extern const char* opt_clientgroup;
extern int         opt_loglevel;
extern int         opt_logdest;
extern const char* opt_group;
extern const char* opt_keepdir;
extern const char* opt_signingtable;
extern const char* opt_modetable;
extern char*       opt_miltersocket;
extern int         opt_timeout;
extern const char* opt_user;
extern int   opt_addxheader;
extern int   opt_signerfromheader;

extern const char* opt_redis_uri;
extern const char* opt_redis_prefix;
extern const char* opt_redis_passphrase;

extern struct DICT dict_signingtable;

extern struct DICT dict_modetable;

/*
 * where logging goes
 */
#define LOG_DEST_SYSLOG 1
#define LOG_DEST_STDOUT 2

#endif
