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
    char*          cdb_path;
} DICT;

#define DICT_FLAG_TRY0NULL      (1<<2)  /* do not append 0 to key/value */
#define DICT_FLAG_TRY1NULL      (1<<3)  /* append 0 to key/value */

/*
 * Maximum message size the milter will keep in memory.  This must stay
 * below INT_MAX so the accumulated buffer can safely be passed to
 * OpenSSL's BIO_new_mem_buf() and similar int-length APIs.
 */
#define MAX_MESSAGE_SIZE (64 * 1024 * 1024)

/*
 * Bound the number and aggregate size of retained Content-* headers to
 * prevent a remote message author from exhausting worker memory or
 * spending quadratic time in list appends (CWE-400/CWE-407).
 */
#define MAX_HEADER_CHAIN_NODES  1024
#define MAX_HEADER_CHAIN_BYTES  (1024 * 1024)

/*
 * Maximum Redis-returned PEM and certificate chain sizes we are willing
 * to allocate.  These are intentionally generous but bounded to prevent
 * a compromised or misconfigured Redis from causing unbounded allocation.
 */
#define MAX_REDIS_PEM_SIZE  (1024 * 1024)
#define MAX_REDIS_CHAIN_SIZE (4 * 1024 * 1024)

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

    /* header chain tail and resource budget tracking */
    NODE*           headerchain_tail;
    size_t          headerchain_count;
    size_t          headerchain_bytes;

    /* per-recipient mode-table decisions and untrusted control header tracking */
    size_t          rcpt_count;
    size_t          rcpt_skip_count;
    int             skip_signing_header_seen;
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
extern int         opt_addxheader;
extern int         opt_signerfromheader;
extern int         opt_allow_inet;

extern const char* opt_redis_password_file;
extern const char* opt_redis_credentials_file;
extern char*       opt_redis_password;
extern char*       opt_redis_username;

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
