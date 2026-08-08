#include "redis.h"

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "utils.h"

extern const char* opt_redis_uri;
extern const char* opt_redis_prefix;
extern char* opt_redis_username;
extern char* opt_redis_password;

#define REDIS_KEY_MAX 1024

static pthread_key_t redis_tls;
static int redis_tls_initialized = 0;

#ifdef WITH_REDIS
#include <hiredis.h>
#include <hiredis/read.h>
#include <sys/time.h>

/*
 * Hard limits on how much data hiredis may buffer or allocate for a single
 * bulk reply.  The 8 MiB input cap is the real security boundary: it bounds
 * what hiredis can feed into its parser before the application-level size
 * checks run.  The 4 MiB bulk cap, array cap, and buffer-trim cap provide
 * defence-in-depth (CWE-770 / CWE-789).
 */
#define REDIS_MAX_INPUT_LEN      (8 * 1024 * 1024)
#define REDIS_MAX_BULK_LEN       (4 * 1024 * 1024)
#define REDIS_READER_MAX_ARRAY   1024
#define REDIS_READER_MAX_BUF_SIZE (64 * 1024)

/*
 * Per-context wrapper state.  Each redisContext gets its own copies of the
 * function tables; we never mutate hiredis' shared tables, only the copies.
 */
typedef struct {
    const redisContextFuncs*    orig;             /* original context funcs */
    redisContextFuncs           guarded;          /* copy with wrapped read */
    redisReplyObjectFunctions*  orig_reader_fns;  /* original reader funcs */
    redisReplyObjectFunctions   guarded_reader_fns; /* copy with wrapped createString */
    size_t                      max_input;
    size_t                      max_bulk;
} redis_conn_extra;

#ifdef WITH_REDIS_SSL
#include <arpa/inet.h>
#include <hiredis/hiredis_ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#define TLS_VERIFY_NONE 0
#define TLS_VERIFY_PEER 1
#endif

typedef struct redis_uri {
    int is_unix;
    int use_tls;
    char* host;
    int port;
    int db;
    char* unix_socket;
    char* username;
    char* password;
    /* TLS options (rediss://) */
    char* tls_cacert;
    char* tls_capath;
    char* tls_cert;
    char* tls_key;
    char* tls_sni;
    char* tls_verify_name;
    int   tls_verify;
} redis_uri_t;

static redis_uri_t g_uri = {
    0, 0,
    NULL, 6379, 0, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
#ifdef WITH_REDIS_SSL
    TLS_VERIFY_PEER
#else
    0
#endif
};

static int redis_enabled = 0;

#ifdef WITH_REDIS_SSL
static SSL_CTX* g_ssl_ctx = NULL;
#endif

static void redis_uri_free(void) {
    free(g_uri.host);
    free(g_uri.unix_socket);
    free(g_uri.username);
    if (g_uri.password != NULL) {
        OPENSSL_cleanse(g_uri.password, strlen(g_uri.password));
        free(g_uri.password);
        g_uri.password = NULL;
    }
    free(g_uri.tls_cacert);
    free(g_uri.tls_capath);
    free(g_uri.tls_cert);
    free(g_uri.tls_key);
    free(g_uri.tls_sni);
    free(g_uri.tls_verify_name);
    memset(&g_uri, 0, sizeof(g_uri));
    g_uri.port = 6379;
    g_uri.db = 0;
#ifdef WITH_REDIS_SSL
    g_uri.tls_verify = TLS_VERIFY_PEER;
#else
    g_uri.tls_verify = 0;
#endif
}

static void redisFreeGuarded(redisContext* c);

static void redis_free_ctx(void* p) {
    if (p != NULL) {
        redisContext* c = (redisContext*) p;
        redisFreeGuarded(c);
    }
}

/*
 * Parse a non-negative decimal integer from a complete, NUL-terminated string.
 * The whole string must be consumed; no trailing garbage is allowed.
 */
static int redis_parse_number(const char* s, long min, long max, long* out) {
    char* end;
    long  v;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
        return -1;

    *out = v;
    return 0;
}

#ifdef WITH_REDIS_SSL

/*
 * Return non-zero if host is an IPv4 or IPv6 literal.
 */
static int redis_host_is_ip(const char* host) {
    unsigned char buf[16];

    if (host == NULL || *host == '\0')
        return 0;

    if (inet_pton(AF_INET, host, buf) == 1)
        return 1;
    if (inet_pton(AF_INET6, host, buf) == 1)
        return 1;
    return 0;
}

/*
 * Parse the optional TLS query parameters for rediss:// URIs.
 *
 * Supported parameters (after the ?):
 *   verify={none,peer}       -- default: peer
 *   verify_name=hostname     -- identity to verify (default: URI host)
 *   cacert=/path/to/ca.pem   -- CA certificate/bundle
 *   capath=/path/to/cadir    -- CA certificate directory
 *   cert=/path/to/cert.pem   -- client certificate for mTLS
 *   key=/path/to/key.pem     -- client private key for mTLS
 *   sni=hostname             -- SNI to send (default: verify_name if DNS)
 *
 * Duplicate parameters, unknown parameters, malformed values and mismatched
 * cert/key are rejected.  On error the function returns -1; redis_parse_uri()
 * frees the partially-parsed URI.
 */
static int redis_parse_tls_query(const char* query) {
    char*         buf;
    char*         p;
    char*         amp;
    char*         eq;
    unsigned int  seen = 0;
    const char*   key;
    const char*   val;

#define SEEN_VERIFY      0x01
#define SEEN_VERIFY_NAME 0x02
#define SEEN_CACERT      0x04
#define SEEN_CAPATH      0x08
#define SEEN_CERT        0x10
#define SEEN_KEY         0x20
#define SEEN_SNI         0x40

    if (query == NULL || *query == '\0')
        return 0;

    buf = strdup(query);
    if (buf == NULL)
        return -1;

    p = buf;
    while (p != NULL) {
        amp = strchr(p, '&');
        if (amp != NULL)
            *amp = '\0';

        eq = strchr(p, '=');
        if (eq == NULL || eq == p || *(eq + 1) == '\0') {
            logmsg(LOG_ERR, "redis: malformed TLS query parameter (URI redacted)");
            free(buf);
            return -1;
        }

        *eq = '\0';
        key = p;
        val = eq + 1;

        if (strcmp(key, "verify") == 0) {
            if (seen & SEEN_VERIFY) {
                logmsg(LOG_ERR, "redis: duplicate TLS verify parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_VERIFY;
            if (strcmp(val, "peer") == 0)
                g_uri.tls_verify = TLS_VERIFY_PEER;
            else {
                logmsg(LOG_ERR, "redis: invalid TLS verify mode '%s'; only 'peer' is permitted (URI redacted)", val);
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "verify_name") == 0) {
            if (seen & SEEN_VERIFY_NAME) {
                logmsg(LOG_ERR, "redis: duplicate TLS verify_name parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_VERIFY_NAME;
            g_uri.tls_verify_name = strdup(val);
            if (g_uri.tls_verify_name == NULL) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "cacert") == 0) {
            if (seen & SEEN_CACERT) {
                logmsg(LOG_ERR, "redis: duplicate TLS cacert parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_CACERT;
            g_uri.tls_cacert = strdup(val);
            if (g_uri.tls_cacert == NULL) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "capath") == 0) {
            if (seen & SEEN_CAPATH) {
                logmsg(LOG_ERR, "redis: duplicate TLS capath parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_CAPATH;
            g_uri.tls_capath = strdup(val);
            if (g_uri.tls_capath == NULL) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "cert") == 0) {
            if (seen & SEEN_CERT) {
                logmsg(LOG_ERR, "redis: duplicate TLS cert parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_CERT;
            g_uri.tls_cert = strdup(val);
            if (g_uri.tls_cert == NULL) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "key") == 0) {
            if (seen & SEEN_KEY) {
                logmsg(LOG_ERR, "redis: duplicate TLS key parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_KEY;
            g_uri.tls_key = strdup(val);
            if (g_uri.tls_key == NULL) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "sni") == 0) {
            if (seen & SEEN_SNI) {
                logmsg(LOG_ERR, "redis: duplicate TLS sni parameter (URI redacted)");
                free(buf);
                return -1;
            }
            seen |= SEEN_SNI;
            g_uri.tls_sni = strdup(val);
            if (g_uri.tls_sni == NULL) {
                free(buf);
                return -1;
            }
        } else {
            logmsg(LOG_ERR, "redis: unknown TLS query parameter '%s' (URI redacted)", key);
            free(buf);
            return -1;
        }

        p = (amp != NULL) ? amp + 1 : NULL;
    }

    free(buf);

    if ((seen & SEEN_CERT) != 0 && (seen & SEEN_KEY) == 0) {
        logmsg(LOG_ERR, "redis: TLS cert given without key (URI redacted)");
        return -1;
    }
    if ((seen & SEEN_KEY) != 0 && (seen & SEEN_CERT) == 0) {
        logmsg(LOG_ERR, "redis: TLS key given without cert (URI redacted)");
        return -1;
    }

    return 0;

#undef SEEN_VERIFY
#undef SEEN_VERIFY_NAME
#undef SEEN_CACERT
#undef SEEN_CAPATH
#undef SEEN_CERT
#undef SEEN_KEY
#undef SEEN_SNI
}
#endif /* WITH_REDIS_SSL */

static int redis_parse_uri(const char* uri) {
    char* work;
    char* p;
    char* at;
    char* slash;
    char* colon;
    char* qm;
    char* query = NULL;
    int   rc;

    if (uri == NULL || *uri == '\0') {
        logmsg(LOG_INFO, "redis: no URI configured");
        return 0;
    }

    work = strdup(uri);
    if (work == NULL) {
        logmsg(LOG_ERR, "redis: strdup(uri) failed: %s", strerror(errno));
        return -1;
    }

    if (strncmp(work, "unix:", 5) == 0) {
        p = work + 5;
        if (strncmp(p, "//", 2) == 0)
            p += 2;

        g_uri.is_unix = 1;
        qm = strchr(p, '?');
        if (qm != NULL)
            *qm = '\0';

        g_uri.unix_socket = strdup(p);
        if (g_uri.unix_socket == NULL) {
            logmsg(LOG_ERR, "redis: strdup(unix_socket) failed: %s", strerror(errno));
            free(work);
            return -1;
        }

        g_uri.db = 0;
        if (qm != NULL) {
            if (strncmp(qm + 1, "db=", 3) != 0) {
                logmsg(LOG_ERR, "redis: unknown query parameter in Unix socket URI (URI redacted)");
                free(work);
                redis_uri_free();
                return -1;
            }
            {
                long db;
                if (redis_parse_number(qm + 4, 0, INT_MAX, &db) != 0) {
                    logmsg(LOG_ERR, "redis: invalid db query in Unix socket URI (URI redacted)");
                    free(work);
                    redis_uri_free();
                    return -1;
                }
                g_uri.db = (int) db;
            }
        }

        free(work);
        return 0;
    }

    if (strncmp(work, "rediss:", 7) == 0) {
#ifdef WITH_REDIS_SSL
        g_uri.use_tls = 1;
#else
        logmsg(LOG_ERR, "redis: rediss:// (TLS) is not supported in this build");
        free(work);
        redis_uri_free();
        return -1;
#endif
        p = work + 7;
        if (strncmp(p, "//", 2) == 0)
            p += 2;
    } else if (strncmp(work, "redis:", 6) == 0) {
        g_uri.use_tls = 0;
        p = work + 6;
        if (strncmp(p, "//", 2) == 0)
            p += 2;
    } else {
        logmsg(LOG_ERR, "redis: unsupported URI scheme (URI redacted)");
        free(work);
        redis_uri_free();
        return -1;
    }

    g_uri.is_unix = 0;

    /*
     * Extract the query string before we start modifying the URI parts.
     */
    qm = strchr(p, '?');
    if (qm != NULL) {
        *qm = '\0';
        query = strdup(qm + 1);
    }

    at = strchr(p, '@');
    if (at != NULL) {
        char* userpass;
        *at = '\0';

        /* p now points to the user:pass part, at+1 to the host part */
        userpass = strdup(p);
        if (userpass == NULL) {
            logmsg(LOG_ERR, "redis: strdup(userpass) failed: %s", strerror(errno));
            free(query);
            free(work);
            return -1;
        }

        g_uri.host = strdup(at + 1);
        if (g_uri.host == NULL) {
            logmsg(LOG_ERR, "redis: strdup(host) failed: %s", strerror(errno));
            free(userpass);
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }

        colon = strchr(userpass, ':');
        if (colon != NULL) {
            *colon = '\0';
            if (*userpass != '\0') {
                g_uri.username = strdup(userpass);
                if (g_uri.username == NULL) {
                    logmsg(LOG_ERR, "redis: strdup(username) failed: %s", strerror(errno));
                    free(userpass);
                    free(query);
                    free(work);
                    redis_uri_free();
                    return -1;
                }
            }
            if (*(colon + 1) != '\0') {
                g_uri.password = strdup(colon + 1);
                if (g_uri.password == NULL) {
                    logmsg(LOG_ERR, "redis: strdup(password) failed: %s", strerror(errno));
                    free(userpass);
                    free(query);
                    free(work);
                    redis_uri_free();
                    return -1;
                }
            }
        } else {
            if (*userpass != '\0') {
                g_uri.password = strdup(userpass);
                if (g_uri.password == NULL) {
                    logmsg(LOG_ERR, "redis: strdup(password) failed: %s", strerror(errno));
                    free(userpass);
                    free(query);
                    free(work);
                    redis_uri_free();
                    return -1;
                }
            }
        }

        free(userpass);
    } else {
        g_uri.host = strdup(p);
        if (g_uri.host == NULL) {
            logmsg(LOG_ERR, "redis: strdup(host) failed: %s", strerror(errno));
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }
    }

    /* database number */
    slash = strrchr(g_uri.host, '/');
    if (slash != NULL) {
        *slash = '\0';
        if (*(slash + 1) != '\0') {
            long db;
            if (redis_parse_number(slash + 1, 0, INT_MAX, &db) != 0) {
                logmsg(LOG_ERR, "redis: invalid database in URI (URI redacted)");
                free(query);
                free(work);
                redis_uri_free();
                return -1;
            }
            g_uri.db = (int) db;
        }
    }

    /*
     * Port extraction: bracketed IPv6 literals ([::1]:6380) are handled
     * explicitly so colons inside the address are not mistaken for a port
     * separator.  Unbracketed TCP hosts use the usual strrchr(':') split.
     */
    if (*g_uri.host == '[') {
        char* end = strchr(g_uri.host, ']');
        if (end == NULL) {
            logmsg(LOG_ERR, "redis: malformed IPv6 literal in URI (URI redacted)");
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }
        *end = '\0';
        if (*(end + 1) == ':') {
            long port;
            if (redis_parse_number(end + 2, 1, 65535, &port) != 0) {
                logmsg(LOG_ERR, "redis: invalid port in IPv6 URI (URI redacted)");
                free(query);
                free(work);
                redis_uri_free();
                return -1;
            }
            g_uri.port = (int) port;
        } else if (*(end + 1) != '\0') {
            logmsg(LOG_ERR, "redis: malformed IPv6 URI (URI redacted)");
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }
        {
            size_t iplen = strlen(g_uri.host + 1);
            memmove(g_uri.host, g_uri.host + 1, iplen);
            g_uri.host[iplen] = '\0';
        }
    } else {
        colon = strrchr(g_uri.host, ':');
        if (colon != NULL) {
            *colon = '\0';
            long port;
            if (redis_parse_number(colon + 1, 1, 65535, &port) != 0) {
                logmsg(LOG_ERR, "redis: invalid port in URI (URI redacted)");
                free(query);
                free(work);
                redis_uri_free();
                return -1;
            }
            g_uri.port = (int) port;
        }
    }

    if (*g_uri.host == '\0' && !g_uri.is_unix) {
        logmsg(LOG_ERR, "redis: empty host in URI (URI redacted)");
        free(query);
        free(work);
        redis_uri_free();
        return -1;
    }

    if (query != NULL) {
#ifdef WITH_REDIS_SSL
        if (!g_uri.use_tls) {
            logmsg(LOG_ERR, "redis: TLS query parameters are not allowed for plaintext redis://");
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }
        rc = redis_parse_tls_query(query);
        if (rc < 0) {
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }
#else
        logmsg(LOG_ERR, "redis: query parameters are not allowed for redis://");
        free(query);
        free(work);
        redis_uri_free();
        return -1;
#endif
        free(query);
    }

    if (g_uri.username != NULL) {
        logmsg(LOG_INFO, "redis: configured for %s at %s:%d/%d%s",
               g_uri.username, g_uri.host, g_uri.port, g_uri.db,
               g_uri.use_tls ? " (TLS)" : "");
    } else if (g_uri.password != NULL) {
        logmsg(LOG_INFO, "redis: configured for %s:%d/%d with auth%s",
               g_uri.host, g_uri.port, g_uri.db,
               g_uri.use_tls ? " (TLS)" : "");
    } else {
        logmsg(LOG_INFO, "redis: configured for %s:%d/%d%s",
               g_uri.host, g_uri.port, g_uri.db,
               g_uri.use_tls ? " (TLS)" : "");
    }

    free(work);
    return 0;
}

static int redis_reply_is_ok(redisReply* r) {
    return r != NULL &&
           r->type == REDIS_REPLY_STATUS &&
           r->str != NULL &&
           strcmp(r->str, "OK") == 0;
}

/*
 * Connection-specific wrapper functions that enforce resource limits before
 * hiredis allocates unbounded amounts of memory.  Each redisContext owns a
 * private copy of its function tables; we never mutate hiredis' shared tables.
 */

static ssize_t redis_guarded_read(redisContext* c, char* buf, size_t bufcap);
static void* redis_guarded_create_string(const redisReadTask* task, char* str, size_t len);

static redis_conn_extra* redis_conn_extra_new(const redisContextFuncs* orig,
                                              redisReplyObjectFunctions* reader_fns) {
    redis_conn_extra* e = calloc(1, sizeof(*e));
    if (e == NULL)
        return NULL;

    e->orig = orig;
    e->guarded = *orig;
    e->guarded.read = redis_guarded_read;

    e->orig_reader_fns = reader_fns;
    e->guarded_reader_fns = *reader_fns;
    e->guarded_reader_fns.createString = redis_guarded_create_string;

    e->max_input = REDIS_MAX_INPUT_LEN;
    e->max_bulk = REDIS_MAX_BULK_LEN;
    return e;
}

/*
 * Restore the hiredis-owned function tables and detach the guard state before
 * redisFree() is called.  This ensures hiredis does not dereference any guard
 * memory (e.g. e->guarded) during the redisFree() teardown sequence.
 */
static void redis_conn_extra_detach(redisContext* c) {
    redis_conn_extra* e = c->privdata;

    if (e == NULL)
        return;

    c->funcs = e->orig;
    if (c->reader != NULL) {
        c->reader->fn = e->orig_reader_fns;
        c->reader->privdata = NULL;
    }
    c->privdata = NULL;
    c->free_privdata = NULL;
}

/*
 * Free a guarded redisContext.  This restores the original hiredis function
 * tables first, then lets hiredis tear down the context, and finally releases
 * the per-context guard state.  This avoids a UAF where redisFree() would
 * call c->funcs->free_privctx() through a pointer that lives inside the guard
 * state being freed.
 */
static void redisFreeGuarded(redisContext* c) {
    redis_conn_extra* e = NULL;

    if (c != NULL) {
        e = c->privdata;
        if (e != NULL)
            redis_conn_extra_detach(c);
        redisFree(c);
    }
    if (e != NULL)
        free(e);
}

static ssize_t redis_guarded_read(redisContext* c, char* buf, size_t bufcap) {
    redis_conn_extra* e = c->privdata;

    if (e == NULL)
        return -1;

    /* 8 MiB hard cap on how much data can be fed into the parser. */
    if (c->reader != NULL && c->reader->len >= e->max_input) {
        c->err = REDIS_ERR_OTHER;
        snprintf(c->errstr, sizeof(c->errstr),
                 "redis: input buffer size limit exceeded");
        return -1;
    }

    return e->orig->read(c, buf, bufcap);
}

static void* redis_guarded_create_string(const redisReadTask* task, char* str, size_t len) {
    redis_conn_extra* e = task->privdata;

    if (e == NULL)
        return NULL;

    if (len > e->max_bulk) {
        logmsg(LOG_ERR, "redis: bulk string reply exceeds maximum allowed size (%zu > %zu)",
               len, e->max_bulk);
        return NULL;
    }
    return e->orig_reader_fns->createString(task, str, len);
}

static int redis_install_guards(redisContext* c) {
    redis_conn_extra* e;

    if (c->privdata != NULL)
        return 0;

    e = redis_conn_extra_new(c->funcs, c->reader->fn);
    if (e == NULL) {
        logmsg(LOG_ERR, "redis: cannot allocate connection guards");
        return -1;
    }

    c->privdata = e;
    /* Do not set free_privdata: guard teardown is handled by redisFreeGuarded. */
    c->free_privdata = NULL;
    c->funcs = &e->guarded;
    c->reader->fn = &e->guarded_reader_fns;
    c->reader->privdata = e;
    c->reader->maxelements = REDIS_READER_MAX_ARRAY;
    c->reader->maxbuf = REDIS_READER_MAX_BUF_SIZE;

    return 0;
}

static redisContext* redis_do_connect(void) {
    redisContext* c = NULL;
    struct timeval tv = { 5, 0 };

    if (g_uri.is_unix) {
        c = redisConnectUnix(g_uri.unix_socket);
    } else {
        c = redisConnectWithTimeout(g_uri.host, g_uri.port, tv);
    }

    if (c == NULL || c->err) {
        if (c != NULL) {
            logmsg(LOG_ERR, "redis: connection failed: %s", c->errstr);
            redisFreeGuarded(c);
        } else {
            logmsg(LOG_ERR, "redis: connection failed: unknown error");
        }
        return NULL;
    }

    if (redisSetTimeout(c, tv) != REDIS_OK) {
        logmsg(LOG_ERR, "redis: redisSetTimeout() failed");
        redisFreeGuarded(c);
        return NULL;
    }

#ifdef WITH_REDIS_SSL
    if (g_uri.use_tls) {
        SSL*          ssl = NULL;
        const char*   verify_name;
        const char*   sni;

        if (g_ssl_ctx == NULL) {
            logmsg(LOG_ERR, "redis: TLS context not initialized");
            redisFreeGuarded(c);
            return NULL;
        }

        ssl = SSL_new(g_ssl_ctx);
        if (ssl == NULL) {
            logmsg(LOG_ERR, "redis: SSL_new() failed");
            redisFreeGuarded(c);
            return NULL;
        }

        verify_name = g_uri.tls_verify_name != NULL ? g_uri.tls_verify_name : g_uri.host;
        sni = g_uri.tls_sni != NULL ? g_uri.tls_sni : verify_name;

        if (g_uri.tls_verify == TLS_VERIFY_PEER) {
            if (redis_host_is_ip(verify_name)) {
                if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), verify_name) != 1) {
                    logmsg(LOG_ERR, "redis: X509_VERIFY_PARAM_set1_ip_asc(%s) failed", verify_name);
                    SSL_free(ssl);
                    redisFreeGuarded(c);
                    return NULL;
                }
            } else {
                if (X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), verify_name, 0) != 1) {
                    logmsg(LOG_ERR, "redis: X509_VERIFY_PARAM_set1_host(%s) failed", verify_name);
                    SSL_free(ssl);
                    redisFreeGuarded(c);
                    return NULL;
                }
            }
            SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
        } else {
            SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        }

        /*
         * SNI is only sent for DNS names.  If no explicit sni= is given, we
         * fall back to the verification identity only when it is a hostname.
         */
        if (sni != NULL && !redis_host_is_ip(sni)) {
            if (SSL_set_tlsext_host_name(ssl, sni) != 1) {
                logmsg(LOG_ERR, "redis: SSL_set_tlsext_host_name(%s) failed", sni);
                SSL_free(ssl);
                redisFreeGuarded(c);
                return NULL;
            }
        }

        if (redisInitiateSSL(c, ssl) != REDIS_OK) {
            logmsg(LOG_ERR, "redis: TLS handshake failed: %s",
                   c->err ? c->errstr : "unknown");
            SSL_free(ssl);
            redisFreeGuarded(c);
            return NULL;
        }

        /*
         * OpenSSL's SSL_VERIFY_PEER only guarantees a trusted chain; hostname
         * identity must be verified explicitly (CWE-297).
         */
        if (g_uri.tls_verify == TLS_VERIFY_PEER) {
            long verify_result = SSL_get_verify_result(ssl);
            if (verify_result != X509_V_OK) {
                logmsg(LOG_ERR, "redis: TLS peer verification failed: %s",
                       X509_verify_cert_error_string(verify_result));
                SSL_free(ssl);
                redisFreeGuarded(c);
                return NULL;
            }

            if (!redis_host_is_ip(verify_name)) {
                X509* cert = SSL_get1_peer_certificate(ssl);
                if (cert == NULL) {
                    logmsg(LOG_ERR, "redis: no peer certificate presented");
                    SSL_free(ssl);
                    redisFreeGuarded(c);
                    return NULL;
                }
                if (X509_check_host(cert, verify_name, strlen(verify_name), 0, NULL) != 1) {
                    logmsg(LOG_ERR, "redis: TLS certificate does not match hostname '%s'", verify_name);
                    X509_free(cert);
                    SSL_free(ssl);
                    redisFreeGuarded(c);
                    return NULL;
                }
                X509_free(cert);
            }
        }
    }
#endif

    if (redis_install_guards(c) != 0) {
        redisFreeGuarded(c);
        return NULL;
    }

    if (g_uri.password != NULL) {
        redisReply* r;
        if (g_uri.username != NULL) {
            r = redisCommand(c, "AUTH %s %s", g_uri.username, g_uri.password);
        } else {
            r = redisCommand(c, "AUTH %s", g_uri.password);
        }
        if (!redis_reply_is_ok(r)) {
            if (r != NULL && r->type == REDIS_REPLY_ERROR)
                logmsg(LOG_ERR, "redis: AUTH rejected: %s", r->str);
            else
                logmsg(LOG_ERR, "redis: AUTH failed");
            if (r != NULL)
                freeReplyObject(r);
            redisFreeGuarded(c);
            return NULL;
        }
        freeReplyObject(r);
    }

    if (g_uri.db != 0) {
        redisReply* r = redisCommand(c, "SELECT %d", g_uri.db);
        if (!redis_reply_is_ok(r)) {
            if (r != NULL && r->type == REDIS_REPLY_ERROR)
                logmsg(LOG_ERR, "redis: SELECT %d rejected: %s", g_uri.db, r->str);
            else
                logmsg(LOG_ERR, "redis: SELECT %d failed", g_uri.db);
            if (r != NULL)
                freeReplyObject(r);
            redisFreeGuarded(c);
            return NULL;
        }
        freeReplyObject(r);
    }

    return c;
}

static redisContext* redis_get_ctx(void) {
    redisContext* c = pthread_getspecific(redis_tls);

    if (c != NULL && c->err == 0)
        return c;

    if (c != NULL) {
        /*
         * Clear the TLS slot *before* freeing, otherwise a concurrent or
         * subsequent caller could retrieve the freed pointer if
         * redis_do_connect() fails below.
         */
        (void) pthread_setspecific(redis_tls, NULL);
        redisFreeGuarded(c);
    }

    c = redis_do_connect();
    if (c == NULL)
        return NULL;

    {
        int rc = pthread_setspecific(redis_tls, c);
        if (rc != 0) {
            logmsg(LOG_ERR, "redis: pthread_setspecific() failed: %s", strerror(rc));
            redisFreeGuarded(c);
            return NULL;
        }
    }

    return c;
}

/*
 * Safely clear the per-thread Redis context.  Used by the explicit reconnect
 * paths in redis_lookup_cert() and redis_auth_signing_lookup() so the TLS
 * slot never points at a context that is about to be freed.
 */
static void redis_tls_clear_ctx(redisContext* c) {
    redisContext* current = pthread_getspecific(redis_tls);

    if (current == c)
        (void) pthread_setspecific(redis_tls, NULL);

    if (c != NULL)
        redisFreeGuarded(c);
}

/*
 * Install a newly created Redis context in the TLS slot.  On failure the
 * context is freed and the slot remains clear.
 */
static int redis_tls_set_ctx(redisContext* c) {
    int rc = pthread_setspecific(redis_tls, c);
    if (rc != 0) {
        logmsg(LOG_ERR, "redis: pthread_setspecific() failed: %s", strerror(rc));
        redisFreeGuarded(c);
        return -1;
    }
    return 0;
}

#endif /* WITH_REDIS */

int redis_global_init(void) {
    int rc;

    if (opt_redis_uri == NULL || *opt_redis_uri == '\0') {
        logmsg(LOG_INFO, "redis: no Redis URI configured");
        return 0;
    }

#ifndef WITH_REDIS
    logmsg(LOG_WARNING, "redis: -r was given but Redis support is not compiled in");
    return 0;
#else
    rc = redis_parse_uri(opt_redis_uri);
    if (rc < 0)
        return -1;

    /*
     * Redis passwords must never be passed on the command line.  If a password
     * is embedded in the URI, reject it immediately.
     */
    if (g_uri.password != NULL) {
        logmsg(LOG_ERR, "redis: passwords must not be embedded in the URI; use -p or -C");
        goto init_failed;
    }

    if (opt_redis_username != NULL && *opt_redis_username != '\0') {
        free(g_uri.username);
        g_uri.username = strdup(opt_redis_username);
        if (g_uri.username == NULL) {
            logmsg(LOG_ERR, "redis: strdup(username) failed: %s", strerror(errno));
            goto init_failed;
        }
    }

    if (opt_redis_password != NULL && *opt_redis_password != '\0') {
        g_uri.password = strdup(opt_redis_password);
        if (g_uri.password == NULL) {
            logmsg(LOG_ERR, "redis: strdup(password) failed: %s", strerror(errno));
            goto init_failed;
        }
    }

    if (!g_uri.is_unix && !g_uri.use_tls && g_uri.host != NULL) {
        logmsg(LOG_ERR,
               "redis: plaintext TCP (redis://) is not permitted; "
               "use rediss:// with peer verification or a Unix-domain socket");
        goto init_failed;
    }

#ifdef WITH_REDIS_SSL
    if (g_uri.use_tls) {
        if (redisInitOpenSSL() != REDIS_OK) {
            logmsg(LOG_ERR, "redis: redisInitOpenSSL() failed");
            goto init_failed;
        }

        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (g_ssl_ctx == NULL) {
            logmsg(LOG_ERR, "redis: SSL_CTX_new() failed");
            goto init_failed;
        }

        /*
         * The shared SSL context is fully configured before any worker thread
         * is created and is treated as immutable afterwards.  Each Redis
         * connection obtains its own SSL object via SSL_new(g_ssl_ctx); only
         * per-connection state is modified on that SSL object.
         */
        if (SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION) != 1) {
            logmsg(LOG_ERR, "redis: SSL_CTX_set_min_proto_version(TLS1_2_VERSION) failed");
            goto init_failed;
        }
        (void) SSL_CTX_set_options(g_ssl_ctx,
                                   SSL_OP_NO_SSLv2 |
                                   SSL_OP_NO_SSLv3 |
                                   SSL_OP_NO_TLSv1 |
                                   SSL_OP_NO_TLSv1_1);

        if (g_uri.tls_cert != NULL && g_uri.tls_key != NULL) {
            if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, g_uri.tls_cert) != 1) {
                logmsg(LOG_ERR, "redis: failed to load client certificate chain %s", g_uri.tls_cert);
                goto init_failed;
            }
            if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_uri.tls_key, SSL_FILETYPE_PEM) != 1) {
                logmsg(LOG_ERR, "redis: failed to load client private key %s", g_uri.tls_key);
                goto init_failed;
            }
            if (SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
                logmsg(LOG_ERR, "redis: client certificate and private key do not match");
                goto init_failed;
            }
        }

        if (g_uri.tls_cacert != NULL || g_uri.tls_capath != NULL) {
            if (SSL_CTX_load_verify_locations(g_ssl_ctx, g_uri.tls_cacert, g_uri.tls_capath) != 1) {
                logmsg(LOG_ERR, "redis: failed to load CA certificate(s) from %s",
                       g_uri.tls_cacert != NULL ? g_uri.tls_cacert : g_uri.tls_capath);
                goto init_failed;
            }
        } else if (g_uri.tls_verify == TLS_VERIFY_PEER) {
            if (SSL_CTX_set_default_verify_paths(g_ssl_ctx) != 1) {
                logmsg(LOG_ERR, "redis: failed to load default CA certificate paths");
                goto init_failed;
            }
        }
    }
#endif

    if (g_uri.is_unix) {
        logmsg(LOG_INFO, "redis: initialized for unix socket %s", g_uri.unix_socket);
    } else if (g_uri.host != NULL) {
        logmsg(LOG_INFO, "redis: initialized for %s:%d/%d%s",
               g_uri.host, g_uri.port, g_uri.db,
               g_uri.use_tls ? " (TLS)" : "");
    }

    rc = pthread_key_create(&redis_tls, redis_free_ctx);
    if (rc != 0) {
        logmsg(LOG_ERR, "redis: pthread_key_create() failed: %s", strerror(rc));
        goto init_failed;
    }
    redis_tls_initialized = 1;
    redis_enabled = 1;

    return 0;

init_failed:
#ifdef WITH_REDIS_SSL
    if (g_ssl_ctx != NULL) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
#endif
    redis_uri_free();
    return -1;
#endif
}

void redis_global_cleanup(void) {
    if (!redis_tls_initialized)
        return;

    (void) pthread_key_delete(redis_tls);
    redis_tls_initialized = 0;

#ifdef WITH_REDIS_SSL
    /*
     * The shared SSL context is freed at milter shutdown after all worker
     * threads have finished handling connections.  Reconnect paths create a
     * brand new SSL object from this immutable context, so there is never a
     * stale SSL* or SSL_CTX* reference once the previous context is freed.
     */
    if (g_ssl_ctx != NULL) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
#endif

#ifdef WITH_REDIS
    redis_uri_free();
    redis_enabled = 0;
#endif
}

/*
 * Query the server-reported length of a hash field with HSTRLEN before we
 * request the actual value.  This prevents a compromised or misconfigured
 * Redis from causing the application (and hiredis) to allocate an oversized
 * reply (CWE-770).
 */
static int redis_check_field_size(redisContext* c, const char* key,
                                  const char* field, size_t max_size,
                                  size_t* out_len) {
    redisReply* r;
    long long   len;

    r = redisCommand(c, "HSTRLEN %s %s", key, field);
    if (r == NULL || c->err) {
        logmsg(LOG_ERR, "redis: HSTRLEN %s %s failed: %s",
               key, field, c->err ? c->errstr : "no reply");
        if (r != NULL)
            freeReplyObject(r);
        return -1;
    }

    if (r->type != REDIS_REPLY_INTEGER) {
        logmsg(LOG_ERR, "redis: unexpected HSTRLEN reply type %d", r->type);
        freeReplyObject(r);
        return -1;
    }

    len = r->integer;
    freeReplyObject(r);

    if (len < 0) {
        logmsg(LOG_ERR, "redis: HSTRLEN %s %s returned negative length", key, field);
        return -1;
    }

    if ((size_t) len > max_size) {
        logmsg(LOG_ERR, "redis: %s %s too large (%lld > %zu)", key, field, len, max_size);
        return -1;
    }

    *out_len = (size_t) len;
    return 0;
}

int redis_lookup_cert(const char* raw_address,
                      char** pem, size_t* pem_len,
                      char** chain, size_t* chain_len) {
    *pem = NULL;
    *pem_len = 0;
    *chain = NULL;
    *chain_len = 0;

    if (raw_address == NULL || *raw_address == '\0')
        return 1;

#ifndef WITH_REDIS
    (void) raw_address;
    return 1;
#else
    {
        char norm[REDIS_KEY_MAX];
        char key[REDIS_KEY_MAX];
        const char* prefix = opt_redis_prefix ? opt_redis_prefix : "signing-milter:";
        redisContext* c;
        redisReply* r;
        char* pem_tmp = NULL;
        char* chain_tmp = NULL;

        if (!redis_enabled)
            return 1;

        if (!normalize_address_safe(raw_address, norm, sizeof(norm))) {
            logmsg(LOG_ERR, "redis: signer identity too long for Redis lookup: %s", raw_address);
            return -1;
        }
        if (snprintf(key, sizeof(key), "%s%s", prefix, norm) >= (int) sizeof(key)) {
            logmsg(LOG_ERR, "redis: key too long for %s", raw_address);
            return -1;
        }

        c = redis_get_ctx();
        if (c == NULL)
            return -1;

        {
            size_t pem_size, chain_size;
            if (redis_check_field_size(c, key, "pem", MAX_REDIS_PEM_SIZE, &pem_size) != 0)
                return -1;
            if (redis_check_field_size(c, key, "chain", MAX_REDIS_CHAIN_SIZE, &chain_size) != 0)
                return -1;
            (void) pem_size;
            (void) chain_size;
        }

        r = redisCommand(c, "HMGET %s pem chain", key);
        if (r == NULL || c->err) {
            logmsg(LOG_ERR, "redis: HMGET failed: %s",
                   c->err ? c->errstr : "no reply");
            if (r != NULL)
                freeReplyObject(r);

            /* try to reconnect once */
            redis_tls_clear_ctx(c);
            c = redis_do_connect();
            if (c == NULL)
                return -1;
            if (redis_tls_set_ctx(c) != 0)
                return -1;
            r = redisCommand(c, "HMGET %s pem chain", key);
            if (r == NULL || c->err) {
                logmsg(LOG_ERR, "redis: HMGET failed after reconnect: %s",
                       c->err ? c->errstr : "no reply");
                if (r != NULL)
                    freeReplyObject(r);
                return -1;
            }
        }

        if (r->type != REDIS_REPLY_ARRAY || r->elements != 2) {
            logmsg(LOG_ERR, "redis: unexpected reply type %d", r->type);
            freeReplyObject(r);
            return -1;
        }

        if (r->element[0]->type == REDIS_REPLY_STRING && r->element[0]->len > 0) {
            if ((size_t) r->element[0]->len > MAX_REDIS_PEM_SIZE) {
                logmsg(LOG_ERR, "redis: pem value too large for %s", raw_address);
                freeReplyObject(r);
                return -1;
            }
            pem_tmp = malloc(r->element[0]->len + 1);
            if (pem_tmp == NULL) {
                logmsg(LOG_ERR, "redis: malloc(pem) failed: %s", strerror(errno));
                freeReplyObject(r);
                return -1;
            }
            memcpy(pem_tmp, r->element[0]->str, r->element[0]->len);
            pem_tmp[r->element[0]->len] = '\0';
            *pem = pem_tmp;
            *pem_len = (size_t) r->element[0]->len;
        }

        if (*pem != NULL &&
            r->element[1]->type == REDIS_REPLY_STRING && r->element[1]->len > 0) {
            if ((size_t) r->element[1]->len > MAX_REDIS_CHAIN_SIZE) {
                logmsg(LOG_ERR, "redis: chain value too large for %s", raw_address);
                free(pem_tmp);
                freeReplyObject(r);
                return -1;
            }
            chain_tmp = malloc(r->element[1]->len + 1);
            if (chain_tmp == NULL) {
                logmsg(LOG_ERR, "redis: malloc(chain) failed: %s", strerror(errno));
                free(pem_tmp);
                freeReplyObject(r);
                return -1;
            }
            memcpy(chain_tmp, r->element[1]->str, r->element[1]->len);
            chain_tmp[r->element[1]->len] = '\0';
            *chain = chain_tmp;
            *chain_len = (size_t) r->element[1]->len;
        }

        freeReplyObject(r);

        if (*pem == NULL)
            return 1;

        return 0;
    }
#endif
}

int redis_auth_signing_lookup(const char* auth_identity, const char* signer_identity) {

    if (auth_identity == NULL || *auth_identity == '\0' ||
        signer_identity == NULL || *signer_identity == '\0')
        return 0;

#ifndef WITH_REDIS
    (void) auth_identity;
    (void) signer_identity;
    return 0;
#else
    {
        char        key[REDIS_KEY_MAX];
        const char* prefix = opt_redis_prefix ? opt_redis_prefix : "signing-milter:";
        redisContext* c;
        redisReply* r;

        if (!redis_enabled)
            return -1;

        /*
         * auth_identity is the exact, opaque SASL principal.  It is used
         * verbatim as the Redis key, so only the key length is checked.
         */
        if (snprintf(key, sizeof(key), "%sauth:%s", prefix, auth_identity) >= (int) sizeof(key)) {
            logmsg(LOG_ERR, "redis: auth key too long for %s", auth_identity);
            return -1;
        }

        /* signer_identity must already be normalized (lowercase, no <>). */

        c = redis_get_ctx();
        if (c == NULL)
            return -1;

        r = redisCommand(c, "SISMEMBER %s %s", key, signer_identity);
        if (r == NULL || c->err) {
            logmsg(LOG_ERR, "redis: SISMEMBER failed: %s",
                   c->err ? c->errstr : "no reply");
            if (r != NULL)
                freeReplyObject(r);

            /* try to reconnect once */
            redis_tls_clear_ctx(c);
            c = redis_do_connect();
            if (c == NULL)
                return -1;
            if (redis_tls_set_ctx(c) != 0)
                return -1;
            r = redisCommand(c, "SISMEMBER %s %s", key, signer_identity);
            if (r == NULL || c->err) {
                logmsg(LOG_ERR, "redis: SISMEMBER failed after reconnect: %s",
                       c->err ? c->errstr : "no reply");
                if (r != NULL)
                    freeReplyObject(r);
                return -1;
            }
        }

        if (r->type != REDIS_REPLY_INTEGER) {
            logmsg(LOG_ERR, "redis: unexpected reply type %d", r->type);
            freeReplyObject(r);
            return -1;
        }

        {
            int result = (int) r->integer;
            freeReplyObject(r);
            return result;
        }
    }
#endif
}
