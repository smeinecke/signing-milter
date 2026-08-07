#include "redis.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "utils.h"

extern const char* opt_redis_uri;
extern const char* opt_redis_prefix;

#define REDIS_KEY_MAX 1024

static pthread_key_t redis_tls;
static int redis_tls_initialized = 0;

#ifdef WITH_REDIS
#include <hiredis.h>
#include <sys/time.h>

#ifdef WITH_REDIS_SSL
#include <arpa/inet.h>
#include <hiredis/hiredis_ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

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
    free(g_uri.password);
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

static void redis_free_ctx(void* p) {
    if (p != NULL) {
        redisContext* c = (redisContext*) p;
        redisFree(c);
    }
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
            if (strcmp(val, "none") == 0)
                g_uri.tls_verify = TLS_VERIFY_NONE;
            else if (strcmp(val, "peer") == 0)
                g_uri.tls_verify = TLS_VERIFY_PEER;
            else {
                logmsg(LOG_ERR, "redis: invalid TLS verify mode '%s' (URI redacted)", val);
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
            if (sscanf(qm + 1, "db=%d", &g_uri.db) == 1) {
                if (g_uri.db < 0)
                    g_uri.db = 0;
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
        if (sscanf(slash + 1, "%d", &g_uri.db) != 1)
            g_uri.db = 0;
        if (g_uri.db < 0)
            g_uri.db = 0;
    }

    /* port */
    colon = strrchr(g_uri.host, ':');
    if (colon != NULL) {
        *colon = '\0';
        if (sscanf(colon + 1, "%d", &g_uri.port) != 1)
            g_uri.port = 6379;
        if (g_uri.port <= 0 || g_uri.port > 65535)
            g_uri.port = 6379;
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
        rc = redis_parse_tls_query(query);
        if (rc < 0) {
            free(query);
            free(work);
            redis_uri_free();
            return -1;
        }
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
            redisFree(c);
        } else {
            logmsg(LOG_ERR, "redis: connection failed: unknown error");
        }
        return NULL;
    }

    if (redisSetTimeout(c, tv) != REDIS_OK) {
        logmsg(LOG_ERR, "redis: redisSetTimeout() failed");
        redisFree(c);
        return NULL;
    }

#ifdef WITH_REDIS_SSL
    if (g_uri.use_tls) {
        SSL*          ssl = NULL;
        const char*   verify_name;
        const char*   sni;

        if (g_ssl_ctx == NULL) {
            logmsg(LOG_ERR, "redis: TLS context not initialized");
            redisFree(c);
            return NULL;
        }

        ssl = SSL_new(g_ssl_ctx);
        if (ssl == NULL) {
            logmsg(LOG_ERR, "redis: SSL_new() failed");
            redisFree(c);
            return NULL;
        }

        verify_name = g_uri.tls_verify_name != NULL ? g_uri.tls_verify_name : g_uri.host;
        sni = g_uri.tls_sni != NULL ? g_uri.tls_sni : verify_name;

        if (g_uri.tls_verify == TLS_VERIFY_PEER) {
            if (redis_host_is_ip(verify_name)) {
                if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), verify_name) != 1) {
                    logmsg(LOG_ERR, "redis: X509_VERIFY_PARAM_set1_ip_asc(%s) failed", verify_name);
                    SSL_free(ssl);
                    redisFree(c);
                    return NULL;
                }
            } else {
                if (X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), verify_name, 0) != 1) {
                    logmsg(LOG_ERR, "redis: X509_VERIFY_PARAM_set1_host(%s) failed", verify_name);
                    SSL_free(ssl);
                    redisFree(c);
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
                redisFree(c);
                return NULL;
            }
        }

        if (redisInitiateSSL(c, ssl) != REDIS_OK) {
            logmsg(LOG_ERR, "redis: TLS handshake failed: %s",
                   c->err ? c->errstr : "unknown");
            SSL_free(ssl);
            redisFree(c);
            return NULL;
        }
    }
#endif

    if (g_uri.password != NULL) {
        redisReply* r;
        if (g_uri.username != NULL) {
            r = redisCommand(c, "AUTH %s %s", g_uri.username, g_uri.password);
        } else {
            r = redisCommand(c, "AUTH %s", g_uri.password);
        }
        if (r == NULL || c->err) {
            logmsg(LOG_ERR, "redis: AUTH failed: %s",
                   c->err ? c->errstr : "no reply");
            if (r != NULL)
                freeReplyObject(r);
            redisFree(c);
            return NULL;
        }
        freeReplyObject(r);
    }

    if (g_uri.db != 0) {
        redisReply* r = redisCommand(c, "SELECT %d", g_uri.db);
        if (r == NULL || c->err) {
            logmsg(LOG_ERR, "redis: SELECT %d failed: %s",
                   g_uri.db, c->err ? c->errstr : "no reply");
            if (r != NULL)
                freeReplyObject(r);
            redisFree(c);
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
        redisFree(c);
    }

    c = redis_do_connect();
    if (c == NULL)
        return NULL;

    if (pthread_setspecific(redis_tls, c) != 0) {
        logmsg(LOG_ERR, "redis: pthread_setspecific() failed: %s", strerror(errno));
        redisFree(c);
        return NULL;
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
        redisFree(c);
}

/*
 * Install a newly created Redis context in the TLS slot.  On failure the
 * context is freed and the slot remains clear.
 */
static int redis_tls_set_ctx(redisContext* c) {
    if (pthread_setspecific(redis_tls, c) != 0) {
        logmsg(LOG_ERR, "redis: pthread_setspecific() failed: %s", strerror(errno));
        redisFree(c);
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

    if (!g_uri.is_unix && !g_uri.use_tls && g_uri.host != NULL) {
        logmsg(LOG_WARNING,
               "redis: using unencrypted TCP (redis://). "
               "Credentials, private keys and certificate data will be "
               "transmitted in plaintext. Prefer rediss:// or a Unix-domain "
               "socket when possible.");
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

        if (g_uri.tls_cert != NULL && g_uri.tls_key != NULL) {
            if (SSL_CTX_use_certificate_file(g_ssl_ctx, g_uri.tls_cert, SSL_FILETYPE_PEM) != 1) {
                logmsg(LOG_ERR, "redis: failed to load client certificate %s", g_uri.tls_cert);
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
        logmsg(LOG_ERR, "redis: pthread_key_create() failed: %s", strerror(errno));
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
        }

        if (pem_tmp != NULL &&
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
        }

        freeReplyObject(r);

        if (pem_tmp == NULL) {
            free(chain_tmp);
            return 1;
        }

        *pem = pem_tmp;
        *pem_len = strlen(pem_tmp);
        *chain = chain_tmp;
        *chain_len = chain_tmp ? strlen(chain_tmp) : 0;
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
