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

typedef struct redis_uri {
    int is_unix;
    char* host;
    int port;
    int db;
    char* unix_socket;
    char* username;
    char* password;
} redis_uri_t;

static redis_uri_t g_uri = { 0, NULL, 6379, 0, NULL, NULL, NULL };
static int redis_enabled = 0;

static void redis_uri_free(void) {
    free(g_uri.host);
    free(g_uri.unix_socket);
    free(g_uri.username);
    free(g_uri.password);
    memset(&g_uri, 0, sizeof(g_uri));
    g_uri.port = 6379;
    g_uri.db = 0;
}

static void redis_free_ctx(void* p) {
    if (p != NULL) {
        redisContext* c = (redisContext*) p;
        redisFree(c);
    }
}

static int redis_parse_uri(const char* uri) {
    char* work;
    char* p;
    char* at;
    char* slash;
    char* colon;
    char* qm;

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
        logmsg(LOG_WARNING, "redis: rediss:// (TLS) is not supported, treating as redis://");
        p = work + 7;
        if (strncmp(p, "//", 2) == 0)
            p += 2;
    } else if (strncmp(work, "redis:", 6) == 0) {
        p = work + 6;
        if (strncmp(p, "//", 2) == 0)
            p += 2;
    } else {
        logmsg(LOG_ERR, "redis: unsupported URI scheme in %s", opt_redis_uri);
        free(work);
        return -1;
    }

    g_uri.is_unix = 0;

    at = strchr(p, '@');
    if (at != NULL) {
        char* userpass;
        *at = '\0';

        /* p now points to the user:pass part, at+1 to the host part */
        userpass = strdup(p);
        if (userpass == NULL) {
            logmsg(LOG_ERR, "redis: strdup(userpass) failed: %s", strerror(errno));
            free(work);
            return -1;
        }

        g_uri.host = strdup(at + 1);
        if (g_uri.host == NULL) {
            logmsg(LOG_ERR, "redis: strdup(host) failed: %s", strerror(errno));
            free(userpass);
            free(work);
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
                    free(work);
                    return -1;
                }
            }
            if (*(colon + 1) != '\0') {
                g_uri.password = strdup(colon + 1);
                if (g_uri.password == NULL) {
                    logmsg(LOG_ERR, "redis: strdup(password) failed: %s", strerror(errno));
                    free(userpass);
                    free(work);
                    return -1;
                }
            }
        } else {
            if (*userpass != '\0') {
                g_uri.password = strdup(userpass);
                if (g_uri.password == NULL) {
                    logmsg(LOG_ERR, "redis: strdup(password) failed: %s", strerror(errno));
                    free(userpass);
                    free(work);
                    return -1;
                }
            }
        }

        free(userpass);
    } else {
        g_uri.host = strdup(p);
        if (g_uri.host == NULL) {
            logmsg(LOG_ERR, "redis: strdup(host) failed: %s", strerror(errno));
            free(work);
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
        logmsg(LOG_ERR, "redis: empty host in URI %s", opt_redis_uri);
        free(work);
        return -1;
    }

    if (g_uri.username != NULL) {
        logmsg(LOG_INFO, "redis: configured for %s at %s:%d/%d",
               g_uri.username, g_uri.host, g_uri.port, g_uri.db);
    } else if (g_uri.password != NULL) {
        logmsg(LOG_INFO, "redis: configured for %s:%d/%d with auth",
               g_uri.host, g_uri.port, g_uri.db);
    } else {
        logmsg(LOG_INFO, "redis: configured for %s:%d/%d",
               g_uri.host, g_uri.port, g_uri.db);
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

    redisSetTimeout(c, tv);

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

    if (c != NULL)
        redisFree(c);

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

    if (g_uri.is_unix) {
        logmsg(LOG_INFO, "redis: initialized for unix socket %s", g_uri.unix_socket);
    } else if (g_uri.host != NULL) {
        logmsg(LOG_INFO, "redis: initialized for %s:%d/%d",
               g_uri.host, g_uri.port, g_uri.db);
    }

    rc = pthread_key_create(&redis_tls, redis_free_ctx);
    if (rc != 0) {
        logmsg(LOG_ERR, "redis: pthread_key_create() failed: %s", strerror(errno));
        return -1;
    }
    redis_tls_initialized = 1;
    redis_enabled = 1;

    return 0;
#endif
}

void redis_global_cleanup(void) {
    if (!redis_tls_initialized)
        return;

    (void) pthread_key_delete(redis_tls);
    redis_tls_initialized = 0;

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

        normalize_address(raw_address, norm, sizeof(norm));
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
            redisFree(c);
            c = redis_do_connect();
            if (c == NULL) {
                (void) pthread_setspecific(redis_tls, NULL);
                return -1;
            }
            if (pthread_setspecific(redis_tls, c) != 0) {
                logmsg(LOG_ERR, "redis: pthread_setspecific() failed: %s", strerror(errno));
                redisFree(c);
                return -1;
            }
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
        char        norm[REDIS_KEY_MAX];
        char        key[REDIS_KEY_MAX];
        const char* prefix = opt_redis_prefix ? opt_redis_prefix : "signing-milter:";
        redisContext* c;
        redisReply* r;
        size_t      i;
        int         found = 0;

        if (!redis_enabled)
            return 0;

        normalize_address(auth_identity, norm, sizeof(norm));
        if (norm[0] == '\0' || strcmp(norm, "<>") == 0)
            return 0;

        if (snprintf(key, sizeof(key), "%sauth:%s", prefix, norm) >= (int) sizeof(key)) {
            logmsg(LOG_ERR, "redis: auth key too long for %s", auth_identity);
            return -1;
        }

        c = redis_get_ctx();
        if (c == NULL)
            return -1;

        r = redisCommand(c, "SMEMBERS %s", key);
        if (r == NULL || c->err) {
            logmsg(LOG_ERR, "redis: SMEMBERS failed: %s",
                   c->err ? c->errstr : "no reply");
            if (r != NULL)
                freeReplyObject(r);

            /* try to reconnect once */
            redisFree(c);
            c = redis_do_connect();
            if (c == NULL) {
                (void) pthread_setspecific(redis_tls, NULL);
                return -1;
            }
            if (pthread_setspecific(redis_tls, c) != 0) {
                logmsg(LOG_ERR, "redis: pthread_setspecific() failed: %s", strerror(errno));
                redisFree(c);
                return -1;
            }
            r = redisCommand(c, "SMEMBERS %s", key);
            if (r == NULL || c->err) {
                logmsg(LOG_ERR, "redis: SMEMBERS failed after reconnect: %s",
                       c->err ? c->errstr : "no reply");
                if (r != NULL)
                    freeReplyObject(r);
                return -1;
            }
        }

        if (r->type != REDIS_REPLY_ARRAY) {
            logmsg(LOG_ERR, "redis: unexpected reply type %d", r->type);
            freeReplyObject(r);
            return -1;
        }

        for (i = 0; i < r->elements; i++) {
            char mem_norm[REDIS_KEY_MAX];

            if (r->element[i]->type != REDIS_REPLY_STRING || r->element[i]->len == 0)
                continue;

            normalize_address(r->element[i]->str, mem_norm, sizeof(mem_norm));
            if (mem_norm[0] != '\0' && strcmp(mem_norm, "<>") != 0 &&
                strcmp(mem_norm, signer_identity) == 0) {
                found = 1;
                break;
            }
        }

        freeReplyObject(r);
        return found;
    }
#endif
}
