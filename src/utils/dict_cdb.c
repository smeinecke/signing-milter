#include "dict_cdb.h"

#include <ctype.h>
#include <pthread.h>

#include "address.h"

static pthread_mutex_t dict_global_lock = PTHREAD_MUTEX_INITIALIZER;

void dict_open(const char* path, DICT* dict) {

    struct stat st;
    size_t      len;
    size_t      path_len;

    if ((dict->stat_fd = open(path, O_RDONLY)) < 0) {
        logmsg(LOG_ERR, "open database %s: %m", path, strerror(errno));
        exit(EX_SOFTWARE);
    }

    if (cdb_init(&(dict->cdb), dict->stat_fd) != 0) {
        logmsg(LOG_ERR, "dict_open: unable to init %s: %m", path, strerror(errno));
        exit(EX_SOFTWARE);
    }

    if (fstat(dict->stat_fd, &st) < 0) {
        logmsg(LOG_ERR, "dict_open: fstat: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }

    dict->mtime = st.st_mtime;

    path_len = strlen(path);
    if ((dict->cdb_path = malloc(path_len + 1)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc cdb_path: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    memcpy(dict->cdb_path, path, path_len + 1);

    /*
     * allocate a per-dict work buffer used while the global lock is held
     */
    if ((dict->buffer = malloc(DICT_BUFFER_LEN)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }

    /*
     * Warn if the source file is newer than the indexed file, except when
     * the source file changed only seconds ago.
     */
    path_len = strlen(path);
    if (path_len >= 4) {
        len = path_len - 4;
    } else {
        len = 0;
    }
    if (len + 1 > DICT_BUFFER_LEN) {
        logmsg(LOG_ERR, "dict_open: buffer to small: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    if (len > 0) {
        strncpy(dict->buffer, path, len);
    }
    dict->buffer[len] = '\0';

    if (len > 0 && stat(dict->buffer, &st) == 0
        && st.st_mtime > dict->mtime
        && st.st_mtime < time((time_t *) 0) - 100)
        logmsg(LOG_WARNING, "dict_open: database %s is older than source file %s", path, dict->buffer);
}

int dict_reload(DICT* dict) {

    struct stat st;
    struct stat new_st;
    int         new_fd = -1;
    struct cdb  new_cdb;

    pthread_mutex_lock(&dict_global_lock);

    if (dict->stat_fd < 0 || dict->cdb_path == NULL) {
        pthread_mutex_unlock(&dict_global_lock);
        return 0;
    }

    if (dict->stat_fd >= 0 && fstat(dict->stat_fd, &st) == 0) {
        if (st.st_mtime == dict->mtime && st.st_nlink > 0) {
            pthread_mutex_unlock(&dict_global_lock);
            return 0;
        }
        logmsg(LOG_INFO, "%s has changed, reloading", dict->name);
    } else if (dict->stat_fd >= 0) {
        logmsg(LOG_WARNING, "dict_reload: fstat %s: %m", dict->name, strerror(errno));
        /* the old fd may be stale; try to (re)open the database */
    } else {
        logmsg(LOG_WARNING, "dict_reload: %s has no open file", dict->name);
    }

    if (dict->cdb_path == NULL) {
        logmsg(LOG_ERR, "dict_reload: %s has no path", dict->name);
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    if ((new_fd = open(dict->cdb_path, O_RDONLY)) < 0) {
        logmsg(LOG_WARNING, "dict_reload: open %s: %m", dict->cdb_path, strerror(errno));
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    if (cdb_init(&new_cdb, new_fd) != 0) {
        logmsg(LOG_WARNING, "dict_reload: cdb_init %s: %m", dict->cdb_path, strerror(errno));
        close(new_fd);
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    if (fstat(new_fd, &new_st) < 0) {
        logmsg(LOG_WARNING, "dict_reload: fstat %s: %m", dict->cdb_path, strerror(errno));
        cdb_free(&new_cdb);
        close(new_fd);
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    /*
     * Only replace the old dictionary once the new one has been fully
     * validated.  This keeps the previous (trusted) table active if the new
     * file cannot be loaded.
     */
    cdb_free(&dict->cdb);
    if (dict->stat_fd >= 0)
        close(dict->stat_fd);

    dict->cdb = new_cdb;
    dict->stat_fd = new_fd;
    dict->mtime = new_st.st_mtime;

    pthread_mutex_unlock(&dict_global_lock);
    return 0;
}

/*
 * Look up key in dict and copy the value into the caller-owned result buffer.
 *
 * Returns:
 *   1  - value found and copied into result (NUL-terminated)
 *   0  - key not found (result[0] set to '\0')
 *  -1  - error (key too long, CDB read error, or result buffer too small)
 *
 * The result buffer is always owned by the caller; no internal shared storage
 * is ever returned.
 */
int dict_lookup(DICT* dict, const char* key, char* result, size_t result_len) {

    size_t          keylen;
    unsigned        vlen;
    const char*     src = key;
    char*           p;
    int             status = 0;

    if (result == NULL || result_len == 0)
        return -1;

    result[0] = '\0';

    pthread_mutex_lock(&dict_global_lock);

    if (dict->stat_fd < 0 || dict->buffer == NULL) {
        pthread_mutex_unlock(&dict_global_lock);
        return 0;
    }

    if (key == NULL) {
        pthread_mutex_unlock(&dict_global_lock);
        return 0;
    }

    keylen = strlen(key);
    if (keylen + 1 > DICT_BUFFER_LEN) {
        logmsg(LOG_ERR, "dict_lookup: key too long");
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    /*
     * non_smtpd_milter: addresses have *no* <>
     * smtpd_milter:     addresses *have* <>
     * assumption: if the first character is a <,
     *             the last character will be a >.
     * To do this, keylen is decremented twice.
     */
    if (*src == '<' && keylen >= 2 && src[keylen - 1] == '>') {
        src++;
        keylen -= 2;
    }
    /* empty sender is, unfortunately, empty now */

    if (keylen > DICT_BUFFER_LEN - 1) {
        logmsg(LOG_ERR, "dict_lookup: key too long after address normalization");
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    memcpy(dict->buffer, src, keylen);
    p = dict->buffer + keylen;
    *p = '\0';

    if (strlen(dict->buffer) == 0) {
        /*
         * empty sender:
         * query with <> in the cdb file
         */
        memcpy(dict->buffer, "<>", 3);
        keylen = 2;
    }

    /*
     * convert uppercase letters to lowercase
     */
    key = lowercase(dict->buffer);

    /*
     * See if this CDB file was written with one null byte appended to key
     * and value.
     */
    if (dict->flags & DICT_FLAG_TRY1NULL) {
        status = cdb_find(&dict->cdb, key, keylen + 1);
        if (status > 0)
            dict->flags &= ~DICT_FLAG_TRY0NULL;
    }

    /*
     * See if this CDB file was written with no null byte appended to key and
     * value.
     */
    if (status == 0 && (dict->flags & DICT_FLAG_TRY0NULL)) {
        status = cdb_find(&dict->cdb, key, keylen);
        if (status > 0)
            dict->flags &= ~DICT_FLAG_TRY1NULL;
    }
    if (status < 0) {
        logmsg(LOG_ERR, "error reading %s: %m", dict->name, strerror(errno));
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    if (status) {
        vlen = cdb_datalen(&dict->cdb);
        if (vlen == 0) {
            /* an empty value is equivalent to "not found" */
            result[0] = '\0';
            pthread_mutex_unlock(&dict_global_lock);
            return 0;
        }
        if ((size_t) vlen + 1 > result_len) {
            logmsg(LOG_ERR, "dict_lookup: result for %s too long for caller buffer", dict->name);
            pthread_mutex_unlock(&dict_global_lock);
            return -1;
        }
        if (cdb_read(&dict->cdb, result, vlen, cdb_datapos(&dict->cdb)) < 0) {
            logmsg(LOG_ERR, "error reading %s: %m", dict->name, strerror(errno));
            pthread_mutex_unlock(&dict_global_lock);
            return -1;
        }
        result[vlen] = '\0';
        pthread_mutex_unlock(&dict_global_lock);
        return 1;
    }

    pthread_mutex_unlock(&dict_global_lock);
    return 0;
}

/*
 * Tokenize a CDB auth table value and check whether it contains the normalized
 * signer identity.  A single record may contain a list delimited by commas
 * and/or whitespace.  Each token is normalized before comparison; a token that
 * does not fit into the normalization buffer is a lookup error (fail closed).
 */
static int auth_signing_value_match(const char* val, size_t vlen, const char* signer_norm) {

    char*  buf;
    char*  p;
    char*  end;
    size_t toklen;
    char   tok[DICT_BUFFER_LEN];
    char   tok_norm[DICT_BUFFER_LEN];
    int    found = 0;
    int    norm_ok;

    if (vlen == 0)
        return 0;

    if ((buf = malloc(vlen + 1)) == NULL) {
        logmsg(LOG_ERR, "dict_auth_signing_lookup: malloc(value) failed");
        return -1;
    }
    memcpy(buf, val, vlen);
    buf[vlen] = '\0';

    p = buf;
    end = buf + vlen;
    while (p < end) {
        /* skip leading delimiters */
        while (p < end && (isspace((unsigned char) *p) || *p == ','))
            p++;
        if (p >= end)
            break;

        toklen = 0;
        while (p < end && !isspace((unsigned char) *p) && *p != ',') {
            if (toklen < sizeof(tok) - 1)
                tok[toklen] = *p;
            toklen++;
            p++;
        }
        if (toklen == 0)
            continue;

        if (toklen >= sizeof(tok)) {
            logmsg(LOG_ERR, "dict_auth_signing_lookup: signer token too long");
            free(buf);
            return -1;
        }

        tok[toklen] = '\0';

        norm_ok = normalize_address_safe(tok, tok_norm, sizeof(tok_norm));
        if (!norm_ok) {
            logmsg(LOG_ERR, "dict_auth_signing_lookup: signer token too long: '%s'", tok);
            free(buf);
            return -1;
        }
        if (tok_norm[0] != '\0' && strcmp(tok_norm, "<>") != 0 &&
            strcmp(tok_norm, signer_norm) == 0) {
            /* keep scanning; an overlong later token must still fail closed */
            found = 1;
        }
    }

    free(buf);
    return found;
}

int dict_auth_signing_lookup(DICT* dict, const char* auth_raw, const char* signer_raw) {

    size_t         keylen;
    struct cdb_find cdbfp;
    int            status;
    int            found = 0;
    char*          val = NULL;

    if (dict == NULL ||
        auth_raw == NULL || *auth_raw == '\0' ||
        signer_raw == NULL || *signer_raw == '\0')
        return 0;

    pthread_mutex_lock(&dict_global_lock);

    if (dict->stat_fd < 0 || dict->buffer == NULL) {
        pthread_mutex_unlock(&dict_global_lock);
        return 0;
    }

    /*
     * The authenticated identity is an opaque SASL principal and is matched
     * case-sensitively.  It is only length-checked.
     */
    keylen = strlen(auth_raw);
    if (keylen == 0 || keylen >= DICT_BUFFER_LEN) {
        logmsg(LOG_ERR, "dict_auth_signing_lookup: auth identity too long or empty");
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }
    memcpy(dict->buffer, auth_raw, keylen);
    dict->buffer[keylen] = '\0';

    if (signer_raw[0] == '\0' || strcmp(signer_raw, "<>") == 0) {
        pthread_mutex_unlock(&dict_global_lock);
        return 0;
    }

    if (cdb_findinit(&cdbfp, &dict->cdb, dict->buffer, keylen) < 0) {
        logmsg(LOG_ERR, "dict_auth_signing_lookup: cdb_findinit error for %s", auth_raw);
        pthread_mutex_unlock(&dict_global_lock);
        return -1;
    }

    while ((status = cdb_findnext(&cdbfp)) > 0) {
        unsigned vlen = cdb_datalen(&dict->cdb);

        if (vlen == 0)
            continue;

        if ((val = malloc(vlen + 1)) == NULL) {
            logmsg(LOG_ERR, "dict_auth_signing_lookup: malloc(value) failed");
            status = -1;
            break;
        }

        if (cdb_read(&dict->cdb, val, vlen, cdb_datapos(&dict->cdb)) < 0) {
            logmsg(LOG_ERR, "dict_auth_signing_lookup: cdb_read error for %s", auth_raw);
            free(val);
            val = NULL;
            status = -1;
            break;
        }
        val[vlen] = '\0';

        status = auth_signing_value_match(val, vlen, signer_raw);
        free(val);
        val = NULL;
        if (status == 1) {
            found = 1;
            break;
        }
        if (status < 0)
            break;
    }

    pthread_mutex_unlock(&dict_global_lock);

    if (status < 0)
        return -1;

    return found;
}

void dict_close(DICT* dict) {
    if (dict->stat_fd >= 0) {
        cdb_free(&dict->cdb);
        close(dict->stat_fd);
    }
    dict->stat_fd = -1;
    free(dict->buffer);
    dict->buffer = NULL;
    free(dict->cdb_path);
    dict->cdb_path = NULL;
}
