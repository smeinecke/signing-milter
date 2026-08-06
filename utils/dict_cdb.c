#include "dict_cdb.h"

#include <pthread.h>

static pthread_mutex_t dict_global_lock = PTHREAD_MUTEX_INITIALIZER;

void dict_open(const char* path, DICT* dict) {

    struct stat st;
    size_t      len;

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

    if ((dict->cdb_path = malloc(strlen(path) + 1)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc cdb_path: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    strcpy(dict->cdb_path, path);

    /*
     * allocte some memory
     */
    /* temp. buffer */
    if ((dict->buffer = malloc(DICT_BUFFER_LEN)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    /* result buffer */
    if ((dict->result = malloc(DICT_BUFFER_LEN)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    /* grows dynamically, remember its size */
    dict->result_len = DICT_BUFFER_LEN;

    /*
     * Warn if the source file is newer than the indexed file, except when
     * the source file changed only seconds ago.
     */
    len = strlen(path) - 4;
    if (len + 1 > DICT_BUFFER_LEN) {
        logmsg(LOG_ERR, "dict_open: buffer to small: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    strncpy(dict->buffer, path, len);

    if (stat(dict->buffer, &st) == 0
        && st.st_mtime > dict->mtime
        && st.st_mtime < time((time_t *) 0) - 100)
        logmsg(LOG_WARNING, "dict_open: database %s is older than source file %s", path, dict->buffer);
}

void dict_reload(DICT* dict) {

    struct stat st;
    struct stat new_st;
    int         new_fd;
    struct cdb  new_cdb;

    pthread_mutex_lock(&dict_global_lock);

    if (dict->stat_fd >= 0 && fstat(dict->stat_fd, &st) == 0) {
        if (st.st_mtime == dict->mtime && st.st_nlink > 0) {
            pthread_mutex_unlock(&dict_global_lock);
            return;
        }
        logmsg(LOG_INFO, "%s has changed, reloading", dict->name);
    } else if (dict->stat_fd >= 0) {
        logmsg(LOG_WARNING, "dict_reload: fstat %s: %m", dict->name, strerror(errno));
    } else {
        logmsg(LOG_WARNING, "dict_reload: %s has no open file", dict->name);
    }

    if (dict->cdb_path == NULL) {
        logmsg(LOG_ERR, "dict_reload: %s has no path", dict->name);
        pthread_mutex_unlock(&dict_global_lock);
        return;
    }

    if ((new_fd = open(dict->cdb_path, O_RDONLY)) < 0) {
        logmsg(LOG_WARNING, "dict_reload: open %s: %m", dict->cdb_path, strerror(errno));
        pthread_mutex_unlock(&dict_global_lock);
        return;
    }

    if (cdb_init(&new_cdb, new_fd) != 0) {
        logmsg(LOG_WARNING, "dict_reload: cdb_init %s: %m", dict->cdb_path, strerror(errno));
        close(new_fd);
        pthread_mutex_unlock(&dict_global_lock);
        return;
    }

    if (fstat(new_fd, &new_st) < 0) {
        logmsg(LOG_WARNING, "dict_reload: fstat %s: %m", dict->cdb_path, strerror(errno));
        cdb_free(&new_cdb);
        close(new_fd);
        pthread_mutex_unlock(&dict_global_lock);
        return;
    }

    cdb_free(&dict->cdb);
    if (dict->stat_fd >= 0)
        close(dict->stat_fd);

    dict->cdb = new_cdb;
    dict->stat_fd = new_fd;
    dict->mtime = new_st.st_mtime;

    pthread_mutex_unlock(&dict_global_lock);
}

const char* dict_lookup(DICT* dict, const char* key) {

    size_t          keylen;
    unsigned        vlen;
    char*           p;
    char*           new_result = NULL;
    int             status = 0;

    pthread_mutex_lock(&dict_global_lock);

    /*
     * set the defined return value
     */
    *(dict->result) = '\0';

    keylen = strlen(key);
    if (keylen + 1 > DICT_BUFFER_LEN) {
        logmsg(LOG_ERR, "dict_lookup: buffer to small: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }

    /* non_smtpd_milter: addresses have *no* <>
     * smtpd_milter:     addresses *have* <>
     * assumption: if the first character is a <,
     *             the last character will be a >.
     * To do this, keylen is decremented twice.
     */
    p = (char*) key;
    if (*p == '<') {
        p++;
        keylen-=2;
    }
    /* empty sender is, unfortunately, empty now */

    strncpy(dict->buffer, p, keylen);
    /* the terminating \0 is still missing */
    p = dict->buffer + keylen;
    *p = '\0';

    if (strlen(dict->buffer) == 0) {
        /*
         * empty sender:
         * query with <> in the cdb file
         */
        strcpy(dict->buffer, "<>");
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
        exit(EX_SOFTWARE);
    }

    if (status) {
        vlen = cdb_datalen(&dict->cdb);
        if (dict->result_len < vlen) {
            new_result = realloc(dict->result, vlen + 1);
            if (new_result == NULL) {
                logmsg(LOG_ERR, "dict_lookup: realloc: %m", strerror(errno));
                exit(EX_SOFTWARE);
            }
            dict->result = new_result;
            dict->result_len = vlen;
        }
        if (cdb_read(&dict->cdb, dict->result, vlen, cdb_datapos(&dict->cdb)) < 0) {
            logmsg(LOG_ERR, "error reading %s: %m", dict->name, strerror(errno));
            exit(EX_SOFTWARE);
        }
        dict->result[vlen] = '\0';
    }

    pthread_mutex_unlock(&dict_global_lock);
    return (dict->result);

}

void dict_close(DICT* dict) {
    cdb_free(&dict->cdb);
    if (dict->stat_fd >= 0)
        close(dict->stat_fd);
    free(dict->buffer);
    free(dict->result);
    free(dict->cdb_path);
}
