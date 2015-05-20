/*
 * signing-milter - utils/dict_cdb.c
 * Copyright (C) 2010,2011  Andreas Schulze
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
 *      Andreas Schulze <signing-milter at andreasschulze.de> based on
 *      postfix/src/utils/dict_cdb.c by
 *      Michael Tokarev <mjt@tls.msk.ru> based on dict_db.c by
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 *
 */

#include "dict_cdb.h"

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

    /*
     * allocte some memory
     */
    /* temp. puffer */
    if ((dict->buffer = malloc(DICT_BUFFER_LEN)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    /* Ergebnispuffer */
    if ((dict->result = malloc(DICT_BUFFER_LEN)) == NULL) {
        logmsg(LOG_ERR, "dict_open: malloc: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }
    /* wird dynamisch vergroessert, als Groesse merken */
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

int warn_if_dict_changed(DICT* dict) {

    struct stat st;

    if (dict->mtime == 0)                   /* not bloody likely */
        logmsg(LOG_WARNING, "dict_reload: table %s: null time stamp", dict->name);

    if (fstat(dict->stat_fd, &st) < 0) {
        logmsg(LOG_ERR, "dict_reload: fstat: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }

    if (st.st_mtime != dict->mtime || st.st_nlink == 0) {
        logmsg(LOG_INFO, "%s has changed", dict_signingtable.name);
        return (1);
    }

    return (0);
}

const char* dict_lookup(DICT* dict, const char* key) {

    size_t          keylen;
    unsigned        vlen;
    char*           p;
    int             status = 0;

    /*
     * definierten rueckgabewert setzen
     */
    *(dict->result) = '\0';

    keylen = strlen(key);
    if (keylen + 1 > DICT_BUFFER_LEN) {
        logmsg(LOG_ERR, "dict_lookup: buffer to small: %m", strerror(errno));
        exit(EX_SOFTWARE);
    }

    /* non_smtpd_milter: adressen haben *keine* <>
     * smtpd_milter:     adressen *haben* <>
     * Annahme: wenn das erste Zeichen ein < ist,
     *          wird das letzte Zeichen ein > sein.
     * Dazu wird keylen zweimal dekrementiert.
     */
    p = (char*) key;
    if (*p == '<') {
        p++;
        keylen-=2;
    }
    /* leerer Absender ist nun leider leer */

    strncpy(dict->buffer, p, keylen);
    /* nun fehlt noch die abschliessende \0 */
    p = dict->buffer + keylen;
    *p = '\0';

    if (strlen(dict->buffer) == 0) {
        /*
         * leerer Absender:
         * mit <> in der cdb-Datei anfragen
         */
        strcpy(dict->buffer, "<>");
        keylen = 2;
    }

    /*
     * Grossbuchstaben umwandeln
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
            dict->result = realloc(dict->result, vlen + 1);
            /* TODO: realloc kann fehlschlagen; Fehler abfangen */
            dict->result_len = vlen;
        }
        if (cdb_read(&dict->cdb, dict->result, vlen, cdb_datapos(&dict->cdb)) < 0) {
            logmsg(LOG_ERR, "error reading %s: %m", dict->name, strerror(errno));
            exit(EX_SOFTWARE);
        }
        dict->result[vlen] = '\0';
    }

    return (dict->result);

}

void dict_close(DICT* dict) {
    cdb_free(&dict->cdb);
    close(dict->stat_fd);
    free(dict->buffer);
    free(dict->result);
}
