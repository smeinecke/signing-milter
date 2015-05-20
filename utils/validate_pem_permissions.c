/*
 * signing-milter - utils/validate_pem_permissions.c
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
 *   Andreas Schulze <signing-milter at andreasschulze.de>
 *
 */

#include "validate_pem_permissions.h"

/*
 * prüfen, ob die Datei existiert und ob es eine Datei ist
 * Datei darf nicht zugreifbar für "other" sein
 * Datei darf nicht schreib- oder ausführbar für die aktuelle UID sein
 * Datei muss lesbar für die aktuelle UID sein
 */

int validate_pem_permissions(const char* pemfilename) {

    struct stat st;

    if (stat(pemfilename, &st) < 0) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': %m", pemfilename, strerror(errno));
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s' is not a file", pemfilename);
        return 1;
    }
    if (S_IRWXO & st.st_mode) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove any access for other", pemfilename);
        return 1;
    }
    if (access(pemfilename, R_OK|W_OK) == 0) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove write access for myself", pemfilename);
        return 1;
    }
    if (access(pemfilename, R_OK) < 0 && errno == EACCES) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too strong: no read access", pemfilename);
        return 1;
    }

    return 0;
}
