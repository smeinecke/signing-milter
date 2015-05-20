/*
 * signing-milter - utils/separate_header.c
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

#include "separate_header.h"

char* separate_header(const char* line, char** headerf) {

    char* p = NULL;
    char* q = NULL;
    char* headerv = NULL;

    if (line == NULL || *line == '\0') {
        return (0);
    }

    if ((p = strchr(line, ':')) != NULL) {
        *p = '\0';
        *headerf = (char*) line;
    }

    /* die trennende \0 überspringen */
    p++;

    /* fuehrende Leerzeichen im headerv überspringen */
    while (*p == ' ')
      p++;

    if ((headerv = malloc(MAXHEADERLEN)) == NULL) {
        logmsg(LOG_ERR, "separate_header: failed to allocate %i byte (MAXHEADERLEN)", MAXHEADERLEN);
        return NULL;
    }

    q = headerv;
    /* abschliessendes \r\n oder \n abschneiden */
    while (*p != '\r' && *p != '\n') {
        *q = *p;
        p++;
        q++;
    }

    *q = '\0';

    return (headerv);
}
