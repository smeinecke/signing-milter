/*
 * signing-milter - utils/break_after_semicolon.c
 * Copyright (C) 2010-2018  Andreas Schulze
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

#include "break_after_semicolon.h"

/*
 * replaces the ";" followed by any character in a string
 * in the phase before signing with "; \r \n \t"
 * and in the phase after signing with "; \n \t"
 * assumption: after a ; there is always a space. This is ensured by a call to hdrdup.
 *
 * argument: - a memory area allocated with malloc containing a null-terminated string
 *           - PHASE_PRE_SIGN (3) or PHASE_POST_SIGN (2)
 * return:   - in case of error:
 *             NULL
 *           - if the string contains no ;:
 *             the original string
 *           - if the string is < 70 characters:
 *             the original string
 *           - if the string contains at least one ;:
 *             a new memory area allocated with malloc.
 *             the memory passed as argument is freed with free.
 */
char* break_after_semicolon(char* string, int phase) {

    int    num_semicolon = -1;
    char*  new_string;
    char*  p_old;
    char*  p_new;

    if ((num_semicolon = get_num_semicolons(string)) < 0) {
        return(NULL);
    }

    if (!num_semicolon) {
        /* no semicolons in string */
        return (string);
    }

    /* per semicolon 2 or 3 additional bytes + one space (or empty?) */
    if ((new_string = malloc(strlen(string) + (num_semicolon*phase) + 1)) == NULL) {
        logmsg(LOG_ERR, "FATAL: break_after_semicolon: malloc failed");
        return(NULL);
    }

    p_old = string;
    p_new = new_string;
    while (*p_old) { /* until \0 */
        *p_new = *p_old;

        if (*p_old != ';') {
            p_old++; p_new++;
        } else {
            if (PHASE_PRE_SIGN == phase) {
                p_new++;
                *p_new = '\r';
            }
            p_new++;
            *p_new = '\n';
            p_new++;
            *p_new = ' ';
            p_new++;
            p_old++; /* character after ; */
            if (*p_old != ' ')
                logmsg(LOG_ERR, "break_after_semicolon: no SPACE after ; in ->%s<-", string);
            p_old++; /* hopefully the <SPACE> */
        }
    }
    *p_new = '\0';
    logmsg(LOG_DEBUG, "break_after_semicolon: replaced ->%s<- with ->%s<-", string, new_string);
    free(string);
    return (new_string);
}
