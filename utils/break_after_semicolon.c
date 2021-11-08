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
 * Ersetzt in einem String das ";" gefolgt von einem beliebigen Zeichen
 * in der Phase vor dem Signieren durch "; \r \n \t"
 * und in der Phase nach dem Signieren durch "; \n \t"
 * Annahme : nach einem ; kommt immer ein Leerzeichen. Dies ist jedoch durch einen Aufruf von hdrdup sichergestellt.
 *
 * Argument: - ein mit malloc allokierter Speicherbereich mit einem nullterminierten String
 *           - PHASE_PRE_SIGN (3) oder PHASE_POST_SIGN (2)
 * Rückgabe: - im Fehlerfall:
 *             NULL
 *           - wenn string keine ; enthielt:
 *             der urspüngliche String
 *           - wenn der String < 70 Zeichen ist:
 *             der urspüngliche String
 *           - wenn string mindestens ein ; enthielt:
 *             ein neuer, mit malloc allokierter Speicher.
 *             der als Argument übergebene Speicher ist mit free bereinigt.
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
        /* keine semikolons in string enthalten */
        return (string);
    }

    /* pro Semokolon 2 oder 3 zusätzliches Byte + ein Leerzeichen (oder Luft?) */
    if ((new_string = malloc(strlen(string) + (num_semicolon*phase) + 1)) == NULL) {
        logmsg(LOG_ERR, "FATAL: break_after_semicolon: malloc failed");
        return(NULL);
    }

    p_old = string;
    p_new = new_string;
    while (*p_old) { /* bis \0 */
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
            p_old++; /* Zeichen nach ; */
            if (*p_old != ' ')
                logmsg(LOG_ERR, "break_after_semicolon: no SPACE after ; in ->%s<-", string);
            p_old++; /* hoffentlich das <SPACE> */
        }
    }
    *p_new = '\0';
    logmsg(LOG_DEBUG, "break_after_semicolon: replaced ->%s<- with ->%s<-", string, new_string);
    free(string);
    return (new_string);
}
