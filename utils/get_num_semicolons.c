/*
 * signing-milter - utils/get_num_semicolons.c
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

#include "get_num_semicolons.h"

/*
 * count the number of semicolons in a string
 *
 * argument: pointer to a null-terminated string
 * return:   number of semicolons
 *           -1 if the argument is a NULL pointer
 * bugs    : integer overflow if more than sizeof(int)/2 - 1
 *           semicolons occur in the string
 */
int get_num_semicolons(char* string) {

    int num_semicolon = 0;
    char* p;

    if (string == NULL) {
        logmsg(LOG_ERR, "FATAL: get_num_semikolons failed: got empty string");
        return(-1);
    }

    p = string;
    while (*p) { /* until \0 */
        if (*p == ';')
            num_semicolon++;
        p++;
    }
    logmsg(LOG_DEBUG, "get_num_semicolons: %i Semicolon in ->%s<-", num_semicolon, string);
    return(num_semicolon);
}
