/*
 * signing-milter - utils/lowercase.c
 * Copyright (C) 2011-2018  Andreas Schulze
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
 *      postfix/src/utils/{lowercase.c,sys_defs.h} by
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 *
 */

#include "lowercase.h"

char *lowercase(char *string)
{
    char   *cp;
    int     ch;

    for (cp = string; (ch = *(unsigned char *) cp) != 0; cp++)
	if (isupper(ch))
	    *(unsigned char *) cp = tolower(ch);
    return (string);
}
