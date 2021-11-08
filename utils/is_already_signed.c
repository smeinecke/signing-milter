/*
 * signing-milter - utils/is_already_signed.c
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

#include "is_already_signed.h"

/* TODO: diese Funktion geht davon aus, dass in einer Mail die
 *       Header immer aus kleinbuchstaben bestehen
 */
int is_already_signed(char* headerf, char* headerv) {

    if (strcasecmp(headerf, "content-type"))
        return (0);

    if (strstr(headerv, "multipart/signed") == NULL)
        return (0);

    if (strstr(headerv, "pkcs7-signature") == NULL)
        return (0);

    logmsg(LOG_DEBUG, "is_already_signed: header indicates message already signed");
    return (1);
}
