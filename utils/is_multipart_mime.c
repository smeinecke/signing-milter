/*
 * signing-milter - utils/is_multipart_mime.c
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

#include "is_multipart_mime.h"

/*
 * testet, ob ein Content-Type Header auf multipart lautet.
 */
int is_multipart_mime(char* headerf, char* headerv) {

    if (strcasecmp(headerf, "content-type"))
        return (0);

    if (strstr(headerv, "multipart/") != NULL)
        return (1);

    return (0);
}
