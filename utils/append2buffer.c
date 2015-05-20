/*
 * signing-milter - utils/append2buffer.c
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

#include "append2buffer.h"

int append2buffer(unsigned char** buf, size_t* buf_size, char* data2append, size_t append_data_size) {

    unsigned char*  new_buf;
    size_t          new_buf_size;
    unsigned char*  append_pointer;

    new_buf_size = *buf_size + append_data_size;
    new_buf = realloc(*buf, new_buf_size);
    if (new_buf == NULL) {
        logmsg(LOG_ERR, "append2buffer: realloc failed\n");
        return(1);
    }

    append_pointer = new_buf + *buf_size;
    *buf = new_buf;
    *buf_size = new_buf_size;

    memcpy(append_pointer, data2append, append_data_size);

    return(0);
}
