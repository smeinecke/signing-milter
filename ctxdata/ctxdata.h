/*
 * signing-milter - ctxdata/ctxdata.h
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

#ifndef _CTXDATA_H_INCLUDED_
#define _CTXDATA_H_INCLUDED_

#include <openssl/ssl.h>

#include "../signing-milter.h"

extern void ctxdata_cleanup(CTXDATA* ctxdata);
extern CTXDATA* ctxdata_create(void);
extern void ctxdata_free(CTXDATA* ctxdata);
extern int ctxdata_setup(CTXDATA* ctxdata, const char* pemfilename);

#endif
