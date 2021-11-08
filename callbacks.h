/*
 * signing-milter - callbacks.h
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

#ifndef _CALLBACKS_H_INCLUDED_
#define _CALLBACKS_H_INCLUDED_

#include <assert.h>
#include <libmilter/mfapi.h>
#include <openssl/pkcs7.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>

#include "signing-milter.h"

#include "stats.h"
#include "ctxdata/ctxdata.h"
#include "utils/utils.h"

extern struct smfiDesc callbacks;

sfsistat callback_envfrom(SMFICTX* ctx, char** argv);
sfsistat callback_envrcpt(SMFICTX* ctx, char** argv);
sfsistat callback_header(SMFICTX* ctx, char* headerf, char* headerv);
sfsistat callback_eoh(SMFICTX *ctx);
sfsistat callback_body(SMFICTX* ctx, unsigned char *bodyp, size_t len);
sfsistat callback_eom(SMFICTX* ctx);
sfsistat callback_abort(SMFICTX* ctx);
sfsistat callback_close(SMFICTX* ctx);

#endif
