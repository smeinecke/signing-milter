/*
 * signing-milter - main.h
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

#ifndef _MAIN_H_INCLUDED_
#define _MAIN_H_INCLUDED_

#include <grp.h>
#include <pwd.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include "signing-milter.h"

#include "callbacks.h"
#include "main.h"
#include "stats.h"
#include "utils/utils.h"

/* parameter fuer smfi_opensocket */
#define REMOVE_EXISTING_SOCKETS 1

#ifdef DMALLOC
#include <dmalloc.h>
#endif

int main(int argc, char** argv);
void sig_handler(int signal);

#endif
