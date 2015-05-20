/*
 * signing-milter - utils/logmsg.c
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

#include "logmsg.h"

void logmsg(int priority, const char *fmt, ...) {

    char    buf[LOG_MAXLOGBUF];
    va_list ap;

    if (priority <= opt_loglevel || priority <= LOG_WARNING) {

        /* Format message */
        va_start(ap, fmt);
        (void) vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        /* Write message to syslog */
        syslog(priority, "%s", buf);

        /* Print message to terminal */
        if (opt_loglevel >= LOG_DEBUG || priority <= LOG_WARNING) {
            fprintf(stdout, "%s\n", buf);
        }
    }
}
