/*
 * signing-milter - utils/usage.c
 * Copyright (C) 2010,2015  Andreas Schulze
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

#include "usage.h"

void usage(void) {
    printf("\nUsage: %s [OPTIONS]\n", STR_PROGNAME);
    printf("Options are:\n");
    printf("  -h              show help and exit\n");
    printf("  -v              show version and exit\n");
    printf("  -c clientgroup  make a local socket accessible for clientgroup\n");
    printf("                  default: none\n");
    printf("  -d loglevel     set loglevel\n");
    printf("                  default: %i\n", opt_loglevel);
    printf("  -f              use mailheader %s to determine the signeraddress.\n", HEADERNAME_SIGNER);
    printf("  -g group        the group signing-milter should run as\n");
    printf("                  default: %s\n", opt_group);
    printf("  -k dir          keep tempfile in dir %s\n", opt_keepdir ? opt_keepdir : "");
    printf("                  default: none\n");
    printf("  -m signingtable full path to a lookuptable containing senderaddresses\n");
    printf("                  and corresponding signing keyfiles\n");
    printf("                  default: %s\n", opt_signingtable);
    printf("  -n modetable    full path to a lookuptable containing recipientaddresses\n");
    printf("                  for which the alternativ signingmode is enabled\n");
    printf("                  default: %s\n", opt_modetable);
    printf("  -s socket       Milter socket in sendmail notation\n");
    printf("                  - unix|local:PATH\n");
    printf("                  - inet:PORT[@HOST]\n");
    printf("                  - inet6:PORT[@HOST]\n");
    printf("                  default: %s\n", opt_miltersocket);
    printf("  -t timeout      timeout for MTA communication in seconds\n");
    printf("                  default: %i\n", opt_timeout);
    printf("  -u user         the user signing-milter should run as\n");
    printf("                  default: %s\n", opt_user);
    printf("  -x              add an X-Header to every signed mail\n");
    printf("                  default: %s\n", opt_addxheader ? "on" : "off");
    printf("\n");
}

void version(void) {
    printf("\n%s Version %s\n", STR_PROGNAME, STR_PROGVERSION);
    printf("\n");
}
