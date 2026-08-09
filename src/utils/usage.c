#include "usage.h"

#include "auth_signing.h"

void usage(void) {
    printf("\nUsage: %s [OPTIONS]\n", STR_PROGNAME);
    printf("Options are:\n");
    printf("  -a authtable    CDB table that maps an authenticated SMTP identity\n");
    printf("                  to the signing identities it is allowed to use.\n");
    printf("                  Required for authenticated-sender signing; without\n");
    printf("                  -a or -R no authenticated principal may sign.\n");
    printf("                  default: none\n");
    printf("  -h              show help and exit\n");
    printf("  -v              show version and exit\n");
    printf("  -c clientgroup  make a local socket accessible for clientgroup;\n");
    printf("                  use the magic value ':relax' to create a\n");
    printf("                  world-writable socket (insecure, test-only)\n");
    printf("                  default: none\n");
    printf("  -d loglevel     set loglevel\n");
    printf("                  default: %i\n", opt_loglevel);
    printf("  -f              use mailheader %s to determine the signeraddress.\n", HEADERNAME_SIGNER);
    printf("  -g group        the group signing-milter should run as\n");
    printf("  -I              allow an INET/INET6 milter socket (opt-in, dangerous:\n");
    printf("                  the Milter protocol has no peer authentication and\n");
    printf("                  loopback binding does not provide a trust boundary)\n");
    printf("                  default: off\n");
    printf("  -k dir          keep tempfile in dir %s\n", opt_keepdir ? opt_keepdir : "");
    printf("                  default: none\n");
    printf("  -l              log to STDOUT, don't use SYSLOG\n");
    printf("  -m signingtable full path to a lookuptable containing senderaddresses\n");
    printf("                  and corresponding signing keyfiles\n");
    printf("                  default: %s\n", opt_signingtable);
    printf("  -n modetable    full path to a lookuptable containing recipientaddresses\n");
    printf("                  for which the alternativ signingmode is enabled\n");
    printf("                  default: %s\n", opt_modetable);
    printf("  -P prefix       Redis key prefix for certificate and auth-signing lookup\n");
    printf("                  default: %s\n", opt_redis_prefix);
    printf("  -r uri          Redis URI for dynamic certificate lookup\n");
    printf("                  - rediss://host:port/db?verify=peer (TLS 1.2+)\n");
    printf("                    peer verification is mandatory; verify=peer is the\n");
    printf("                    default and only supported mode\n");
    printf("                    passwords must not appear in the URI; use -p or -C\n");
    printf("                    verify_name= sets the expected server identity\n");
    printf("                    sni= sets only the TLS SNI extension\n");
    printf("                    cacert=/capath=/cert=/key= for CA and mTLS\n");
    printf("                    cert= may include the leaf plus intermediate chain\n");
    printf("                    IPv6 hosts must be bracketed: rediss://[::1]:6380/0\n");
    printf("                  - unix:///path/to/redis.sock\n");
    printf("                    plaintext TCP (redis://) and verify=none are rejected\n");
    printf("                  default: none\n");
    printf("  -p file         file containing the Redis password; the password must\n");
    printf("                  not appear in the URI or command line\n");
    printf("                  default: none\n");
    printf("  -R              enable Redis-backed auth-signing table (requires -r)\n");
    printf("                  uses the key prefix set with -P under the auth: namespace\n");
    printf("                  default: off\n");
    printf("  -C file         file containing Redis username and password on two\n");
    printf("                  separate lines (first line is the username, second\n");
    printf("                  the password; a single line is treated as the password)\n");
    printf("                  default: none\n");
    printf("  -s socket       Milter socket in sendmail notation\n");
    printf("                  - unix|local:PATH (default, recommended)\n");
    printf("                  - inet:PORT[@HOST]   (requires -I)\n");
    printf("                  - inet6:PORT[@HOST]  (requires -I)\n");
    printf("                  default: %s\n", opt_miltersocket);
    printf("  -t timeout      timeout for MTA communication in seconds\n");
    printf("                  default: %i\n", opt_timeout);
    printf("  -u user         the user signing-milter should run as\n");
    printf("                  default: %s\n", opt_user);
    printf("  -W file         file containing the static passphrase for encrypted\n");
    printf("                  private keys loaded from Redis\n");
    printf("                  default: none\n");
    printf("  -x              add an X-Header to every signed mail\n");
    printf("                  default: %s\n", opt_addxheader ? "on" : "off");
    printf("\n");
}

void version(void) {
    printf("\n%s Version %s\n", STR_PROGNAME, STR_PROGVERSION);
    printf("\n");
}
