#include "usage.h"

#include "auth_signing.h"

void usage(void) {
    printf("\nUsage: %s [OPTIONS]\n", STR_PROGNAME);
    printf("Options are:\n");
    printf("  -a authtable    optional CDB table that maps an authenticated SMTP\n");
    printf("                  identity to the signing identities it is allowed to use\n");
    printf("                  default: none\n");
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
    printf("                  - redis://[password@]host:port/db\n");
    printf("                  - rediss://[password@]host:port/db?verify=peer\n");
    printf("                    (TLS 1.2+; verify={none,peer}; default peer)\n");
    printf("                    verify_name= sets the expected server identity\n");
    printf("                    sni= sets only the TLS SNI extension\n");
    printf("                    cacert=/capath=/cert=/key= for CA and mTLS\n");
    printf("                    cert= may include the leaf plus intermediate chain\n");
    printf("                    IPv6 hosts must be bracketed: rediss://[::1]:6380/0\n");
    printf("                  - unix:///path/to/redis.sock\n");
    printf("                  default: none\n");
    printf("  -R              enable Redis-backed auth-signing table (requires -r)\n");
    printf("                  uses the key prefix set with -P under the auth: namespace\n");
    printf("                  default: off\n");
    printf("  -s socket       Milter socket in sendmail notation\n");
    printf("                  - unix|local:PATH\n");
    printf("                  - inet:PORT[@HOST]\n");
    printf("                  - inet6:PORT[@HOST]\n");
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
