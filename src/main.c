#include <unistd.h>

#include "main.h"

/* set default values */
const char* opt_clientgroup  = NULL;
int         opt_loglevel     = LOG_NOTICE;
int         opt_logdest      = LOG_DEST_SYSLOG;
const char* opt_group        = "signing-milter";
const char* opt_keepdir      = NULL;
const char* opt_signingtable = "/etc/signing-milter/signingtable.cdb";
const char* opt_modetable    = NULL;
static char opt_miltersocket_default[] = "inet6:30053@[::1]";
char*       opt_miltersocket = opt_miltersocket_default;
int         opt_timeout      = 600;
const char* opt_user         = "signing-milter";
int         opt_addxheader   = 0;
int         opt_signerfromheader = 0;

const char* opt_redis_uri = NULL;
const char* opt_redis_prefix = "signing-milter:";
const char* opt_redis_passphrase = NULL;
static int  opt_signingtable_explicit = 0;

/* writable strings for libmilter calls */
char STR_PROGNAME[]      = "signing-milter";
char HEADERNAME_XHEADER[]      = "X-Signed-by";
char HEADERNAME_SIGNER[]       = "X-Signer";
char HEADERNAME_SKIP_SIGNING[] = "X-Skip-Signing";

/* global variables */
struct DICT dict_signingtable = {
    "signingtable",      /* name       */
    DICT_FLAG_TRY0NULL,  /* flags      */
    -1,                  /* stat_fd    */
    0,                   /* mtime      */
    CDB_STATIC_INIT,     /* cdb        */
    NULL,                /* buffer     */
    NULL,                /* result     */
    0,                   /* result_len */
    NULL                 /* cdb_path   */
};
struct DICT dict_modetable = {
    "modetable",         /* name       */
    DICT_FLAG_TRY0NULL,  /* flags      */
    -1,                  /* stat_fd    */
    0,                   /* mtime      */
    CDB_STATIC_INIT,     /* cdb        */
    NULL,                /* buffer     */
    NULL,                /* result     */
    0,                   /* result_len */
    NULL                 /* cdb_path   */
};


int main(int argc, char** argv) {
    int            c;
    char*          p;
    uid_t          uid, gid, client_gid, root_gid;
    struct passwd* pw;
    struct group*  gr;
    struct stat    st;
    int            localsocket = 1;
    mode_t         socket_mode;
    const char*    socket_mode_str;


    /*
     * compiler warning: "client_gid may be used uninitialized"
     * no one wants that ...
     */
    client_gid = 0;

    while ((c = getopt(argc, argv, "bc:d:hfg:k:lm:n:P:r:s:t:u:vxW:")) > 0) {
        switch (c) {
        case 'b': /* break contentheader */
            logmsg(LOG_INFO, "option -b is ignored for compatibily reasons, you may remove it safely");
            break;
        case 'c': /* clientgroup */
            opt_clientgroup = optarg;
            if (strcmp(opt_clientgroup, ":relax") != 0) {
              if ((gr = getgrnam(opt_clientgroup)) == NULL) {
                  logmsg(LOG_ERR, "unknown clientgroup: getgrnam(%s) failed", opt_group);
                  exit(EX_DATAERR);
              }
              client_gid = gr->gr_gid;
            }
            break;
        case 'd': /* log level */
            opt_loglevel = (int) strtoul(optarg, &p, 10);
            if (p != NULL && *p != '\0') {
                printf("debug-level is not valid integer: %s\n", optarg);
                exit(EX_DATAERR);
            }
            p = NULL;
            if (opt_loglevel < 0 || opt_loglevel > 7) {
                printf("loglevel out of range 0..7: %i\n", opt_loglevel);
                exit(EX_DATAERR);
            }
            break;
        case 'f': /* signer from header, not from envelope */
            opt_signerfromheader = 1;
            break;
        case 'g': /* group */
            opt_group = optarg;
            if (getgrnam(opt_group) == NULL) {
                printf("unknown group: getgrnam(%s) failed", opt_group);
                exit(EX_DATAERR);
            }
            break;
        case 'k': /* keepdir */
            opt_keepdir = optarg;
            if (stat(opt_keepdir, &st) < 0) {
                printf("directory to keep data: %s: %s", opt_keepdir, strerror(errno));
                exit(EX_DATAERR);
            }
            if (!S_ISDIR(st.st_mode)) {
                printf("directory to keep data: %s is not a directory", opt_keepdir);
                exit(EX_DATAERR);
            }
            /* access permissions will be checked later, after switching to the correct uid */
            break;
        case '?': /* help */
        case 'h':
            usage();
            exit(EX_OK);
        case 'l': /* switch log destination from SYSLOG (default) to STDOUT */
            opt_logdest = LOG_DEST_STDOUT;
            break;
        case 'm': /* signing table CDB filename */
            opt_signingtable = optarg;
            opt_signingtable_explicit = 1;
            break;
        case 'n': /* mode table CDB filename */
            opt_modetable = optarg;
            break;
        case 'P': /* Redis key prefix */
            opt_redis_prefix = optarg;
            break;
        case 'r': /* Redis URI */
            opt_redis_uri = optarg;
            break;
        case 's': /* milter socket */
            opt_miltersocket = optarg;
            break;
        case 't': /* Timeout */
            opt_timeout = (int) strtoul(optarg, &p, 10);
            if (p != NULL && *p != '\0') {
                printf("timeout is not valid integer: %s\n", optarg);
                exit(EX_DATAERR);
            }
            p = NULL;
            if (opt_timeout < 0 ) {
                printf("negative milter connection timeout: %i\n", opt_timeout);
                exit(EX_DATAERR);
            }
            break;
        case 'u': /* user */
            opt_user = optarg;
            /* get passwd/group entries for opt_user and opt_group */
            if (getpwnam(opt_user) == NULL) {
                logmsg(LOG_ERR, "unknown user: getpwnam(%s) failed", opt_user);
                exit(EX_DATAERR);
            }
            break;
        case 'v': /* Version */
            version();
            exit(EX_OK);
        case 'W': /* Redis static passphrase file */
            {
                int fd;
                ssize_t r;
                size_t len;
                char buf[4096];

                if ((fd = open(optarg, O_RDONLY)) < 0) {
                    logmsg(LOG_ERR, "cannot open passphrase file %s: %s", optarg, strerror(errno));
                    exit(EX_DATAERR);
                }
                r = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                if (r < 0) {
                    logmsg(LOG_ERR, "cannot read passphrase file %s: %s", optarg, strerror(errno));
                    exit(EX_DATAERR);
                }
                buf[r] = '\0';
                len = strlen(buf);
                if (len > 0 && buf[len - 1] == '\n')
                    buf[len - 1] = '\0';

                opt_redis_passphrase = strdup(buf);
                if (opt_redis_passphrase == NULL) {
                    logmsg(LOG_ERR, "strdup(passphrase) failed: %s", strerror(errno));
                    exit(EX_SOFTWARE);
                }
            }
            break;
        case 'x': /* add X-Header */
            opt_addxheader = (int) !opt_addxheader;
            break;
        default:
            usage();
            exit(EX_USAGE);
        }
    }

    /* open syslog */
    if (LOG_DEST_SYSLOG == opt_logdest)
        openlog(STR_PROGNAME, LOG_PID, LOG_MAIL);

    /* say helo */
    logmsg(LOG_NOTICE, "starting %s %s listening on %s, loglevel %i",
               STR_PROGNAME, STR_PROGVERSION, opt_miltersocket, opt_loglevel);

    /* force a new processgroup */
    if ((setsid() == -1))
        logmsg(LOG_DEBUG, "ignoring that setsid() failed");

    if (opt_timeout > 0 && smfi_settimeout(opt_timeout) != MI_SUCCESS) {
        logmsg(LOG_ERR, "could not set milter timeout");
        exit(EX_SOFTWARE);
    }
    logmsg(LOG_INFO, "miltertimeout set to %i", opt_timeout);

    if (smfi_setconn(opt_miltersocket) != MI_SUCCESS) {
        logmsg(LOG_ERR, "could not set milter socket");
        exit(EX_SOFTWARE);
    }

    if (smfi_register(callbacks) != MI_SUCCESS) {
        logmsg(LOG_ERR, "could not register milter");
        exit(EX_SOFTWARE);
    }

    /*
     * user and group names are now fixed. test whether they exist
     * and determine uid / gid
     */
    if ((pw = getpwnam(opt_user)) == NULL) {
        logmsg(LOG_ERR, "unknown user: getpwnam(%s) failed", opt_user);
        exit(EX_DATAERR);
    }
    uid = pw->pw_uid;
    if ((gr = getgrnam(opt_group)) == NULL) {
        logmsg(LOG_ERR, "unknown group: getgrnam(%s) failed", opt_group);
        exit(EX_SOFTWARE);
    }
    gid = gr->gr_gid;

    /* if not specified as a parameter, a Unix socket initially belongs to the same group */
    if (opt_clientgroup == NULL)
        client_gid = gid;

    /* :relax allows every client to use the socket; nevertheless chown() must
     * work for the process group, even if signing-milter is not running as root
     * (e.g. in local tests). */
    if (opt_clientgroup != NULL && strcmp(opt_clientgroup, ":relax") == 0)
        client_gid = gid;

    /* if 'inet' is found in optarg *and* right at the beginning,
     * then it is not a local socket */
    if (((p = strstr(opt_miltersocket, "inet")) != NULL) && opt_miltersocket == p)
        localsocket = 0;

    if (localsocket == 1) {
        /* open the socket */
        if (smfi_opensocket(REMOVE_EXISTING_SOCKETS) != MI_SUCCESS) {
            logmsg(LOG_ERR, "could not open milter socket %s", opt_miltersocket);
            exit(EX_SOFTWARE);
        }
        /* test whether the socket now exists */
        p = opt_miltersocket + strlen("local:");
        if (stat(p, &st) < 0) {
            p = opt_miltersocket + strlen("unix:");
            if (stat(p, &st) < 0) {
                logmsg(LOG_ERR, "miltersocket does not exist: %m", strerror(errno));
                exit(EX_DATAERR);
            }
        }

        /* gid of the root group */
        if ((gr = getgrnam("root")) == NULL) {
            logmsg(LOG_ERR, "unknown rootgroup: getgrnam(root) failed");
            exit(EX_SOFTWARE);
        }
        root_gid = gr->gr_gid;

        /* clientgroup must be != root and != opt_group */
        if (((client_gid == gid) || (client_gid == root_gid)) && (opt_clientgroup != NULL) && strcmp(opt_clientgroup, ":relax") != 0) {
            logmsg(LOG_ERR, "clientgroup %s must be neither %s nor %s", opt_clientgroup, "root", opt_group);
            exit(EX_DATAERR);
        }

        /* now set the permissions */
        if (chown(p, uid, client_gid) != 0) {
            logmsg(LOG_ERR, "chown(%s, %i, %i) failed: %m", p, uid, client_gid, strerror(errno));
            exit(EX_SOFTWARE);
        }

        socket_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
        socket_mode_str = "0660";
        if ((opt_clientgroup != NULL) && strcmp(opt_clientgroup, ":relax") == 0) {
          socket_mode = socket_mode | S_IROTH | S_IWOTH;
          socket_mode_str = "0666";
        }

        if (chmod(p, socket_mode) != 0) {
            logmsg(LOG_ERR, "chmod(%s, %s) failed: %m", p, socket_mode_str, strerror(errno));
            exit(EX_SOFTWARE);
        }

        logmsg(LOG_INFO, "changed socket %s to owner/group: %i/%i, mode: %s", opt_miltersocket, uid, client_gid, socket_mode_str);
    }

    /* set gid/uid */
    if (setgid(gid) != 0) {
        logmsg(LOG_ERR, "setgid(%i) failed: %s", gr->gr_gid, strerror(errno));
        exit(EX_SOFTWARE);
    }
    if (setgroups(0, NULL) != 0) {
        if (errno == EPERM) {
            logmsg(LOG_INFO, "setgroups(0, NULL) not permitted, continuing");
        } else {
            logmsg(LOG_ERR, "setgroups(0, NULL) failed: %s", strerror(errno));
            exit(EX_SOFTWARE);
        }
    }
    if (setuid(uid) != 0) {
        logmsg(LOG_ERR, "setuid(%i) failed: %s", pw->pw_uid, strerror(errno));
        exit(EX_SOFTWARE);
    }

    /* check and log the current uid/gid */
    uid = getuid();
    gid = getgid();
    if (uid == 0 || gid == 0) {
        logmsg(LOG_ERR, "too much privileges, %s will not start under root", STR_PROGNAME);
        exit(EX_DATAERR);
    }
    logmsg(LOG_INFO, "running as uid: %i, gid: %i", (int) uid, (int) gid);

    if (opt_keepdir != NULL) {
        if (stat(opt_keepdir, &st) < 0) {
            logmsg(LOG_ERR, "directory to keep data: %s: %m", opt_keepdir, strerror(errno));
            exit(EX_DATAERR);
        }
        if (!S_ISDIR(st.st_mode)) {
            logmsg(LOG_ERR, "directory to keep data: %s is not a directory", opt_keepdir);
            exit(EX_DATAERR);
        }
        if (S_IRWXO & st.st_mode) {
            logmsg(LOG_ERR, "directory to keep data: %s: permissions too open: remove any access for other", opt_keepdir);
            exit(EX_DATAERR);
        }
        if (access(opt_keepdir, R_OK) < 0 && errno == EACCES) {
            logmsg(LOG_ERR, "directory to keep data: %s: permissions too strong: no read access", opt_keepdir);
            exit(EX_DATAERR);
        }
        if (access(opt_keepdir, W_OK) < 0 && errno == EACCES) {
            logmsg(LOG_ERR, "directory to keep data: %s: permissions too strong: no write access", opt_keepdir);
            exit(EX_DATAERR);
        }
        if (access(opt_keepdir, X_OK) < 0 && errno == EACCES) {
            logmsg(LOG_ERR, "directory to keep data: %s: permissions too strong: no execute access", opt_keepdir);
            exit(EX_DATAERR);
        }
        logmsg(LOG_INFO, "directory to keep data: %s", opt_keepdir);
    }

    if (opt_redis_uri != NULL && *opt_redis_uri != '\0' &&
        !opt_signingtable_explicit &&
        access(opt_signingtable, F_OK) < 0) {
        logmsg(LOG_INFO, "signingtable %s not found, skipping CDB fallback because Redis is configured", opt_signingtable);
    } else {
        dict_open(opt_signingtable, &dict_signingtable);
    }

    if (opt_modetable)
        dict_open(opt_modetable, &dict_modetable);

    if (redis_global_init() < 0)
        exit(EX_SOFTWARE);

    /* initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* get meaningful error messages */
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    /* initialize statistics */
    init_stats();

    /* signal handlers */
    signal(SIGALRM, sig_handler);

    /* Run milter */
    if ((c = smfi_main()) != MI_SUCCESS)
        logmsg(LOG_ERR, "Milter startup failed");
    else
        logmsg(LOG_NOTICE, "stopping %s %s listening on %s", STR_PROGNAME, STR_PROGVERSION, opt_miltersocket);

    redis_global_cleanup();

    dict_close(&dict_signingtable);
    if (opt_modetable)
        dict_close(&dict_modetable);

    /* cleanup OpenSSL */
    ERR_free_strings();
    EVP_cleanup();

    output_stats();

#ifdef DMALLOC
    dmalloc_log_stats();
    dmalloc_log_unfreed();
    dmalloc_shutdown();
#endif
    exit(c);
}

/* under Linux a sighandler must reenable itself */
void sig_handler(int sig) {

    logmsg(LOG_INFO, "%s: signal %i received", STR_PROGNAME, sig);
    signal(sig, sig_handler);

    output_stats();
    reset_stats();

#ifdef DMALLOC
    logmsg(LOG_DEBUG, "%s: dumping dmalloc statistics", STR_PROGNAME);
    dmalloc_log_stats();
    dmalloc_log_unfreed();
#endif
}
