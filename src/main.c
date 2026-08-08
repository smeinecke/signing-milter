/* For fchownat/fchmodat/fstatat with AT_SYMLINK_NOFOLLOW */
#define _GNU_SOURCE

#include <unistd.h>

#include "main.h"
#include <openssl/crypto.h>
#include "utils/auth_signing.h"

/* set default values */
const char* opt_clientgroup  = NULL;
int         opt_loglevel     = LOG_NOTICE;
int         opt_logdest      = LOG_DEST_SYSLOG;
const char* opt_group        = "signing-milter";
const char* opt_keepdir      = NULL;
const char* opt_signingtable = "/etc/signing-milter/signingtable.cdb";
const char* opt_modetable    = NULL;
static char opt_miltersocket_default[] = "unix:/run/signing-milter/signing-milter.sock";
char*       opt_miltersocket = opt_miltersocket_default;
int         opt_allow_inet = 0;
int         opt_timeout      = 600;
const char* opt_user         = "signing-milter";
int         opt_addxheader   = 0;
int         opt_signerfromheader = 0;

const char* opt_redis_uri = NULL;
const char* opt_redis_prefix = "signing-milter:";
const char* opt_redis_passphrase = NULL;
const char* opt_redis_password_file = NULL;
const char* opt_redis_credentials_file = NULL;
char*       opt_redis_password = NULL;
char*       opt_redis_username = NULL;
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
    NULL                 /* cdb_path   */
};
struct DICT dict_modetable = {
    "modetable",         /* name       */
    DICT_FLAG_TRY0NULL,  /* flags      */
    -1,                  /* stat_fd    */
    0,                   /* mtime      */
    CDB_STATIC_INIT,     /* cdb        */
    NULL,                /* buffer     */
    NULL                 /* cdb_path   */
};

/* statistics signal watcher thread */
static pthread_t stats_thread;

#define MAX_REDIS_SECRET_SIZE 4096

/*
 * Read a single secret from a file.  The file must not be a symlink, must be
 * readable by the milter process, and must not be overly permissive.  The
 * returned string is NUL terminated and has any trailing newline removed; the
 * caller is responsible for clearing and freeing it.
 */
static char* read_redis_password_file(const char* path, uid_t milter_uid, gid_t milter_gid) {
    int         fd;
    struct stat st;
    char*       buf = NULL;
    ssize_t     n;
    size_t      len;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        logmsg(LOG_ERR, "cannot open Redis password file %s: %s", path, strerror(errno));
        return NULL;
    }

    if (fstat(fd, &st) < 0) {
        logmsg(LOG_ERR, "cannot stat Redis password file %s: %s", path, strerror(errno));
        close(fd);
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        logmsg(LOG_ERR, "Redis password file %s is not a regular file", path);
        close(fd);
        return NULL;
    }
    if (st.st_uid != 0 && st.st_uid != milter_uid) {
        logmsg(LOG_ERR, "Redis password file %s must be owned by root or the milter user", path);
        close(fd);
        return NULL;
    }
    if (st.st_mode & S_IWOTH) {
        logmsg(LOG_ERR, "Redis password file %s must not be world-writable", path);
        close(fd);
        return NULL;
    }
    if (st.st_mode & S_IWGRP) {
        logmsg(LOG_ERR, "Redis password file %s must not be group-writable", path);
        close(fd);
        return NULL;
    }
    if (st.st_mode & S_IROTH) {
        logmsg(LOG_ERR, "Redis password file %s must not be world-readable", path);
        close(fd);
        return NULL;
    }
    if ((st.st_mode & S_IRGRP) && st.st_gid != milter_gid) {
        logmsg(LOG_ERR, "Redis password file %s must not be group-readable by an untrusted group", path);
        close(fd);
        return NULL;
    }
    if (st.st_size > MAX_REDIS_SECRET_SIZE) {
        logmsg(LOG_ERR, "Redis password file %s is too large", path);
        close(fd);
        return NULL;
    }

    buf = malloc((size_t) st.st_size + 1);
    if (buf == NULL) {
        logmsg(LOG_ERR, "cannot allocate buffer for Redis password file %s: %s", path, strerror(errno));
        close(fd);
        return NULL;
    }

    n = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (n < 0) {
        logmsg(LOG_ERR, "cannot read Redis password file %s: %s", path, strerror(errno));
        OPENSSL_cleanse(buf, (size_t) st.st_size + 1);
        free(buf);
        return NULL;
    }
    buf[n] = '\0';

    if (n != st.st_size) {
        logmsg(LOG_ERR, "Redis password file %s changed size while reading", path);
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
        return NULL;
    }

    if (memchr(buf, '\0', (size_t) n) != NULL) {
        logmsg(LOG_ERR, "Redis password file %s contains embedded NUL bytes", path);
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
        return NULL;
    }

    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[--len] = '\0';
    if (len > 0 && buf[len - 1] == '\r')
        buf[--len] = '\0';

    if (len == 0) {
        logmsg(LOG_ERR, "Redis password file %s is empty", path);
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
        return NULL;
    }

    return buf;
}

/*
 * Read a credentials file containing up to two non-empty lines.  The first
 * line is the Redis username and the second line is the password.  If only
 * one line is present, it is treated as the password (useful for ACL users
 * without a username).  The on-disk copy of the password is cleared before
 * freeing the temporary read buffer.
 */
static int read_redis_credentials_file(const char* path, uid_t milter_uid, gid_t milter_gid) {
    int         fd;
    struct stat st;
    char*       buf = NULL;
    char*       line;
    char*       saveptr = NULL;
    const char* seps = "\r\n";
    ssize_t     n;
    size_t      len;
    char*       parts[2] = { NULL, NULL };
    int         count = 0;
    int         i;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        logmsg(LOG_ERR, "cannot open Redis credentials file %s: %s", path, strerror(errno));
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        logmsg(LOG_ERR, "cannot stat Redis credentials file %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        logmsg(LOG_ERR, "Redis credentials file %s is not a regular file", path);
        close(fd);
        return -1;
    }
    if (st.st_uid != 0 && st.st_uid != milter_uid) {
        logmsg(LOG_ERR, "Redis credentials file %s must be owned by root or the milter user", path);
        close(fd);
        return -1;
    }
    if (st.st_mode & S_IWOTH) {
        logmsg(LOG_ERR, "Redis credentials file %s must not be world-writable", path);
        close(fd);
        return -1;
    }
    if (st.st_mode & S_IWGRP) {
        logmsg(LOG_ERR, "Redis credentials file %s must not be group-writable", path);
        close(fd);
        return -1;
    }
    if (st.st_mode & S_IROTH) {
        logmsg(LOG_ERR, "Redis credentials file %s must not be world-readable", path);
        close(fd);
        return -1;
    }
    if ((st.st_mode & S_IRGRP) && st.st_gid != milter_gid) {
        logmsg(LOG_ERR, "Redis credentials file %s must not be group-readable by an untrusted group", path);
        close(fd);
        return -1;
    }
    if (st.st_size > MAX_REDIS_SECRET_SIZE) {
        logmsg(LOG_ERR, "Redis credentials file %s is too large", path);
        close(fd);
        return -1;
    }

    buf = malloc((size_t) st.st_size + 1);
    if (buf == NULL) {
        logmsg(LOG_ERR, "cannot allocate buffer for Redis credentials file %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    n = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (n < 0) {
        logmsg(LOG_ERR, "cannot read Redis credentials file %s: %s", path, strerror(errno));
        OPENSSL_cleanse(buf, (size_t) st.st_size);
        free(buf);
        return -1;
    }
    buf[n] = '\0';

    if (n != st.st_size) {
        logmsg(LOG_ERR, "Redis credentials file %s changed size while reading", path);
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
        return -1;
    }

    if (memchr(buf, '\0', (size_t) n) != NULL) {
        logmsg(LOG_ERR, "Redis credentials file %s contains embedded NUL bytes", path);
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
        return -1;
    }

    for (line = strtok_r(buf, seps, &saveptr);
         line != NULL && count < 2;
         line = strtok_r(NULL, seps, &saveptr)) {
        while (*line == ' ' || *line == '\t')
            ++line;
        if (*line == '\0' || *line == '#')
            continue;
        parts[count] = strdup(line);
        if (parts[count] == NULL) {
            logmsg(LOG_ERR, "strdup(credentials) failed: %s", strerror(errno));
            for (i = 0; i < count; i++)
                free(parts[i]);
            OPENSSL_cleanse(buf, (size_t) n);
            free(buf);
            return -1;
        }
        count++;
    }

    if (count == 0) {
        logmsg(LOG_ERR, "Redis credentials file %s contains no credentials", path);
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
        return -1;
    }

    if (count == 1) {
        opt_redis_password = parts[0];
        opt_redis_username = NULL;
    } else {
        opt_redis_username = parts[0];
        opt_redis_password = parts[1];
    }

    if (buf != NULL) {
        OPENSSL_cleanse(buf, (size_t) n);
        free(buf);
    }

    return 0;
}

int main(int argc, char** argv) {
    int            c;
    char*          p;
    uid_t          uid, gid, client_gid, root_gid;
    struct passwd* pw;
    struct group*  gr;
    struct stat    st;
    struct stat    dir_st;
    int            localsocket = 1;
    mode_t         socket_mode;
    const char*    socket_mode_str;



    /*
     * compiler warning: "client_gid may be used uninitialized"
     * no one wants that ...
     */
    client_gid = 0;

    while ((c = getopt(argc, argv, "a:bc:d:hfg:k:Il:m:n:p:P:Rr:s:t:u:vxW:C:")) > 0) {
        switch (c) {
        case 'a': /* auth-signing table CDB filename */
            opt_auth_signing_table = optarg;
            break;
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
        case 'I': /* allow INET milter socket (opt-in, no cryptographic peer auth) */
            opt_allow_inet = 1;
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
        case 'p': /* Redis password file */
            opt_redis_password_file = optarg;
            break;
        case 'R': /* Redis auth-signing table */
            opt_redis_auth_signing_table = 1;
            break;
        case 'r': /* Redis URI */
            opt_redis_uri = optarg;
            break;
        case 'C': /* Redis credentials file (username + password) */
            opt_redis_credentials_file = optarg;
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

    if (opt_redis_auth_signing_table) {
#ifndef WITH_REDIS
        logmsg(LOG_ERR, "Redis auth-signing table requested but Redis support is not compiled in");
        exit(EX_SOFTWARE);
#else
        if (opt_redis_uri == NULL || *opt_redis_uri == '\0') {
            logmsg(LOG_ERR, "Redis auth-signing table requires a Redis URI (-r)");
            exit(EX_DATAERR);
        }
#endif
    }

    if (opt_auth_signing_table != NULL && opt_redis_auth_signing_table) {
        logmsg(LOG_WARNING, "both local (-a) and Redis (-R) auth-signing tables configured; using local table");
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

    /*
     * The milter protocol has no peer authentication.  Network sockets are
     * disabled by default; they require an explicit opt-in and must still be
     * bound to loopback so they are not exposed to arbitrary clients.
     */
    if (localsocket == 0) {
        if (!opt_allow_inet) {
            logmsg(LOG_ERR, "milter network socket %s is not allowed by default; use -I only if no untrusted clients can reach it, or use a Unix-domain socket", opt_miltersocket);
            exit(EX_DATAERR);
        }

        logmsg(LOG_WARNING, "INET milter socket selected: the Milter protocol has no peer authentication and loopback binding is NOT a substitute for a Unix-domain socket trust boundary");

        const char* at = strrchr(opt_miltersocket, '@');
        const char* host = at ? at + 1 : NULL;

        if (host == NULL ||
            !(strcmp(host, "127.0.0.1") == 0 ||
              strcmp(host, "[::1]") == 0 ||
              strcmp(host, "::1") == 0 ||
              strcmp(host, "localhost") == 0 ||
              strcmp(host, "localhost.localdomain") == 0)) {
            logmsg(LOG_ERR, "milter network socket %s must be bound to a loopback address; use a Unix-domain socket for untrusted clients", opt_miltersocket);
            exit(EX_DATAERR);
        }
    }

    if (localsocket == 1) {
        const char* socket_path;
        const char* socket_base;
        char*       socket_path_copy = NULL;
        char*       slash;
        const char* socket_dir;
        int         socket_dirfd;

        /* open the socket */
        if (smfi_opensocket(REMOVE_EXISTING_SOCKETS) != MI_SUCCESS) {
            logmsg(LOG_ERR, "could not open milter socket %s", opt_miltersocket);
            exit(EX_SOFTWARE);
        }

        /*
         * Resolve the socket path unambiguously from the libmilter socket
         * specification (CWE-367 / prefix confusion).
         */
        if (strncmp(opt_miltersocket, "local:", 6) == 0)
            socket_path = opt_miltersocket + 6;
        else if (strncmp(opt_miltersocket, "unix:", 5) == 0)
            socket_path = opt_miltersocket + 5;
        else {
            logmsg(LOG_ERR, "milter socket is not a local/unix socket: %s", opt_miltersocket);
            exit(EX_DATAERR);
        }

        if (socket_path[0] != '/') {
            logmsg(LOG_ERR, "milter Unix socket path must be absolute: %s", socket_path);
            exit(EX_DATAERR);
        }

        socket_path_copy = strdup(socket_path);
        if (socket_path_copy == NULL) {
            logmsg(LOG_ERR, "strdup(socket_path) failed: %s", strerror(errno));
            exit(EX_SOFTWARE);
        }

        slash = strrchr(socket_path_copy, '/');
        if (slash != NULL) {
            if (slash == socket_path_copy) {
                socket_dir = "/";
            } else {
                *slash = '\0';
                socket_dir = socket_path_copy;
            }
            socket_base = slash + 1;
        } else {
            /* absolute paths always contain a slash; this path is unreachable */
            socket_dir = ".";
            socket_base = socket_path_copy;
        }

        /*
         * Open the parent directory without following symlinks.  The directory
         * is the trust boundary; subsequent socket operations are safe only if
         * the directory cannot be renamed or replaced by an untrusted user
         * (CWE-367).
         */
        socket_dirfd = open(socket_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (socket_dirfd < 0) {
            logmsg(LOG_ERR, "could not open socket directory %s: %s", socket_dir, strerror(errno));
            free(socket_path_copy);
            exit(EX_DATAERR);
        }

        /*
         * The parent directory must be a trusted, non-writable boundary.  If an
         * untrusted user can rename entries here, fstatat/fchownat/fchmodat
         * would be subject to a TOCTOU race even with AT_SYMLINK_NOFOLLOW.
         */
        if (fstat(socket_dirfd, &dir_st) < 0) {
            logmsg(LOG_ERR, "could not stat socket directory %s: %s", socket_dir, strerror(errno));
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }
        if (!S_ISDIR(dir_st.st_mode)) {
            logmsg(LOG_ERR, "socket path parent is not a directory: %s", socket_dir);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }
        /*
         * If the startup process is privileged, the socket directory must be
         * owned by root.  A directory owned by the unprivileged daemon UID
         * would let a prior (compromised) daemon instance race the root-time
         * fstatat/fchownat/fchmodat sequence.
         */
        if (getuid() == 0 && dir_st.st_uid != 0) {
            logmsg(LOG_ERR, "socket directory %s must be owned by root when milter starts as root", socket_dir);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }

        if (dir_st.st_uid != 0 && dir_st.st_uid != uid) {
            logmsg(LOG_ERR, "socket directory %s must be owned by root or the milter user", socket_dir);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }
        if (dir_st.st_mode & S_IWOTH) {
            logmsg(LOG_ERR, "socket directory %s must not be world-writable", socket_dir);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }
        if ((dir_st.st_mode & S_IWGRP) &&
            !(dir_st.st_gid == gid ||
              (opt_clientgroup != NULL && dir_st.st_gid == client_gid))) {
            logmsg(LOG_ERR, "socket directory %s must not be group-writable by an untrusted group", socket_dir);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }

        /*
         * For a privileged startup the directory must not be group-writable by
         * a non-root group either; otherwise a process in that group can
         * rename the socket between smfi_opensocket() and fchownat().
         */
        if (getuid() == 0 && (dir_st.st_mode & S_IWGRP) && dir_st.st_gid != 0) {
            logmsg(LOG_ERR, "socket directory %s must not be group-writable by a non-root group when milter starts as root", socket_dir);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }

        /* Verify the created object is actually a socket and was not replaced. */
        if (fstatat(socket_dirfd, socket_base, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            logmsg(LOG_ERR, "milter socket does not exist: %s", strerror(errno));
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }
        if (!S_ISSOCK(st.st_mode)) {
            logmsg(LOG_ERR, "milter socket path is not a socket: %s", socket_path);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }

        /* gid of the root group */
        if ((gr = getgrnam("root")) == NULL) {
            logmsg(LOG_ERR, "unknown rootgroup: getgrnam(root) failed");
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_SOFTWARE);
        }
        root_gid = gr->gr_gid;

        /* clientgroup must be != root and != opt_group */
        if (((client_gid == gid) || (client_gid == root_gid)) && (opt_clientgroup != NULL) && strcmp(opt_clientgroup, ":relax") != 0) {
            logmsg(LOG_ERR, "clientgroup %s must be neither %s nor %s", opt_clientgroup, "root", opt_group);
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_DATAERR);
        }

        /* now set the permissions, bound to the directory fd and without following symlinks */
        socket_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
        socket_mode_str = "0660";
        if ((opt_clientgroup != NULL) && strcmp(opt_clientgroup, ":relax") == 0) {
            logmsg(LOG_WARNING, "clientgroup :relax selected: the milter socket will be world-writable (0666)");
            socket_mode = socket_mode | S_IROTH | S_IWOTH;
            socket_mode_str = "0666";
        }

        if (fchownat(socket_dirfd, socket_base, uid, client_gid, AT_SYMLINK_NOFOLLOW) != 0) {
            logmsg(LOG_ERR, "fchownat(%s, %i, %i) failed: %s", socket_path, (int)uid, (int)client_gid, strerror(errno));
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_SOFTWARE);
        }

        if (fchmodat(socket_dirfd, socket_base, socket_mode, AT_SYMLINK_NOFOLLOW) != 0) {
            logmsg(LOG_ERR, "fchmodat(%s, %s) failed: %s", socket_path, socket_mode_str, strerror(errno));
            close(socket_dirfd);
            free(socket_path_copy);
            exit(EX_SOFTWARE);
        }

        close(socket_dirfd);
        free(socket_path_copy);

        logmsg(LOG_INFO, "changed socket %s to owner/group: %i/%i, mode: %s", opt_miltersocket, (int)uid, (int)client_gid, socket_mode_str);
    }

    /* set gid/uid */
    if (setgid(gid) != 0) {
        logmsg(LOG_ERR, "setgid(%i) failed: %s", gr->gr_gid, strerror(errno));
        exit(EX_SOFTWARE);
    }
    if (setgroups(0, NULL) != 0) {
        if (errno == EPERM) {
            /*
             * EPERM can happen when the process is not running as root or
             * lacks CAP_SETGID.  When started as root we must not keep any
             * supplementary groups; in non-root test/development mode we
             * tolerate the ones the invoking user already has.
             */
            if (getuid() == 0 && getgroups(0, NULL) > 0) {
                logmsg(LOG_ERR, "setgroups(0, NULL) not permitted and supplementary groups remain");
                exit(EX_SOFTWARE);
            }
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

    if (opt_auth_signing_table)
        dict_open(opt_auth_signing_table, &dict_auth_signingtable);

    /*
     * Redis credentials must never appear in the URI or on the command line.
     * Read any requested secret from a file so the value is not exposed in
     * /proc/<pid>/cmdline (CWE-798).
     */
    if (opt_redis_credentials_file != NULL) {
        if (read_redis_credentials_file(opt_redis_credentials_file, uid, gid) != 0)
            exit(EX_DATAERR);
    } else if (opt_redis_password_file != NULL) {
        opt_redis_password = read_redis_password_file(opt_redis_password_file, uid, gid);
        if (opt_redis_password == NULL)
            exit(EX_DATAERR);
    }

    if (redis_global_init() < 0)
        exit(EX_SOFTWARE);

    /*
     * The Redis password has been transferred to the Redis URI structure.
     * Clear the in-process copy that was read from the credentials or
     * password file so it is not retained longer than necessary.
     */
    if (opt_redis_password != NULL) {
        OPENSSL_cleanse(opt_redis_password, strlen(opt_redis_password));
        free(opt_redis_password);
        opt_redis_password = NULL;
    }

    /* initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* get meaningful error messages */
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    /* initialize statistics */
    init_stats();

    /* signal handlers */
    {
        sigset_t set;
        struct sigaction sa;

        sigemptyset(&set);
        sigaddset(&set, SIGALRM);
        sigaddset(&set, SIGHUP);
        sigaddset(&set, SIGINT);
        sigaddset(&set, SIGTERM);
        if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
            logmsg(LOG_ERR, "pthread_sigmask(SIG_BLOCK) failed: %s", strerror(errno));
            exit(EX_SOFTWARE);
        }

        /*
         * Ensure SIGALRM has the default action.  sigwait() cannot catch a
         * signal whose action is SIG_IGN, and libmilter would otherwise catch
         * SIGHUP/SIGINT/SIGTERM for its own shutdown path.
         */
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_DFL;
        if (sigaction(SIGALRM, &sa, NULL) != 0) {
            logmsg(LOG_ERR, "sigaction(SIGALRM) failed: %s", strerror(errno));
            exit(EX_SOFTWARE);
        }

        if (pthread_create(&stats_thread, NULL, stats_signal_thread, NULL) != 0) {
            logmsg(LOG_ERR, "pthread_create(stats_signal_thread) failed: %s", strerror(errno));
            exit(EX_SOFTWARE);
        }
    }

    /* Run milter */
    if ((c = smfi_main()) != MI_SUCCESS)
        logmsg(LOG_ERR, "Milter startup failed");
    else
        logmsg(LOG_NOTICE, "stopping %s %s listening on %s", STR_PROGNAME, STR_PROGVERSION, opt_miltersocket);

    redis_global_cleanup();

    dict_close(&dict_signingtable);
    if (opt_modetable)
        dict_close(&dict_modetable);
    if (opt_auth_signing_table)
        dict_close(&dict_auth_signingtable);

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

/* statistics signal watcher: sigwait for SIGALRM and dump/reset stats */
void* stats_signal_thread(void* arg) {

    sigset_t wait_set;
    sigset_t block_set;
    int      sig;

    (void) arg;

    /*
     * Block ALRM, HUP, INT and TERM in this thread.  The main loop uses
     * sigwait() for ALRM, while libmilter has its own sigwait() thread for
     * HUP/INT/TERM.  Blocking them here prevents the default action from
     * killing the process if one of those signals is directed at this thread.
     */
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGALRM);
    sigaddset(&block_set, SIGHUP);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    (void) pthread_sigmask(SIG_SETMASK, &block_set, NULL);

    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGALRM);

    for (;;) {
        if (sigwait(&wait_set, &sig) != 0) {
            logmsg(LOG_ERR, "%s: sigwait failed: %s", STR_PROGNAME, strerror(errno));
            continue;
        }

        if (sig != SIGALRM)
            continue;

        logmsg(LOG_INFO, "%s: SIGALRM received, dumping statistics", STR_PROGNAME);

        output_stats();
        reset_stats();

#ifdef DMALLOC
        logmsg(LOG_DEBUG, "%s: dumping dmalloc statistics", STR_PROGNAME);
        dmalloc_log_stats();
        dmalloc_log_unfreed();
#endif
    }

    return(NULL);
}
