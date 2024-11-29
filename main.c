/*
 * signing-milter - main.c
 * Copyright (C) 2010-2023  Andreas Schulze
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

#include "main.h"

/* Standardwerte setzen */
char* opt_clientgroup  = NULL;
int   opt_loglevel     = LOG_NOTICE;
int   opt_logdest      = LOG_DEST_SYSLOG;
char* opt_group        = "signing-milter";
char* opt_keepdir      = NULL;
char* opt_signingtable = "/etc/signing-milter/signingtable.cdb";
char* opt_modetable    = NULL;
char* opt_miltersocket = "inet6:30053@[::1]";
int   opt_timeout      = 600;
char* opt_user         = "signing-milter";
int   opt_addxheader   = 0;
int   opt_signerfromheader = 0;

/* globale Variablen */
struct DICT dict_signingtable = {
    "signingtable",      /* name       */
    DICT_FLAG_TRY0NULL,  /* flags      */
    0,                   /* stat_fd    */
    0,                   /* mtime      */
    CDB_STATIC_INIT,     /* cdb        */
    NULL,                /* buffer     */
    NULL,                /* result     */
    0                    /* result_len */
};
struct DICT dict_modetable = {
    "modetable",         /* name       */
    DICT_FLAG_TRY0NULL,  /* flags      */
    0,                   /* stat_fd    */
    0,                   /* mtime      */
    CDB_STATIC_INIT,     /* cdb        */
    NULL,                /* buffer     */
    NULL,                /* result     */
    0                    /* result_len */
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
    char*          socket_mode_str;


    /*
     * compilerwarnung: "client_gid may be used uninitialized"
     * sowas will man ja nun wirklich nicht ...
     */
    uid = gid = client_gid = root_gid = 0;

    while ((c = getopt(argc, argv, "bc:d:hfg:k:lm:n:s:t:u:vx")) > 0) {
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
        case 'd': /* Loglevel */
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
            if ((gr = getgrnam(opt_group)) == NULL) {
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
            /* Zugriffsrechte werden spaeter geprueft, wenn zur richtigen uid gewechselt wurde */
            break;
        case '?': /* help */
        case 'h':
            usage();
            exit(EX_OK);
        case 'l': /* switch log destination from SYSLOG (default) to STDOUT */
            opt_logdest = LOG_DEST_STDOUT;
            break;
        case 'm': /* Signingtable cdbfilename */
            opt_signingtable = optarg;
            break;
        case 'n': /* Modetable cdbfilename */
            opt_modetable = optarg;
            break;
        case 's': /* Miltersocket */
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
            if ((pw = getpwnam(opt_user)) == NULL) {
                logmsg(LOG_ERR, "unknown user: getpwnam(%s) failed", opt_user);
                exit(EX_DATAERR);
            }
            break;
        case 'v': /* Version */
            version();
            exit(EX_OK);
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
     * User- und Gruppennamen stehen nun fest. Testen, ob es diese gibt
     * und uid / gid ermitteln
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

    /* wenn nicht als Parameter angegeben, gehört ein Unix-Socket erstmal der gleichen Gruppe */
    if (opt_clientgroup == NULL)
        client_gid = gid;

    /* wenn inet in optarg gefunden wird *und* das auch noch direkt am Anfang
     * dann ist's kein lokaler socket */
    if (((p = strstr(opt_miltersocket, "inet")) != NULL) && opt_miltersocket == p)
        localsocket = 0;

    if (localsocket == 1) {
        /* den Socket oeffnen */
        if (smfi_opensocket(REMOVE_EXISTING_SOCKETS) != MI_SUCCESS) {
            logmsg(LOG_ERR, "could not open milter socket %s", opt_miltersocket);
            exit(EX_SOFTWARE);
        }
        /* testen, ob's den Socket nun gibt */
        p = opt_miltersocket + strlen("local:");
        if (stat(p, &st) < 0) {
            p = opt_miltersocket + strlen("unix:");
            if (stat(p, &st) < 0) {
                logmsg(LOG_ERR, "miltersocket does not exist: %m", strerror(errno));
                exit(EX_DATAERR);
            }
        }

        /* gid der Gruppe root */
        if ((gr = getgrnam("root")) == NULL) {
            logmsg(LOG_ERR, "unknown rootgroup: getgrnam(root) failed");
            exit(EX_SOFTWARE);
        }
        root_gid = gr->gr_gid;

        /* clientgroup muss != root und != opt_group sein */
        if (((client_gid == gid) || (client_gid == root_gid)) && (opt_clientgroup != NULL) && strcmp(opt_clientgroup, ":relax") != 0) {
            logmsg(LOG_ERR, "clientgroup %s must be neither %s nor %s", opt_clientgroup, "root", opt_group);
            exit(EX_DATAERR);
        }

        /* nun die Rechte setzen */
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

    /* gid/uid setzen */
    if (setgid(gid) != 0) {
        logmsg(LOG_ERR, "setgid(%i) failed: %s", gr->gr_gid, strerror(errno));
        exit(EX_SOFTWARE);
    }
    if (setuid(uid) != 0) {
        logmsg(LOG_ERR, "setuid(%i) failed: %s", pw->pw_uid, strerror(errno));
        exit(EX_SOFTWARE);
    }

    /* aktuelle uid/gid pruefen und loggen */
    uid = getuid();
    gid = getgid();
    if (uid == 0 || gid == 0) {
        logmsg(LOG_ERR, "too much privileges, %s will not start under root", STR_PROGNAME);
        exit(EX_DATAERR);
    }
    logmsg(LOG_INFO, "running as uid: %i, gid: %i", (int) uid, (int) gid);

    if (opt_keepdir != NULL) {
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

    dict_open(opt_signingtable, &dict_signingtable);
    if (opt_modetable)
        dict_open(opt_modetable, &dict_modetable);

    /* initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* get meaningful error messages */
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    /* Statistik initialisieren */
    init_stats();

    /* Signal-Handler fuer SIGALRM */
    signal(SIGALRM, sig_handler);

    /* Run milter */
    if ((c = smfi_main()) != MI_SUCCESS)
        logmsg(LOG_ERR, "Milter startup failed");
    else
        logmsg(LOG_NOTICE, "stopping %s %s listening on %s", STR_PROGNAME, STR_PROGVERSION, opt_miltersocket);

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
