#include "callbacks.h"

#include <limits.h>
#include <unistd.h>

#include "auth_signing.h"

/*
 * Bound the number and aggregate allocated size of retained Content-*
 * headers.  Returns non-zero if appending another header would exceed the
 * configured per-message limits (CWE-400/CWE-407).
 */
static int headerchain_would_exceed(const CTXDATA* ctxdata,
                                    const char* headerf,
                                    const char* headerv) {
    size_t hf_len;
    size_t hv_len;
    size_t num_semicolon;
    size_t add = 0;
    size_t need;

    if (ctxdata->headerchain_count >= MAX_HEADER_CHAIN_NODES)
        return 1;

    if (headerf == NULL || headerv == NULL)
        return 1;

    hf_len = strlen(headerf) + 1;
    hv_len = strlen(headerv);

    num_semicolon = get_num_semicolons(headerv);
    if (num_semicolon == (size_t)-1)
        return 1;

    /* break_after_semicolon expands only when the value is long enough. */
    if (num_semicolon > 0 && hv_len >= 70) {
        if (num_semicolon > SIZE_MAX / (size_t)PHASE_PRE_SIGN)
            return 1;
        add = num_semicolon * (size_t)PHASE_PRE_SIGN;
    }

    /* node + field + value + terminator + expansion, checking overflow. */
    need = sizeof(NODE);
    if (add > SIZE_MAX - need)
        return 1;
    need += add;

    if (hf_len > SIZE_MAX - need)
        return 1;
    need += hf_len;

    if ((hv_len + 1) > SIZE_MAX - need)
        return 1;
    need += hv_len + 1;

    /* A single header must not exceed the total per-message budget. */
    if (need > MAX_HEADER_CHAIN_BYTES)
        return 1;

    if (ctxdata->headerchain_bytes > MAX_HEADER_CHAIN_BYTES - need)
        return 1;

    return 0;
}

static char* get_auth_identity(SMFICTX* ctx) {

    const char* raw;
    char*       out;
    size_t      len;

    raw = smfi_getsymval(ctx, "{auth_authen}");
    if (raw == NULL || *raw == '\0')
        return NULL;

    /*
     * {auth_authen} is the SASL login name.  It is an opaque principal and
     * must not be treated as an email address (no lowercasing, no <> stripping).
     */
    len = strlen(raw);
    out = malloc(len + 1);
    if (out == NULL)
        return NULL;

    memcpy(out, raw, len);
    out[len] = '\0';
    return out;
}

struct smfiDesc callbacks = {
    STR_PROGNAME,           /* filter name */
    SMFI_VERSION,           /* version code -- do not change */
    SMFIF_ADDHDRS |
    SMFIF_CHGHDRS |
    SMFIF_CHGBODY,          /* filter actions */
    NULL,                   /* connection info filter */
    NULL,                   /* SMTP HELO command filter */
    callback_envfrom,       /* envelope sender filter */
    callback_envrcpt,       /* envelope recipient filter */
    callback_header,        /* header filter */
    callback_eoh,           /* end of header */
    callback_body,          /* body block filter */
    callback_eom,           /* end of message */
    callback_abort,         /* message aborted */
    callback_close,         /* connection cleanup */
    NULL,                   /* any unrecognized or unimplemented command filter */
    NULL,                   /* SMTP DATA command filter */
    NULL                    /* negotiation callback */
};

/*
 * Container for signer material resolved before authorization.  This allows
 * certificate-CN fallback to inspect the certificate (and only the certificate)
 * before the private key is loaded.
 */
typedef struct {
    X509* cert;
    int   from_redis;
    int   resolved;
    int   pemfd;
    char  signing_value[4096];
    char* redis_pem;
    size_t redis_pem_len;
    char* redis_chain;
    size_t redis_chain_len;
} signer_lookup_t;

static void signer_lookup_init(signer_lookup_t* sl) {
    bzero(sl, sizeof(*sl));
    sl->pemfd = -1;
}

static void signer_lookup_cleanup(signer_lookup_t* sl) {
    if (sl == NULL)
        return;
    if (sl->cert != NULL) {
        X509_free(sl->cert);
        sl->cert = NULL;
    }
    if (sl->pemfd >= 0) {
        close(sl->pemfd);
        sl->pemfd = -1;
    }
    if (sl->redis_pem != NULL) {
        OPENSSL_cleanse(sl->redis_pem, sl->redis_pem_len);
        free(sl->redis_pem);
        sl->redis_pem = NULL;
        sl->redis_pem_len = 0;
    }
    if (sl->redis_chain != NULL) {
        free(sl->redis_chain);
        sl->redis_chain = NULL;
        sl->redis_chain_len = 0;
    }
}

/*
 * Resolve a signer identity to a certificate for authorization purposes.
 * Returns 1 if a certificate was found, 0 if no signing material exists, and
 * -1 on error.  On success, sl->cert is set and sl->resolved is set; the
 * caller may also use sl->signing_value (local) or sl->redis_pem/chain (Redis)
 * to load the full signing material after authorization succeeds.  The private
 * key is never parsed by this function.
 */
static int signer_lookup_cert(const char* signer_identity, signer_lookup_t* sl) {

    int lookup_rc = 0;

    if (signer_identity == NULL || *signer_identity == '\0')
        return 0;

    if (opt_redis_uri != NULL && *opt_redis_uri != '\0') {
        int rc = redis_lookup_cert(signer_identity,
                                   &sl->redis_pem, &sl->redis_pem_len,
                                   &sl->redis_chain, &sl->redis_chain_len);
        if (rc == -1) {
            logmsg(LOG_ERR, "signer_lookup_cert: redis lookup failed for '%s'", signer_identity);
            return -1;
        }
        if (rc == 0 && sl->redis_pem != NULL) {
            sl->cert = load_pem_cert_mem(sl->redis_pem, sl->redis_pem_len);
            if (sl->cert == NULL) {
                logmsg(LOG_ERR, "signer_lookup_cert: certificate parsing failed for Redis signer '%s'", signer_identity);
                return -1;
            }
            sl->resolved = 1;
            sl->from_redis = 1;
            return 1;
        }
    }

    if (dict_reload(&dict_signingtable) < 0) {
        logmsg(LOG_ERR, "signer_lookup_cert: signing table reload failed");
        return -1;
    }

    lookup_rc = dict_lookup(&dict_signingtable, signer_identity,
                            sl->signing_value, sizeof(sl->signing_value));
    if (lookup_rc == -1) {
        logmsg(LOG_ERR, "signer_lookup_cert: signing table lookup failed for '%s'", signer_identity);
        return -1;
    }
    if (lookup_rc == 1 && sl->signing_value[0] != '\0') {
        sl->pemfd = validate_pem_permissions(sl->signing_value);
        if (sl->pemfd < 0) {
            sl->pemfd = -1;
            logmsg(LOG_ERR, "signer_lookup_cert: cannot open/validate PEM for '%s'", signer_identity);
            return -1;
        }
        sl->cert = load_pem_cert(sl->pemfd);
        if (sl->cert == NULL) {
            logmsg(LOG_ERR, "signer_lookup_cert: certificate parsing failed for '%s'", sl->signing_value);
            return -1;
        }
        sl->resolved = 1;
        return 1;
    }

    return 0;
}

/*
 * Free any early-allocated envfrom resources and release an existing ctxdata
 * when returning an early, non-CONTINUE status.
 */
static void envfrom_early_cleanup(SMFICTX* ctx, CTXDATA* ctxdata,
                                  char* auth_identity,
                                  char* redis_pem, char* redis_chain) {
    if (ctxdata != NULL) {
        ctxdata_cleanup(ctxdata);
        ctxdata_free(ctxdata);
        (void) smfi_setpriv(ctx, NULL);
    }
    free(auth_identity);
    /*
     * redis_pem and redis_chain are owned by ctxdata_setup_from_redis(),
     * which frees them whether the setup succeeds or fails.  The callers of
     * envfrom_early_cleanup() may still hold those pointers, but they have
     * already been freed or are NULL.
     */
    (void) redis_pem;
    (void) redis_chain;
}

/*
 * called once at the beginning of each message (MAIL command),
 * before xxfi_envrcpt.
 */
sfsistat callback_envfrom(SMFICTX* ctx, char** argv) {

    signer_lookup_t lookup;
    CTXDATA*        ctxdata = NULL;
    const char*     daemon_name;
    int             i;
    int             auth_rc = 0;
    char*           auth_identity = NULL;
    int             setup_ready = 0;
    int             deny_reason = 0;

    signer_lookup_init(&lookup);

    char sym_daemon_name[] = "{daemon_name}";
    if ((daemon_name = smfi_getsymval(ctx, sym_daemon_name)) == NULL) {
        daemon_name = "smfi_getsymval(daemon_name) failed";
        logmsg(LOG_WARNING, "warning: callback_envfrom smfi_getsymval(daemon_name) failed, continue");
    }

    /*
     * emty sender has different representations.
     * in smtpd_milter it is '<>'
     * in non_smtpd_milter it is ''
     */
    logmsg(LOG_DEBUG, "MAIL FROM: '%s' (via %s)", argv[0], daemon_name);

    auth_identity = NULL;
    if (auth_signing_required()) {
        auth_identity = get_auth_identity(ctx);

        if (auth_signing_has_explicit_backend()) {
            /*
             * Explicit auth tables are authoritative.  Authorize first, then
             * resolve the signing material only for authorized signers.
             */
            auth_rc = auth_signing_authorized(auth_identity, argv[0], NULL);
            if (auth_rc == -1) {
                logmsg(LOG_ERR, "callback_envfrom: auth_signing_authorized() failed");
                free(auth_identity);
                signer_lookup_cleanup(&lookup);
                return SMFIS_TEMPFAIL;
            }
            if (auth_rc == 1) {
                int rc = signer_lookup_cert(argv[0], &lookup);
                if (rc == -1) {
                    logmsg(LOG_ERR, "callback_envfrom: signer lookup failed for '%s'", argv[0]);
                    free(auth_identity);
                    signer_lookup_cleanup(&lookup);
                    return SMFIS_TEMPFAIL;
                }
                if (rc == 1) {
                    setup_ready = 1;
                } else {
                    deny_reason = 1;
                    auth_rc = 0;
                }
            } else {
                deny_reason = 0;
            }
        } else {
            /*
             * Certificate-CN fallback: resolve the certificate before the
             * private key is loaded, then authorize against the certificate
             * subject CN.
             */
            int rc = signer_lookup_cert(argv[0], &lookup);
            if (rc == -1) {
                logmsg(LOG_ERR, "callback_envfrom: signer lookup failed for '%s'", argv[0]);
                free(auth_identity);
                signer_lookup_cleanup(&lookup);
                return SMFIS_TEMPFAIL;
            }
            if (rc == 1) {
                auth_rc = auth_signing_authorized(auth_identity, argv[0], lookup.cert);
                if (auth_rc == -1) {
                    logmsg(LOG_ERR, "callback_envfrom: certificate authorization failed for '%s'", argv[0]);
                    free(auth_identity);
                    signer_lookup_cleanup(&lookup);
                    return SMFIS_TEMPFAIL;
                }
                if (auth_rc == 1) {
                    setup_ready = 1;
                } else {
                    deny_reason = 0;
                    signer_lookup_cleanup(&lookup);
                    signer_lookup_init(&lookup);
                }
            } else {
                deny_reason = 1;
                auth_rc = 0;
            }
        }
    } else {
        /*
         * Legacy sender-address-only behavior: no authentication required.
         * Resolve the signing material directly from the envelope sender.
         */
        int rc = signer_lookup_cert(argv[0], &lookup);
        if (rc == -1) {
            logmsg(LOG_ERR, "callback_envfrom: signer lookup failed for '%s'", argv[0]);
            free(auth_identity);
            signer_lookup_cleanup(&lookup);
            return SMFIS_TEMPFAIL;
        }
        if (rc == 1) {
            setup_ready = 1;
        } else {
            deny_reason = 1;
            auth_rc = 0;
        }
    }

    if (!setup_ready) {
        if (!opt_signerfromheader) {
            if (deny_reason == 0) {
                logmsg(LOG_INFO, "callback_envfrom: authenticated identity '%s' not authorized for signer '%s'; mail will not be signed",
                       auth_identity ? auth_identity : "(none)", argv[0]);
            } else {
                logmsg(LOG_INFO, "no signingdata for '%s'; mail will not be signed", argv[0]);
            }
            free(auth_identity);
            signer_lookup_cleanup(&lookup);
            return SMFIS_CONTINUE;
        }
        logmsg(LOG_DEBUG, "callback_envfrom: no usable/authorized envelope signer, will look for '%s'", HEADERNAME_SIGNER);
    }

    /*
     * Prepare the private data structure
     */
    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) != NULL) {
        ctxdata_cleanup(ctxdata);
    } else {
        if ((ctxdata = ctxdata_create()) == NULL) {
            free(auth_identity);
            signer_lookup_cleanup(&lookup);
            return SMFIS_TEMPFAIL;
        }
    }

    ctxdata->auth_identity = auth_identity;

    if (setup_ready) {
        if (lookup.from_redis) {
            logmsg(LOG_INFO, "signingdata from redis for envsender '%s'", argv[0]);
            if ((i = ctxdata_setup_from_redis(ctxdata, argv[0], lookup.redis_pem, lookup.redis_pem_len,
                                              lookup.redis_chain, lookup.redis_chain_len,
                                              opt_redis_passphrase)) != 0) {
                logmsg(LOG_ERR, "callback_envfrom: ctxdata_setup_from_redis() failed: rc=%i, envsender='%s'", i, argv[0]);
                envfrom_early_cleanup(ctx, ctxdata, NULL, NULL, NULL);
                lookup.redis_pem = NULL;
                lookup.redis_chain = NULL;
                signer_lookup_cleanup(&lookup);
                return SMFIS_TEMPFAIL;
            }
            lookup.redis_pem = NULL;
            lookup.redis_chain = NULL;
        } else {
            logmsg(LOG_INFO, "signingdata from envsender '%s'", argv[0]);
            if (lookup.pemfd < 0) {
                logmsg(LOG_ERR, "callback_envfrom: no open PEM file for envsender='%s', file=%s", argv[0], lookup.signing_value);
                envfrom_early_cleanup(ctx, ctxdata, NULL, NULL, NULL);
                signer_lookup_cleanup(&lookup);
                return SMFIS_TEMPFAIL;
            }
            i = ctxdata_setup_from_fd(ctxdata, lookup.signing_value, lookup.pemfd);
            lookup.pemfd = -1;
            if (i != 0) {
                logmsg(LOG_ERR, "callback_envfrom: ctxdata_setup_from_fd() failed: rc=%i, envsender='%s', file=%s", i, argv[0], lookup.signing_value);
                envfrom_early_cleanup(ctx, ctxdata, NULL, NULL, NULL);
                signer_lookup_cleanup(&lookup);
                return SMFIS_TEMPFAIL;
            }
        }
        signer_lookup_cleanup(&lookup);
    } else {
        signer_lookup_cleanup(&lookup);
    }

    /*
     * save the private data
     */
    if (smfi_setpriv(ctx, ctxdata) != MI_SUCCESS) {
        logmsg(LOG_ERR, "error: callback_envfrom: setpriv failed, envsender='%s'", argv[0]);
        envfrom_early_cleanup(ctx, ctxdata, NULL, NULL, NULL);
        signer_lookup_cleanup(&lookup);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

sfsistat callback_envrcpt(SMFICTX* ctx, char** argv) {

    CTXDATA*       ctxdata;
    char           mode_value[DICT_BUFFER_LEN];
    int            mode_rc;

    if (!opt_modetable)
        return SMFIS_CONTINUE;

    logmsg(LOG_DEBUG, "RCPT TO: %s", argv[0]);

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_envrcpt: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);

    if (dict_reload(&dict_modetable) < 0) {
        logmsg(LOG_ERR, "callback_envrcpt: mode table reload failed");
        return SMFIS_TEMPFAIL;
    }

    mode_rc = dict_lookup(&dict_modetable, argv[0], mode_value, sizeof(mode_value));
    if (mode_rc == -1) {
        logmsg(LOG_ERR, "callback_envrcpt: mode table lookup failed for '%s'", argv[0]);
        return SMFIS_TEMPFAIL;
    }

    if (mode_rc == 1 && *mode_value != '\0') {
        /*
         * Recipient found in the mode table.
         */
        logmsg(LOG_DEBUG, "callback_envrcpt: %s found in modetable: value='%s'", argv[0], mode_value);

        if (strstr(mode_value, "skip") != NULL) {
            logmsg(LOG_INFO, "modetable hit: skip signing requested for %s", argv[0]);
            ctxdata->rcpt_skip_count++;
        }
        if (strstr(mode_value, "opaque") != NULL) {
            logmsg(LOG_DEBUG, "callback_envrcpt: opaque signingmode enabled for %s", argv[0]);
            ctxdata->mailflags |= MF_SIGNMODE_OPAQUE;
        }
        if (strstr(mode_value, "keep") != NULL) {
            if (opt_keepdir != NULL) {
                logmsg(LOG_INFO, "modetable hit: keep message for %s in %s", argv[0], opt_keepdir);
                ctxdata->keepdir = opt_keepdir;
            } else {
                logmsg(LOG_WARNING, "modetable hit: keep requested for %s but no keep directory configured (-k); ignoring", argv[0]);
            }
        }
    }

    ctxdata->rcpt_count++;
    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);
    return SMFIS_CONTINUE;
}

/*
 * called once for each message header.
 */
/*
 * Delete the first N occurrences of a header by repeatedly deleting
 * occurrence 1.  smfi_chgheader uses 1-based header indices; calling with
 * index 1 removes the first remaining occurrence.  Failure to delete a
 * requested occurrence is logged and stops further attempts.
 */
static void delete_header_occurrences(SMFICTX* ctx, const char* queueid,
                                      const char* headerf, int count) {
    int i;
    for (i = 0; i < count; i++) {
        if (smfi_chgheader(ctx, (char*) headerf, 1, NULL) != MI_SUCCESS) {
            logmsg(LOG_ERR, "%s: error: delete header %s failed, continue",
                   queueid, headerf);
            break;
        }
    }
}

sfsistat callback_header(SMFICTX* ctx, char* headerf, char* headerv) {

    CTXDATA*       ctxdata;
    NODE*          n;

    /* logmsg(LOG_DEBUG, "HEADER: %s %s", headerf, headerv);*/

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_header: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    if (!ctxdata->queueid) {
        char sym_i[] = "{i}";
        if ((ctxdata->queueid = smfi_getsymval(ctx, sym_i)) == NULL) {
            ctxdata->queueid = "unknown";
            logmsg(LOG_WARNING, "%s: warning: callback_header: smfi_getsymval(queueid) failed", ctxdata->queueid);
        }
        logmsg(LOG_INFO, "callback_header: got queuid: %s", ctxdata->queueid);
    }

    if (strcasecmp(headerf, "mime-version") == 0) {
        logmsg(LOG_DEBUG, "callback_header: Mime-Mail erkannt");
        ctxdata->mailflags |= MF_TYPE_MIME;
    }

    /*
     * RFC 2045 defines
     * Content-Type, Content-Transfer-Encoding, Content-ID and Content-Description
     * Section 9 states that all extensions will begin with content-
     */
    if (strncasecmp(headerf, "content-", 8) == 0) {

        /*
         * A syntactic Content-Type declaration is not a trustworthy
         * proof of a valid S/MIME signature (CWE-345).  Continue
         * processing under the configured signing policy instead of
         * accepting the message solely based on attacker-controllable
         * MIME metadata.
         */
        if (is_already_signed(headerf, headerv)) {
            logmsg(LOG_NOTICE, "%s: mail declares a pre-existing S/MIME signature; continuing with milter policy",
                   ctxdata->queueid);
        }

        if (is_multipart_mime(headerf, headerv)) {
            logmsg(LOG_DEBUG, "callback_header: multipart Mime-Mail erkannt");
            ctxdata->mailflags |= MF_TYPE_MULTIPART;
        }

        if (headerchain_would_exceed(ctxdata, headerf, headerv)) {
            logmsg(LOG_ERR, "%s: error: callback_header: header chain budget exceeded",
                   ctxdata->queueid);
            return SMFIS_TEMPFAIL;
        }

        if ((n = newnode(headerf, headerv, PHASE_PRE_SIGN)) == NULL) {
            logmsg(LOG_ERR, "error: callback_header: alloc new node failed");
            return SMFIS_TEMPFAIL;
        }
        appendnode(&(ctxdata->headerchain), &(ctxdata->headerchain_tail), n);
        ctxdata->headerchain_count++;
        ctxdata->headerchain_bytes += sizeof(NODE) + strlen(n->headerf) + 1 + strlen(n->headerv) + 1;
    }

    if (!opt_signerfromheader)
        return SMFIS_CONTINUE;

    if (strcasecmp(headerf, HEADERNAME_SIGNER) == 0) {

        signer_lookup_t lookup;
        int             auth_rc = 0;
        int             setup_ready = 0;
        int             i;

        signer_lookup_init(&lookup);

        /*
         * Process at most one X-Signer header.  Duplicates are untrusted
         * message-controlled policy and are stripped without expensive
         * authorization or key lookup, but the total number is remembered so
         * that all occurrences can be deleted in callback_eom.
         */
        ctxdata->signer_header_count++;
        if (ctxdata->signer_header_count > 1) {
            ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
            logmsg(LOG_INFO, "%s: ignoring duplicate %s header", ctxdata->queueid, headerf);
            return SMFIS_CONTINUE;
        }

        logmsg(LOG_DEBUG, "callback_header: signerfrom_header: %s", headerv);

        /*
         * X-Signer is a control header and must not be trusted without an
         * explicit authorization binding (CWE-807).  A rejected, unknown, or
         * unusable X-Signer must not suppress an already-authorized envelope
         * signer.
         */
        if (auth_signing_required()) {
            if (auth_signing_has_explicit_backend()) {
                auth_rc = auth_signing_authorized(ctxdata->auth_identity, headerv, NULL);
                if (auth_rc == -1) {
                    logmsg(LOG_ERR, "%s: callback_header: X-Signer authorization check failed for '%s'",
                           ctxdata->queueid, headerv);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    if (ctxdata->cert != NULL)
                        return SMFIS_CONTINUE;
                    ctxdata_cleanup(ctxdata);
                    ctxdata_free(ctxdata);
                    (void) smfi_setpriv(ctx, NULL);
                    return SMFIS_TEMPFAIL;
                }
                if (auth_rc == 0) {
                    logmsg(LOG_NOTICE, "%s: X-Signer '%s' not authorized for authenticated identity '%s'; keeping any authorized envelope signer",
                           ctxdata->queueid, headerv, ctxdata->auth_identity ? ctxdata->auth_identity : "(none)");
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    return SMFIS_CONTINUE;
                }

                if (signer_lookup_cert(headerv, &lookup) != 1) {
                    logmsg(LOG_INFO, "%s: no signingdata for X-Signer %s; keeping any authorized envelope signer", ctxdata->queueid, headerv);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    signer_lookup_cleanup(&lookup);
                    return SMFIS_CONTINUE;
                }
                setup_ready = 1;
            } else {
                /* Certificate-CN fallback: resolve cert before private key. */
                int rc = signer_lookup_cert(headerv, &lookup);
                if (rc == -1) {
                    logmsg(LOG_ERR, "%s: callback_header: signer lookup failed for X-Signer '%s'",
                           ctxdata->queueid, headerv);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    signer_lookup_cleanup(&lookup);
                    if (ctxdata->cert != NULL)
                        return SMFIS_CONTINUE;
                    ctxdata_cleanup(ctxdata);
                    ctxdata_free(ctxdata);
                    (void) smfi_setpriv(ctx, NULL);
                    return SMFIS_TEMPFAIL;
                }
                if (rc == 1) {
                    auth_rc = auth_signing_authorized(ctxdata->auth_identity, headerv, lookup.cert);
                    if (auth_rc == -1) {
                        logmsg(LOG_ERR, "%s: callback_header: X-Signer certificate authorization failed for '%s'",
                               ctxdata->queueid, headerv);
                        ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                        signer_lookup_cleanup(&lookup);
                        if (ctxdata->cert != NULL)
                            return SMFIS_CONTINUE;
                        ctxdata_cleanup(ctxdata);
                        ctxdata_free(ctxdata);
                        (void) smfi_setpriv(ctx, NULL);
                        return SMFIS_TEMPFAIL;
                    }
                    if (auth_rc == 0) {
                        logmsg(LOG_NOTICE, "%s: X-Signer '%s' certificate CN does not match authenticated identity '%s'; keeping any authorized envelope signer",
                               ctxdata->queueid, headerv, ctxdata->auth_identity ? ctxdata->auth_identity : "(none)");
                        ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                        signer_lookup_cleanup(&lookup);
                        return SMFIS_CONTINUE;
                    }
                    setup_ready = 1;
                } else {
                    logmsg(LOG_INFO, "%s: no signingdata for X-Signer %s; keeping any authorized envelope signer", ctxdata->queueid, headerv);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    signer_lookup_cleanup(&lookup);
                    return SMFIS_CONTINUE;
                }
            }
        } else {
            /*
             * Legacy X-Signer behavior: no authentication required.
             * Resolve the signing material directly from the header value.
             */
            int rc = signer_lookup_cert(headerv, &lookup);
            if (rc == -1) {
                logmsg(LOG_ERR, "%s: callback_header: signer lookup failed for X-Signer '%s'",
                       ctxdata->queueid, headerv);
                ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                signer_lookup_cleanup(&lookup);
                if (ctxdata->cert != NULL)
                    return SMFIS_CONTINUE;
                ctxdata_cleanup(ctxdata);
                ctxdata_free(ctxdata);
                (void) smfi_setpriv(ctx, NULL);
                return SMFIS_TEMPFAIL;
            }
            if (rc == 1) {
                setup_ready = 1;
            } else {
                logmsg(LOG_INFO, "%s: no signingdata for X-Signer %s; keeping any authorized envelope signer", ctxdata->queueid, headerv);
                ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                signer_lookup_cleanup(&lookup);
                return SMFIS_CONTINUE;
            }
        }

        if (setup_ready) {
            if (lookup.from_redis) {
                logmsg(LOG_INFO, "signingdata from redis for header signer '%s'", headerv);
                if ((i = ctxdata_setup_from_redis(ctxdata, headerv, lookup.redis_pem, lookup.redis_pem_len,
                                                  lookup.redis_chain, lookup.redis_chain_len,
                                                  opt_redis_passphrase)) != 0) {
                    logmsg(LOG_ERR, "callback_header: ctxdata_setup_from_redis() failed: rc=%i, headerf=%s, headerv=%s", i, headerf, headerv);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    lookup.redis_pem = NULL;
                    lookup.redis_chain = NULL;
                    signer_lookup_cleanup(&lookup);
                    if (ctxdata->cert != NULL)
                        return SMFIS_CONTINUE;
                    ctxdata_cleanup(ctxdata);
                    ctxdata_free(ctxdata);
                    (void) smfi_setpriv(ctx, NULL);
                    return SMFIS_TEMPFAIL;
                }
                lookup.redis_pem = NULL;
                lookup.redis_chain = NULL;
            } else {
                if (lookup.pemfd < 0) {
                    logmsg(LOG_ERR, "callback_header: no open PEM file for headerf=%s, headerv=%s, file=%s", headerf, headerv, lookup.signing_value);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    signer_lookup_cleanup(&lookup);
                    if (ctxdata->cert != NULL)
                        return SMFIS_CONTINUE;
                    ctxdata_cleanup(ctxdata);
                    ctxdata_free(ctxdata);
                    (void) smfi_setpriv(ctx, NULL);
                    return SMFIS_TEMPFAIL;
                }
                i = ctxdata_setup_from_fd(ctxdata, lookup.signing_value, lookup.pemfd);
                lookup.pemfd = -1;
                if (i != 0) {
                    logmsg(LOG_ERR, "callback_header: ctxdata_setup_from_fd() failed: rc=%i, headerf=%s, headerv=%s, file=%s", i, headerf, headerv, lookup.signing_value);
                    ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
                    signer_lookup_cleanup(&lookup);
                    if (ctxdata->cert != NULL)
                        return SMFIS_CONTINUE;
                    ctxdata_cleanup(ctxdata);
                    ctxdata_free(ctxdata);
                    (void) smfi_setpriv(ctx, NULL);
                    return SMFIS_TEMPFAIL;
                }
            }
            signer_lookup_cleanup(&lookup);
        }

        /*
         * Header field must be deleted in callback_eom
         */
        ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
    }

    if (strcasecmp(headerf, HEADERNAME_SKIP_SIGNING) == 0) {
        /*
         * X-Skip-Signing is untrusted message-controlled policy.  Record that
         * we saw it so all occurrences can be stripped, but do not honor the
         * skip request (CWE-807).
         */
        ctxdata->skip_signing_header_seen++;
        logmsg(LOG_INFO, "%s: ignoring untrusted %s header", ctxdata->queueid, headerf);
    }

    return SMFIS_CONTINUE;
}

sfsistat callback_eoh(SMFICTX* ctx) {

    CTXDATA*       ctxdata;

    logmsg(LOG_DEBUG, "EOH");

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_eoh: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    /*
     * After DATA, the QueueID is fixed. Since this milter does not
     * implement a callback at the DATA command, this is the first
     * callback where the QueueID can be retrieved.
     */
    if (!ctxdata->queueid) {
        char sym_i[] = "{i}";
        if ((ctxdata->queueid = smfi_getsymval(ctx, sym_i)) == NULL) {
            ctxdata->queueid = "unknown";
            logmsg(LOG_WARNING, "%s: warning: callback_eoh: smfi_getsymval(queueid) failed", ctxdata->queueid);
        }
    }

    /*
     * Do not let a single skip-mode recipient suppress signing for every
     * recipient.  Only skip if all recipients are marked skip (CWE-284).
     */
    if (ctxdata->rcpt_count > 0 &&
        ctxdata->rcpt_skip_count == ctxdata->rcpt_count) {
        logmsg(LOG_INFO, "%s: all %zu recipients requested skip signing", ctxdata->queueid, ctxdata->rcpt_count);
        ctxdata->mailflags |= MF_SKIP_SIGNING;
    }

    /*
     * If no signing material has been loaded (unauthorized sender, missing
     * certificate, or X-Signer not found), fall through without signing.
     * A rejected or missing X-Signer must not become the reason to skip
     * signing when an authorized envelope signer was already loaded.
     */
    if (ctxdata->cert == NULL) {
        logmsg(LOG_INFO, "%s: no signing material loaded; skip signing", ctxdata->queueid);
        ctxdata->mailflags |= MF_SKIP_SIGNING;
    }

    if (ctxdata->mailflags & MF_SKIP_SIGNING) {
       logmsg(LOG_INFO, "%s: skip signing requested", ctxdata->queueid);
       return SMFIS_CONTINUE;
    }

    /*
     * RFC 2045: MIME-Version header is mandatory when Content-* headers are used.
     * Some MUAs (Apple Mail, Outlook) occasionally send Content-* headers
     * without MIME-Version. Instead of rejecting the mail, we treat it as MIME and
     * mark that callback_eom must adopt the generated MIME-Version header.
     */
    if ( (ctxdata->headerchain != NULL) && ((ctxdata->mailflags & MF_TYPE_MIME) == 0) ) {

        logmsg(LOG_WARNING, "%s: callback_eoh: no 'MIME-Version' header but 'Content-*' header found. Treating as MIME and adding default MIME-Version", ctxdata->queueid);

        ctxdata->mailflags |= MF_TYPE_MIME | MF_MIME_VERSION_DEFAULT;
    }

    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);

    if ((headerchain2signingbuffer(ctx, ctxdata)) != 0) {
        logmsg(LOG_ERR, "%s: callback_eoh: headerchain2signingbuffer failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    if (ctxdata->mailflags & MF_SIGNMODE_OPAQUE) {
        ctxdata->pkcs7flags &= ~PKCS7_DETACHED;
        ctxdata->pkcs7flags &= ~PKCS7_STREAM;
    }

    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);
    return SMFIS_CONTINUE;
}

sfsistat callback_body(SMFICTX* ctx, unsigned char* bodyp, size_t len) {

    CTXDATA*       ctxdata;
    unsigned char* start = bodyp;
    size_t         length = len;

    logmsg(LOG_DEBUG, "BODY (%i byte)", len);

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_body: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    if (ctxdata->mailflags & MF_SKIP_SIGNING) {
       return SMFIS_CONTINUE;
    }

    /*
     * If the mail is a multipart MIME mail,
     * it begins with a preamble (RFC 2046, 5.1.1).
     * This preamble ends with the first boundary (^--) and is not included in the signature.
     */
    if ((ctxdata->first_bodychunk_seen == 0) && (ctxdata->mailflags & MF_TYPE_MULTIPART)) {
        /* first chunk */
        ctxdata->first_bodychunk_seen = 1;
        while (length > 0) {
            if (*start == '-' && length >= 2 && start[1] == '-')
                break;
            start++;
            length--;
        }
        logmsg(LOG_DEBUG, "%s: skip %lu bytes RFC 2046 prolog discarded", ctxdata->queueid, start - bodyp);
    }

    if ((append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), (char*) start, length)) != 0) {
        logmsg(LOG_ERR, "%s: error: callback_body: append2buffer failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

sfsistat callback_eom(SMFICTX* ctx) {

    CTXDATA*       ctxdata;
    BUF_MEM*       outmem;
    struct timeval start_time, end_time, duration;
    const char*    keepdir;

    logmsg(LOG_DEBUG, "EOM");

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_eom: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    if (ctxdata->mailflags & MF_SKIP_SIGNING) {
        if (ctxdata->signer_header_count > 0) {
            delete_header_occurrences(ctx, ctxdata->queueid,
                                      HEADERNAME_SIGNER,
                                      ctxdata->signer_header_count);
        }
        if (ctxdata->skip_signing_header_seen > 0) {
            delete_header_occurrences(ctx, ctxdata->queueid,
                                      HEADERNAME_SKIP_SIGNING,
                                      ctxdata->skip_signing_header_seen);
        }
        ctxdata_cleanup(ctxdata);
       return SMFIS_CONTINUE;
    }

    /*
     * X-Skip-Signing may have been ignored, but the header still has to be
     * stripped so it is not visible in the delivered message.
     */
    if (ctxdata->skip_signing_header_seen > 0) {
        delete_header_occurrences(ctx, ctxdata->queueid,
                                  HEADERNAME_SKIP_SIGNING,
                                  ctxdata->skip_signing_header_seen);
    }

    /*
     *  "echo | /usr/sbin/sendmail rcpt" creates messages with 0-byte body,
     *  but BIO_new_mem_buf doesn't like 0 bytes at all. So we add a line break.
     */
    if (0 == ctxdata->data2sign_len) {
        if ((append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), "\r\n", 2)) != 0) {
            logmsg(LOG_ERR, "%s: error: callback_eom: append2buffer failed", ctxdata->queueid);
            return SMFIS_TEMPFAIL;
        }
    }

    logmsg(LOG_DEBUG, "callback_eom: ctxdata->data2sign_len=%zu", ctxdata->data2sign_len);

    /*
     * The OpenSSL BIO API takes an int length.  Keep the cap below INT_MAX
     * both here and in append2buffer().
     */
    if (ctxdata->data2sign_len > (size_t) INT_MAX) {
        logmsg(LOG_ERR, "%s: error: callback_eom: message too large", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    /*
     * discard/don't sign the optional epilogue
     */
    if (ctxdata->mailflags & MF_TYPE_MULTIPART) {

        unsigned char* old_end = ctxdata->data2sign + ctxdata->data2sign_len;
        unsigned char* new_end;
        size_t         skipped_epilog_bytes;
        int            found = 0;

        logmsg(LOG_DEBUG, "%s: try discarding optional RFC 2046 epilogue",
                          ctxdata->queueid);

        for (new_end = old_end;
             new_end > ctxdata->data2sign;
             new_end--) {
            /* logmsg(LOG_DEBUG, "%c, %c, %c, %c",
                              *(new_end-4), *(new_end-3),
                              *(new_end-2), *(new_end-1)); */
            if ((size_t)(new_end - ctxdata->data2sign) < 4)
                continue;
            if (   *(new_end-1) == '\n' && *(new_end-2) == '\r'
                && *(new_end-3) == '-'  && *(new_end-4) == '-'  ) {
              skipped_epilog_bytes = old_end - new_end;
              found = 1;
              if (skipped_epilog_bytes > 0) {
                  logmsg(LOG_INFO, "%s: %lu bytes RFC 2046 epilogue discarded",
                                   ctxdata->queueid, skipped_epilog_bytes);
              }
              ctxdata->data2sign_len -= skipped_epilog_bytes;
              break;
            }
        }

        if (new_end == ctxdata->data2sign && found == 0) {
            logmsg(LOG_WARNING, "%s: callback_eom: strange: RFC 2046 close-delimiter not found", ctxdata->queueid);
        }
        logmsg(LOG_DEBUG, "callback_eom: ctxdata->data2sign_len=%zu", ctxdata->data2sign_len);
    }

    gettimeofday(&start_time, NULL);

    /*
     * Header and body are now complete in the data2sign buffer.
     * A BIO is now created from this buffer
     */
    if ((ctxdata->inbio = BIO_new_mem_buf(ctxdata->data2sign, (int) ctxdata->data2sign_len)) == NULL) {
        logmsg(LOG_ERR, "%s: error: callback_eom: creating inBIO failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    /* keep data globally or on demand (modetable) */
    if ((keepdir = opt_keepdir) == NULL) {
        keepdir = ctxdata->keepdir;
    }

    if (keepdir != NULL) {
      bio2file(ctxdata->inbio, keepdir, "plain", ctxdata->queueid);
    }

    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);

    if ((ctxdata->pkcs7 = PKCS7_sign(ctxdata->cert, ctxdata->key, ctxdata->chain, ctxdata->inbio, ctxdata->pkcs7flags)) == NULL) {
        logmsg(LOG_ERR, "%s: error: callback_eom: creating PKCS#7 structure failed, cert=%s", ctxdata->queueid, ctxdata->pemfilename);
        return SMFIS_TEMPFAIL;
    }

    if ((ctxdata->outbio = BIO_new(BIO_s_mem())) == NULL) {
        logmsg(LOG_ERR, "%s: error: callback_eom: creating outBIO failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    if (SMIME_write_PKCS7(ctxdata->outbio, ctxdata->pkcs7, ctxdata->inbio, ctxdata->pkcs7flags) == 0) {
        logmsg(LOG_ERR, "%s: error: callback_eom: SMIME_write_PKCS7 failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    gettimeofday(&end_time, NULL);
    duration.tv_sec = end_time.tv_sec - start_time.tv_sec;
    duration.tv_usec = end_time.tv_usec - start_time.tv_usec;
    if(duration.tv_usec < 0) {
        duration.tv_usec += 1000000;
        duration.tv_sec--;
    }

    /*
     * Now really delete the Content-Type header
     */
    if (delete_marked_headers(ctx, ctxdata) != 0) {
        logmsg(LOG_ERR, "%s: error: callback_eom: delete_marked_headers failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    /*
     * if present: delete all X-Signer headers
     */
    if (ctxdata->signer_header_count > 0) {
        delete_header_occurrences(ctx, ctxdata->queueid,
                                  HEADERNAME_SIGNER,
                                  ctxdata->signer_header_count);
    }

    if (keepdir != NULL) {
        bio2file(ctxdata->outbio, keepdir, "signed", ctxdata->queueid);
    }

    /*
     * extract the new MIME headers from outbio
     */
    for(;;) {
        char* headerline;
        char* headerf;
        char* headerv;

        if ((headerline = malloc(MAXHEADERLEN)) == NULL) {
            logmsg(LOG_ERR, "%s: error: callback_eom: allocation of %i byte (MAXHEADERLEN) to read signed data failed", ctxdata->queueid, MAXHEADERLEN);
            return SMFIS_TEMPFAIL;
        }

        if (BIO_gets(ctxdata->outbio, headerline, MAXHEADERLEN) < 0) {
            logmsg(LOG_ERR, "%s: error: callback_eom: reading headerline from outBIO failed", ctxdata->queueid);
            if (headerline)
                free(headerline);
            return SMFIS_TEMPFAIL;
        }

        /* empty line: header is complete */
        if ((strcmp(headerline, "\r\n") == 0) || (strcmp(headerline, "\n") == 0)) {
            if (headerline)
                free(headerline);
            break;
	}

        logmsg(LOG_DEBUG, "%s: Header aus PKCS7: %s", ctxdata->queueid, headerline);

        /*
         * If a 7-bit ASCII mail was signed, it did not contain a MIME header,
         * then: adopt it here.
         *
         * If callback_eoh has added a missing MIME-Version header,
         * we must adopt the generated MIME-Version header from the PKCS7 output.
         */
        if ( (strncasecmp(headerline, "mime-version", 12) == 0) &&
             ((ctxdata->mailflags & MF_TYPE_MIME) != 0) &&
             ((ctxdata->mailflags & MF_MIME_VERSION_DEFAULT) == 0) ) {
            logmsg(LOG_DEBUG, "%s: skip mime-version header", ctxdata->queueid);
            if (headerline)
                free(headerline);
            continue;
        }

        /*
         * separate the line into 2 parts. ':' is replaced by '\0'
         * and leading spaces in headerv are skipped
         */
        if ((headerv = separate_header(headerline, &headerf)) == NULL) {
            logmsg(LOG_ERR, "%s: error: callback_eom: separate_header failed", ctxdata->queueid);
            if (headerline)
                free(headerline);
            return SMFIS_TEMPFAIL;
        }

        if ((headerv = break_after_semicolon(headerv, PHASE_POST_SIGN)) == NULL) {
            logmsg(LOG_ERR, "%s: error: callback_eom: break_after_semicolon failed", ctxdata->queueid);
            if (headerline)
                free(headerline);
            return SMFIS_TEMPFAIL;
        }

        logmsg(LOG_DEBUG, "%s: separierter, umgebrochener Header: %s:%s", ctxdata->queueid, headerf, headerv);

        /*
         * now set the headers again
         */
        if ((smfi_addheader(ctx, headerf, headerv)) != MI_SUCCESS) {
            logmsg(LOG_ERR, "%s: error: callback_eom: smfi_addheader %s:%s failed", ctxdata->queueid, headerf, headerv);
            if (headerline)
                free(headerline);
            if (headerv)
                free(headerv);
            return SMFIS_TEMPFAIL;
        }

        if (headerline)
            free(headerline);
        if (headerv)
            free(headerv);
    }

    /* then replace body */
    BIO_get_mem_ptr(ctxdata->outbio, &outmem);
    if (outmem == NULL) {
        logmsg(LOG_ERR, "%s: error: callback_eom: BIO_get_mem_ptr failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    if (outmem->length > (size_t) INT_MAX) {
        logmsg(LOG_ERR, "%s: error: callback_eom: signed output too large", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    if (smfi_replacebody(ctx, (unsigned char*)(outmem->data), (int) outmem->length) != MI_SUCCESS) {
        logmsg(LOG_ERR, "%s: error: callback_eom: replacebody failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    /* BUF_MEM_free(outmem); */

    /*
     * provide some information ...
     */
    logmsg(LOG_NOTICE, "%s: %ssigned with %s%s", ctxdata->queueid, ctxdata->mailflags & MF_SIGNMODE_OPAQUE ? "opaque" : "clear", ctxdata->pemfilename, ctxdata->chain != NULL ? " (+chain)" : " (no chain)");
    logmsg(LOG_INFO, "%s: signing %ld byte took %d.%d sec", ctxdata->queueid, ctxdata->data2sign_len, duration.tv_sec, duration.tv_usec);

    /*
     * finally stamp an X-Header into the mail
     */
    if (opt_addxheader) {
        char  xhdr[MAXHEADERLEN + 1];
        const char* hostname;

        bzero(xhdr, sizeof(xhdr));
        char sym_j[] = "{j}";
        if ((hostname = smfi_getsymval(ctx, sym_j)) == NULL) {
            logmsg(LOG_WARNING, "%s: warning: callback_eom: smfi_getsymval(hostname) failed, cannot addxheader, continue", ctxdata->queueid);
        } else {
            snprintf(xhdr, MAXHEADERLEN, "%s %s on %s", STR_PROGNAME, STR_PROGVERSION, hostname);

            if (smfi_addheader(ctx, HEADERNAME_XHEADER, xhdr) != MI_SUCCESS)
                logmsg(LOG_WARNING, "%s: warning: callback_eom: adding X-Header failed, continue", ctxdata->queueid);
        }
    }

    /* statistics */
    inc_stats(&duration);

    /*
     * Per-message heavyweight state is no longer needed; release it before the
     * SMTP connection becomes idle.
     */
    ctxdata_cleanup(ctxdata);

    return SMFIS_CONTINUE;
}

/*
 * may be called at any time during message processing
 * (i.e. between some message-oriented routine and xxfi_eom).
 */
sfsistat callback_abort(SMFICTX* ctx) {

    CTXDATA*       ctxdata;

    logmsg(LOG_DEBUG, "ABORT");

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_abort: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    ctxdata_cleanup(ctxdata);

    return SMFIS_CONTINUE;
}

/*
 * always called once at the end of each connection.
 */
sfsistat callback_close(SMFICTX* ctx) {

    CTXDATA*       ctxdata;

    logmsg(LOG_DEBUG, "CLOSE");

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_close: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    ctxdata_cleanup(ctxdata);
    ctxdata_free(ctxdata);

    if (smfi_setpriv(ctx, NULL) != MI_SUCCESS) {
        /* NOTE: smfi_setpriv return MI_FAILURE when ctx is NULL */
        logmsg(LOG_ERR, "error: callback_close: release milter context failed");
    }

    return SMFIS_CONTINUE;
}
