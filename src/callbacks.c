#include "callbacks.h"

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
 * called once at the beginning of each message (MAIL command),
 * before xxfi_envrcpt.
 *
 * argv: Null-terminated SMTP command arguments;
 *       argv[0] is guaranteed to be the sender address.
 *       Later arguments are the ESMTP arguments.
 *
 * May be called multiple times within one connection.
 * Could be that ctxdata is already filled.
 *
 */
sfsistat callback_envfrom(SMFICTX* ctx, char** argv) {

    const char*    pemfilename = NULL;
    CTXDATA*       ctxdata;
    const char*    daemon_name;
    int            i;

    char*          redis_pem = NULL;
    size_t         redis_pem_len = 0;
    char*          redis_chain = NULL;
    size_t         redis_chain_len = 0;
    int            redis_found = 0;

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

    dict_reload(&dict_signingtable);

    if (opt_redis_uri != NULL && *opt_redis_uri != '\0') {
        i = redis_lookup_cert(argv[0], &redis_pem, &redis_pem_len, &redis_chain, &redis_chain_len);
        if (i == -1)
            return SMFIS_TEMPFAIL;
        if (i == 0)
            redis_found = 1;
    }

    if (!redis_found) {
        pemfilename = dict_lookup(&dict_signingtable, argv[0]);
        if (pemfilename == NULL || *pemfilename == '\0') {
            /*
             * Sender not found in the signing table.
             * No further action needed.
             */
            if (opt_signerfromheader) {
                logmsg(LOG_DEBUG, "no cert for envsender, will look for '%s'", HEADERNAME_SIGNER);
            } else {
                logmsg(LOG_INFO, "no signingdata for '%s'", argv[0]);
                return SMFIS_ACCEPT;
            }
        }
    }

    /*
     * Prepare the private data structure
     */
    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) != NULL) {
        /* actually LOG_INFO / not important, but I want to see this in the log once */
        logmsg(LOG_WARNING, "callback_envfrom: REUSED CONNECTION !!!!");
        ctxdata_cleanup(ctxdata);
    } else {
        if ((ctxdata = ctxdata_create()) == NULL)
            return SMFIS_TEMPFAIL;
    }

    if (redis_found) {
        logmsg(LOG_INFO, "signingdata from redis for envsender '%s'", argv[0]);
        if ((i = ctxdata_setup_from_redis(ctxdata, argv[0], redis_pem, redis_pem_len, redis_chain, redis_chain_len, opt_redis_passphrase)) != 0) {
            logmsg(LOG_ERR, "callback_envfrom: ctxdata_setup_from_redis() failed: rc=%i, envsender='%s'", i, argv[0]);
            return SMFIS_TEMPFAIL;
        }
    } else if (pemfilename != NULL && *pemfilename != '\0') {
        logmsg(LOG_INFO, "signingdata from envsender '%s'", argv[0]);
        if ((i = ctxdata_setup(ctxdata, pemfilename)) != 0) {
            logmsg(LOG_ERR, "callback_envfrom: ctxdata_setup() failed: rc=%i, envsender='%s', file=%s", i, argv[0], pemfilename);
            return SMFIS_TEMPFAIL;
        }
    }

    /*
     * save the private data
     */
    if (smfi_setpriv(ctx, ctxdata) != MI_SUCCESS) {
        logmsg(LOG_ERR, "error: callback_envfrom: setpriv failed, envsender='%s'", argv[0]);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

sfsistat callback_envrcpt(SMFICTX* ctx, char** argv) {

    CTXDATA*       ctxdata;

    if (!opt_modetable)
        return SMFIS_CONTINUE;

    logmsg(LOG_DEBUG, "RCPT TO: %s", argv[0]);

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_envrcpt: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);

    dict_reload(&dict_modetable);
    dict_lookup(&dict_modetable, argv[0]);
    if (dict_modetable.result != NULL && *dict_modetable.result != '\0') {
        /*
         * Recipient found in the mode table.
         * The result applies to *all* recipients.
         */
        logmsg(LOG_DEBUG, "callback_envrcpt: %s found in modetable: value='%s'", argv[0], dict_modetable.result);

        if (strstr(dict_modetable.result, "skip") != NULL) {
            logmsg(LOG_INFO, "modetable hit: skip signing for %s", argv[0]);
            /* ctxdata is owned by the milter context and is cleaned up
             * in callback_envfrom or callback_close.  No extra free here. */
            return SMFIS_ACCEPT;
        }
        if (strstr(dict_modetable.result, "opaque") != NULL) {
            logmsg(LOG_DEBUG, "callback_envrcpt: opaque signingmode enabled for %s", argv[0]);
            ctxdata->mailflags |= MF_SIGNMODE_OPAQUE;
        }
        if (strstr(dict_modetable.result, "keep") != NULL) {
            logmsg(LOG_INFO, "modetable hit: keep message for %s in /tmp", argv[0]);
            ctxdata->keepdir = "/tmp";
        }
    }
    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);
    return SMFIS_CONTINUE;
}

/*
 * called once for each message header.
 * headerf: Header field name.
 * headerv: Header field value. The content of the header may include folded white space,
 *          i.e., multiple lines with following white space where lines are separated by LF (not CR/LF).
 *          The trailing line terminator (CR/LF) is removed.
 *
 * Starting with sendmail 8.14, spaces after the colon in a header field are preserved
 * if requested using the flag SMFIP_HDR_LEADSPC
 * -> https://www.milter.org/developers/api/xxfi_header
 */
sfsistat callback_header(SMFICTX* ctx, char* headerf, char* headerv) {

    CTXDATA*       ctxdata;
    NODE*          n;
    int            i;

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
         * Already signed messages do not need to be
         * processed further
         */
        if (is_already_signed(headerf, headerv)) {
            logmsg(LOG_NOTICE, "mail seemes already signed.");
            return SMFIS_ACCEPT;
        }

        if (is_multipart_mime(headerf, headerv)) {
            logmsg(LOG_DEBUG, "callback_header: multipart Mime-Mail erkannt");
            ctxdata->mailflags |= MF_TYPE_MULTIPART;
        }

        if ((n = newnode(headerf, headerv, PHASE_PRE_SIGN)) == NULL) {
            logmsg(LOG_ERR, "error: callback_header: alloc new node failed");
            return SMFIS_TEMPFAIL;
        }
        appendnode(&(ctxdata->headerchain), n);
    }

    if (!opt_signerfromheader)
        return SMFIS_CONTINUE;

    if (strcasecmp(headerf, HEADERNAME_SIGNER) == 0) {

        const char*    pemfilename = NULL;
        char*          redis_pem = NULL;
        size_t         redis_pem_len = 0;
        char*          redis_chain = NULL;
        size_t         redis_chain_len = 0;
        int            redis_found = 0;

        logmsg(LOG_DEBUG, "callback_header: signerfrom_header: %s", headerv);

        dict_reload(&dict_signingtable);

        if (opt_redis_uri != NULL && *opt_redis_uri != '\0') {
            i = redis_lookup_cert(headerv, &redis_pem, &redis_pem_len, &redis_chain, &redis_chain_len);
            if (i == -1)
                return SMFIS_TEMPFAIL;
            if (i == 0)
                redis_found = 1;
        }

        if (!redis_found) {
            pemfilename = dict_lookup(&dict_signingtable, headerv);
            if (pemfilename == NULL || *pemfilename == '\0') {
                /*
                 * Sender not found in the signing table.
                 * No further action needed.
                 */
                logmsg(LOG_INFO, "no signingdata for %s", headerv);
                return SMFIS_ACCEPT;
            }
        }

        if (redis_found) {
            logmsg(LOG_INFO, "signingdata from redis for header signer '%s'", headerv);
            if ((i = ctxdata_setup_from_redis(ctxdata, headerv, redis_pem, redis_pem_len, redis_chain, redis_chain_len, opt_redis_passphrase)) != 0) {
                logmsg(LOG_ERR, "callback_header: ctxdata_setup_from_redis() failed: rc=%i, headerf=%s, headerv=%s", i, headerf, headerv);
                return SMFIS_TEMPFAIL;
            }
        } else {
            if ((i = ctxdata_setup(ctxdata, pemfilename)) != 0) {
                logmsg(LOG_ERR, "callback_header: ctxdata_setup() failed: rc=%i, headerf=%s, headerv=%s, file=%s", i, headerf, headerv, pemfilename);
                return SMFIS_TEMPFAIL;
            }
        }

        /*
         * Header field must be deleted in callback_eom
         */
        ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
    }

    if (strcasecmp(headerf, HEADERNAME_SKIP_SIGNING) == 0) {
        /*
         * we can't simply 'return SMFIS_ACCEPT' as we must remove the header later
         */
        ctxdata->mailflags |= MF_SKIP_SIGNING;
        logmsg(LOG_DEBUG, "callback_header: header %s found: skip signing", headerf);
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

    if (ctxdata->mailflags & MF_SKIP_SIGNING) {
       logmsg(LOG_INFO, "%s: skip signing requested by header", ctxdata->queueid);
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

    /*
     * only a MIME-Version header present, no Content-* header
     * https://tools.ietf.org/html/rfc2045#section-5.2 mention an implicit default
     */
    if ( (ctxdata->headerchain == NULL) && ((ctxdata->mailflags & MF_TYPE_MIME) != 0) ) {

        NODE* n;
        const char* headerf = "Content-Type";
        const char* headerv = "text/plain; charset=\"us-ascii\"";

        logmsg(LOG_WARNING, "%s: malformed Content: 'MIME-Version' header but no 'Content-*' header found. Please read RFC 2045, Section 5.2. Adding '%s: %s'" , ctxdata->queueid, headerf, headerv);

        if ((n = newnode(headerf, headerv, PHASE_PRE_SIGN)) == NULL) {
            logmsg(LOG_ERR, "error: callback_eoh: alloc new node failed");
            return SMFIS_TEMPFAIL;
        }
        appendnode(&(ctxdata->headerchain), n);
    }

    dump_mailflags(ctxdata->mailflags);
    dump_pkcs7flags(ctxdata->pkcs7flags);

    if (opt_signerfromheader && ctxdata->pemfilename == NULL) {
        logmsg(LOG_INFO, "%s: callback_eoh: no signingdata ...", ctxdata->queueid);
        return SMFIS_ACCEPT;
    }

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
        if (smfi_chgheader(ctx, HEADERNAME_SKIP_SIGNING, 0, NULL) != MI_SUCCESS) {
            logmsg(LOG_ERR, "%s: error: callback_eom: delete Header %s failed, continue", ctxdata->queueid, HEADERNAME_SKIP_SIGNING);
        }
       return SMFIS_CONTINUE;
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
            if (new_end - 4 < ctxdata->data2sign)
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
    if ((ctxdata->inbio = BIO_new_mem_buf(ctxdata->data2sign, ctxdata->data2sign_len)) == NULL) {
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
     * if present: delete HEADERNAME_SIGNER
     */
    if (ctxdata->mailflags & MF_SIGNER_FROM_HEADER) {
        if (smfi_chgheader(ctx, HEADERNAME_SIGNER, 0, NULL) != MI_SUCCESS) {
            logmsg(LOG_ERR, "%s: error: callback_eom: delete Header %s failed, continue", ctxdata->queueid, HEADERNAME_SIGNER);
        }
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

    if (smfi_replacebody(ctx, (unsigned char*)(outmem->data), outmem->length) != MI_SUCCESS) {
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
