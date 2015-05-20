/*
 * signing-milter - callbacks.c
 * Copyright (C) 2010-2015  Andreas Schulze
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
 * Wird möglicherweise mehrfach innerhalb einer Verbindung
 * aufgerufen. Könnte also sein. das ctxdata schon befüllt ist.
 *
 */
sfsistat callback_envfrom(SMFICTX* ctx, char** argv) {

    const char*    pemfilename = NULL;
    CTXDATA*       ctxdata;
    char*          daemon_name;
    int            i;


    if ((daemon_name = smfi_getsymval(ctx, "{daemon_name}")) == NULL) {
        daemon_name = "smfi_getsymval(daemon_name) failed";
        logmsg(LOG_WARNING, "warning: callback_envfrom smfi_getsymval(daemon_name) failed, continue");
    }

    /*
     * emty sender has different representations.
     * in smtpd_milter it is '<>'
     * in non_smtpd_milter it is ''
     */
    logmsg(LOG_DEBUG, "MAIL FROM: '%s' (via %s)", argv[0], daemon_name);

    /*
     * Testen, ob die Tabelle aktuell ist.
     * TODO: automaischer reload
     */
    warn_if_dict_changed(&dict_signingtable);

    pemfilename = dict_lookup(&dict_signingtable, argv[0]);
    if (pemfilename == NULL || *pemfilename == '\0') {
        /*
         * Absender nicht in der Signingtable gefunden.
         *  keine weitere Aktion noetig.
         */
        if (opt_signerfromheader) {
            logmsg(LOG_DEBUG, "no cert for envsender, will look for '%s'", HEADERNAME_SIGNER);
        } else {
            logmsg(LOG_INFO, "no signingdata for '%s'", argv[0]);
            return SMFIS_ACCEPT;
        }
    }

    /*
     * Private Datenstruktur vorbereiten
     */
    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) != NULL) {
        /* eigentlich LOG_INFO / unbedeutend, aber ich möchte das mal im Log sehen */
        logmsg(LOG_WARNING, "callback_envfrom: REUSED CONNECTION !!!!");
        ctxdata_cleanup(ctxdata);
    } else {
        if ((ctxdata = ctxdata_create()) == NULL)
            return SMFIS_TEMPFAIL;
    }

    if (pemfilename != NULL && *pemfilename != '\0') {
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

    warn_if_dict_changed(&dict_modetable);
    dict_lookup(&dict_modetable, argv[0]);
    if (dict_modetable.result != NULL && *dict_modetable.result != '\0') {
        /*
         * Empfaenger in der modetable gefunden.
         * Ergebnis gilt fuer *alle* Empfaenger.
         */
        logmsg(LOG_DEBUG, "callback_envrcpt: %s found in modetable: value='%s'", argv[0], dict_modetable.result);

        if (strstr(dict_modetable.result, "skip") != NULL) {
            logmsg(LOG_INFO, "modetable hit: skip signing for %s", argv[0]);
            /* TODO: muss hier noch Speicher freigegeben werden? */
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
        if ((ctxdata->queueid = smfi_getsymval(ctx, "{i}")) == NULL) {
            ctxdata->queueid = "unknown";
            logmsg(LOG_WARNING, "%s: warning: callback_eoh: smfi_getsymval(queueid) failed", ctxdata->queueid);
        }
        logmsg(LOG_NOTICE, "callback_header: got queuid: %s", ctxdata->queueid);
    }

    if (strcasecmp(headerf, "mime-version") == 0) {
        logmsg(LOG_DEBUG, "callback_header: Mime-Mail erkannt");
        ctxdata->mailflags |= MF_TYPE_MIME;
    }
 
    /*
     * RFC 2045 definiert
     * Content-Type, Content-Transfer-Encoding, Content-ID und Content-Description
     * Abschnitt 9 legt fest, dass alle Erweiterungen mit content- beginnen werden
     */
    if (strncasecmp(headerf, "content-", 8) == 0) { 

        /*
         * schon signierte Nachrichten brauchen nicht weiter
         * bearbeitet werden
         * TODO: die Erkennung, ob eine Mail schon signiert ist,
         *       ist sicher noch nocht perfekt
         */
        if (is_already_signed(headerf, headerv)) {
            logmsg(LOG_NOTICE, "mail seemes allready signed.");
            return SMFIS_ACCEPT;
        }

        if (is_multipart_mime(headerf, headerv)) {
            logmsg(LOG_DEBUG, "callback_header: multipart Mime-Mail erkannt");
            ctxdata->mailflags |= MF_TYPE_MULTIPART;
        }

        if ((n = newnode(headerf, headerv)) == NULL) {
            logmsg(LOG_ERR, "error: callback_header: alloc new node failed");
            return SMFIS_TEMPFAIL;
        }
        appendnode(&(ctxdata->headerchain), n);
    }

    if (!opt_signerfromheader)
        return SMFIS_CONTINUE;

    if (strcasecmp(headerf, HEADERNAME_SIGNER) == 0) {

        const char*    pemfilename;

        logmsg(LOG_DEBUG, "callback_header: signerfrom_header: %s", headerv);

        /*
         * Testen, ob die Tabelle aktuell ist.
         * TODO: automatischer reload
         */
        warn_if_dict_changed(&dict_signingtable);

        pemfilename = dict_lookup(&dict_signingtable, headerv);
        if (pemfilename == NULL || *pemfilename == '\0') {
            /*
             * Absender nicht in der Signingtable gefunden.
             *  keine weitere Aktion noetig.
             */
            logmsg(LOG_INFO, "no signingdata for %s", headerv);
            return SMFIS_ACCEPT;
        }

        if ((i = ctxdata_setup(ctxdata, pemfilename)) != 0) {
            logmsg(LOG_ERR, "callback_header: ctxdata_setup() failed: rc=%i, headerf=, headerv=, file=%s", i, headerf, headerv, pemfilename);
            return SMFIS_TEMPFAIL;
        }

        /*
         * Headerfeld muss in callback_eom geloescht werden
         */
        ctxdata->mailflags |= MF_SIGNER_FROM_HEADER;
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
     * Nach dem DATA steht die QueueID fest. Da dieser Milter kein
     * callback beim DATA-Kommano implementiert, ist dies der erste
     * callback, wo die QueueID abrufbar ist.
     */
    if (!ctxdata->queueid) {
        if ((ctxdata->queueid = smfi_getsymval(ctx, "{i}")) == NULL) {
            ctxdata->queueid = "unknown";
            logmsg(LOG_WARNING, "%s: warning: callback_eoh: smfi_getsymval(queueid) failed", ctxdata->queueid);
        }
    }

    /* RFC 2045: MIME-Version Header ist Pflicht, wenn Content-* Header benutzt werden */
    if ( (ctxdata->headerchain != NULL) && ((ctxdata->mailflags & MF_TYPE_MIME) == 0) ) {

        char reply[] = "invalid Content: no 'MIME-Version' header but 'Content-*' header found. That violates RFC 2045";
        logmsg(LOG_ERR, "%s: callback_eoh: %s", ctxdata->queueid, reply);
        smfi_setreply(ctx, "550", "5.6.0", reply);
        return SMFIS_REJECT;
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
    unsigned char* next_c;
    size_t         length = len;

    logmsg(LOG_DEBUG, "BODY (%i byte)", len);

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_body: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    /*
     * wenn die Mail eine Multipart-Mime-Mail ist,
     * beginnt sie mit einer Preambel ( RFC 2046, 5.1.1 )
     * diese Preambel endet mit der ersten Boundary ( ^-- ) und wird nicht in die Signatur einbezogen.
     */
    if ((ctxdata->first_bodychunk_seen == 0) && (ctxdata->mailflags & MF_TYPE_MULTIPART)) {
        /* erster Chunk */
        ctxdata->first_bodychunk_seen = 1;
        for(;;) {
            while (*start != '-' && length > 0) {
                start++;
                length--;
            }
            next_c = start; next_c++;
            if (*next_c == '-') break;
            start++;
            length--;
        }
        logmsg(LOG_DEBUG, "%s: skipping %lu/%lu first bytes while copying body to signingbuffer", ctxdata->queueid, start - bodyp, len - length);
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
    char*          keepdir;

    logmsg(LOG_DEBUG, "EOM");

    if ((ctxdata = (CTXDATA*) smfi_getpriv(ctx)) == NULL) {
        logmsg(LOG_DEBUG, "callback_eom: context is not set, continue");
        return SMFIS_CONTINUE;
    }

    /*
     *  "echo | /usr/sbin/sendmail rcpt" erzeugt Nachrichten mit 0 Byte body
     *  aber BIO_new_mem_buf mag 0 Byte gar nicht. Also spendieren wir einen Zeilenumbruch
     */
    if (0 == ctxdata->data2sign_len) {
        if ((append2buffer(&(ctxdata->data2sign), &(ctxdata->data2sign_len), "\r\n", 2)) != 0) {
            logmsg(LOG_ERR, "%s: error: callback_eom: append2buffer failed", ctxdata->queueid);
            return SMFIS_TEMPFAIL;
        }
    }

    logmsg(LOG_DEBUG, "callback_eom: ctxdata->data2sign_len=%zu", ctxdata->data2sign_len);

    gettimeofday(&start_time, NULL);

    /*
     * Header und Body sind nun komplett im Puffer data2sign.
     * Aus diesem Puffer wird nun ein BIO gemacht
     */
    if ((ctxdata->inbio = BIO_new_mem_buf(ctxdata->data2sign, ctxdata->data2sign_len)) == NULL) {
        logmsg(LOG_ERR, "%s: error: callback_eom: creating inBIO failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }

    /* global oder bei Bedarf (modetable) Daten aufheben */
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
     * Content-Type Header nun wirklich löschen
     */
    if (delete_marked_headers(ctx, ctxdata) != 0) {
        logmsg(LOG_ERR, "%s: error: callback_eom: delete_marked_headers failed", ctxdata->queueid);
        return SMFIS_TEMPFAIL;
    }
 
    /*
     * wenn vorhanden: HEADERNAME_SIGNER loeschen 
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
     * aus outbio die neuen MIME-Header rausziehen
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
            return SMFIS_TEMPFAIL;
        }

        /* leere Zeile: header ist komplett */
        if ((strcmp(headerline, "\r\n") == 0) || (strcmp(headerline, "\n") == 0)) {
            if (headerline)
                free(headerline);
            break;
	}

        logmsg(LOG_DEBUG, "%s: Header aus PKCS7: %s", ctxdata->queueid, headerline);

	/* XXX: was ist, wenn eine 7bit ASCII Mail signiert wurde?
         *      dann fehlt doch der Mime-Version: 1.0 Header?
         */
        if (strncasecmp(headerline, "mime-version", 12) == 0) {
            logmsg(LOG_DEBUG, "%s: skip mime-version header", ctxdata->queueid);
            if (headerline)
                free(headerline);
            continue;
        }

        /*
         * separieren der Zeile in 2 Teile. Dazu wird ':' durch '\0' ersetzt
         * und im headerv führende Leerzeichen übersprungen
         */
        if ((headerv = separate_header(headerline, &headerf)) == NULL) {
            logmsg(LOG_ERR, "%s: error: callback_eom: separate_header failed", ctxdata->queueid);
            if (headerline)
                free(headerline);
            return SMFIS_TEMPFAIL;
        }

        if ((headerv = break_after_semicolon(headerv)) == NULL) {
            logmsg(LOG_ERR, "%s: error: callback_eom: break_after_semicolon failed", ctxdata->queueid);
            if (headerline)
                free(headerline);
            return SMFIS_TEMPFAIL;
        }

        logmsg(LOG_DEBUG, "%s: separierter, umgebrochener Header: %s:%s", ctxdata->queueid, headerf, headerv);

        /*
         * nun die Header neu setzen
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

    /* dann body replace */
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
     * etwas angeben ...
     */
    logmsg(LOG_NOTICE, "%s: %ssigned with %s%s", ctxdata->queueid, ctxdata->mailflags & MF_SIGNMODE_OPAQUE ? "opaque" : "clear", ctxdata->pemfilename, ctxdata->chain != NULL ? " (+chain)" : "(ohne chain");
    logmsg(LOG_INFO, "%s: signing %ld byte took %d.%d sec", ctxdata->queueid, ctxdata->data2sign_len, duration.tv_sec, duration.tv_usec);

    /*
     * abschliessend einen X-Header in die Mail stempeln
     */
    if (opt_addxheader) {
        char  xhdr[MAXHEADERLEN + 1];
        char* hostname;

        bzero(xhdr, sizeof(xhdr));
        if ((hostname = smfi_getsymval(ctx, "{j}")) == NULL) {
            logmsg(LOG_WARNING, "%s: warning: callback_eom: smfi_getsymval(hostname) failed, cannot addxheader, continue", ctxdata->queueid);
        } else {
            snprintf(xhdr, MAXHEADERLEN, "%s %s on %s", STR_PROGNAME, STR_PROGVERSION, hostname);

            if (smfi_addheader(ctx, HEADERNAME_XHEADER, xhdr) != MI_SUCCESS)
                logmsg(LOG_WARNING, "%s: warning: callback_eom: adding X-Header failed, continue", ctxdata->queueid); 
        }
    }

    /* Statistik */
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
