#include "logmsg.h"

/*
 * Escape control and non-printable bytes in a log line so that untrusted
 * message values cannot inject new log lines, fold headers into multi-line
 * records, or hide content with terminal control characters.  Printable ASCII
 * (0x20-0x7e) and high bytes (UTF-8 continuations) are copied as-is.
 */
static void log_sanitize(const char* in, char* out, size_t out_len) {
    size_t i, o;

    for (i = 0, o = 0; in[i] != '\0' && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char) in[i];
        if ((c >= 0x20 && c < 0x7F) || c >= 0x80) {
            out[o++] = (char) c;
        } else if (o + 4 < out_len) {
            out[o++] = '\\';
            out[o++] = 'x';
            out[o++] = "0123456789abcdef"[c >> 4];
            out[o++] = "0123456789abcdef"[c & 0x0f];
        } else {
            break;
        }
    }

    if (in[i] != '\0') {
        if (o + 3 < out_len) {
            out[o++] = '.';
            out[o++] = '.';
            out[o++] = '.';
        } else if (o + 1 < out_len) {
            out[o++] = '.';
        }
    }

    out[o] = '\0';
}

void logmsg(int priority, const char *fmt, ...) {

    char    raw[LOG_MAXLOGBUF];
    char    sanitized[LOG_MAXLOGBUF];
    va_list ap;

    if (priority <= opt_loglevel || priority <= LOG_WARNING) {

        /* Format message */
        va_start(ap, fmt);
        (void) vsnprintf(raw, sizeof(raw), fmt, ap);
        va_end(ap);

        log_sanitize(raw, sanitized, sizeof(sanitized));

        /* Write message to syslog */
        if (LOG_DEST_SYSLOG == opt_logdest)
            syslog(priority, "%s", sanitized);

        /* Print message to terminal */
        if (LOG_DEST_STDOUT == opt_logdest || opt_loglevel >= LOG_DEBUG || priority <= LOG_WARNING) {
            fprintf(stdout, "%s\n", sanitized);
        }
    }
}
