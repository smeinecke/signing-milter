#include "hdrdup.h"

/* idea: postfix:src/global/lex_822.h */
#define IS_CR_LF(ch)            (ch == '\r' || ch == '\n')
#define IS_NOT_SPACE_TAB(ch)    (ch != ' '  && ch != '\t')

/*
 * hdrdup, analogous to strdup
 * string is headerf or headerv
 *
 * replaces \n, \r\n and following SPACES or TABS with exactly one SPACE
 */
char* hdrdup(const char* string) {

    char*  dup;
    char   c;
    char*  p;
    size_t string_len;
    size_t dup_len;
    int    skip = 0;

    assert(string != NULL);

    string_len = strlen(string) + 1; /* for the terminating \0 */
    if ((dup = malloc(string_len)) == NULL)
        return NULL;

    p = dup;
    while ((c = *string) != '\0') {
        string++;

        /*
         * skip and remember the line break.
         */
        if (IS_CR_LF(c)) {
            skip = 1;
            continue;
        }
        /* only when no SPACE or TAB follows a line break,
         * the line break is finished
         * -> so insert a space
         */
        if (skip && IS_NOT_SPACE_TAB(c)) {
            *p = ' ';
            p++;
            skip = 0;
        }

        if (skip)
            continue;

        *p = c;
        p++;
    }
    *p = '\0'; /* terminate string */

    dup_len = strlen(dup) + 1; /* for the terminating \0 */
    if (string_len > dup_len) {
        logmsg(LOG_INFO, "hdrdup: string_len/%u != dup_len/%u, val=%s", (unsigned int) string_len, (unsigned int) dup_len, dup);
        if ((p = realloc(dup, dup_len)) != NULL)
            dup = p;
        else
            logmsg(LOG_ERR, "hdrdup: realloc failed");
    }

    return (dup);
}
