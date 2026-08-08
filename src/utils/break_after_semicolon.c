#include "break_after_semicolon.h"

/*
 * replaces the ";" followed by any character in a string
 * in the phase before signing with "; \r \n \t"
 * and in the phase after signing with "; \n \t"
 * assumption: after a ; there is always a space. This is ensured by a call to hdrdup.
 *
 * argument: - a memory area allocated with malloc containing a null-terminated string
 *           - PHASE_PRE_SIGN (3) or PHASE_POST_SIGN (2)
 * return:   - in case of error:
 *             NULL
 *           - if the string contains no ;:
 *             the original string
 *           - if the string is < 70 characters:
 *             the original string
 *           - if the string contains at least one ;:
 *             a new memory area allocated with malloc.
 *             the memory passed as argument is freed with free.
 */
char* break_after_semicolon(char* string, int phase) {

    size_t     num_semicolon;
    size_t     orig_len;
    size_t     add;
    size_t     need;
    char*      new_string;
    char*      p_old;
    char*      p_new;

    if (string == NULL) {
        logmsg(LOG_ERR, "FATAL: break_after_semicolon: got NULL string");
        return(NULL);
    }

    num_semicolon = get_num_semicolons(string);
    if (num_semicolon == (size_t)-1)
        return(NULL);

    if (num_semicolon == 0) {
        /* no semicolons in string */
        return (string);
    }

    orig_len = strlen(string);

    /*
     * Each semicolon adds `phase' additional bytes.  Compute the total
     * additional size using unsigned arithmetic with an explicit overflow
     * check (CWE-190).
     */
    if (num_semicolon > SIZE_MAX / (size_t)phase)
        return(NULL);
    add = num_semicolon * (size_t)phase;

    if (add > SIZE_MAX - orig_len - 1)
        return(NULL);
    need = orig_len + add + 1;

    if ((new_string = malloc(need)) == NULL) {
        logmsg(LOG_ERR, "FATAL: break_after_semicolon: malloc failed");
        return(NULL);
    }

    p_old = string;
    p_new = new_string;
    while (*p_old) { /* until \0 */
        *p_new = *p_old;

        if (*p_old != ';') {
            p_old++; p_new++;
        } else {
            if (PHASE_PRE_SIGN == phase) {
                p_new++;
                *p_new = '\r';
            }
            p_new++;
            *p_new = '\n';
            p_new++;
            *p_new = ' ';
            p_new++;
            p_old++; /* character after ; */
            /* skip any whitespace that was already present, but stop at \0 */
            while (*p_old == ' ' || *p_old == '\t')
                p_old++;
        }
    }
    *p_new = '\0';
    logmsg(LOG_DEBUG, "break_after_semicolon: replaced ->%s<- with ->%s<-", string, new_string);
    free(string);
    return (new_string);
}
