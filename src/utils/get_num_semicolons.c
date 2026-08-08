#include "get_num_semicolons.h"

/*
 * count the number of semicolons in a string
 *
 * argument: pointer to a null-terminated string
 * return:   number of semicolons
 *           (size_t)-1 if the argument is a NULL pointer
 */
size_t get_num_semicolons(const char* string) {

    size_t      num_semicolon = 0;
    const char* p;

    if (string == NULL) {
        logmsg(LOG_ERR, "FATAL: get_num_semikolons failed: got empty string");
        return (size_t)-1;
    }

    p = string;
    while (*p) { /* until \0 */
        if (*p == ';')
            num_semicolon++;
        p++;
    }
    logmsg(LOG_DEBUG, "get_num_semicolons: %zu Semicolon in ->%s<-", num_semicolon, string);
    return num_semicolon;
}
