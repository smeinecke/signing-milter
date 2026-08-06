#include "get_num_semicolons.h"

/*
 * count the number of semicolons in a string
 *
 * argument: pointer to a null-terminated string
 * return:   number of semicolons
 *           -1 if the argument is a NULL pointer
 * bugs    : integer overflow if more than sizeof(int)/2 - 1
 *           semicolons occur in the string
 */
int get_num_semicolons(char* string) {

    int num_semicolon = 0;
    char* p;

    if (string == NULL) {
        logmsg(LOG_ERR, "FATAL: get_num_semikolons failed: got empty string");
        return(-1);
    }

    p = string;
    while (*p) { /* until \0 */
        if (*p == ';')
            num_semicolon++;
        p++;
    }
    logmsg(LOG_DEBUG, "get_num_semicolons: %i Semicolon in ->%s<-", num_semicolon, string);
    return(num_semicolon);
}
