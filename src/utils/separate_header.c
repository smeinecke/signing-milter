#include "separate_header.h"

char* separate_header(char* line, char** headerf) {

    char* p = NULL;
    char* q = NULL;
    char* headerv = NULL;
    size_t i;

    if (line == NULL || *line == '\0') {
        return NULL;
    }

    if ((p = strchr(line, ':')) == NULL) {
        return NULL;
    }

    *p = '\0';
    *headerf = line;

    /* skip the colon and leading whitespace in headerv */
    p++;
    while (*p == ' ' || *p == '\t')
        p++;

    if ((headerv = malloc(MAXHEADERLEN)) == NULL) {
        logmsg(LOG_ERR, "separate_header: failed to allocate %i byte (MAXHEADERLEN)", MAXHEADERLEN);
        return NULL;
    }

    q = headerv;
    /* copy value, cutting off trailing \r\n, \n, or end of string, bounded by buffer size */
    i = 0;
    while (*p != '\0' && *p != '\r' && *p != '\n' && i < MAXHEADERLEN - 1) {
        *q++ = *p++;
        i++;
    }
    *q = '\0';

    return headerv;
}
