#include "separate_header.h"

char* separate_header(const char* line, char** headerf) {

    char* p = NULL;
    char* q = NULL;
    char* headerv = NULL;

    if (line == NULL || *line == '\0') {
        return (0);
    }

    if ((p = strchr(line, ':')) != NULL) {
        *p = '\0';
        *headerf = (char*) line;
    }

    /* skip the terminating \0 */
    p++;

    /* skip leading spaces in headerv */
    while (*p == ' ')
      p++;

    if ((headerv = malloc(MAXHEADERLEN)) == NULL) {
        logmsg(LOG_ERR, "separate_header: failed to allocate %i byte (MAXHEADERLEN)", MAXHEADERLEN);
        return NULL;
    }

    q = headerv;
    /* cut off trailing \r\n or \n */
    while (*p != '\r' && *p != '\n') {
        *q = *p;
        p++;
        q++;
    }

    *q = '\0';

    return (headerv);
}
