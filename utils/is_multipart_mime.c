#include "is_multipart_mime.h"

/*
 * tests whether a Content-Type header says multipart.
 */
int is_multipart_mime(char* headerf, char* headerv) {

    if (strcasecmp(headerf, "content-type"))
        return (0);

    if (strstr(headerv, "multipart/") != NULL)
        return (1);

    return (0);
}
