#include "is_multipart_mime.h"

/*
 * tests whether a Content-Type header says multipart.
 */
int is_multipart_mime(const char* headerf, const char* headerv) {
    const char* p;
    const char* end;
    size_t len;

    if (strcasecmp(headerf, "content-type"))
        return (0);

    if (headerv == NULL)
        return (0);

    /* skip leading whitespace, extract the media-type token */
    p = headerv;
    while (*p == ' ' || *p == '\t')
        p++;
    end = strpbrk(p, " \t;\r\n");
    if (end == NULL)
        len = strlen(p);
    else
        len = (size_t)(end - p);

    if (len > 10 && strncasecmp(p, "multipart/", 10) == 0)
        return (1);

    return (0);
}
