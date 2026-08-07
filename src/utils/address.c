#include "address.h"

#include <ctype.h>
#include <string.h>

char* lowercase(char* string);

int normalize_address_safe(const char* raw, char* out, size_t out_len) {

    size_t      len;
    const char* src;
    char*       cp;
    int         ch;

    if (raw == NULL || out == NULL || out_len == 0)
        return 0;

    src = raw;
    len = strlen(src);

    if (*src == '<' && len >= 2 && src[len - 1] == '>') {
        src++;
        len -= 2;
    }

    if (len == 0) {
        if (out_len >= 3) {
            memcpy(out, "<>", 3);
            return 1;
        }
        *out = '\0';
        return 0;
    }

    if (len >= out_len) {
        *out = '\0';
        return 0;
    }

    memcpy(out, src, len);
    out[len] = '\0';

    for (cp = out; (ch = *(unsigned char*) cp) != 0; cp++)
        if (isupper(ch))
            *(unsigned char*) cp = (char) tolower(ch);

    return 1;
}

void normalize_address(const char* raw, char* out, size_t out_len) {

    size_t      len;
    const char* src;
    char*       cp;
    int         ch;

    if (raw == NULL || out == NULL || out_len == 0)
        return;

    *out = '\0';
    src = raw;
    len = strlen(src);

    if (*src == '<' && len >= 2 && src[len - 1] == '>') {
        src++;
        len -= 2;
    }

    if (len == 0) {
        if (out_len >= 3) {
            memcpy(out, "<>", 3);
        }
        return;
    }

    if (len >= out_len)
        len = out_len - 1;

    memcpy(out, src, len);
    out[len] = '\0';

    for (cp = out; (ch = *(unsigned char*) cp) != 0; cp++)
        if (isupper(ch))
            *(unsigned char*) cp = tolower(ch);
}
