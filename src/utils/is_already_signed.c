#include "is_already_signed.h"

static const char* skip_whitespace(const char* s) {
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

static size_t token_len(const char* s, const char* stop) {
    if (stop == NULL)
        return strlen(s);
    return (size_t)(stop - s);
}

int is_already_signed(const char* headerf, const char* headerv) {
    const char* p;
    const char* end;
    const char* q;
    size_t type_len;

    if (strcasecmp(headerf, "content-type"))
        return (0);

    if (headerv == NULL)
        return (0);

    /* extract the media type / subtype token */
    p = skip_whitespace(headerv);
    end = strpbrk(p, " \t;\r\n");
    type_len = token_len(p, end);

    if (type_len != 16 || strncasecmp(p, "multipart/signed", 16) != 0)
        return (0);

    /* need a protocol parameter with value application/pkcs7-signature */
    if (end == NULL)
        return (0);

    q = end;
    while (*q != '\0') {
        const char* attr;
        const char* attr_end;
        size_t attr_len;
        const char* val;
        size_t val_len;
        int quoted;

        /* skip separator and whitespace */
        while (*q == ' ' || *q == '\t' || *q == ';')
            q++;
        if (*q == '\0')
            break;

        attr = q;
        attr_end = strpbrk(q, " \t=\r\n;");
        if (attr_end == NULL)
            attr_end = q + strlen(q);
        attr_len = token_len(attr, attr_end);

        q = attr_end;
        q = skip_whitespace(q);
        if (*q != '=')
            continue;
        q++;
        q = skip_whitespace(q);

        quoted = 0;
        if (*q == '"') {
            quoted = 1;
            q++;
        }

        val = q;
        if (quoted) {
            while (*q != '\0' && *q != '"')
                q++;
            val_len = token_len(val, q);
            if (*q == '"')
                q++;
        } else {
            while (*q != '\0' && *q != ';' && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n')
                q++;
            val_len = token_len(val, q);
        }

        if (attr_len == 8 && strncasecmp(attr, "protocol", 8) == 0) {
            if (val_len == 27 && strncasecmp(val, "application/pkcs7-signature", 27) == 0)
                return (1);
            return (0);
        }
    }

    return (0);
}
