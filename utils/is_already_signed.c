#include "is_already_signed.h"

int is_already_signed(char* headerf, char* headerv) {
    char headerv_lower[MAXHEADERLEN + 1];

    if (strcasecmp(headerf, "content-type"))
        return (0);

    if (headerv == NULL)
        return (0);

    strncpy(headerv_lower, headerv, MAXHEADERLEN);
    headerv_lower[MAXHEADERLEN] = '\0';
    (void) lowercase(headerv_lower);

    if (strstr(headerv_lower, "multipart/signed") == NULL)
        return (0);

    if (strstr(headerv_lower, "pkcs7-signature") == NULL)
        return (0);

    logmsg(LOG_DEBUG, "is_already_signed: header indicates message already signed");
    return (1);
}
