#include "validate_pem_permissions.h"

/*
 * check whether the file exists and whether it is a file
 * the file must not be accessible for "other"
 * the file must not be writable or executable for the current UID
 * the file must be readable for the current UID
 */

int validate_pem_permissions(const char* pemfilename) {

    struct stat st;

    if (stat(pemfilename, &st) < 0) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': %m", pemfilename, strerror(errno));
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s' is not a file", pemfilename);
        return 1;
    }
    if (S_IRWXO & st.st_mode) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove any access for other", pemfilename);
        return 1;
    }
    if (access(pemfilename, R_OK|W_OK) == 0) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove write access for myself", pemfilename);
        return 1;
    }
    if (access(pemfilename, R_OK) < 0 && errno == EACCES) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too strong: no read access", pemfilename);
        return 1;
    }

    return 0;
}
