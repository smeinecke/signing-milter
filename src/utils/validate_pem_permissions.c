#include "validate_pem_permissions.h"

#include <fcntl.h>

/*
 * Internal: validate that an already-open PEM file has acceptable
 * permissions: regular file, no access for others, no write/execute
 * for group, no write/execute for owner, and owner readable.
 */
static int check_pem_permissions(int fd, const char* pemfilename) {
    struct stat st;

    if (fstat(fd, &st) < 0) {
        logmsg(LOG_ERR, "validate_pem_permissions: fstat '%s': %m", pemfilename, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s' is not a file", pemfilename);
        return -1;
    }
    if (S_IRWXO & st.st_mode) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove any access for other", pemfilename);
        return -1;
    }
    if (S_IWUSR & st.st_mode || S_IXUSR & st.st_mode) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove write/execute access for owner", pemfilename);
        return -1;
    }
    if (S_IWGRP & st.st_mode || S_IXGRP & st.st_mode) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too open: remove write/execute access for group", pemfilename);
        return -1;
    }
    if (!(S_IRUSR & st.st_mode)) {
        logmsg(LOG_ERR, "validate_pem_permissions: '%s': file permissions too strong: no read access", pemfilename);
        return -1;
    }

    return 0;
}

/*
 * Open a PEM file once with O_NOFOLLOW, validate it with fstat,
 * and return the file descriptor.  Returns -1 on failure.
 * If optional is non-zero and the file does not exist (ENOENT),
 * no error is logged.
 */
int open_and_validate_pem(const char* pemfilename, int optional) {

    int fd;

    if ((fd = open(pemfilename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
        if (optional && errno == ENOENT)
            return -1;
        logmsg(LOG_ERR, "validate_pem_permissions: open '%s': %m", pemfilename, strerror(errno));
        return -1;
    }

    if (check_pem_permissions(fd, pemfilename) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Non-optional wrapper.  Open and validate a PEM file.
 */
int validate_pem_permissions(const char* pemfilename) {
    return open_and_validate_pem(pemfilename, 0);
}
