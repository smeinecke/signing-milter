#include "append2buffer.h"

#include <stdint.h>

int append2buffer(unsigned char** buf, size_t* buf_size, const char* data2append, size_t append_data_size) {

    unsigned char*  new_buf;
    size_t          new_buf_size;
    unsigned char*  append_pointer;

    if (append_data_size > SIZE_MAX - *buf_size) {
        logmsg(LOG_ERR, "append2buffer: size overflow");
        return(1);
    }

    new_buf_size = *buf_size + append_data_size;
    if (new_buf_size > MAX_MESSAGE_SIZE) {
        logmsg(LOG_ERR, "append2buffer: message size limit exceeded");
        return(1);
    }

    new_buf = realloc(*buf, new_buf_size);
    if (new_buf == NULL) {
        logmsg(LOG_ERR, "append2buffer: realloc failed");
        return(1);
    }

    append_pointer = new_buf + *buf_size;
    *buf = new_buf;
    *buf_size = new_buf_size;

    memcpy(append_pointer, data2append, append_data_size);

    return(0);
}
