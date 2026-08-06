#include "append2buffer.h"

int append2buffer(unsigned char** buf, size_t* buf_size, char* data2append, size_t append_data_size) {

    unsigned char*  new_buf;
    size_t          new_buf_size;
    unsigned char*  append_pointer;

    new_buf_size = *buf_size + append_data_size;
    new_buf = realloc(*buf, new_buf_size);
    if (new_buf == NULL) {
        logmsg(LOG_ERR, "append2buffer: realloc failed\n");
        return(1);
    }

    append_pointer = new_buf + *buf_size;
    *buf = new_buf;
    *buf_size = new_buf_size;

    memcpy(append_pointer, data2append, append_data_size);

    return(0);
}
