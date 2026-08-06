#include "node.h"

NODE* newnode(char* headerf, char* headerv, int phase) {

    NODE* n;

    if ((n = (NODE*) malloc(sizeof(NODE))) == NULL) {
        logmsg(LOG_ERR, "newnode: malloc failed");
        return (NULL);
    }
    bzero(n, sizeof(NODE));

    assert(headerf != NULL);
    assert(headerv != NULL);

    if ((n->headerf = hdrdup(headerf)) == NULL) {
        logmsg(LOG_ERR, "newnode: hdrdup(headerf) failed");
        free(n);
        return (NULL);
    }
    if ((n->headerv = hdrdup(headerv)) == NULL) {
        logmsg(LOG_ERR, "newnode: hdrdup(headerv) failed");
        free(n->headerf);
        free(n);
        return (NULL);
    }
    if ((n->headerv = break_after_semicolon(n->headerv, phase)) == NULL) {
        logmsg(LOG_ERR, "newnode: break_after_semicolon(headerv) failed");
        free(n->headerf);
        free(n);
        return (NULL);
    }

    return (n);
}

void freenode(NODE* node) {

    assert(node != NULL);
    assert(node->headerf != NULL);
    assert(node->headerv != NULL);

    free(node->headerf);
    free(node->headerv);
    free(node);
}
