/*
 * signing-milter - utils/node.c
 * Copyright (C) 2010-2018  Andreas Schulze
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Authors:
 *   Andreas Schulze <signing-milter at andreasschulze.de>
 *
 */

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
