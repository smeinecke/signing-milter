#include "linkedlist.h"

NODE* get_last(NODE* node) {

    NODE* p = node;

    assert(p != NULL);
    while(p->next != NULL) {             /* continue whilst there are nodes left */
        p = p->next;                     /* goto the next node in the list       */
    }

    assert(p != NULL);
    return (p);
}

/*
 * this adds a node to the end of the list. You must allocate a node and
 * then pass its address to this function.
 * A tail pointer is maintained so appending is O(1) regardless of the
 * current list length.
 */
NODE* appendnode(NODE** head, NODE** tail, NODE* node) {

    assert(node != NULL);
    node->next = NULL;
    if (*head == NULL) {
        *head = node;
        *tail = node;
    } else {
        assert(*tail != NULL);
        (*tail)->next = node; /* link in the new node to the end of the list */
        *tail = node;         /* update tail pointer                       */
    }
    return (*head);
}

/*
 * deletes an arbitrary node
 * if the node to be deleted has a reference to another node,
 * that reference is returned
 */
NODE* deletenode(NODE* node) {

    NODE* next = NULL;

    assert(node != NULL);
    next = node->next;
    freenode(node);

    return (next);
}

void deletechain(NODE* node) {

    assert(node != NULL);

    do {
        node = deletenode(node);
    } while (node != NULL);
}
