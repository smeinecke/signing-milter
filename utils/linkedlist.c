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
 * then pass its address to this function
 */
NODE* appendnode(NODE** head, NODE* node) {

    NODE* end;

    assert(node != NULL);
    if (*head == NULL)
        *head = node;
    else {
        end = get_last(*head);
        end->next = node;    /* link in the new node to the end of the list */
        node->next = NULL;   /* set next field to signify the end of list   */
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
