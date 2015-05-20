/*
 * signing-milter - utils/linkedlist.c
 * Copyright (C) 2010,2011  Andreas Schulze
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
 * loescht einen beliebigen Knoten
 * wenn der zu loeschende Knoten einen Verweis auf einen weiteren Knoten hat,
 * wird dieser Verweis zurueckgegeben
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
