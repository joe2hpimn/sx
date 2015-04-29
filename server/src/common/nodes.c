/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *  Special exception for linking this software with OpenSSL:
 *
 *  In addition, as a special exception, Skylable Ltd. gives permission to
 *  link the code of this program with the OpenSSL library and distribute
 *  linked combinations including the two. You must obey the GNU General
 *  Public License in all respects for all of the code used other than
 *  OpenSSL. You may extend this exception to your version of the program,
 *  but you are not obligated to do so. If you do not wish to do so, delete
 *  this exception statement from your version.
 */

#include "default.h"
#include <string.h>
#include <stdlib.h>

#include "nodes.h"
#include "log.h"
#include "../libsx/src/hostlist.h"

struct _sx_node_t {
    sx_uuid_t id;
    char *addr;
    char *int_addr;
    int64_t capacity;
};

sx_node_t *sx_node_new(const sx_uuid_t *id, const char *addr, const char *internal_addr, int64_t capacity) {
    unsigned int addrlen, iaddrlen;
    sx_node_t *node;

    if(capacity <= 0) {
	WARN("Attempted to create new node with invalid capacity");
	return NULL;
    }

    if(!addr) {
	WARN("Called with NULL address");
	return NULL;
    }
    addrlen = strlen(addr);
    if(!addrlen || !sxi_is_valid_host(addr)) {
	WARN("Attempted to create new node with invalid external address %s", addr);
	return NULL;
    }
    addrlen++;

    if(internal_addr && strcmp(addr, internal_addr)) {
	iaddrlen = strlen(internal_addr);
	if(!iaddrlen || !sxi_is_valid_host(internal_addr)) {
	    WARN("Attempted to create new node with invalid internal address %s", internal_addr);
	    return NULL;
	}
	iaddrlen++;
    } else
	iaddrlen = 0;

    if(!(node = wrap_malloc(sizeof(*node) + addrlen + iaddrlen))) {
	PWARN("Failed to create new node");
	return NULL;
    }

    if(id)
	memcpy(&node->id, id, sizeof(*id));
    else if (uuid_generate(&node->id)) {
        free(node);
        return NULL;
    }
    node->addr = (char *)(node+1);
    node->capacity = capacity;
    memcpy(node->addr, addr, addrlen);
    if(iaddrlen) {
	node->int_addr = node->addr + addrlen;
	memcpy(node->int_addr, internal_addr, iaddrlen);
    } else
	node->int_addr = node->addr;

    return node;
}

sx_node_t *sx_node_dup(const sx_node_t *node) {
    if(!node) {
	WARN("Called with NULL argument");
	return NULL;
    }
    return sx_node_new(&node->id, node->addr, node->int_addr != node->addr ? node->int_addr : NULL, node->capacity);
}

void sx_node_delete(sx_node_t *node) {
    free(node);
}

const sx_uuid_t *sx_node_uuid(const sx_node_t *node) {
    return &node->id;
}

const char *sx_node_uuid_str(const sx_node_t *node) {
    const sx_uuid_t *id = sx_node_uuid(node);
    if(id && id->string[0])
	return id->string;
    else
	return "00000000-0000-0000-0000-000000000000";
}

const char *sx_node_addr(const sx_node_t *node) {
    return node->addr;
}

const char *sx_node_internal_addr(const sx_node_t *node) {
    return node->int_addr;
}

int64_t sx_node_capacity(const sx_node_t *node) {
    return node->capacity;
}

int sx_node_cmp(const sx_node_t *a, const sx_node_t *b) {
    if(!a)
	return -1;
    if(!b)
	return 1;
    return memcmp(a->id.binary, b->id.binary, sizeof(a->id.binary));
}

int sx_node_cmp_addrs(const sx_node_t *a, const sx_node_t *b) {
    int ret;
    if(!a)
	return -1;
    if(!b)
	return 1;
    ret = strcmp(a->addr, b->addr);
    if(!ret ||
       !strcmp(a->addr, b->int_addr) ||
       !strcmp(a->int_addr, b->addr) ||
       !strcmp(a->int_addr, b->int_addr))
	return 0;

    return ret;
}

struct _sx_nodelist_t {
    sx_node_t **nodes;
    unsigned int capacity;
    unsigned int items;
};

sx_nodelist_t *sx_nodelist_new(void) {
    sx_nodelist_t *list = wrap_malloc(sizeof(*list));
    if(!list) {
	PWARN("Cannot create new node list");
	return NULL;
    }
    list->nodes = NULL;
    list->capacity = 0;
    list->items = 0;

    return list;
}

sx_nodelist_t *sx_nodelist_dup(const sx_nodelist_t *other) {
    sx_nodelist_t *l;
    unsigned int i, cnt;

    if(!other) {
	WARN("Called with NULL argument");
	return NULL;
    }
    l = sx_nodelist_new();
    if(!l)
	return NULL;

    cnt = sx_nodelist_count(other);
    for(i=0; i<cnt; i++) {
	if(sx_nodelist_add(l, sx_node_dup(sx_nodelist_get(other, i)))) {
	    sx_nodelist_delete(l);
	    return NULL;
	}
    }
    return l;
}

#define NODELIST_BLOB_MAGIC "$NODELISTBLOB$"
sx_blob_t *sx_nodelist_to_blob(const sx_nodelist_t *list) {
    unsigned int i, nnodes;
    sx_blob_t *ret;

    if(!list)
	return NULL;
    ret = sx_blob_new();
    if(!ret)
	return NULL;

    nnodes = sx_nodelist_count(list);
    if(sx_blob_add_string(ret, NODELIST_BLOB_MAGIC) ||
       sx_blob_add_int32(ret, nnodes)) {
	sx_blob_free(ret);
	return NULL;
    }

    for(i=0; i<nnodes; i++) {
	const sx_node_t *n = sx_nodelist_get(list, i);
	const sx_uuid_t *id;
	const char *addr, *internal_addr;
	int64_t capacity;

	if(!n ||
	   !(id = sx_node_uuid(n)) ||
	   !(addr = sx_node_addr(n)) ||
	   !(internal_addr = sx_node_internal_addr(n)) ||
	   !(capacity = sx_node_capacity(n)) ||
	   sx_blob_add_blob(ret, id->binary, sizeof(id->binary)) ||
	   sx_blob_add_string(ret, addr) ||
	   sx_blob_add_string(ret, internal_addr) ||
	   sx_blob_add_int64(ret, capacity)) {
	    sx_blob_free(ret);
	    return NULL;
	}
    }

    return ret;
}

sx_nodelist_t *sx_nodelist_from_blob(sx_blob_t *blob) {
    unsigned int i, nnodes;
    sx_nodelist_t *ret;
    const char *magic;

    if(!blob)
	return NULL;

    ret = sx_nodelist_new();
    if(!ret)
	return NULL;

    sx_blob_reset(blob);
    if(sx_blob_get_string(blob, &magic) ||
       strcmp(magic, NODELIST_BLOB_MAGIC) ||
       sx_blob_get_int32(blob, (int32_t *)&nnodes))
	goto blob_err;

    for(i=0; i<nnodes; i++) {
	const char *addr, *internal_addr;
	unsigned int idlen;
	const void *iddata;
	sx_uuid_t id;
	int64_t capacity;

	if(sx_blob_get_blob(blob, &iddata, &idlen) ||
	   idlen != sizeof(id.binary) ||
	   sx_blob_get_string(blob, &addr) ||
	   sx_blob_get_string(blob, &internal_addr) ||
	   sx_blob_get_int64(blob, &capacity))
	    goto blob_err;
	uuid_from_binary(&id, iddata);

	if(sx_nodelist_add(ret, sx_node_new(&id, addr, internal_addr, capacity)))
	    goto blob_err;
    }

    return ret;

 blob_err:
    sx_nodelist_delete(ret);
    return NULL;
}


#define NODELIST_ALLOC_ITEMS 16
rc_ty sx_nodelist_add(sx_nodelist_t *list, sx_node_t *node) {
    if(!list || !node) {
	WARN("Called with NULL argument");
	sx_node_delete(node);
	return FAIL_EINTERNAL;
    }

    if(list->capacity == list->items) {
	sx_node_t **newnodes = wrap_realloc(list->nodes, sizeof(sx_node_t *) * (list->capacity + NODELIST_ALLOC_ITEMS));
	if(!newnodes) {
	    PWARN("Failed to grow nodelist to %u entries", (list->capacity + NODELIST_ALLOC_ITEMS));
	    sx_node_delete(node);
	    return FAIL_EINTERNAL;
	}
	list->nodes = newnodes;
	list->capacity += NODELIST_ALLOC_ITEMS;
    }

    list->nodes[list->items] = node;
    list->items++;

    return OK;
}

rc_ty sx_nodelist_addlist(sx_nodelist_t *list, const sx_nodelist_t *other) {
    unsigned int i, nnodes;
    rc_ty ret;

    if(!list || !other) {
	WARN("Called with NULL argument");
	return FAIL_EINTERNAL;
    }

    nnodes = sx_nodelist_count(other);
    for(i=0; i<nnodes; i++) {
	const sx_node_t *n = sx_nodelist_get(other, i);
	if(!n)
	    continue;
	if(sx_nodelist_lookup(list, sx_node_uuid(n)))
	    continue;
	ret = sx_nodelist_add(list, sx_node_dup(n));
	if(ret)
	    return ret;
    }
    return OK;
}

rc_ty sx_nodelist_prepend(sx_nodelist_t *list, sx_node_t *node) {
    if(!list || !node) {
	WARN("Called with NULL argument");
	sx_node_delete(node);
	return FAIL_EINTERNAL;
    }

    if(list->capacity == list->items) {
	sx_node_t **newnodes = wrap_malloc(sizeof(sx_node_t *) * (list->capacity + NODELIST_ALLOC_ITEMS));
	if(!newnodes) {
	    PWARN("Failed to grow nodelist to %u entries", (list->capacity + NODELIST_ALLOC_ITEMS));
	    sx_node_delete(node);
	    return FAIL_EINTERNAL;
	}
	if(list->nodes) {
	    memcpy(&newnodes[1], list->nodes, sizeof(sx_node_t *) * list->items);
	    free(list->nodes);
	}
	list->nodes = newnodes;
	list->capacity += NODELIST_ALLOC_ITEMS;
    } else
	memmove(&list->nodes[1], &list->nodes[0], sizeof(sx_node_t *) * list->items);

    list->nodes[0] = node;
    list->items++;

    return OK;
}

void sx_nodelist_delete(sx_nodelist_t *list) {
    if(!list)
	return;
    sx_nodelist_empty(list);
    free(list);
}


const sx_node_t *sx_nodelist_get(const sx_nodelist_t *list, unsigned int num) {
    if(!list) {
	WARN("Called with NULL argument");
	return NULL;
    }

    if(num >= list->items)
	return NULL;

    return list->nodes[num];
}

unsigned int sx_nodelist_count(const sx_nodelist_t *list) {
    return list ? list->items : 0;
}

void sx_nodelist_empty(sx_nodelist_t *list) {
    unsigned int i;
    if(!list)
	return;
    for(i=0; i<list->items; i++)
	sx_node_delete(list->nodes[i]);
    free(list->nodes);
    list->items = 0;
    list->nodes = NULL;
    list->capacity = 0;
}

const sx_node_t *sx_nodelist_lookup(const sx_nodelist_t *list, const sx_uuid_t *uuid) {
    return sx_nodelist_lookup_index(list, uuid, NULL);
}

const sx_node_t *sx_nodelist_lookup_index(const sx_nodelist_t *list, const sx_uuid_t *uuid, unsigned int *index) {
    unsigned int i;
    if(!list || !uuid) {
	WARN("Called with NULL argument");
	return NULL;
    }

    for(i=0; i<list->items; i++) {
	if(!memcmp(uuid->binary, list->nodes[i]->id.binary, sizeof(uuid->binary))) {
	    if(index)
		*index = i;
	    return list->nodes[i];
	}
    }

    return NULL;
}
