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

#ifndef NODES_H
#define NODES_H

#include "default.h"
#include "errors.h"
#include "utils.h"
#include "blob.h"

typedef struct _sx_node_t sx_node_t;

sx_node_t *sx_node_new(const sx_uuid_t *id, const char *addr, const char *internal_addr, int64_t capacity);
void sx_node_delete(sx_node_t *node);
sx_node_t *sx_node_dup(const sx_node_t *node);
const sx_uuid_t *sx_node_uuid(const sx_node_t *node);
const char *sx_node_uuid_str(const sx_node_t *node);
const char *sx_node_addr(const sx_node_t *node);
const char *sx_node_internal_addr(const sx_node_t *node);
int64_t sx_node_capacity(const sx_node_t *node);
int sx_node_cmp(const sx_node_t *a, const sx_node_t *b);
int sx_node_cmp_addrs(const sx_node_t *a, const sx_node_t *b);

typedef struct _sx_nodelist_t sx_nodelist_t;
sx_nodelist_t *sx_nodelist_new(void);
sx_nodelist_t *sx_nodelist_dup(const sx_nodelist_t *other);
sx_nodelist_t *sx_nodelist_from_blob(sx_blob_t *blob);
sx_blob_t *sx_nodelist_to_blob(const sx_nodelist_t *list);
rc_ty sx_nodelist_add(sx_nodelist_t *list, sx_node_t *node);
rc_ty sx_nodelist_addlist(sx_nodelist_t *list, const sx_nodelist_t *other);
rc_ty sx_nodelist_prepend(sx_nodelist_t *list, sx_node_t *node);
void sx_nodelist_delete(sx_nodelist_t *list);
const sx_node_t *sx_nodelist_get(const sx_nodelist_t *list, unsigned int num);
const sx_node_t *sx_nodelist_lookup(const sx_nodelist_t *list, const sx_uuid_t *uuid);
const sx_node_t *sx_nodelist_lookup_index(const sx_nodelist_t *list, const sx_uuid_t *uuid, unsigned int *index);
unsigned int sx_nodelist_count(const sx_nodelist_t *list);
void sx_nodelist_empty(sx_nodelist_t *list);

#endif
