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

#ifndef __CLSTQRY_H
#define __CLSTQRY_H

#include "default.h"

#include "../libsxclient/src/clustcfg.h"

#include "nodes.h"

typedef struct cstatus clst_t;
clst_t *clst_query(sxi_conns_t *conns, sxi_hostlist_t *hlist);
unsigned int clst_ndists(clst_t *st);
const sx_nodelist_t *clst_nodes(clst_t *st, unsigned int dist);
const char *clst_zones(clst_t *st, unsigned int dist);
const sx_nodelist_t *clst_faulty_nodes(clst_t *st);
const sx_uuid_t *clst_distuuid(clst_t *st, unsigned int *version, uint64_t *checksum);
const char *clst_auth(clst_t *st);

typedef enum _clst_state {
    CLSTOP_NOTRUNNING,
    CLSTOP_INPROGRESS,
    CLSTOP_COMPLETED
} clst_state;

clst_state clst_rebalance_state(clst_t *st, const char **desc);
clst_state clst_replace_state(clst_t *st, const char **desc);
clst_state clst_upgrade_state(clst_t *st, const char **desc);
void clst_destroy(clst_t *st);
int clst_readonly(clst_t *st);

typedef struct _raft_node_data_t {
    sx_uuid_t uuid;
    int64_t last_contact;
    unsigned int state;
} raft_node_data_t;

const char *clst_leader_node(clst_t *st);
const char* clst_raft_role(clst_t *st);
const char* clst_raft_message(clst_t *st);
const raft_node_data_t *clst_raft_nodes_data(clst_t *st, unsigned int *nnodes);

unsigned int clst_get_maxreplica(clst_t *st);
unsigned int clst_get_current_maxreplica(clst_t *st);

#endif

