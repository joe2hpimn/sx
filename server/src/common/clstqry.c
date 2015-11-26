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

#include "clstqry.h"
#include "libsxclient/src/jparse.h"

struct cstatus {
    jparse_t *J;
    sx_nodelist_t *one;
    sx_nodelist_t *two;
    sx_nodelist_t *ign;
    char *addr, *int_addr, *auth;
    char *zone_one, *zone_two;
    sx_uuid_t uuid, distid;
    uint64_t checksum;
    int64_t capa;
    int nsets, have_uuid, have_distid, is_ignd, op_complete;
    int readonly;
    enum {
	OP_NONE,
	OP_REBALANCE,
	OP_REPLACE,
        OP_UPGRADE
    } op_type;
    unsigned int version, replica_count, effective_replica_count;
    char op_msg[1024];
    curlev_context_t *cbdata;

    /* Raft status data */
    char raft_role[16];
    char raft_status_leader[UUID_STRING_SIZE+1];
    raft_node_data_t *raft_nodes;
    unsigned int raft_nnodes;
    char raft_message[1024];
};

/*

{
    "clusterStatus": {
        "distributionModels": [
            [
                {
                    "nodeUUID": "UUID",
                    "nodeAddress": "ADDR",
                    "nodeInternalAddress": "INTADDR",
                    "nodeCapacity": 1234,
                    "nodeFlags": "FLAGS"
                }
            ],
            []
        ],
        "distributionUUID": "UUID",
        "distributionVersion": 123,
        "distributionChecksum": 6667,
        "clusterAuth": "AUTH",
        "opInProgress": {
            "opType": "OP",
            "isComplete": true,
            "opInfo": "MESSAGE"
        },
        "operatingMode": "MODE",
	"maxReplicaCount": 3,
	"effectiveMaxReplicaCount": 2
    },
    "raftStatus": {
        "role": "ROLE",
        "leader": "LEADER",
        "nodeStates": {
            "NODEUUID": {
                "state": "STATE",
                "lastContact": 12345
            }
        }
    }
}

*/

static void cb_cstatus_dist_nuuid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    char uuid[UUID_STRING_SIZE + 1];

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid node UUID (dist %d, entry %d)",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))),
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))))));
	return;
    }
    memcpy(uuid, string, UUID_STRING_SIZE);
    uuid[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&c->uuid, uuid)) {
	sxi_jparse_cancel(J, "Invalid node UUID (dist %d, entry %d)",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))),
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))))));
	return;
    }
    c->have_uuid = 1;
}


static void set_cstatus_naddr(jparse_t *J, char **dest, const char *src, unsigned int len) {
    char *buf;
    if(*dest) {
	sxi_jparse_cancel(J, "Duplicate node address field (dist %d, entry %d)",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))),
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))))));
	return;
    }
    buf = malloc(len + 1);
    if(!buf) {
	sxi_jparse_cancel(J, "Out of memory processing distribution");
	return;
    }
    memcpy(buf, src, len);
    buf[len] = '\0';
    *dest = buf;
}

static void cb_cstatus_dist_naddr(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    set_cstatus_naddr(J, &c->addr, string, length);
}

static void cb_cstatus_dist_nintaddr(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    set_cstatus_naddr(J, &c->int_addr, string, length);
}

static void cb_cstatus_dist_nflags(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    c->is_ignd = memchr(string, 'i', length) != NULL;
}

static void cb_cstatus_dist_ncapa(jparse_t *J, void *ctx, int64_t num) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid node capacity %lld (dist %d, entry %d)", (long long)num,
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))),
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))))));
	return;
    }
    c->capa = num;
}

static void cb_cstatus_replicacnt(jparse_t *J, void *ctx, int32_t num) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid replica count");
	return;
    }
    c->replica_count = num;
}

static void cb_cstatus_effreplicacnt(jparse_t *J, void *ctx, int32_t num) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid effective replica count");
	return;
    }
    c->effective_replica_count = num;
}

static void cb_cstatus_dist_nbegin(jparse_t *J, void *ctx) {
    struct cstatus *c = (struct cstatus *)ctx;
    c->capa = 0;
    c->have_uuid = 0;
    c->is_ignd = 0;
}

static void cb_cstatus_dist_ndone(jparse_t *J, void *ctx) {
    int ndist = sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
    struct cstatus *c = (struct cstatus *)ctx;
    sx_node_t *node;

    if(ndist < 0 || ndist > 1) {
	/* Not reached */
	sxi_jparse_cancel(J, "Internal error processing node distribution");
	return;
    }
    if(!c->have_uuid || !c->addr) {
	sxi_jparse_cancel(J, "Incomplete node description (dist %d, entry %d)", ndist,
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))))));
	return;
    }

    node = sx_node_new(&c->uuid, c->addr, c->int_addr, c->capa);
    if(sx_nodelist_add(ndist ? c->two : c->one, node)) {
	sxi_jparse_cancel(J, "Out of memory processing node distribution");
	return;
    }
    if(c->is_ignd && !sx_nodelist_lookup(c->ign, sx_node_uuid(node)) && sx_nodelist_add(c->ign, sx_node_dup(node))) {
	sxi_jparse_cancel(J, "Out of memory processing node distribution");
	return;
    }
    free(c->addr);
    free(c->int_addr);
    c->addr = NULL;
    c->int_addr = NULL;
    c->nsets = MAX(ndist + 1, c->nsets);
}

static void cb_cstatus_dist_zone(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    int ndist = sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
    struct cstatus *c = (struct cstatus *)ctx;
    char **dest, *zone;

    dest = (ndist == 0) ? &c->zone_one : &c->zone_two;
    if(*dest) {
	sxi_jparse_cancel(J, "Duplicate zone definition on dist %d", ndist);
	return;
    }
    zone = malloc(length + 1);
    if(!zone) {
	sxi_jparse_cancel(J, "Out of memory processing zone definition");
	return;
    }
    memcpy(zone, string, length);
    zone[length] = '\0';
    *dest = zone;
}

static void cb_cstatus_distid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    char uuid[UUID_STRING_SIZE + 1];

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid distribution UUID");
	return;
    }
    memcpy(uuid, string, UUID_STRING_SIZE);
    uuid[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&c->distid, uuid)) {
	sxi_jparse_cancel(J, "Invalid distribution UUID");
	return;
    }
    c->have_distid = 1;
}


static void cb_cstatus_distver(jparse_t *J, void *ctx, int64_t num) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(num < 0 || num > 0xffffffff) {
	sxi_jparse_cancel(J, "Invalid disttribution version %lld", (long long)num);
	return;
    }
    c->version = (unsigned int)(num);
}

static void cb_cstatus_distsum(jparse_t *J, void *ctx, int64_t num) {
    struct cstatus *c = (struct cstatus *)ctx;
    c->checksum = (uint64_t)num;
}

static void cb_cstatus_auth(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(c->auth) {
	sxi_jparse_cancel(J, "Duplicate cluster authentication token");
	return;
    }
    c->auth = malloc(length + 1);
    if(!c->auth) {
	sxi_jparse_cancel(J, "Out of memory processing cluster authentication token");
	return;
    }
    memcpy(c->auth, string, length);
    c->auth[length] = '\0';
}

static void cb_cstatus_mode(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(length == lenof("read-only") && !memcmp("read-only", string, lenof("read-only")))
	c->readonly = 1;
}

static void cb_cstatus_op_type(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(length == lenof("rebalance") && !memcmp("rebalance", string, lenof("rebalance")))
	c->op_type = OP_REBALANCE;
    else if(length == lenof("replace") && !memcmp("replace", string, lenof("replace")))
	c->op_type = OP_REPLACE;
    else if (length == lenof("upgrade") && !memcmp("upgrade", string, lenof("upgrade")))
	c->op_type = OP_UPGRADE;
    else
	c->op_type = OP_NONE;
}

static void cb_cstatus_op_info(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    unsigned int ml = MIN(length, sizeof(c->op_msg) - 1);
    memcpy(c->op_msg, string, ml);
    c->op_msg[ml] = '\0';
}

static void cb_cstatus_op_complete(jparse_t *J, void *ctx, int complete) {
    struct cstatus *c = (struct cstatus *)ctx;
    c->op_complete = complete;
}

static void cb_cstatus_raft_role(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    unsigned int ml = MIN(length, sizeof(c->raft_role) - 1);
    memcpy(c->raft_role, string, ml);
    c->raft_role[ml] = '\0';
}

static void cb_cstatus_raft_leader(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    sx_uuid_t uuid;

    if(length == lenof("<nobody>") && !memcmp(string, "<nobody>", lenof("<nobody>"))) {
	sxi_strlcpy(c->raft_status_leader, "<nobody>", sizeof(c->raft_status_leader));
	return;
    }
    if(length == UUID_STRING_SIZE) {
	memcpy(c->raft_status_leader, string, UUID_STRING_SIZE);
	c->raft_status_leader[UUID_STRING_SIZE] = '\0';
	if(!uuid_from_string(&uuid, c->raft_status_leader))
	    return;
    }
    sxi_jparse_cancel(J, "Invalid raft leader UUID");
}

static void cb_cstatus_raft_message(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    sxi_strlcpy(c->raft_message, string, MIN(sizeof(c->raft_message), length+1));
}

static void cb_cstatus_raft_ns_node(jparse_t *J, void *ctx) {
    const char *node = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
    struct cstatus *c = (struct cstatus *)ctx;
    raft_node_data_t *nunodes;

    if(strlen(node) != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid node UUID %s", node);
	return;
    }

    nunodes = realloc(c->raft_nodes, sizeof(raft_node_data_t) * (c->raft_nnodes+1));
    if(!nunodes) {
	sxi_jparse_cancel(J, "Out of memory processing raft node states");
	return;
    }
    c->raft_nodes = nunodes;
    memset(&c->raft_nodes[c->raft_nnodes], 0, sizeof(c->raft_nodes[c->raft_nnodes]));
    if(uuid_from_string(&c->raft_nodes[c->raft_nnodes].uuid, node)) {
	sxi_jparse_cancel(J, "Invalid node UUID %s", node);
	return;
    }
    c->raft_nnodes++;
}

static void cb_cstatus_raft_ns_state(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cstatus *c = (struct cstatus *)ctx;
    if(length == lenof("alive") && !memcmp(string, "alive", lenof("alive")))
	c->raft_nodes[c->raft_nnodes-1].state = 1;
    else if(length == lenof("dead") && !memcmp(string, "dead", lenof("dead")))
	c->raft_nodes[c->raft_nnodes-1].state = 0;
    else {
	sxi_jparse_cancel(J, "Invalid state %.*s on node %s", length, string,
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
	return;
    }
}

static void cb_cstatus_raft_ns_ts(jparse_t *J, void *ctx, int64_t num) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid last contact value on node %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
	return;
    }
    c->raft_nodes[c->raft_nnodes-1].last_contact = num;
}

const struct jparse_actions cstatus_acts = {
    JPACTS_STRING(
		  JPACT(cb_cstatus_dist_nuuid, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM, JPKEY("nodeUUID")),
		  JPACT(cb_cstatus_dist_naddr, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM, JPKEY("nodeAddress")),
		  JPACT(cb_cstatus_dist_nintaddr, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM, JPKEY("nodeInternalAddress")),
		  JPACT(cb_cstatus_dist_nflags, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM, JPKEY("nodeFlags")),
		  JPACT(cb_cstatus_dist_nuuid, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM, JPKEY("nodeUUID")),
		  JPACT(cb_cstatus_dist_naddr, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM, JPKEY("nodeAddress")),
		  JPACT(cb_cstatus_dist_nintaddr, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM, JPKEY("nodeInternalAddress")),
		  JPACT(cb_cstatus_dist_nflags, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM, JPKEY("nodeFlags")),
		  JPACT(cb_cstatus_dist_zone, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM),
		  JPACT(cb_cstatus_dist_zone, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM),
		  JPACT(cb_cstatus_distid, JPKEY("clusterStatus"), JPKEY("distributionUUID")),
		  JPACT(cb_cstatus_auth, JPKEY("clusterStatus"), JPKEY("clusterAuth")),
		  JPACT(cb_cstatus_mode, JPKEY("clusterStatus"), JPKEY("operatingMode")),
		  JPACT(cb_cstatus_op_type, JPKEY("clusterStatus"), JPKEY("opInProgress"), JPKEY("opType")),
		  JPACT(cb_cstatus_op_info, JPKEY("clusterStatus"), JPKEY("opInProgress"), JPKEY("opInfo")),
		  JPACT(cb_cstatus_raft_role, JPKEY("raftStatus"), JPKEY("role")),
		  JPACT(cb_cstatus_raft_leader, JPKEY("raftStatus"), JPKEY("leader")),
                  JPACT(cb_cstatus_raft_message, JPKEY("raftStatus"), JPKEY("message")),
		  JPACT(cb_cstatus_raft_ns_state, JPKEY("raftStatus"), JPKEY("nodeStates"), JPANYKEY, JPKEY("state"))
		  ),
    JPACTS_INT64(
		 JPACT(cb_cstatus_dist_ncapa, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM, JPKEY("nodeCapacity")),
		 JPACT(cb_cstatus_dist_ncapa, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM, JPKEY("nodeCapacity")),
		 JPACT(cb_cstatus_distver, JPKEY("clusterStatus"), JPKEY("distributionVersion")),
		 JPACT(cb_cstatus_distsum, JPKEY("clusterStatus"), JPKEY("distributionChecksum")),
		 JPACT(cb_cstatus_raft_ns_ts, JPKEY("raftStatus"), JPKEY("nodeStates"), JPANYKEY, JPKEY("lastContact"))
		 ),
    JPACTS_INT32(
		 JPACT(cb_cstatus_replicacnt, JPKEY("clusterStatus"), JPKEY("maxReplicaCount")),
		 JPACT(cb_cstatus_effreplicacnt, JPKEY("clusterStatus"), JPKEY("effectiveMaxReplicaCount"))
		 ),
    JPACTS_MAP_BEGIN(
		     JPACT(cb_cstatus_dist_nbegin, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM),
		     JPACT(cb_cstatus_dist_nbegin, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM),
		     JPACT(cb_cstatus_raft_ns_node, JPKEY("raftStatus"), JPKEY("nodeStates"), JPANYKEY)
		     ),
    JPACTS_MAP_END(
		   JPACT(cb_cstatus_dist_ndone, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(0), JPANYITM),
		   JPACT(cb_cstatus_dist_ndone, JPKEY("clusterStatus"), JPKEY("distributionModels"), JPARR(1), JPANYITM)
		   ),
    JPACTS_BOOL(
		JPACT(cb_cstatus_op_complete, JPKEY("clusterStatus"), JPKEY("opInProgress"), JPKEY("isComplete"))
		)
};


static int cstatus_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cstatus *yactx = (struct cstatus *)ctx;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J  = sxi_jparse_create(&cstatus_acts, yactx, 1))) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    if(yactx->one)
	sx_nodelist_empty(yactx->one);
    else if(!(yactx->one = sx_nodelist_new())) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    if(yactx->two)
	sx_nodelist_empty(yactx->two);
    else if(!(yactx->two = sx_nodelist_new())) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    if(yactx->ign)
	sx_nodelist_empty(yactx->ign);
    else if(!(yactx->ign = sx_nodelist_new())) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    free(yactx->zone_one);
    free(yactx->zone_two);
    yactx->zone_one = NULL;
    yactx->zone_two = NULL;
    free(yactx->auth);
    free(yactx->addr);
    free(yactx->int_addr);
    free(yactx->raft_nodes);
    yactx->auth = NULL;
    yactx->addr = NULL;
    yactx->int_addr = NULL;
    yactx->raft_nodes = NULL;
    yactx->have_uuid = 0;
    yactx->is_ignd = 0;
    yactx->have_distid = 0;
    yactx->nsets = 0;
    yactx->version = 0;
    yactx->checksum = 0;
    yactx->capa = 0;
    yactx->op_type = OP_NONE;
    yactx->op_complete = -1;
    yactx->op_msg[0] = '\0';
    yactx->cbdata = cbdata;
    yactx->readonly = 0;
    yactx->replica_count = 0;
    yactx->effective_replica_count = 0;
    memset(&yactx->raft_status_leader, 0, sizeof(yactx->raft_status_leader));
    memset(yactx->raft_role, 0, sizeof(yactx->raft_role));
    yactx->raft_nnodes = 0;

    return 0;
}

static int cstatus_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cstatus *yactx = (struct cstatus *)ctx;
    if(sxi_jparse_digest(yactx->J, data, size)) {
	CRIT("Error querying cluster: %s", sxi_jparse_geterr(yactx->J));
	return 1;
    } else
	return 0;
}


void clst_destroy(clst_t *st) {
    if(!st)
	return;
    sx_nodelist_delete(st->one);
    sx_nodelist_delete(st->two);
    sx_nodelist_delete(st->ign);
    free(st->zone_one);
    free(st->zone_two);
    free(st->auth);
    free(st->addr);
    free(st->int_addr);
    free(st->raft_nodes);
    sxi_jparse_destroy(st->J);
    free(st);
}

clst_t *clst_query(sxi_conns_t *conns, sxi_hostlist_t *hlist) {
    struct cstatus *yctx = NULL;

    if(!conns)
	return NULL;

    if(!(yctx = calloc(1, sizeof(*yctx))))
	return NULL;

    if(sxi_cluster_query(conns, hlist, REQ_GET, "?clusterStatus&operatingMode&raftStatus&distZones", NULL, 0, cstatus_setup_cb, cstatus_cb, yctx) != 200) {
	clst_destroy(yctx);
	return NULL;
    }

    if(sxi_jparse_done(yctx->J)) {
	CRIT("Error querying cluster: %s", sxi_jparse_geterr(yctx->J));
	clst_destroy(yctx);
	return NULL;
    }

    if(yctx->nsets < 0 || yctx->nsets > 2) {
	CRIT("Error querying cluster: invalid distribution sets");
	clst_destroy(yctx);
	return NULL;
    }

    if(!yctx->replica_count) {
	/* Legacy server */
	switch(yctx->nsets) {
	case 2:
	    yctx->replica_count = MIN(sx_nodelist_count(yctx->one), sx_nodelist_count(yctx->two));
	    yctx->effective_replica_count = yctx->replica_count;
	    break;
	case 1:
	    yctx->replica_count = sx_nodelist_count(yctx->one);
	    yctx->effective_replica_count = yctx->replica_count - sx_nodelist_count(yctx->ign);
	    break;
	default:
	    yctx->replica_count = 0;
	    yctx->effective_replica_count = 0;
	}
    } else if(!yctx->replica_count) {
	/* Just a fallback, not reached */
	yctx->effective_replica_count = yctx->replica_count;
    }

    sxi_jparse_destroy(yctx->J);
    free(yctx->addr);
    free(yctx->int_addr);
    yctx->J = NULL;
    yctx->addr = NULL;
    yctx->int_addr = NULL;
    return yctx;
}

unsigned int clst_ndists(clst_t *st) {
    return st ? st->nsets : 0;
}

const sx_nodelist_t *clst_nodes(clst_t *st, unsigned int dist) {
    if(!st || dist >= st->nsets)
	return NULL;

    return dist ? st->two : st->one;
}

const char *clst_zones(clst_t *st, unsigned int dist) {
    if(!st || dist >= st->nsets)
	return NULL;

    return dist ? st->zone_two : st->zone_one;
}

const sx_nodelist_t *clst_faulty_nodes(clst_t *st) {
    return st->ign;
}

const sx_uuid_t *clst_distuuid(clst_t *st, unsigned int *version, uint64_t *checksum) {
    if(st && st->have_distid) {
	if(version)
	    *version = st->version;
	if(checksum)
	    *checksum = st->checksum;
	return &st->distid;
    }
    return NULL;
}

const char *clst_auth(clst_t *st) {
    return st ? st->auth : NULL;
}

clst_state clst_rebalance_state(clst_t *st, const char **desc) {
    if(!st || st->op_type != OP_REBALANCE)
	return CLSTOP_NOTRUNNING;

    if(desc)
	*desc = st->op_msg[0] ? st->op_msg : "Rebalance operation in progress";
    return st->op_complete ? CLSTOP_COMPLETED : CLSTOP_INPROGRESS;
}

clst_state clst_replace_state(clst_t *st, const char **desc) {
    if(!st || st->op_type != OP_REPLACE)
	return CLSTOP_NOTRUNNING;

    if(desc)
	*desc = st->op_msg[0] ? st->op_msg : "Replace operation in progress";
    return st->op_complete ? CLSTOP_COMPLETED : CLSTOP_INPROGRESS;
}

clst_state clst_upgrade_state(clst_t *st, const char **desc) {
    if(!st || st->op_type != OP_UPGRADE)
	return CLSTOP_NOTRUNNING;

    if(desc)
	*desc = st->op_msg[0] ? st->op_msg : "Upgrade operation in progress";
    return st->op_complete ? CLSTOP_COMPLETED : CLSTOP_INPROGRESS;
}

int clst_readonly(clst_t *st) {
    return st ? st->readonly : 0;
}

const char* clst_leader_node(clst_t *st) {
    return st ? st->raft_status_leader : NULL;
}

const char* clst_raft_role(clst_t *st) {
    return st ? st->raft_role : NULL;
}

const char* clst_raft_message(clst_t *st) {
    return st && *st->raft_message ? st->raft_message : NULL;
}

const raft_node_data_t *clst_raft_nodes_data(clst_t *st, unsigned int *nnodes) {
    if(!st || !nnodes)
        return NULL;
    *nnodes = st->raft_nnodes;
    return st->raft_nodes;
}

unsigned int clst_get_maxreplica(clst_t *st) {
    return st ? st->replica_count : 0;
}

unsigned int clst_get_current_maxreplica(clst_t *st) {
    return st ? st->effective_replica_count : 0;
}
