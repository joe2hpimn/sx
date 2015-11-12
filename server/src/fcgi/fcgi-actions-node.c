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
#include <yajl/yajl_parse.h>
#include "fcgi-utils.h"
#include "utils.h"
#include "fcgi-actions-node.h"

/* {"nodeList":[{"nodeUUID":"%s","nodeAddress":"%s","nodeInternalAddress":"%s","nodeCapacity":%llu}], "distZones":"Zone1:..."} */
struct cb_nodes_ctx {
    enum cb_nodes_state { CB_NODES_START, CB_NODES_ROOT, CB_NODES_ARRAY, CB_NODES_LIST, CB_NODES_NODE, CB_NODES_UUID, CB_NODES_ADDR, CB_NODES_INTADDR, CB_NODES_CAPA, CB_ZONES, CB_NODES_COMPLETE } state;
    sx_uuid_t id;
    char *addr;
    char *intaddr;
    char *zones;
    int64_t capacity;
    int have_uuid;
    sx_nodelist_t *nodes;
};

static int cb_nodes_start_map(void *ctx) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    if(c->state != CB_NODES_START && c->state != CB_NODES_LIST)
	return 0;
    c->state++;
    return 1;
}

static int cb_nodes_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    if(c->state == CB_NODES_ROOT && l == lenof("nodeList") && !strncmp("nodeList", s, lenof("nodeList"))) {
	c->state = CB_NODES_ARRAY;
	return 1;
    }
    if(c->state == CB_NODES_ROOT && l == lenof("distZones") && !strncmp("distZones", s, lenof("distZones"))) {
	c->state = CB_ZONES;
	return 1;
    }
    if(c->state == CB_NODES_NODE) {
	if(l == lenof("nodeUUID") && !strncmp("nodeUUID", s, lenof("nodeUUID")))
	    c->state = CB_NODES_UUID;
	else if(l == lenof("nodeAddress") && !strncmp("nodeAddress", s, lenof("nodeAddress")))
	    c->state = CB_NODES_ADDR;
	else if(l == lenof("nodeInternalAddress") && !strncmp("nodeInternalAddress", s, lenof("nodeInternalAddress")))
	    c->state = CB_NODES_INTADDR;
	else if(l == lenof("nodeCapacity") && !strncmp("nodeCapacity", s, lenof("nodeCapacity")))
	    c->state = CB_NODES_CAPA;
	else
	    return 0;
	return 1;
    }
    return 0;
}

static int cb_nodes_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    if(c->state == CB_NODES_UUID) {
	char uuid[sizeof(c->id.string)];
	if(c->have_uuid || l != sizeof(uuid) - 1)
	    return 0;
	memcpy(uuid, s, l);
	uuid[l] = '\0';
	if(uuid_from_string(&c->id, uuid))
	    return 0;
	c->have_uuid = 1;
    } else if(c->state == CB_NODES_ADDR || c->state == CB_NODES_INTADDR) {
	char **addrptr = c->state == CB_NODES_ADDR ? &c->addr : &c->intaddr, *addr;
	if(*addrptr || !l)
	    return 0;
	*addrptr = addr = wrap_malloc(l+1);
	if(!addr)
	    return 0;
	memcpy(addr, s, l);
	addr[l] = '\0';
    } else if(c->state == CB_ZONES) {
	if(c->zones)
	    return 0;
	c->zones = wrap_malloc(l+1);
	memcpy(c->zones, s, l);
	c->zones[l] = '\0';
	c->state = CB_NODES_ROOT;
	return 1;
    } else
	return 0;

    c->state = CB_NODES_NODE;
    return 1;
}

static int cb_nodes_number(void *ctx, const char *s, size_t l) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    char number[24], *eon;
    if(c->state != CB_NODES_CAPA || c->capacity != -1 || l<1 || l>20)
	return 0;

    memcpy(number, s, l);
    number[l] = '\0';
    c->capacity = strtoll(number, &eon, 10);
    if(*eon || c->capacity < 0)
	return 0;

    c->state = CB_NODES_NODE;
    return 1;
}


static int cb_nodes_end_map(void *ctx) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    if(c->state == CB_NODES_ROOT) {
	c->state = CB_NODES_COMPLETE;
	return 1;
    }
    if(c->state != CB_NODES_NODE)
	return 0;

    if(!c->have_uuid || !c->addr || c->capacity < 1)
	return 0;

    sx_node_t *node = sx_node_new(&c->id, c->addr, c->intaddr, c->capacity);
    free(c->addr);
    c->addr = NULL;
    free(c->intaddr);
    c->intaddr = NULL;
    c->capacity = -1;
    c->have_uuid = 0;
    if(sx_nodelist_add(c->nodes, node))
	return 0;
    c->state = CB_NODES_LIST;
    return 1;
}


static int cb_nodes_start_array(void *ctx) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    if(c->state != CB_NODES_ARRAY)
	return 0;
    c->state = CB_NODES_LIST;
    return 1;
}

static int cb_nodes_end_array(void *ctx) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    if(c->state != CB_NODES_LIST)
	return 0;
    c->state = CB_NODES_ROOT;
    return 1;
}

static const yajl_callbacks nodes_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_nodes_number,
    cb_nodes_string,
    cb_nodes_start_map,
    cb_nodes_map_key,
    cb_nodes_end_map,
    cb_nodes_start_array,
    cb_nodes_end_array
};

void fcgi_set_nodes(void) {
    sx_uuid_t selfid;
    job_t job;
    rc_ty s;

    if(sx_hashfs_self_uuid(hashfs, &selfid))
	quit_errmsg(500, "Cluster not yet initialized");

    struct cb_nodes_ctx yctx;
    yctx.state = CB_NODES_START;
    yctx.addr = NULL;
    yctx.intaddr = NULL;
    yctx.capacity = -1;
    yctx.have_uuid = 0;
    yctx.zones = NULL;
    yctx.nodes = sx_nodelist_new();
    if(!yctx.nodes)
	quit_errmsg(500, "Cannot allocate nodelist");

    yajl_handle yh = yajl_alloc(&nodes_parser, NULL, &yctx);
    if(!yh) {
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(500, "Cannot allocate json parser");
    }

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_NODES_COMPLETE) {
	yajl_free(yh);
	free(yctx.addr);
	free(yctx.intaddr);
	free(yctx.zones);
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    quit_unless_authed();

    if(has_arg("replace")) {
	if(yctx.zones) {
	    sx_nodelist_delete(yctx.nodes);
	    free(yctx.zones);
	    quit_errmsg(400, "Replacement requests cannot alter distribution zones");
	}
	s = sx_hashfs_hdist_replace_req(hashfs, yctx.nodes, &job);
    } else
	s = sx_hashfs_hdist_change_req(hashfs, yctx.nodes, yctx.zones, &job);

    sx_nodelist_delete(yctx.nodes);
    free(yctx.zones);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    send_job_info(job);
}

/* {"faultyNodes":["UUID1", "UUID2", ...]} */
struct cb_ign_ctx {
    enum cb_ign_state { CB_IGN_START, CB_IGN_ROOT, CB_IGN_ARRAY, CB_IGN_NODE, CB_IGN_COMPLETE } state;
    sx_nodelist_t *nodes;
};

static int cb_ign_start_map(void *ctx) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    if(c->state != CB_IGN_START)
	return 0;
    c->state = CB_IGN_ROOT;
    return 1;
}

static int cb_ign_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    if(c->state == CB_IGN_ROOT && l == lenof("faultyNodes") && !strncmp("faultyNodes", s, lenof("faultyNodes"))) {
	c->state = CB_IGN_ARRAY;
	return 1;
    }
    return 0;
}

static int cb_ign_end_map(void *ctx) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    if(c->state == CB_IGN_ROOT) {
	c->state = CB_IGN_COMPLETE;
	return 1;
    }
    return 0;
}

static int cb_ign_start_array(void *ctx) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    if(c->state != CB_IGN_ARRAY)
	return 0;
    c->state = CB_IGN_NODE;
    return 1;
}

static int cb_ign_end_array(void *ctx) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    if(c->state != CB_IGN_NODE)
	return 0;
    c->state = CB_IGN_ROOT;
    return 1;
}

static int cb_ign_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    if(c->state == CB_IGN_NODE) {
	sx_node_t *node;
	sx_uuid_t uuid;
	char ustr[sizeof(uuid.string)];
	if(l != UUID_STRING_SIZE)
	    return 0;
	memcpy(ustr, s, l);
	ustr[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&uuid, ustr))
	    return 0;
	node = sx_node_new(&uuid, "127.0.0.1", "127.0.0.1", 1);
	if(!node || sx_nodelist_add(c->nodes, node))
	    return 0;
    } else
	return 0;
    return 1;
}

static const yajl_callbacks ign_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_ign_string,
    cb_ign_start_map,
    cb_ign_map_key,
    cb_ign_end_map,
    cb_ign_start_array,
    cb_ign_end_array
};


void fcgi_mark_faultynodes(void) {
    struct cb_ign_ctx yctx;
    yajl_handle yh;
    int len;
    rc_ty s;

    yctx.state = CB_IGN_START;
    yctx.nodes = sx_nodelist_new();
    if(!yctx.nodes)
	quit_errmsg(503, "Cannot allocate nodelist");

    yh = yajl_alloc(&ign_parser, NULL, &yctx);
    if(!yh) {
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(503, "Cannot allocate json parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_IGN_COMPLETE) {
	yajl_free(yh);
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    quit_unless_authed();

    if(!sx_nodelist_count(yctx.nodes))
	quit_errmsg(400, "Invalid request content");

    if(has_priv(PRIV_CLUSTER)) {
	/* S2S request */
	s = sx_hashfs_setignored(hashfs, yctx.nodes);
	sx_nodelist_delete(yctx.nodes);
	if(s != OK)
	    quit_errmsg(rc2http(s), msg_get_reason());
	CGI_PUTS("\r\n");
	return;
    } else {
	/* Admin request here */
	const sx_nodelist_t *nodes;
	sx_nodelist_t *targets;
	unsigned int nnode;
	sx_blob_t *joblb;
	const void *job_data;
	unsigned int job_datalen;
	job_t job;

	nodes = sx_hashfs_all_nodes(hashfs, NL_NEXT);
	if(!nodes) {
	    sx_nodelist_delete(yctx.nodes);
	    quit_errmsg(503, "Failed to retrieve cluster members");
	}

	for(nnode = 0; nnode < sx_nodelist_count(yctx.nodes); nnode++) {
	    char reason[128];
	    const sx_node_t *curn = sx_nodelist_get(yctx.nodes, nnode);
	    if(sx_nodelist_lookup(nodes, sx_node_uuid(curn)))
		continue;
	    snprintf(reason, sizeof(reason), "Node %s is not an active cluster member", sx_node_uuid_str(curn));
	    sx_nodelist_delete(yctx.nodes);
	    quit_errmsg(400, reason);
	}

	nodes = sx_hashfs_effective_nodes(hashfs, NL_NEXT);
	if(!nodes) {
	    sx_nodelist_delete(yctx.nodes);
	    quit_errmsg(503, "Failed to retrieve cluster members");
	}
	targets = sx_nodelist_new();
	if(!targets) {
	    sx_nodelist_delete(yctx.nodes);
	    quit_errmsg(503, "Failed to allocate target list");
	}
	for(nnode = 0; nnode < sx_nodelist_count(nodes); nnode++) {
	    const sx_node_t *curn = sx_nodelist_get(nodes, nnode);
	    if(sx_nodelist_lookup(yctx.nodes, sx_node_uuid(curn)))
		continue;
	    if(sx_nodelist_add(targets, sx_node_dup(curn))) {
		sx_nodelist_delete(yctx.nodes);
		sx_nodelist_delete(targets);
		quit_errmsg(503, "Failed to allocate target list");
	    }
	}

	joblb = sx_nodelist_to_blob(yctx.nodes);
	sx_nodelist_delete(yctx.nodes);
	if(!joblb) {
	    sx_nodelist_delete(targets);
	    quit_errmsg(503, "Failed to allocate job data");
	}

	sx_blob_to_data(joblb, &job_data, &job_datalen);
	s = sx_hashfs_job_new(hashfs, uid, &job, JOBTYPE_IGNODES, 20 * sx_nodelist_count(targets), "IGNODES", job_data, job_datalen, targets);
	sx_nodelist_delete(targets);
	sx_blob_free(joblb);
	if(s != OK)
	    quit_errmsg(rc2http(s), msg_get_reason());

	send_job_info(job);
	return;
    }
}


struct distlock_ctx {
    char lockid[AUTH_UID_LEN*2+32]; /* Handle user hash and time string */
    int op;
    enum distlock_state { CB_DISTLOCK_START=0, CB_DISTLOCK_LOCKID, CB_DISTLOCK_OP, CB_DISTLOCK_KEY, CB_DISTLOCK_COMPLETE } state;
};

static int cb_distlock_string(void *ctx, const unsigned char *s, size_t l) {
    struct distlock_ctx *dctx = ctx;
    if(dctx->state == CB_DISTLOCK_LOCKID) {
        if(l >= sizeof(dctx->lockid)) {
            DEBUG("Bad lockID length: %ld", l);
            return 0;
        }
        memcpy(dctx->lockid, s, l);
        dctx->lockid[l] = '\0';
    } else if(dctx->state == CB_DISTLOCK_OP) {
        if(l != lenof("unlock") && l != lenof("lock")) {
            DEBUG("Bad op length: %ld", l);
            return 0;
        }
        if(!strncmp((const char*)s, "lock", l))
            dctx->op = 1;
        else if(!strncmp((const char*)s, "unlock", l))
            dctx->op = 0;
        else {
            DEBUG("Invalid distribution lock operation: %.*s", (unsigned)l, s);
            return 0;
        }
    } else {
        DEBUG("Invalid state: %d, expected %d or %d", dctx->state, CB_DISTLOCK_LOCKID, CB_DISTLOCK_OP);
        return 0;
    }

    dctx->state = CB_DISTLOCK_KEY;
    return 1;
}

static int cb_distlock_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct distlock_ctx *c = ctx;
    if(c->state == CB_DISTLOCK_KEY) {
        if(l == lenof("lockID") && !strncmp("lockID", (const char*)s, l)) {
            c->state = CB_DISTLOCK_LOCKID;
            return 1;
        } else if(l == lenof("op") && !strncmp("op", (const char*)s, l)) {
            c->state = CB_DISTLOCK_OP;
            return 1;
        }
    }
    return 0;
}

static int cb_distlock_start_map(void *ctx) {
    struct distlock_ctx *dctx = ctx;
    if(dctx->state == CB_DISTLOCK_START)
        dctx->state = CB_DISTLOCK_KEY;
    else
        return 0;
    return 1;
}

static int cb_distlock_end_map(void *ctx) {
    struct distlock_ctx *dctx = ctx;
    if(dctx->state == CB_DISTLOCK_KEY)
        dctx->state = CB_DISTLOCK_COMPLETE;
    else
        return 0;
    return 1;
}

static const yajl_callbacks distlock_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_distlock_string,
    cb_distlock_start_map,
    cb_distlock_map_key,
    cb_distlock_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

void fcgi_distlock(void) {
    rc_ty s;
    struct distlock_ctx dctx;
    memset(&dctx, 0, sizeof(dctx));
    int len;

    yajl_handle yh = yajl_alloc(&distlock_parser, NULL, &dctx);
    if(!yh)
        quit_errmsg(500, "Cannot allocate json parser");

    while((len = get_body_chunk((char*)hashbuf, sizeof(hashbuf))) > 0)
        if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || dctx.state != CB_DISTLOCK_COMPLETE) {
        yajl_free(yh);
        quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
        send_authreq();
        return;
    }

    /* If cluster is changing hdist already, then lock shouldn't be acquired */
    if(dctx.op) {
        sx_inprogress_t status = sx_hashfs_get_progress_info(hashfs, NULL);
        if(status == INPRG_ERROR)
            quit_errmsg(500, msg_get_reason());
        if(status != INPRG_IDLE)
            quit_errmsg(409, "Cluster is already locked");
    }

    if(!has_priv(PRIV_CLUSTER)) {
        char hexuser[AUTH_UID_LEN*2+1];
        time_t t = time(NULL);
        struct tm *tm;

        if(dctx.lockid[0]) /* Lock ID should not be send by users */
            quit_errmsg(400, "Invalid request content");

        /* Generate lock ID: first part is performing user UID in hex */
        bin2hex(user, AUTH_UID_LEN, hexuser, AUTH_UID_LEN*2+1);
        snprintf(dctx.lockid, sizeof(dctx.lockid), "%s", hexuser);
        sxi_strlcpy(dctx.lockid, hexuser, sizeof(dctx.lockid));

        /* Generate distlock time value */
        if(!(tm = localtime(&t)))
            WARN("Unable to get time");
        else if (strftime(dctx.lockid + strlen(dctx.lockid), sizeof(dctx.lockid), ":%Y-%m-%d %H:%M:%S", tm) <= 0)
            quit_errmsg(400, "Failed to set lock ID");
    }

    if(!dctx.lockid[0])
        quit_errmsg(400, "Lock ID is not set");

    /* Always apply operations locally */
    if(dctx.op) { /* Lock operation */
        s = sx_hashfs_distlock_acquire(hashfs, dctx.lockid);
        if(s == EEXIST)
            quit_errmsg(rc2http(s), "Cluster is already locked"); 
        else if(s != OK) {
            WARN("Failed to acquire lock %s", dctx.lockid);
            quit_errmsg(rc2http(s), rc2str(s));
        }
    } else { /* Unlock operation */
        s = sx_hashfs_distlock_release(hashfs);
        if(s != OK) {
            WARN("Failed to release lock %s", dctx.lockid);
            quit_errmsg(rc2http(s), rc2str(s));
        }
    }

    if(!has_priv(PRIV_CLUSTER)) {
        /* Request comes in from the user: broadcast to all nodes */
        sx_blob_t *joblb;
        const void *job_data;
        unsigned int job_datalen;
        job_t job;
        rc_ty res;
        const sx_nodelist_t *allnodes;

        allnodes = sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV);
        if(!allnodes)
            quit_errmsg(500, "Cannot get node list");

        if(!(joblb = sx_blob_new()))
            quit_errmsg(500, "Cannot allocate job blob");
 
        if(sx_blob_add_string(joblb, dctx.lockid) || sx_blob_add_int32(joblb, dctx.op)) {
            sx_blob_free(joblb);
            quit_errmsg(500, "Cannot create job blob");
        }
 
        sx_blob_to_data(joblb, &job_data, &job_datalen);
 
        res = sx_hashfs_job_new(hashfs, uid, &job, JOBTYPE_DISTLOCK, 20, "DISTLOCK", job_data, job_datalen, allnodes);
        sx_blob_free(joblb);
        if(res != OK) {
            if(res == FAIL_LOCKED)
                quit_errmsg(409, "Cluster is already locked");
            else
                quit_errmsg(rc2http(res), msg_get_reason());
        }
 
        send_job_info(job);
        return;
    }
    CGI_PUTS("\r\n");
}

/* {"newDistribution":"HEX(blob_cfg)", "softwareVersion":"hashfsVER", "faultyNodes":["uuid1", "uuiid2"]} */
struct cb_updist_ctx {
    enum cb_updist_state { CB_UPDIST_START, CB_UPDIST_KEY, CB_UPDIST_CFG, CB_UPDIST_VER, CB_UPDIST_FAULTY, CB_UPDIST_FAULTYNODE, CB_UPDIST_COMPLETE } state;
    void *cfg;
    char remote_ver[sizeof(((sx_hashfs_version_t *)0)->full)];
    sx_nodelist_t *faulty;
    unsigned int cfg_len;
};

static int cb_updist_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;

    if(c->state == CB_UPDIST_CFG) {
	if(l&1 || c->cfg)
	    return 0;

	c->cfg_len = l/2;
	c->cfg = wrap_malloc(l/2);
	if(!c->cfg)
	    return 0;

	if(hex2bin(s, l, c->cfg, l/2)) {
	    free(c->cfg);
	    c->cfg = NULL;
	    return 0;
	}

	c->state = CB_UPDIST_KEY;
	return 1;
    }

    if(c->state == CB_UPDIST_VER) {
	if(c->remote_ver[0] || l >= sizeof(c->remote_ver))
	    return 0;
	memcpy(c->remote_ver, s, l);
	c->remote_ver[l] = '\0';

	c->state = CB_UPDIST_KEY;
	return 1;
    }

    if(c->state == CB_UPDIST_FAULTYNODE || l != UUID_STRING_SIZE) {
	char uuidstr[UUID_STRING_SIZE+1];
	sx_uuid_t uuid;

	memcpy(uuidstr, s, UUID_STRING_SIZE);
	uuidstr[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&uuid, uuidstr))
	    return 0;
	if(sx_nodelist_add(c->faulty, sx_node_new(&uuid, "127.0.0.1", NULL, 1)))
	    return 0;
	return 1;
    }

    return 0;
}

static int cb_updist_start_map(void *ctx) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;
    return c->state++ == CB_UPDIST_START;
}

static int cb_updist_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;

    if(c->state != CB_UPDIST_KEY)
	return 0;

    if(l == lenof("newDistribution") && !strncmp("newDistribution", s, lenof("newDistribution")))
	c->state = CB_UPDIST_CFG;
    else if(l == lenof("softwareVersion") && !strncmp("softwareVersion", s, lenof("softwareVersion")))
	c->state = CB_UPDIST_VER;
    else if(l == lenof("faultyNodes") && !strncmp("faultyNodes", s, lenof("faultyNodes")))
	c->state = CB_UPDIST_FAULTY;
    else
	return 0;
    return 1;
}

static int cb_updist_end_map(void *ctx) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;

    if(c->state != CB_UPDIST_KEY)
	return 0;
    c->state = CB_UPDIST_COMPLETE;
    return 1;
}

static int cb_updist_start_array(void *ctx) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;

    if(c->state != CB_UPDIST_FAULTY)
	return 0;

    c->state = CB_UPDIST_FAULTYNODE;
    return 1;
}

static int cb_updist_end_array(void *ctx) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;

    if(c->state != CB_UPDIST_FAULTYNODE)
	return 0;

    c->state = CB_UPDIST_KEY;
    return 1;
}

static const yajl_callbacks updist_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_updist_string,
    cb_updist_start_map,
    cb_updist_map_key,
    cb_updist_end_map,
    cb_updist_start_array,
    cb_updist_end_array
};


void fcgi_new_distribution(void) {
    struct cb_updist_ctx yctx;
    yajl_handle yh;
    sx_hashfs_version_t *lver, rver;
    rc_ty s;
    int len, v;

    yctx.cfg = NULL;
    yctx.remote_ver[0] = '\0';
    yctx.state = CB_UPDIST_START;
    yctx.faulty = sx_nodelist_new();
    if(!yctx.faulty)
	quit_errmsg(503, "Cannot allocate replacement node list");

    yh = yajl_alloc(&updist_parser, NULL, &yctx);
    if(!yh) {
	sx_nodelist_delete(yctx.faulty);
	quit_errmsg(503, "Cannot allocate json parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_UPDIST_COMPLETE || !yctx.cfg || !yctx.cfg_len) {
	yajl_free(yh);
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	send_authreq();
	return;
    }

    if(sx_hashfs_version_parse(yctx.remote_ver, &rver)) {
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	quit_errmsg(400, "Invalid software version");
    }

    lver = sx_hashfs_version(hashfs);
    v = sx_hashfs_version_cmp(lver, &rver);
    if(v != 0) {
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	if(v > 0)
	    quit_errmsg(400, "Remote software version is too old");
	else
	    quit_errmsg(400, "Local software version is too old");
    }

    if(!sx_nodelist_count(yctx.faulty))
	s = sx_hashfs_hdist_change_add(hashfs, yctx.cfg, yctx.cfg_len);
    else
	s = sx_hashfs_hdist_replace_add(hashfs, yctx.cfg, yctx.cfg_len, yctx.faulty);

    sx_nodelist_delete(yctx.faulty);
    free(yctx.cfg);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

void fcgi_enable_distribution(void) {
    rc_ty s = sx_hashfs_hdist_change_commit(hashfs);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

void fcgi_revoke_distribution(void) {
    rc_ty s = sx_hashfs_hdist_change_revoke(hashfs);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    CGI_PUTS("\r\n");
}


void fcgi_start_rebalance(void) {
    rc_ty s = sx_hashfs_hdist_rebalance(hashfs);

    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

void fcgi_stop_rebalance(void) {
    rc_ty s = sx_hashfs_hdist_endrebalance(hashfs);

    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

/*
  {
   "clusterName":"name",
   "nodeUUID":"12345678-1234-1234-1234-123356789abcd",
   "secureProtocol":(true|false),
   "httpPort":8080,
   "caCertData":"--- BEGIN ....",
  }
*/
/* MODHDIST: maybe add revision here */
struct cb_nodeinit_ctx {
    enum cb_nodeinit_state { CB_NODEINIT_START, CB_NODEINIT_KEY, CB_NODEINIT_NAME, CB_NODEINIT_NODE, CB_NODEINIT_SSL, CB_NODEINIT_PORT, CB_NODEINIT_CA, CB_NODEINIT_COMPLETE } state;
    unsigned int have_uuid;
    int ssl;
    char *name, *ca;
    sx_uuid_t uuid;
    uint16_t port;
};

static int cb_nodeinit_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(c->state == CB_NODEINIT_NAME) {
	if(!l || c->name)
	    return 0;
	c->name = wrap_malloc(l+1);
	if(!c->name)
	    return 0;
	memcpy(c->name, s, l);
	c->name[l] = '\0';
    } else if(c->state == CB_NODEINIT_NODE) {
	char uuidstr[UUID_STRING_SIZE+1];
	if(l != UUID_STRING_SIZE || c->have_uuid)
	    return 0;
	memcpy(uuidstr, s, UUID_STRING_SIZE);
	uuidstr[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&c->uuid, uuidstr))
	    return 0;
	c->have_uuid = 1;
    } else if(c->state == CB_NODEINIT_CA) {
	if(c->ca)
	    return 0;
	if(l) {
	    c->ca = malloc(l+1);
	    if(!c->ca)
		return 0;
	    memcpy(c->ca, s, l);
	    c->ca[l] = '\0';
	}
    } else
	return 0;

    c->state = CB_NODEINIT_KEY;
    return 1;
}

static int cb_nodeinit_boolean(void *ctx, int boolean) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(c->ssl >= 0 || c->state != CB_NODEINIT_SSL)
	return 0;

    c->ssl = (boolean != 0);
    c->state = CB_NODEINIT_KEY;
    return 1;
}

static int cb_nodeinit_start_map(void *ctx) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;
    return c->state++ == CB_NODEINIT_START;
}

static int cb_nodeinit_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(c->state != CB_NODEINIT_KEY)
	return 0;

    if(l == lenof("clusterName") && !strncmp("clusterName", s, lenof("clusterName"))) {
	c->state = CB_NODEINIT_NAME;
	return 1;
    }

    if(l == lenof("nodeUUID") && !strncmp("nodeUUID", s, lenof("nodeUUID"))) {
	c->state = CB_NODEINIT_NODE;
	return 1;
    }

    if(l == lenof("httpPort") && !strncmp("httpPort", s, lenof("httpPort"))) {
	c->state = CB_NODEINIT_PORT;
	return 1;
    }

    if(l == lenof("secureProtocol") && !strncmp("secureProtocol", s, lenof("secureProtocol"))) {
	c->state = CB_NODEINIT_SSL;
	return 1;
    }

    if(l == lenof("caCertData") && !strncmp("caCertData", s, lenof("caCertData"))) {
	c->state = CB_NODEINIT_CA;
	return 1;
    }

    return 0;
}

static int cb_nodeinit_end_map(void *ctx) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(c->state != CB_NODEINIT_KEY)
	return 0;
    c->state = CB_NODEINIT_COMPLETE;
    return 1;
}


static int cb_nodeinit_number(void *ctx, const char *s, size_t l) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;
    char number[6], *eon;
    long n;

    if(c->state != CB_NODEINIT_PORT || l<1 || l>5)
	return 0;

    memcpy(number, s, l);
    number[l] = '\0';
    n = strtol(number, &eon, 10);
    if(*eon || n < 0 || n > 0xffff)
	return 0;

    c->port = n;
    c->state = CB_NODEINIT_KEY;
    return 1;
}


static const yajl_callbacks nodeinit_parser = {
    cb_fail_null,
    cb_nodeinit_boolean,
    NULL,
    NULL,
    cb_nodeinit_number,
    cb_nodeinit_string,
    cb_nodeinit_start_map,
    cb_nodeinit_map_key,
    cb_nodeinit_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};


void fcgi_node_init(void) {
    if(!sx_storage_is_bare(hashfs))
	quit_errmsg(400, "Node already initialized");

    struct cb_nodeinit_ctx yctx;
    memset(&yctx, 0, sizeof(yctx));
    yctx.state = CB_NODEINIT_START;
    yctx.ssl = -1;

    yajl_handle yh = yajl_alloc(&nodeinit_parser, NULL, &yctx);
    if(!yh)
	quit_errmsg(500, "Cannot allocate json parser");

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_NODEINIT_COMPLETE || !yctx.name || !yctx.have_uuid || yctx.ssl < 0) {
	yajl_free(yh);
	free(yctx.name);
	free(yctx.ca);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    quit_unless_authed();

    rc_ty s = sx_hashfs_setnodedata(hashfs, yctx.name, &yctx.uuid, yctx.port, yctx.ssl, yctx.ca);
    free(yctx.name);
    free(yctx.ca);

    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    NOTICE("We are now joined to cluster %s as member node %s in %s mode",
	 sx_hashfs_uuid(hashfs)->string, yctx.uuid.string, yctx.ssl ? "secure" : "insecure");

    CGI_PUTS("\r\n");
}


/*
    {
        "users":{
            "admin":{"key":"xxxxx","admin":true}
            "luser":{"key":"yyyyy","admin":false,"quota":12345,"desc":"luser description"}
        }
    }

    {
        "volumes":{
	    "volume1":{"owner":"xxxx","replica":1,"revs":1,"size":1234,""meta":{"key":"val","key2":"val2"}},
	    "volume2":{"owner":"yyyy","replica":2,"size":5678},
        }
    }

    {
        "perms":{
            "volume1":{"xxxx":"rw","yyyy":"r"}
        }
    }

    {
        "misc":{
            "mode":"ro",
            "clusterMeta":{"key1":"val1","key2":"val2"},
            "clusterMetaLastModified":123123123,
            "clusterSettings":{"key1":"val1","key2":"val2"},
            "clusterSettingsLastModified":12341234
        }
    }
*/

struct cb_sync_ctx {
    enum cb_sync_state { CB_SYNC_START, CB_SYNC_MAIN, CB_SYNC_USERS, CB_SYNC_VOLUMES, CB_SYNC_PERMS, CB_SYNC_MISC, CB_SYNC_INMISC, CB_SYNC_MODE, CB_SYNC_CLUSTER_SETTINGS_TS, CB_SYNC_CLUSTER_SETTINGS, CB_SYNC_CLUSTER_SETTINGS_KEY, CB_SYNC_CLUSTER_SETTINGS_VAL, CB_SYNC_CLUSTERMETA_TS, CB_SYNC_CLUSTERMETA, CB_SYNC_CLUSTERMETA_KEY, CB_SYNC_CLUSTERMETA_VAL, CB_SYNC_INUSERS, CB_SYNC_INVOLUMES, CB_SYNC_INPERMS, CB_SYNC_USR, CB_SYNC_VOL, CB_SYNC_PRM, CB_SYNC_USRDESC, CB_SYNC_USRID, CB_SYNC_USRQUOTA, CB_SYNC_VOLKEY, CB_SYNC_PRMKEY, CB_SYNC_USRAUTH, CB_SYNC_USRKEY, CB_SYNC_USRROLE, CB_SYNC_VOLOWNR, CB_SYNC_VOLREP, CB_SYNC_VOLREVS, CB_SYNC_VOLSIZ, CB_SYNC_VOLMETA, CB_SYNC_VOLMETAKEY, CB_SYNC_VOLMETAVAL, CB_SYNC_PRMVAL, CB_SYNC_OUTRO, CB_SYNC_COMPLETE } state;
    int64_t size;
    int64_t quota; /* Quota for volumes owned by the user */
    time_t cluster_meta_ts;
    char name[MAX(SXLIMIT_MAX_VOLNAME_LEN, SXLIMIT_MAX_USERNAME_LEN) + 1];
    char mkey[SXLIMIT_META_MAX_KEY_LEN+1];
    char desc[SXLIMIT_META_MAX_VALUE_LEN+1];
    uint8_t key[AUTH_KEY_LEN];
    uint8_t user[AUTH_UID_LEN];
    sx_uid_t uid;
    int admin, have_key, have_user;
    unsigned int replica, revs;
    char setting_key[SXLIMIT_SETTINGS_MAX_KEY_LEN+1];
    sx_setting_type_t setting_type;
    time_t cluster_settings_ts;
    unsigned int nsettings;
    sx_blob_t *settings;
};

static int cb_sync_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    if(c->state == CB_SYNC_USRAUTH) {
	if(l != AUTH_KEY_LEN * 2)
	    return 0;
	if(hex2bin(s, l, c->key, sizeof(c->key)))
	    return 0;
	c->have_key = 1;
	c->state = CB_SYNC_USRKEY;
    } else if(c->state == CB_SYNC_USRID) {
        if(l != AUTH_UID_LEN * 2)
            return 0;
        if(hex2bin(s, l, c->user, sizeof(c->user)))
            return 0;
        c->have_user = 1;
        c->state = CB_SYNC_USRKEY;
    } else if(c->state == CB_SYNC_USRDESC) {
        if (l >= sizeof(c->desc))
            return 0;
        memcpy(c->desc, s, l);
        c->desc[l] = 0;
        c->state = CB_SYNC_USRKEY;
    } else if(c->state == CB_SYNC_VOLOWNR) {
	uint8_t usr[AUTH_UID_LEN];
	if(l != AUTH_UID_LEN * 2)
	    return 0;
	if(hex2bin(s, l, usr, sizeof(usr)))
	    return 0;
	if(sx_hashfs_get_user_info(hashfs, usr, &c->uid, NULL, NULL, NULL, NULL))
	    return 0;
	c->state = CB_SYNC_VOLKEY;
    } else if(c->state == CB_SYNC_VOLMETAVAL) {
	uint8_t val[SXLIMIT_META_MAX_VALUE_LEN];
	if(!l || (l & 1) || l > sizeof(val) * 2)
	    return 0;
	if(hex2bin(s, l, val, sizeof(val)))
	    return 0;
	if(sx_hashfs_volume_new_addmeta(hashfs, c->mkey, val, l/2))
	    return 0;
	c->state = CB_SYNC_VOLMETAKEY;
    } else if(c->state == CB_SYNC_MODE) {
        if(l != 2)
            return 0;
        if(sx_hashfs_cluster_set_mode(hashfs, !strncmp(s, "ro", l) ? 1 : 0))
            return 0;
        c->state = CB_SYNC_INMISC;
    } else if(c->state == CB_SYNC_CLUSTERMETA_VAL) {
        uint8_t val[SXLIMIT_META_MAX_VALUE_LEN];
        if(!l || (l & 1) || l > sizeof(val) * 2)
            return 0;
        if(hex2bin((const char*)s, l, val, sizeof(val)))
            return 0;
        if(sx_hashfs_clustermeta_set_addmeta(hashfs, c->mkey, val, l/2))
            return 0;
        c->state = CB_SYNC_CLUSTERMETA_KEY;
    } else if(c->state == CB_SYNC_CLUSTER_SETTINGS_VAL) {
        char val[SXLIMIT_SETTINGS_MAX_VALUE_LEN+1];
        if((l & 1) || l > SXLIMIT_SETTINGS_MAX_VALUE_LEN * 2)
            return 0;
        if(hex2bin((const char*)s, l, (uint8_t*)val, sizeof(val)))
            return 0;
        l /= 2;
        val[l] = '\0';
        if(sx_blob_add_string(c->settings, c->setting_key) || sx_blob_add_int32(c->settings, c->setting_type) ||
           sx_hashfs_parse_cluster_setting(hashfs, c->setting_key, c->setting_type, val, c->settings)) {
            WARN("Failed to store cluster settings data");
            return 0;
        }
        c->nsettings++;
        c->state = CB_SYNC_CLUSTER_SETTINGS_KEY;
    } else
	return 0;
    return 1;
}

static int cb_sync_boolean(void *ctx, int boolean) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(c->state != CB_SYNC_USRROLE)
	return 0;

    c->admin = boolean;
    c->state = CB_SYNC_USRKEY;
    return 1;
}

static int cb_sync_number(void *ctx, const char *s, size_t l) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    char number[24], *eon;
    int64_t n;

    if(c->state != CB_SYNC_VOLREP && c->state != CB_SYNC_VOLSIZ && c->state != CB_SYNC_VOLREVS && c->state != CB_SYNC_USRQUOTA && c->state != CB_SYNC_CLUSTERMETA_TS && c->state != CB_SYNC_CLUSTER_SETTINGS_TS && c->state != CB_SYNC_PRMVAL)
	return 0;

    if(l<1 || l>20)
	return 0;
    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &eon, 10);
    if(*eon || n < 0)
	return 0;
    /* User quota can be 0 */
    if(c->state != CB_SYNC_USRQUOTA && n == 0)
        return 0;

    if(c->state == CB_SYNC_VOLSIZ)
	c->size = n;
    else if(c->state == CB_SYNC_USRQUOTA)
        c->quota = n;
    else if(c->state == CB_SYNC_CLUSTERMETA_TS)
        c->cluster_meta_ts = (time_t)n;
    else if(c->state == CB_SYNC_CLUSTER_SETTINGS_TS)
        c->cluster_settings_ts = (time_t)n;
    else if(n > 0xffffffff)
	return 0;
    else if (c->state == CB_SYNC_PRMVAL) {
        sx_hashfs_revoke(hashfs, c->uid, c->name, ALL_USER_PRIVS);
        if ((n & ~ALL_USER_PRIVS)) {
            WARN("Bad privilege in sync: %d", (int)n);
            return 0;
        }
        if(sx_hashfs_grant(hashfs, c->uid, c->name, n))
            return 0;
    } else if(c->state == CB_SYNC_VOLREP)
	c->replica = (unsigned int)n;
    else
	c->revs = (unsigned int)n;

    if(c->state == CB_SYNC_USRQUOTA)
        c->state = CB_SYNC_USRKEY;
    else if(c->state == CB_SYNC_CLUSTERMETA_TS)
        c->state = CB_SYNC_INMISC;
    else if(c->state == CB_SYNC_CLUSTER_SETTINGS_TS)
        c->state = CB_SYNC_INMISC;
    else if(c->state == CB_SYNC_PRMVAL)
        c->state = CB_SYNC_PRMKEY;
    else
        c->state = CB_SYNC_VOLKEY;

    return 1;
}

static int cb_sync_start_map(void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(c->state == CB_SYNC_START)
	c->state = CB_SYNC_MAIN;

    else if(c->state == CB_SYNC_USERS)
	c->state = CB_SYNC_INUSERS;
    else if(c->state == CB_SYNC_VOLUMES)
	c->state = CB_SYNC_INVOLUMES;
    else if(c->state == CB_SYNC_PERMS)
	c->state = CB_SYNC_INPERMS;
    else if(c->state == CB_SYNC_MISC)
        c->state = CB_SYNC_INMISC;

    else if(c->state == CB_SYNC_USR)
	c->state = CB_SYNC_USRKEY;
    else if(c->state == CB_SYNC_VOL)
	c->state = CB_SYNC_VOLKEY;
    else if(c->state == CB_SYNC_PRM)
	c->state = CB_SYNC_PRMKEY;

    else if(c->state == CB_SYNC_VOLMETA)
	c->state = CB_SYNC_VOLMETAKEY;
    else if(c->state == CB_SYNC_CLUSTERMETA)
        c->state = CB_SYNC_CLUSTERMETA_KEY;
    else if(c->state == CB_SYNC_CLUSTER_SETTINGS)
        c->state = CB_SYNC_CLUSTER_SETTINGS_KEY;
    else
	return 0;

    return 1;
}

static int cb_sync_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(c->state == CB_SYNC_MAIN) {
	if(l == lenof("users") && !strncmp("users", s, lenof("users")))
	    c->state = CB_SYNC_USERS;
	else if(l == lenof("volumes") && !strncmp("volumes", s, lenof("volumes")))
	    c->state = CB_SYNC_VOLUMES;
	else if(l == lenof("perms") && !strncmp("perms", s, lenof("perms")))
	    c->state = CB_SYNC_PERMS;
        else if(l == lenof("misc") && !strncmp("misc", s, lenof("misc")))
            c->state = CB_SYNC_MISC;
	else
	    return 0;
    } else if(c->state == CB_SYNC_INUSERS ||
	      c->state == CB_SYNC_INVOLUMES ||
	      c->state == CB_SYNC_INPERMS) {
	if(l >= sizeof(c->name))
	    return 0;
	memcpy(c->name, s, l);
	c->name[l] = '\0';
	if(c->state == CB_SYNC_INUSERS) {
	    c->have_key = 0;
	    c->admin = -1;
	    c->state = CB_SYNC_USR;
	} else if(c->state == CB_SYNC_INVOLUMES) {
	    sx_hashfs_volume_new_begin(hashfs);
	    c->uid = -1;
	    c->replica = 0;
	    c->revs = 0;
	    c->size = -1;
	    c->state = CB_SYNC_VOL;
	} else
	    c->state = CB_SYNC_PRM;
    } else if(c->state == CB_SYNC_USRKEY) {
	if(l == lenof("key") && !strncmp("key", s, lenof("key")))
	    c->state = CB_SYNC_USRAUTH;
        else if(l == lenof("user") && !strncmp("user", s, lenof("user")))
            c->state = CB_SYNC_USRID;
	else if(l == lenof("admin") && !strncmp("admin", s, lenof("admin")))
	    c->state = CB_SYNC_USRROLE;
        else if(l == lenof("desc") && !strncmp("desc", s, lenof("desc")))
            c->state = CB_SYNC_USRDESC;
        else if(l == lenof("quota") && !strncmp("quota", s, lenof("quota")))
            c->state = CB_SYNC_USRQUOTA;
	else
	    return 0;
    } else if(c->state == CB_SYNC_VOLKEY) {
	if(l == lenof("owner") && !strncmp("owner", s, lenof("owner")))
	    c->state = CB_SYNC_VOLOWNR;
	else if(l == lenof("replica") && !strncmp("replica", s, lenof("replica")))
	    c->state = CB_SYNC_VOLREP;
	else if(l == lenof("revs") && !strncmp("revs", s, lenof("revs")))
	    c->state = CB_SYNC_VOLREVS;
	else if(l == lenof("size") && !strncmp("size", s, lenof("size")))
	    c->state = CB_SYNC_VOLSIZ;
	else if(l == lenof("meta") && !strncmp("meta", s, lenof("meta")))
	    c->state = CB_SYNC_VOLMETA;
	else
	    return 0;
    } else if(c->state == CB_SYNC_PRMKEY) {
	uint8_t usr[AUTH_UID_LEN];
	if(l != AUTH_UID_LEN * 2)
	    return 0;
	if(hex2bin(s, l, usr, sizeof(usr)))
	    return 0;
	if(sx_hashfs_get_user_info(hashfs, usr, &c->uid, NULL, NULL, NULL, NULL))
	    return 0;
	c->state = CB_SYNC_PRMVAL;
    } else if(c->state == CB_SYNC_VOLMETAKEY) {
	if(l >= sizeof(c->mkey))
	    return 0;
	memcpy(c->mkey, s, l);
	c->mkey[l] = '\0';
	c->state = CB_SYNC_VOLMETAVAL;
    } else if(c->state == CB_SYNC_CLUSTERMETA_KEY) {
        if(l >= sizeof(c->mkey))
            return 0;
        memcpy(c->mkey, s, l);
        c->mkey[l] = '\0';
        c->state = CB_SYNC_CLUSTERMETA_VAL;
    } else if(c->state == CB_SYNC_CLUSTER_SETTINGS_KEY) {
        const char *old_value;
        if(l >= sizeof(c->setting_key))
            return 0;
        memcpy(c->setting_key, s, l);
        c->setting_key[l] = '\0';
        if(sx_hashfs_cluster_settings_get(hashfs, c->setting_key, &c->setting_type, &old_value))
            return 0;
        c->state = CB_SYNC_CLUSTER_SETTINGS_VAL;
    } else if(c->state == CB_SYNC_INMISC) {
        if(l == lenof("mode") && !strncmp("mode", s, lenof("mode")))
            c->state = CB_SYNC_MODE;
        else if(l == lenof("clusterMeta") && !strncmp("clusterMeta", s, lenof("clusterMeta"))) {
            sx_hashfs_clustermeta_set_begin(hashfs);
            c->state = CB_SYNC_CLUSTERMETA;
        } else if(l == lenof("clusterMetaLastModified") && !strncmp("clusterMetaLastModified", s, lenof("clusterMetaLastModified")))
            c->state = CB_SYNC_CLUSTERMETA_TS;
        else if(l == lenof("clusterSettings") && !strncmp("clusterSettings", s, lenof("clusterSettings"))) {
            c->state = CB_SYNC_CLUSTER_SETTINGS;
        } else if(l == lenof("clusterSettingsLastModified") && !strncmp("clusterSettingsLastModified", s, lenof("clusterSettingsLastModified")))
            c->state = CB_SYNC_CLUSTER_SETTINGS_TS;
        else
            return 0;
    } else
	return 0;

    return 1;
}

static int cb_sync_end_map(void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    rc_ty s;
    if(c->state == CB_SYNC_USRKEY) {
	if(!c->have_key || c->admin < 0 || !c->have_user)
	    return 0;
	s = sx_hashfs_create_user(hashfs, c->name, c->user, sizeof(c->user), c->key, sizeof(c->key), c->admin != 0, c->desc, c->quota);
	if(s != OK && s != EEXIST)
	    return 0;
	if(sx_hashfs_user_onoff(hashfs, c->name, 1, 0))
	    return 0;
	c->state = CB_SYNC_INUSERS;
    } else if(c->state == CB_SYNC_VOLKEY) {
	if(c->uid < 0 || c->size <= 0 || !c->replica)
	    return 0;
	if(!c->revs)
	    c->revs = 1;
	s = sx_hashfs_volume_new_finish(hashfs, c->name, c->size, c->replica, c->revs, c->uid, 0);
	if(s != OK && s != EEXIST)
	    return 0;
	if(sx_hashfs_volume_enable(hashfs, c->name))
	    return 0;
	c->state = CB_SYNC_INVOLUMES;
    } else if(c->state == CB_SYNC_PRMKEY) {
	c->state = CB_SYNC_INPERMS;
    } else if(c->state == CB_SYNC_INUSERS ||
	      c->state == CB_SYNC_INVOLUMES ||
	      c->state == CB_SYNC_INPERMS) {
	c->state = CB_SYNC_OUTRO;
    } else if(c->state == CB_SYNC_INMISC) {
        c->state = CB_SYNC_OUTRO;
    } else if(c->state == CB_SYNC_VOLMETAKEY) {
	c->state = CB_SYNC_VOLKEY;	
    } else if(c->state == CB_SYNC_CLUSTERMETA_KEY) {
        if(sx_hashfs_clustermeta_set_finish(hashfs, c->cluster_meta_ts, 0))
            return 0;
        c->state = CB_SYNC_INMISC;
    } else if(c->state == CB_SYNC_CLUSTER_SETTINGS_KEY) {
        unsigned int i;

        sx_blob_reset(c->settings);
        for(i = 0; i < c->nsettings; i++) {
            sx_setting_type_t type;
            const char *key = NULL;
            if(sx_blob_get_string(c->settings, &key) || sx_blob_get_int32(c->settings, (int32_t *)(&type))) {
                WARN("Data corruption detected: Failed to get cluster setting key and type %s", key);
                return 0;
            }

            switch(type) {
                case SX_SETTING_TYPE_INT: {
                    int64_t v;
                    if(sx_blob_get_int64(c->settings, &v)) {
                        WARN("Failed to obtain integer setting from blob");
                        return 0;
                    }

                    if(sx_hashfs_cluster_settings_set_int64(hashfs, key, v)) {
                        WARN("Failed to modify cluster settings");
                        return 0;
                    }
                    break;
                }

                case SX_SETTING_TYPE_UINT: {
                    uint64_t v;
                    if(sx_blob_get_uint64(c->settings, &v)) {
                        WARN("Failed to obtain unsigned integer setting from blob");
                        return 0;
                    }

                    if(sx_hashfs_cluster_settings_set_uint64(hashfs, key, v)) {
                        WARN("Failed to modify cluster settings");
                        return 0;
                    }
                    break;
                }

                case SX_SETTING_TYPE_BOOL: {
                    int v;
                    if(sx_blob_get_bool(c->settings, &v)) {
                        WARN("Failed to obtain boolean setting from blob");
                        return 0;
                    }

                    if(sx_hashfs_cluster_settings_set_bool(hashfs, key, v)) {
                        WARN("Failed to modify cluster settings");
                        return 0;
                    }
                    break;
                }

                case SX_SETTING_TYPE_FLOAT: {
                    double v;
                    if(sx_blob_get_float(c->settings, &v)) {
                        WARN("Failed to obtain float setting from blob");
                        return 0;
                    }

                    if(sx_hashfs_cluster_settings_set_double(hashfs, key, v)) {
                        WARN("Failed to modify cluster settings");
                        return 0;
                    }
                    break;
                }

                case SX_SETTING_TYPE_STRING: {
                    const char *str;
                    if(sx_blob_get_string(c->settings, &str)) {
                        WARN("Failed to obtain string setting from blob");
                        return 0;
                    }

                    if(sx_hashfs_cluster_settings_set_string(hashfs, key, str)) {
                        WARN("Failed to modify cluster settings");
                        return 0;
                    }
                    break;
                }
            }
        }
        if(sx_hashfs_modify_cluster_settings_end(hashfs, c->cluster_settings_ts, 1))
            return 0;
        c->nsettings = 0;
        sx_blob_reset(c->settings);
        c->state = CB_SYNC_INMISC;
    } else if(c->state == CB_SYNC_OUTRO) {
	c->state = CB_SYNC_COMPLETE;
    } else
	return 0;
    return 1;
}

static const yajl_callbacks sync_parser = {
    cb_fail_null,
    cb_sync_boolean,
    NULL,
    NULL,
    cb_sync_number,
    cb_sync_string,
    cb_sync_start_map,
    cb_sync_map_key,
    cb_sync_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};


void fcgi_sync_globs(void) {
    struct cb_sync_ctx *yctx;
    if(!sx_storage_is_bare(hashfs))
	quit_errmsg(400, "Node already initialized");

    if(!(yctx = wrap_calloc(1, sizeof(*yctx))))
	quit_errmsg(503, "Out of memory");

    yctx->settings = sx_blob_new();
    if(!yctx->settings) {
	free(yctx);
        quit_errmsg(500, "Cannot allocate data store");
    }

    yctx->state = CB_SYNC_START;

    yajl_handle yh = yajl_alloc(&sync_parser, NULL, yctx);
    if(!yh) {
	sx_blob_free(yctx->settings);
	free(yctx);
	quit_errmsg(500, "Cannot allocate json parser");
    }

    if(sx_hashfs_syncglobs_begin(hashfs)) {
        yajl_free(yh);
	sx_blob_free(yctx->settings);
	free(yctx);
	quit_errmsg(503, "Failed to prepare object synchronization");
    }

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;
    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx->state != CB_SYNC_COMPLETE) {
	yajl_free(yh);
	sx_blob_free(yctx->settings);
	free(yctx);
	sx_hashfs_syncglobs_abort(hashfs);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
        sx_blob_free(yctx->settings);
	free(yctx);
	sx_hashfs_syncglobs_abort(hashfs);
	send_authreq();
	return;
    }

    if(sx_hashfs_syncglobs_end(hashfs)) {
        sx_blob_free(yctx->settings);
	free(yctx);
	quit_errmsg(503, "Failed to finalize object synchronization");
    }

    sx_blob_free(yctx->settings);
    free(yctx);
    CGI_PUTS("\r\n");
}


void fcgi_node_jlock(void) {
    rc_ty s = sx_hashfs_job_lock(hashfs, path);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}


void fcgi_node_junlock(void) {
    rc_ty s = sx_hashfs_job_unlock(hashfs, strcmp(path, "any") ? path : NULL);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

void fcgi_node_repaired(void) {
    int64_t dist_rev = 0;
    sx_uuid_t nodeid;
    rc_ty s;

    if(has_arg("dist")) {
	char *eon;
	dist_rev = strtoll(get_arg("dist"), &eon, 10);
	if(*eon)
	    dist_rev = 0;
    }
    if(dist_rev <= 0)
	quit_errmsg(400, "Missing or invalid 'dist' argument");

    if(uuid_from_string(&nodeid, path))
	quit_errmsg(400, "Invalid repaired node UUID");

    s = sx_hashfs_set_unfaulty(hashfs, &nodeid, dist_rev);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    
    CGI_PUTS("\r\n");
}

void fcgi_node_status(void) {
    sxi_node_status_t status;
    rc_ty s;

    s = sx_hashfs_node_status(hashfs, &status);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());
    CGI_PUTS("Content-type: application/json\r\n\r\n{");
    CGI_PRINTF("\"osType\":\"%s\",\"osArch\":\"%s\",\"osRelease\":\"%s\",\"osVersion\":\"%s\",\"cores\":%d",
        status.os_name, status.os_arch, status.os_release, status.os_version, status.cores);
    CGI_PRINTF(",\"osEndianness\":\"%s\",\"localTime\":\"%s\",\"utcTime\":\"%s\"", status.endianness, status.localtime, status.utctime);
    CGI_PRINTF(",\"hashFSVersion\":\"%s\",\"libsxclientVersion\":\"%s\"", status.hashfs_version, status.libsxclient_version);
    if(!status.is_bare)
        CGI_PRINTF(",\"address\":\"%s\",\"internalAddress\":\"%s\",\"UUID\":\"%s\"", status.addr, status.internal_addr, status.uuid);
    CGI_PRINTF(",\"nodeDir\":\"%s\"", status.storage_dir);
    CGI_PRINTF(",\"storageAllocated\":");
    CGI_PUTLL(status.storage_allocated);
    CGI_PRINTF(",\"storageUsed\":");
    CGI_PUTLL(status.storage_commited);
    CGI_PUTS(",\"fsBlockSize\":");
    CGI_PUTLL(status.block_size);
    CGI_PUTS(",\"fsTotalBlocks\":");
    CGI_PUTLL(status.total_blocks);
    CGI_PUTS(",\"fsAvailBlocks\":");
    CGI_PUTLL(status.avail_blocks);
    CGI_PUTS(",\"memTotal\":");
    CGI_PUTLL(status.mem_total);
    CGI_PRINTF(",\"heal\":\"%s\"", status.heal_status);
    CGI_PUTC('}');
}

/*
 * Sample body:
 *
 * {
 *      "term":123,
 *      "distributionVersion":3,
 *      "hashFSVersion":"SX-Storage 1.9",
 *      "libsxclientVersion":"1.2",
 *      "candidateID":"6f24df87-d9e1-47e4-a8fa-e39a8244e90c",
 *      "lastLogIndex":273612,
 *      "lastLogTerm":122
 * }
 *
 */

struct cb_request_vote_ctx {
    enum cb_request_vote_state { CB_RV_START, CB_RV_KEY, CB_RV_TERM, CB_RV_HDIST_VERSION, CB_RV_HASHFS_VERSION, CB_RV_LIB_VERSION, CB_RV_CANDIDATE_UUID, CB_RV_LAST_LOG_INDEX, CB_RV_LAST_LOG_TERM, CB_RV_COMPLETE } state;
    int64_t term;
    int64_t last_log_index;
    int64_t last_log_term;
    sx_uuid_t candidate_uuid;
    int64_t hdist_version;
    sx_hashfs_version_t remote_version;
    char libsxclient_version[128];
};

static int cb_request_vote_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;

    if(c->state == CB_RV_CANDIDATE_UUID) {
        char uuid_str[UUID_STRING_SIZE+1];

        if(l != UUID_STRING_SIZE)
            return 0;
        memcpy(uuid_str, s, UUID_STRING_SIZE);
        uuid_str[UUID_STRING_SIZE] = '\0';
        if(uuid_from_string(&c->candidate_uuid, uuid_str))
            return 0;
        c->state = CB_RV_KEY;
        return 1;
    } else if(c->state == CB_RV_HASHFS_VERSION) {
	char ver[sizeof(c->remote_version.full)];
        if(l >= sizeof(ver))
            return 0;
        memcpy(ver, s, l);
        ver[l] = '\0';
	if(sx_hashfs_version_parse(ver, &c->remote_version))
	    return 0;
        c->state = CB_RV_KEY;
        return 1;
    } else if(c->state == CB_RV_LIB_VERSION) {
        if(l >= sizeof(c->libsxclient_version))
            return 0;
        memcpy(c->libsxclient_version, s, l);
        c->libsxclient_version[l] = '\0';
        c->state = CB_RV_KEY;
        return 1;
    }

    return 0;
}

static int cb_request_vote_number(void *ctx, const char *s, size_t l) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx *)ctx;
    char number[24], *eon;
    int64_t n;

    if(c->state != CB_RV_TERM && c->state != CB_RV_HDIST_VERSION && c->state != CB_RV_LAST_LOG_INDEX && c->state != CB_RV_LAST_LOG_TERM)
        return 0;

    if(l<1 || l>20)
        return 0;
    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &eon, 10);
    if(*eon || n < 0)
        return 0;

    if(c->state == CB_RV_TERM) {
        c->term = n;
        c->state = CB_RV_KEY;
    } else if(c->state == CB_RV_HDIST_VERSION) {
        c->hdist_version = n;
        c->state = CB_RV_KEY;
    } else if(c->state == CB_RV_LAST_LOG_INDEX) {
        c->last_log_index = n;
        c->state = CB_RV_KEY;
    } else if(c->state == CB_RV_LAST_LOG_TERM) {
        c->last_log_term = n;
    } else
        return 0;
    c->state = CB_RV_KEY;
    return 1;
}

static int cb_request_vote_start_map(void *ctx) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;

    if(c->state == CB_RV_START)
        c->state = CB_RV_KEY;
    else
        return 0;

    return 1;
}

static int cb_request_vote_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;

    if(c->state == CB_RV_KEY) {
        if(l == lenof("term") && !strncmp("term", (const char *)s, lenof("term")))
            c->state = CB_RV_TERM;
        else if(l == lenof("candidateID") && !strncmp("candidateID", (const char *)s, lenof("candidateID")))
            c->state = CB_RV_CANDIDATE_UUID;
        else if(l == lenof("lastLogIndex") && !strncmp("lastLogIndex", (const char *)s, lenof("lastLogIndex")))
            c->state = CB_RV_LAST_LOG_INDEX;
        else if(l == lenof("lastLogTerm") && !strncmp("lastLogTerm", (const char *)s, lenof("lastLogTerm")))
            c->state = CB_RV_LAST_LOG_TERM;
        else if(l == lenof("distributionVersion") && !strncmp("distributionVersion", (const char *)s, lenof("distributionVersion")))
            c->state = CB_RV_HDIST_VERSION;
        else if(l == lenof("hashFSVersion") && !strncmp("hashFSVersion", (const char *)s, lenof("hashFSVersion")))
            c->state = CB_RV_HASHFS_VERSION;
        else if(l == lenof("libsxclientVersion") && !strncmp("libsxclientVersion", (const char *)s, lenof("libsxclientVersion")))
            c->state = CB_RV_LIB_VERSION;
        else
            return 0;
    } else
        return 0;

    return 1;
}

static int cb_request_vote_end_map(void *ctx) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;

    if(c->state == CB_RV_KEY)
        c->state = CB_RV_COMPLETE;
    else
        return 0;
    return 1;
}

static const yajl_callbacks request_vote_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_request_vote_number,
    cb_request_vote_string,
    cb_request_vote_start_map,
    cb_request_vote_map_key,
    cb_request_vote_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

void fcgi_raft_request_vote(void) {
    const sx_hashfs_version_t *local_version;
    struct cb_request_vote_ctx ctx;
    sx_raft_state_t state;
    int len;
    int success = 0;
    int state_changed = 0;
    yajl_handle yh;

    memset(&ctx, 0, sizeof(ctx));
    local_version = sx_hashfs_version(hashfs);

    yh = yajl_alloc(&request_vote_parser, NULL, &ctx);
    if(!yh)
        quit_errmsg(500, "Cannot allocate json parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
        if(yajl_parse(yh, hashbuf, len) != yajl_status_ok)
            break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || ctx.state != CB_RV_COMPLETE) {
        yajl_free(yh);
        quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
        send_authreq();
        return;
    }

    if(sx_hashfs_raft_state_begin(hashfs))
        quit_errmsg(500, "Database is locked");

    if(sx_hashfs_raft_state_get(hashfs, &state)) {
        sx_hashfs_raft_state_abort(hashfs);
        quit_errmsg(500, "Failed to obtain current raft state");
    }

    if(sx_hashfs_is_node_ignored(hashfs, &ctx.candidate_uuid)) {
        DEBUG("Node %s is ignored, but is sending RequestVote requests", ctx.candidate_uuid.string);
        goto request_vote_out;
    }

    /* Check, if candidate's term is not obsolete */
    if(ctx.term < state.current_term.term) {
        DEBUG("Current term (%lld) is greater than candidate's (%lld): rejecting",
                (long long)state.current_term.term, (long long)ctx.term);
        goto request_vote_out;
    }
    if(ctx.hdist_version < sx_hashfs_hdist_getversion(hashfs)) {
        DEBUG("Current hdist version (%lld) is newer than candidate's (%lld): rejecting",
                (long long)sx_hashfs_hdist_getversion(hashfs), (long long)ctx.hdist_version);
        goto request_vote_out;
    }
    if(sx_hashfs_version_cmp(&ctx.remote_version, local_version) < 0) {
        DEBUG("Local hashfs version (%s) is newer than candidate's (%s): rejecting",
	      local_version->string, ctx.remote_version.string);
        goto request_vote_out;
    }


    /* Check if current term is not obsolete */
    if(state.current_term.term < ctx.term || sx_hashfs_hdist_getversion(hashfs) < ctx.hdist_version || sx_hashfs_version_cmp(&ctx.remote_version, local_version) > 0) {
        DEBUG("Becoming a follower, current term: (%lld), term for %s: (%lld)", (long long)state.current_term.term,
                ctx.candidate_uuid.string, (long long)ctx.term);
        state.role = RAFT_ROLE_FOLLOWER;
        state.voted = 0;
        state.current_term.term = ctx.term;
        state_changed = 1;
    }

    /* Check, if this cluster has not voted already */
    if(state.voted && strcmp(state.voted_for.string, ctx.candidate_uuid.string)) {
        DEBUG("This node has already voted for %s", ctx.candidate_uuid.string);
        goto request_vote_out;
    }

    /* Grant vote */
    memcpy(&state.voted_for, &ctx.candidate_uuid, sizeof(state.voted_for));
    state.voted = 1;
    DEBUG("Granted vote for %s", ctx.candidate_uuid.string);

    success = 1;
    state_changed = 1;
request_vote_out:
    /* Save new state when necessary */
    if(state_changed) {
        if(sx_hashfs_raft_state_set(hashfs, &state)) {
            WARN("Failed to update raft state");
            sx_hashfs_raft_state_abort(hashfs);
            sx_hashfs_raft_state_empty(hashfs, &state);
            quit_errmsg(500, "Failed to update raft state");
        }

        if(sx_hashfs_raft_state_end(hashfs)) {
            WARN("Failed to update raft state");
            sx_hashfs_raft_state_empty(hashfs, &state);
            quit_errmsg(500, "Failed to update raft state");
        }
    } else
        sx_hashfs_raft_state_abort(hashfs);

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"success\":%s,\"term\":", success ? "true" : "false");
    CGI_PUTLL(state.current_term.term);
    CGI_PRINTF(",\"distributionVersion\":");
    CGI_PUTLL(sx_hashfs_hdist_getversion(hashfs));
    CGI_PRINTF(",\"hashFSVersion\":\"%s\",\"libsxclientVersion\":\"%s\"}", local_version->string, sxc_get_version());
    sx_hashfs_raft_state_empty(hashfs, &state);
}

struct raft_log_entry {
    int64_t index;
    uint8_t data[MAX_RAFT_LOG_ENTRY_LEN];
    unsigned int data_len;
};

/*
 * Sample body:
 *
 * {
 *      "term":123,
 *      "distributionVersion":3,
 *      "leaderID":"6f24df87-d9e1-47e4-a8fa-e39a8244e90c",
 *      "prevLogIndex":23445,
 *      "prevLogTerm":123,
 *      "leaderCommit":23447,
 *      "hashFSVersion":"SX-Storage 1.9",
 *      "libsxclientVersion":"1.2",
 *      "entries":[
 *              {"index":23446,"entry":"abababababababababab"},
 *              {"index":23447,"entry":"acacacacacacacacacacacac"},
 *              {"index":23446,"entry":"ffffffff"}
 *      ]
 * }
 *
 */

struct cb_append_entries_ctx {
    enum cb_append_entries_state { CB_AE_START, CB_AE_KEY, CB_AE_TERM, CB_AE_HDIST_VERSION, CB_AE_HASHFS_VERSION, CB_AE_LIB_VERSION, CB_AE_LEADER_UUID, CB_AE_PREV_LOG_INDEX, CB_AE_PREV_LOG_TERM, CB_AE_LEADER_COMMIT, CB_AE_ENTRIES_ARRAY, CB_AE_ENTRIES, CB_AE_ENTRIES_KEY, CB_AE_ENTRIES_INDEX, CB_AE_ENTRIES_ENTRY, CB_AE_COMPLETE } state;
    int64_t term;
    int64_t prev_log_index;
    int64_t prev_log_term;
    sx_uuid_t leader_uuid;
    int64_t leader_commit;
    int64_t hdist_version;
    sx_hashfs_version_t remote_version;
    char libsxclient_version[128];
    unsigned int nentries;
    struct raft_log_entry entries[MAX_RAFT_LOG_ENTRIES];
};

static int cb_append_entries_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx*)ctx;

    if(c->state == CB_AE_LEADER_UUID) {
        char uuid_str[UUID_STRING_SIZE+1];

        if(l != UUID_STRING_SIZE)
            return 0;
        memcpy(uuid_str, s, UUID_STRING_SIZE);
        uuid_str[UUID_STRING_SIZE] = '\0';
        if(uuid_from_string(&c->leader_uuid, uuid_str))
            return 0;
        c->state = CB_AE_KEY;
        return 1;
    } else if(c->state == CB_AE_ENTRIES_ENTRY) {
        if(l > MAX_RAFT_LOG_ENTRY_LEN / 2) {
            INFO("Too long log entry");
            return 0;
        }

        if(sxi_hex2bin((const char*)s, l, c->entries[c->nentries].data, MAX_RAFT_LOG_ENTRY_LEN)) {
            INFO("Failed to parse log entry");
            return 0;
        }
        c->state = CB_AE_ENTRIES_KEY;
        return 1;
    } else if(c->state == CB_AE_HASHFS_VERSION) {
	char ver[sizeof(c->remote_version.full)];
        if(l >= sizeof(ver))
            return 0;
        memcpy(ver, s, l);
        ver[l] = '\0';
	if(sx_hashfs_version_parse(ver, &c->remote_version))
	    return 0;
        c->state = CB_AE_KEY;
        return 1;
    } else if(c->state == CB_AE_LIB_VERSION) {
        if(l >= sizeof(c->libsxclient_version))
            return 0;
        memcpy(c->libsxclient_version, s, l);
        c->libsxclient_version[l] = '\0';
        c->state = CB_AE_KEY;
        return 1;
    }

    return 0;
}

static int cb_append_entries_number(void *ctx, const char *s, size_t l) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx *)ctx;
    char number[24], *eon;
    int64_t n;

    if(c->state != CB_AE_TERM && c->state != CB_AE_HDIST_VERSION && c->state != CB_AE_PREV_LOG_INDEX &&
        c->state != CB_AE_PREV_LOG_TERM && c->state != CB_AE_LEADER_COMMIT)
        return 0;

    if(l<1 || l>20)
        return 0;
    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &eon, 10);
    if(*eon || n < -1)
        return 0;

    if(c->state == CB_AE_TERM) {
        c->term = n;
        c->state = CB_AE_KEY;
    } else if(c->state == CB_AE_HDIST_VERSION) {
        c->hdist_version = n;
        c->state = CB_AE_KEY;
    } else if(c->state == CB_AE_PREV_LOG_INDEX) {
        c->prev_log_index = n;
        c->state = CB_AE_KEY;
    } else if(c->state == CB_AE_PREV_LOG_TERM) {
        c->prev_log_term = n;
        c->state = CB_AE_KEY;
    } else if(c->state == CB_AE_LEADER_COMMIT) {
        c->leader_commit = n;
        c->state = CB_AE_KEY;
    } else if(c->state == CB_AE_ENTRIES_INDEX) {
        c->entries[c->nentries].index = n;
        c->state = CB_AE_ENTRIES_KEY;
    } else
        return 0;
    return 1;
}

static int cb_append_entries_start_map(void *ctx) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx*)ctx;

    if(c->state == CB_AE_START)
        c->state = CB_AE_KEY;
    else if(c->state == CB_AE_ENTRIES)
        c->state = CB_AE_ENTRIES_KEY;
    else
        return 0;

    return 1;
}

static int cb_append_entries_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx*)ctx;

    if(c->state == CB_AE_KEY) {
        if(l == lenof("term") && !strncmp("term", (const char *)s, lenof("term")))
            c->state = CB_AE_TERM;
        else if(l == lenof("leaderID") && !strncmp("leaderID", (const char *)s, lenof("leaderID")))
            c->state = CB_AE_LEADER_UUID;
        else if(l == lenof("prevLogIndex") && !strncmp("prevLogIndex", (const char *)s, lenof("prevLogIndex")))
            c->state = CB_AE_PREV_LOG_INDEX;
        else if(l == lenof("prevLogTerm") && !strncmp("prevLogTerm", (const char *)s, lenof("prevLogTerm")))
            c->state = CB_AE_PREV_LOG_TERM;
        else if(l == lenof("leaderCommit") && !strncmp("leaderCommit", (const char *)s, lenof("leaderCommit")))
            c->state = CB_AE_LEADER_COMMIT;
        else if(l == lenof("entries") && !strncmp("entries", (const char *)s, lenof("entries")))
            c->state = CB_AE_ENTRIES_ARRAY;
        else if(l == lenof("distributionVersion") && !strncmp("distributionVersion", (const char *)s, lenof("distributionVersion")))
            c->state = CB_AE_HDIST_VERSION;
        else if(l == lenof("hashFSVersion") && !strncmp("hashFSVersion", (const char *)s, lenof("hashFSVersion")))
            c->state = CB_AE_HASHFS_VERSION;
        else if(l == lenof("libsxclientVersion") && !strncmp("libsxclientVersion", (const char *)s, lenof("libsxclientVersion")))
            c->state = CB_AE_LIB_VERSION;
        else
            return 0;
    } else if(c->state == CB_AE_ENTRIES_KEY) {
        if(l == lenof("index") && !strncmp("index", (const char *)s, lenof("index")))
            c->state = CB_AE_ENTRIES_INDEX;
        else if(l == lenof("entry") && !strncmp("entry", (const char *)s, lenof("entry")))
            c->state = CB_AE_ENTRIES_ENTRY;
        else
            return 0;
    } else
        return 0;

    return 1;
}

static int cb_append_entries_end_map(void *ctx) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx*)ctx;

    if(c->state == CB_AE_KEY)
        c->state = CB_AE_COMPLETE;
    else if(c->state == CB_AE_ENTRIES_KEY) {
        c->nentries++;
        c->state = CB_AE_ENTRIES;
    } else
        return 0;
    return 1;
}

static int cb_append_entries_start_array(void *ctx) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx*)ctx;

    if(c->state == CB_AE_ENTRIES_ARRAY)
        c->state = CB_AE_ENTRIES;
    else
        return 0;
    return 1;
}

static int cb_append_entries_end_array(void *ctx) {
    struct cb_append_entries_ctx *c = (struct cb_append_entries_ctx*)ctx;

    if(c->state == CB_AE_ENTRIES)
        c->state = CB_AE_KEY;
    else
        return 0;
    return 1;
}

static const yajl_callbacks append_entries_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_append_entries_number,
    cb_append_entries_string,
    cb_append_entries_start_map,
    cb_append_entries_map_key,
    cb_append_entries_end_map,
    cb_append_entries_start_array,
    cb_append_entries_end_array
};

void fcgi_raft_append_entries(void) {
    const sx_hashfs_version_t *local_version;
    struct cb_append_entries_ctx ctx;
    sx_raft_state_t state;
    int len;
    int success = 0;
    int state_changed = 0;
    yajl_handle yh;

    memset(&ctx, 0, sizeof(ctx));
    local_version = sx_hashfs_version(hashfs);

    yh = yajl_alloc(&append_entries_parser, NULL, &ctx);
    if(!yh)
        quit_errmsg(500, "Cannot allocate json parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
        if(yajl_parse(yh, hashbuf, len) != yajl_status_ok)
            break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || ctx.state != CB_AE_COMPLETE) {
        yajl_free(yh);
        quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    if(!is_authed()) {
        send_authreq();
        return;
    }

    if(sx_hashfs_raft_state_begin(hashfs))
        quit_errmsg(500, "Database is locked");

    if(sx_hashfs_raft_state_get(hashfs, &state)) {
        sx_hashfs_raft_state_abort(hashfs);
        quit_errmsg(500, "Failed to obtain current raft state");
    }
    
    if(sx_hashfs_is_node_ignored(hashfs, &ctx.leader_uuid)) {
        DEBUG("Node %s is ignored, but is sending AppendEntries requests", ctx.leader_uuid.string);
        goto append_entries_out;
    }

    /* Check, if candidate's term is not obsolete */
    if(ctx.term < state.current_term.term) {
        DEBUG("Current term (%lld) is greater than candidate's (%lld): rejecting", (long long)state.current_term.term, (long long)ctx.term);
        goto append_entries_out;
    }
    if(ctx.hdist_version < sx_hashfs_hdist_getversion(hashfs)) {
        DEBUG("Current hdist version (%lld) is newer than candidate's (%lld): rejecting",
                (long long)sx_hashfs_hdist_getversion(hashfs), (long long)ctx.hdist_version);
        goto append_entries_out;
    }

    if(sx_hashfs_version_cmp(&ctx.remote_version, local_version) < 0) {
        DEBUG("Local hashfs version (%s) is newer than candidate's (%s): rejecting",
                local_version->string, ctx.remote_version.string);
        goto append_entries_out;
    }

    /* This node has obsolete term, become a follower */
    if(state.current_term.term < ctx.term || sx_hashfs_hdist_getversion(hashfs) < ctx.hdist_version || sx_hashfs_version_cmp(&ctx.remote_version, local_version) > 0) {
        DEBUG("Becoming a follower, current term: (%lld), term for %s: (%lld)", (long long)state.current_term.term, ctx.leader_uuid.string, (long long)ctx.term);
        state.role = RAFT_ROLE_FOLLOWER;
        state.current_term.term = ctx.term;
        state.voted = 0;
    }

    if(state.role == RAFT_ROLE_CANDIDATE) {
        /* I am a candidate, but received a ping from another leader, terms are the same. 
         * This means that I lost voting! */
        DEBUG("Another node (%s) won the voting, becoming a follower", ctx.leader_uuid.string);
        state.role = RAFT_ROLE_FOLLOWER;
        state.current_term.term = ctx.term;
        state.voted = 0;
    }

    if(state.role == RAFT_ROLE_LEADER) {
        /* I am the leader, but received a ping from another viable leader (which could establish itself via voting),
         * terms are the same. Become a follower and respect remote node as the legitimate leader. */
        DEBUG("Another node (%s) is a viable leader, becoming a follower", ctx.leader_uuid.string);
        state.role = RAFT_ROLE_FOLLOWER;
        state.current_term.term = ctx.term;
        state.voted = 0;
    }

    gettimeofday(&state.last_contact, NULL);
    memcpy(&state.current_term.leader, &ctx.leader_uuid, sizeof(state.current_term.leader));
    state.current_term.has_leader = 1;

    success = 1;
    state_changed = 1;
append_entries_out:
    /* Save new state when necessary */
    if(state_changed) {
        if(sx_hashfs_raft_state_set(hashfs, &state)) {
            WARN("Failed to update raft state");
            sx_hashfs_raft_state_abort(hashfs);
            sx_hashfs_raft_state_empty(hashfs, &state);
            quit_errmsg(500, "Failed to update raft state");
        }

        if(sx_hashfs_raft_state_end(hashfs)) {
            WARN("Failed to update raft state");
            sx_hashfs_raft_state_empty(hashfs, &state);
            quit_errmsg(500, "Failed to update raft state");
        }
    } else
        sx_hashfs_raft_state_abort(hashfs);

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"success\":%s,\"term\":", success ? "true" : "false");
    CGI_PUTLL(state.current_term.term);
    CGI_PRINTF(",\"distributionVersion\":");
    CGI_PUTLL(sx_hashfs_hdist_getversion(hashfs));
    CGI_PRINTF(",\"hashFSVersion\":\"%s\",\"libsxclientVersion\":\"%s\"}", local_version->string, sxc_get_version());
    sx_hashfs_raft_state_empty(hashfs, &state);
}
