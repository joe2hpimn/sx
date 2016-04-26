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
#include "fcgi-utils.h"
#include "utils.h"
#include "fcgi-actions-node.h"

#include "libsxclient/src/jparse.h"

/* {"nodeList":[{"nodeUUID":"%s","nodeAddress":"%s","nodeInternalAddress":"%s","nodeCapacity":%llu}], "distZones":"Zone1:..."} */
struct cb_nodes_ctx {
    sx_uuid_t id;
    char *addr;
    char *intaddr;
    char *zones;
    int64_t capacity;
    int have_uuid, oom;
    sx_nodelist_t *nodes;
};

static void cb_setnodes_uuid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;
    char uuid[sizeof(c->id.string)];

    if(c->have_uuid) {
	sxi_jparse_cancel(J, "Multiple UUIDs received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }

    if(length != sizeof(uuid) - 1) {
	sxi_jparse_cancel(J, "Invalid UUID received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    memcpy(uuid, string, length);
    uuid[length] = '\0';

    if(uuid_from_string(&c->id, uuid)) {
	sxi_jparse_cancel(J, "Invalid UUID received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    c->have_uuid = 1;
}

static void cb_setnodes_addr(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;

    if(c->addr) {
	sxi_jparse_cancel(J, "Multiple addresses received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    if(!length) {
	sxi_jparse_cancel(J, "Invalid addres received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }

    c->addr = wrap_malloc(length+1);
    if(!c->addr) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
	return;
    }
    memcpy(c->addr, string, length);
    c->addr[length] = '\0';
}

static void cb_setnodes_intaddr(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;

    if(c->intaddr) {
	sxi_jparse_cancel(J, "Multiple internal addresses received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    if(!length) {
	sxi_jparse_cancel(J, "Invalid internal addres received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }

    c->intaddr = wrap_malloc(length+1);
    if(!c->intaddr) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
	return;
    }
    memcpy(c->intaddr, string, length);
    c->intaddr[length] = '\0';
}

static void cb_setnodes_capa(jparse_t *J, void *ctx, int64_t capacity) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;

    if(c->capacity >0) {
	sxi_jparse_cancel(J, "Multiple capacities received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    if(capacity <= 0) {
	sxi_jparse_cancel(J, "Invalid capacity received for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }

    c->capacity = capacity;
}


static void cb_setnodes_endnode(jparse_t *J, void *ctx) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;

    if(!c->have_uuid || !c->addr || c->capacity < 0) {
	sxi_jparse_cancel(J, "One or more required fields are missing for node entry %d",
			  sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }

    sx_node_t *node = sx_node_new(&c->id, c->addr, c->intaddr, c->capacity);
    if(sx_nodelist_add(c->nodes, node)) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
	return;
    }
    free(c->addr);
    c->addr = NULL;
    free(c->intaddr);
    c->intaddr = NULL;
    c->capacity = -1;
    c->have_uuid = 0;
}

static void cb_setnodes_zones(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodes_ctx *c = (struct cb_nodes_ctx *)ctx;

    if(c->zones) {
	sxi_jparse_cancel(J, "Multiple zone definitions received");
	return;
    }
    c->zones = wrap_malloc(length+1);
    if(!c->zones) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory processing zone definition");
	return;
    }
    memcpy(c->zones, string, length);
    c->zones[length] = '\0';
}

void fcgi_set_nodes(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_setnodes_uuid, JPKEY("nodeList"), JPANYITM, JPKEY("nodeUUID")),
		      JPACT(cb_setnodes_addr, JPKEY("nodeList"), JPANYITM, JPKEY("nodeAddress")),
		      JPACT(cb_setnodes_intaddr, JPKEY("nodeList"), JPANYITM, JPKEY("nodeInternalAddress")),
		      JPACT(cb_setnodes_zones, JPKEY("distZones"))
		      ),
	JPACTS_INT64(
		     JPACT(cb_setnodes_capa, JPKEY("nodeList"), JPANYITM, JPKEY("nodeCapacity"))
		     ),
	JPACTS_MAP_END(
		     JPACT(cb_setnodes_endnode, JPKEY("nodeList"), JPANYITM)
		     )
    };
    sx_uuid_t selfid;
    jparse_t *J;
    job_t job;
    int len;
    rc_ty s;

    if(sx_hashfs_self_uuid(hashfs, &selfid))
	quit_errmsg(500, "Cluster not yet initialized");

    struct cb_nodes_ctx yctx;
    yctx.addr = NULL;
    yctx.intaddr = NULL;
    yctx.capacity = -1;
    yctx.have_uuid = 0;
    yctx.zones = NULL;
    yctx.nodes = sx_nodelist_new();
    if(!yctx.nodes)
	quit_errmsg(500, "Cannot allocate nodelist");

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J) {
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(yctx.oom ? 503 : 400, sxi_jparse_geterr(J));
	free(yctx.addr);
	free(yctx.intaddr);
	free(yctx.zones);
	sx_nodelist_delete(yctx.nodes);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

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
    sx_nodelist_t *nodes;
    int oom;
};

static void cb_markfaulty(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_ign_ctx *c = (struct cb_ign_ctx *)ctx;
    sx_node_t *node;
    sx_uuid_t uuid;
    char ustr[sizeof(uuid.string)];

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid UUID '%.*s'", length, string);
	return;
    }

    memcpy(ustr, string, length);
    ustr[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&uuid, ustr)) {
	sxi_jparse_cancel(J, "Invalid UUID '%s'", ustr);
	return;
    }

    node = sx_node_new(&uuid, "127.0.0.1", "127.0.0.1", 1);
    if(!node || sx_nodelist_add(c->nodes, node)) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory processing request");
	return;
    }
}

void fcgi_mark_faultynodes(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_markfaulty, JPKEY("faultyNodes"), JPANYITM))
    };
    struct cb_ign_ctx yctx;
    jparse_t *J;
    int len;
    rc_ty s;

    yctx.oom = 0;
    yctx.nodes = sx_nodelist_new();
    if(!yctx.nodes)
	quit_errmsg(503, "Cannot allocate nodelist");

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J) {
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(yctx.oom ? 503 : 400, sxi_jparse_geterr(J));
	sx_nodelist_delete(yctx.nodes);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    quit_unless_authed();

    if(!sx_nodelist_count(yctx.nodes))
	quit_errmsg(400, "Invalid request content");

    if(sx_hashfs_is_changing_volume_replica(hashfs) == 1)
        quit_errmsg(400, "The cluster is already performing volume replica changes");

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

/* {"lockID":"LOCKID", "op":"lock|unlock"} */

struct distlock_ctx {
    char lockid[AUTH_UID_LEN*2+32]; /* Handle user hash and time string */
    enum distloc_t { DL_UNSET, DL_LOCK, DL_UNLOCK } op;
};

static void cb_distlock_id(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct distlock_ctx *dctx = ctx;
    if(length >= sizeof(dctx->lockid)) {
	sxi_jparse_cancel(J, "Invalid lock ID");
	return;
    }
    memcpy(dctx->lockid, string, length);
    dctx->lockid[length] = '\0';
}

static void cb_distlock_op(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct distlock_ctx *dctx = ctx;

    if(!strncmp(string, "lock", length))
	dctx->op = DL_LOCK;
    else if(!strncmp(string, "unlock", length))
	dctx->op = DL_UNLOCK;
    else {
	sxi_jparse_cancel(J, "Invalid lock operation requested");
	return;
    }
}

void fcgi_distlock(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_distlock_id, JPKEY("lockID")),
		      JPACT(cb_distlock_op, JPKEY("op"))
		      )
    };
    struct distlock_ctx dctx;
    jparse_t *J;
    int len;
    rc_ty s;

    dctx.lockid[0] = '\0';
    dctx.op = DL_UNSET;

    J = sxi_jparse_create(&acts, &dctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(400, sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    if(!is_authed()) {
        send_authreq();
        return;
    }

    if(dctx.op == DL_UNSET)
	quit_errmsg(400, "Missing operation type");

    /* If cluster is changing hdist already, then lock shouldn't be acquired */
    if(dctx.op == DL_LOCK) {
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
    if(dctx.op == DL_LOCK) { /* Lock operation */
        s = sx_hashfs_distlock_acquire(hashfs, dctx.lockid);
        if(s == EEXIST)
            quit_errmsg(rc2http(s), "Cluster is already locked");
        else if(s != OK) {
            WARN("Failed to acquire lock %s", dctx.lockid);
            quit_errmsg(rc2http(s), rc2str(s));
        }
	INFO("Distlock successfully applied to this node");
    } else { /* Unlock operation */
        s = sx_hashfs_distlock_release(hashfs);
        if(s != OK) {
            WARN("Failed to release lock %s", dctx.lockid);
            quit_errmsg(rc2http(s), rc2str(s));
        }
	INFO("Distlock successfully removed from this node");
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
 
        if(sx_blob_add_string(joblb, dctx.lockid) || sx_blob_add_int32(joblb, dctx.op == DL_LOCK ? 1 : 0)) {
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
    void *cfg;
    sx_hashfs_version_t rver;
    sx_nodelist_t *faulty;
    unsigned int cfg_len, oom, have_rver;
};

static void cb_newdist_dist(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;
    unsigned int binlen = length / 2;

    if(c->cfg) {
	sxi_jparse_cancel(J, "Multiple configurations received");
	return;
    }
    if(length&1) {
	sxi_jparse_cancel(J, "Invalid configuration");
	return;
    }

    c->cfg_len = binlen;
    c->cfg = wrap_malloc(binlen);
    if(!c->cfg) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory allocating configuration buffer");
	return;
    }

    if(hex2bin(string, length, c->cfg, binlen)) {
	sxi_jparse_cancel(J, "Invalid configuration");
	return;
    }
}

static void cb_newdist_swver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;

    if(sx_hashfs_version_parse(&c->rver, string, length)) {
	sxi_jparse_cancel(J, "Invalid software version");
	return;
    }
    c->have_rver = 1;
}

static void cb_newdist_faulty(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_updist_ctx *c = (struct cb_updist_ctx *)ctx;
    char uuidstr[UUID_STRING_SIZE+1];
    sx_uuid_t uuid;

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid node UUID '%.*s'", length, string);
	return;
    }

    memcpy(uuidstr, string, UUID_STRING_SIZE);
    uuidstr[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&uuid, uuidstr)) {
	sxi_jparse_cancel(J, "Invalid node UUID '%s'", uuidstr);
	return;
    }

    if(sx_nodelist_add(c->faulty, sx_node_new(&uuid, "127.0.0.1", NULL, 1))) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory building faulty node list");
	return;
    }
}

void fcgi_new_distribution(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_newdist_dist, JPKEY("newDistribution")),
		      JPACT(cb_newdist_faulty, JPKEY("faultyNodes"), JPANYITM),
		      JPACT(cb_newdist_swver, JPKEY("softwareVersion"))
		      )
    };
    struct cb_updist_ctx yctx;
    sx_hashfs_version_t *lver;
    jparse_t *J;
    rc_ty s;
    int len, v;

    yctx.cfg = NULL;
    yctx.have_rver = 0;
    yctx.oom = 0;
    yctx.faulty = sx_nodelist_new();
    if(!yctx.faulty)
	quit_errmsg(503, "Cannot allocate replacement node list");

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J) {
	sx_nodelist_delete(yctx.faulty);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(yctx.oom ? 503 : 400, sxi_jparse_geterr(J));
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    if(!is_authed()) {
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	send_authreq();
	return;
    }

    if(!yctx.cfg) {
	sx_nodelist_delete(yctx.faulty);
	quit_errmsg(400, "No distribution provided");
    }

    if(!yctx.have_rver) {
	sx_nodelist_delete(yctx.faulty);
	free(yctx.cfg);
	quit_errmsg(400, "No software version provided");
    }

    lver = sx_hashfs_version(hashfs);
    v = sx_hashfs_version_cmp(lver, &yctx.rver);
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
    rc_ty s = sx_hashfs_hdist_change_commit(hashfs, has_arg("replaceNodes"));
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
    unsigned int have_uuid;
    int ssl, oom;
    char *name, *ca;
    sx_uuid_t uuid;
    uint16_t port;
};

static void cb_nodeinit_name(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(!length) {
	sxi_jparse_cancel(J, "Invalid cluster name");
	return;
    }
    if(c->name) {
	sxi_jparse_cancel(J, "Cluster names indicated more than once");
	return;
    }
    c->name = wrap_malloc(length+1);
    if(!c->name) {
	c->oom = 1;
	sxi_jparse_cancel(J, "Out of memory processing cluster name");
	return;
    }
    memcpy(c->name, string, length);
    c->name[length] = '\0';
}

static void cb_nodeinit_uuid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;
    char uuidstr[UUID_STRING_SIZE+1];

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid node UUID");
	return;
    }
    if(c->have_uuid) {
	sxi_jparse_cancel(J, "Node UUID indicated more than once");
	return;
    }

    memcpy(uuidstr, string, UUID_STRING_SIZE);
    uuidstr[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&c->uuid, uuidstr)) {
	sxi_jparse_cancel(J, "Invalid node UUID");
	return;
    }
    c->have_uuid = 1;
}

static void cb_nodeinit_cert(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(c->ca) {
	sxi_jparse_cancel(J, "CA certificate indicated more than once");
	return;
    }
    if(length) {
	c->ca = wrap_malloc(length+1);
	if(!c->ca) {
	    c->oom = 1;
	    sxi_jparse_cancel(J, "Out of memory processing CA certificate");
	    return;
	}
	memcpy(c->ca, string, length);
	c->ca[length] = '\0';
    }
}

static void cb_nodeinit_port(jparse_t *J, void *ctx, int32_t port) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    if(port <= 0 || port > 0xffff) {
	sxi_jparse_cancel(J, "Invalid HTTP port");
	return;
    }

    c->port = port;
}

static void cb_nodeinit_ssl(jparse_t *J, void *ctx, int secure) {
    struct cb_nodeinit_ctx *c = (struct cb_nodeinit_ctx *)ctx;

    c->ssl = secure;
}

void fcgi_node_init(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_nodeinit_name, JPKEY("clusterName")),
		      JPACT(cb_nodeinit_uuid, JPKEY("nodeUUID")),
		      JPACT(cb_nodeinit_cert, JPKEY("caCertData"))
		      ),
	JPACTS_INT32(
		     JPACT(cb_nodeinit_port, JPKEY("httpPort"))
		     ),
	JPACTS_BOOL(
		    JPACT(cb_nodeinit_ssl, JPKEY("secureProtocol"))
		    )
    };
    struct cb_nodeinit_ctx yctx;
    jparse_t *J;
    int len;

    if(!sx_storage_is_bare(hashfs))
	quit_errmsg(400, "Node already initialized");

    memset(&yctx, 0, sizeof(yctx));
    yctx.ssl = -1;

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(yctx.oom ? 503 : 400, sxi_jparse_geterr(J));
	free(yctx.name);
	free(yctx.ca);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    if(!yctx.name || !yctx.have_uuid || yctx.ssl < 0) {
	free(yctx.name);
	free(yctx.ca);
	quit_errmsg(400, "Invalid request content (required element missing)");
    }

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
            "admin":{"key":"xxxxx","admin":true,"user":"hex_uid"}
            "luser":{"key":"yyyyy","admin":false,"quota":12345,"desc":"luser description","user":"hex_uid","userMeta":{"key1":"112233","key2":"445566aa"}}
        }
    }

    {
        "volumes":{
	    "volume1":{"owner":"xxxx","replica":1,"revs":1,"size":1234,"meta":{"key":"val","key2":"val2"},"global_id":"aabb...ccdd"},
	    "volume2":{"owner":"yyyy","replica":2,"size":5678,"global_id":"1122...4567"},
        }
    }

    {
        "perms":{
            "volume1_global_id":{"xxxx":val,"yyyy":val}
        }
    }

    {
        "misc":{
            "mode":"ro",
            "clusterMeta":[timestamp, {"key1":"val1","key2":"val2"}],
            "clusterSettings":[timestamp, {"key1":"val1","key2":"val2"}],
        }
    }
*/

struct cb_sync_ctx {
    int64_t size;
    int64_t quota; /* Quota for volumes owned by the user */
    time_t timestamp;
    char desc[SXLIMIT_META_MAX_VALUE_LEN+1];
    uint8_t key[AUTH_KEY_LEN];
    uint8_t user[AUTH_UID_LEN];
    sx_uid_t uid;
    int admin, have_key, have_user;
    unsigned int replica, revs;
    unsigned int nsettings;
    unsigned int nmeta;
    sx_blob_t *settings;
    sx_hash_t global_vol_id;
    int has_global_vol_id;
};

/* USER callbacks */
static void cb_syncusr_key(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(length != AUTH_KEY_LEN * 2 || hex2bin(string, AUTH_KEY_LEN * 2, c->key, sizeof(c->key))) {
	sxi_jparse_cancel(J, "Invalid key for user %s",
		      sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    c->have_key = 1;
}

static void cb_syncusr_desc(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(length >= sizeof(c->desc)) {
	sxi_jparse_cancel(J, "Invalid description for user %s",
		      sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    memcpy(c->desc, string, length);
    c->desc[length] = '\0';
}

static void cb_syncusr_userid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(length != AUTH_UID_LEN * 2 || hex2bin(string, AUTH_UID_LEN * 2, c->user, sizeof(c->user))) {
	sxi_jparse_cancel(J, "Invalid userid for user %s",
		      sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    c->have_user = 1;
}

static void cb_syncusr_quota(jparse_t *J, void *ctx, int64_t num) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    c->quota = num;
}

static void cb_syncusr_role(jparse_t *J, void *ctx, int isadmin) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    c->admin = isadmin;
}

static void cb_syncusr_init(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    /* Required fields */
    c->admin = -1;
    c->have_user = 0;
    c->have_key = 0;

    /* Default fields */
    c->desc[0] = '\0';
    c->quota = 0;
    c->nmeta = 0;
}

static void cb_syncusr_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *metakey = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
    uint8_t metavalue[SXLIMIT_META_MAX_VALUE_LEN];
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(c->nmeta >= SXLIMIT_META_MAX_ITEMS) {
        sxi_jparse_cancel(J, "Too many user metadata entries (max: %u)", SXLIMIT_META_MAX_ITEMS);
        return;
    }

    if(hex2bin(string, length, metavalue, sizeof(metavalue))) {
        sxi_jparse_cancel(J, "Invalid user metadata value for key '%s'", metakey);
        return;
    }

    length /= 2;
    if(sx_hashfs_check_user_meta(metakey, metavalue, length, 0)) {
        const char *reason = msg_get_reason();
        sxi_jparse_cancel(J, "'%s'", reason ? reason : "Invalid user metadata");
        return;
    }

    if(!c->nmeta)
        sx_hashfs_create_user_begin(hashfs);

    if(sx_hashfs_create_user_addmeta(hashfs, metakey, metavalue, length)) {
        sxi_jparse_cancel(J, "Out of memory processing user creation request");
        return;
    }
    c->nmeta++;
}

static void cb_syncusr_create(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    const char *name = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    rc_ty s;

    if(!name) {
	/* Not reached */
	sxi_jparse_cancel(J, "Internal error (no username)");
	return;
    }

    if(!*name || !c->have_key || c->admin < 0 || !c->have_user) {
	sxi_jparse_cancel(J, "User '%s' lacks one or more required fields", name);
	return;
    }

    s = sx_hashfs_create_user_finish(hashfs, name, c->user, sizeof(c->user), c->key, sizeof(c->key), c->admin != 0, c->desc, c->quota, 0);
    if(s != OK && s != EEXIST) {
	sxi_jparse_cancel(J, "Failed to create user '%s': %s", name, msg_get_reason());
	return;
    }
    if(sx_hashfs_user_onoff(hashfs, name, 1, 0)) {
	sxi_jparse_cancel(J, "Failed to enable user '%s': %s", name, msg_get_reason());
	return;
    }
}

/* VOLUME callbacks */
static void cb_syncvol_global_id(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(length != sizeof(c->global_vol_id.b) * 2 || hex2bin(string, sizeof(c->global_vol_id.b) * 2, c->global_vol_id.b, sizeof(c->global_vol_id.b))) {
        sxi_jparse_cancel(J, "Invalid global ID for volume %s",
                          sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
        return;
    }
    c->has_global_vol_id = 1;
}

static void cb_syncvol_owner(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    uint8_t usr[AUTH_UID_LEN];

    if(length != AUTH_UID_LEN * 2 || hex2bin(string, AUTH_UID_LEN * 2, usr, sizeof(usr))) {
	sxi_jparse_cancel(J, "Invalid owner for volume %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    if(sx_hashfs_get_user_info(hashfs, usr, &c->uid, NULL, NULL, NULL, NULL)) {
	sxi_jparse_cancel(J, "Owner lookup failed for volume %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
}

static void cb_syncvol_size(jparse_t *J, void *ctx, int64_t num) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid size for volume %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    c->size = num;
}

static void cb_syncvol_replica(jparse_t *J, void *ctx, int32_t num) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid replica count for volume %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    c->replica = (unsigned int)num;
}

static void cb_syncvol_revs(jparse_t *J, void *ctx, int32_t num) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid number of revisions for volume %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))));
	return;
    }
    c->revs = (unsigned int)num;
}

static void cb_syncvol_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
    uint8_t val[SXLIMIT_META_MAX_VALUE_LEN];

    if(hex2bin(string, length, val, sizeof(val))) {
	sxi_jparse_cancel(J, "Invalid meta value on volume %s (key %s)",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))),
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
	return;
    }
    if(sx_hashfs_volume_new_addmeta(hashfs, key, val, length/2)) {
	sxi_jparse_cancel(J, "Invalid meta value on volume %s (key %s): %s",
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))),
			  sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))),
			  msg_get_reason());
	return;
    }
}

static void cb_syncvol_init(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    sx_hashfs_volume_new_begin(hashfs);
    /* Required fields */
    c->uid = -1;
    c->size = -1;
    c->replica = 0;
    c->has_global_vol_id = 0;
    /* Optional fields */
    c->revs = 0;
}

static void cb_syncvol_create(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    const char *name = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    rc_ty s;

    if(!name) {
	/* Not reached */
	sxi_jparse_cancel(J, "Internal error (no volume name)");
	return;
    }

    if(!*name || c->uid < 0 || c->size <= 0 || !c->replica || !c->has_global_vol_id) {
	sxi_jparse_cancel(J, "Volume '%s' lacks one or more required fields", name);
	return;
    }
    if(!c->revs)
	c->revs = 1;
    s = sx_hashfs_volume_new_finish(hashfs, name, &c->global_vol_id, c->size, c->replica, c->revs, c->uid, 0);
    if(s != OK && s != EEXIST) {
	sxi_jparse_cancel(J, "Failed to create volume '%s': %s", name, msg_get_reason());
	return;
    }
    if(sx_hashfs_volume_enable(hashfs, &c->global_vol_id)) {
	sxi_jparse_cancel(J, "Failed to enable volume '%s': %s", name, msg_get_reason());
	return;
    }
}

/* PERMS callbacks */
static void cb_syncperms(jparse_t *J, void *ctx, int32_t perm) {
    const char *global_vol_id_hex = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    const char *userhex = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
    uint8_t usrid[AUTH_UID_LEN];
    sx_uid_t uid;
    sx_hash_t global_vol_id;

    if(!global_vol_id_hex || strlen(global_vol_id_hex) != SXI_SHA1_TEXT_LEN || !userhex ||
       hex2bin(global_vol_id_hex, SXI_SHA1_TEXT_LEN, global_vol_id.b, sizeof(global_vol_id.b))) {
	/* Not reached */
	sxi_jparse_cancel(J, "Internal error (NULL privilege)");
	return;
    }
    if((perm & ~ALL_USER_PRIVS)) {
	sxi_jparse_cancel(J, "Invalid privilege value %d for userid(hex) '%s' on volume ID '%s'", perm, userhex, global_vol_id_hex);
	return;
    }
    if(strlen(userhex) != AUTH_UID_LEN * 2 ||
       hex2bin(userhex, AUTH_UID_LEN * 2, usrid, sizeof(usrid))) {
	sxi_jparse_cancel(J, "Privilege with invalid userid(hex) '%s' on volume ID '%s'", userhex, global_vol_id_hex);
	return;
    }
    if(sx_hashfs_get_user_info(hashfs, usrid, &uid, NULL, NULL, NULL, NULL)) {
	sxi_jparse_cancel(J, "Lookup failed for userid(hex) '%s': %s", userhex, msg_get_reason());
	return;
    }
    sx_hashfs_revoke(hashfs, uid, &global_vol_id, ALL_USER_PRIVS);
    if(sx_hashfs_grant(hashfs, uid, &global_vol_id, perm)) {
	sxi_jparse_cancel(J, "Failed to grant %d to userid(hex) '%s' on volume  ID '%s': %s", perm, userhex, global_vol_id_hex, msg_get_reason());
	return;
    }
}


/* MISC callbacks */

static void cb_syncmisc_mode(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    if(length != 2 || (memcmp(string, "ro", 2) && memcmp(string, "rw", 2))) {
	sxi_jparse_cancel(J, "Invalid cluster mode '%.*s' requested", length, string);
	return;
    }
    if(sx_hashfs_cluster_set_mode(hashfs, !memcmp(string, "ro", 2))) {
	sxi_jparse_cancel(J, "Failed to set cluster mode to %.*s: %s", length, string, msg_get_reason());
	return;
    }
}


static void cb_syncmisc_cmetainit(jparse_t *J, void *ctx) {
    sx_hashfs_clustermeta_set_begin(hashfs);
}

static void cb_syncmisc_timestamp(jparse_t *J, void *ctx, int64_t num) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid timestamp %lld", (long long)num);
	return;
    }
    c->timestamp = num;
}

static void cb_syncmisc_cmeta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
    uint8_t val[SXLIMIT_META_MAX_VALUE_LEN];

    if(hex2bin(string, length, val, sizeof(val))) {
	sxi_jparse_cancel(J, "Invalid cluster meta value (key %s)", key);
	return;
    }
    if(sx_hashfs_clustermeta_set_addmeta(hashfs, key, val, length/2)) {
	sxi_jparse_cancel(J, "Invalid cluster meta value (key %s): %s", key, msg_get_reason());
	return;
    }
}

static void cb_syncmisc_cmetadone(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    if(sx_hashfs_clustermeta_set_finish(hashfs, c->timestamp, 0)) {
	sxi_jparse_cancel(J, "Failed to set cluster metadata: %s", msg_get_reason());
	return;
    }
}

static void cb_syncmisc_csetsinit(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    c->nsettings = 0;
    sx_blob_reset(c->settings);
}

static void cb_syncmisc_csets(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))))), *old_value;
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    uint8_t val[SXLIMIT_SETTINGS_MAX_VALUE_LEN+1];
    sx_setting_type_t setting_type;

    if(sx_hashfs_cluster_settings_get(hashfs, key, &setting_type, &old_value)) {
	sxi_jparse_cancel(J, "Failed to get previous setting value for '%s': %s", key, msg_get_reason());
	return;
    }

    /* FIXME: this should carry blobs not freeform strings!  */
    if(hex2bin(string, length, val, sizeof(val))) {
	sxi_jparse_cancel(J, "Invalid cluster setting value for '%s'", key);
	return;
    }
    val[length/2] = '\0';
    if(sx_blob_add_string(c->settings, key) || sx_blob_add_int32(c->settings, setting_type)) {
	sxi_jparse_cancel(J, "Out of memory storing cluster settings");
	return;
    }
    if(sx_hashfs_parse_cluster_setting(hashfs, key, setting_type, val, c->settings)) {
	sxi_jparse_cancel(J, "Failed to store cluster setting %s", key);
	return;
    }
    c->nsettings++;
}


static void cb_syncmisc_csetsdone(jparse_t *J, void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;
    unsigned int i;

    sx_blob_reset(c->settings);
    for(i = 0; i < c->nsettings; i++) {
	sx_setting_type_t type;
	const char *key = NULL;
	if(sx_blob_get_string(c->settings, &key) || sx_blob_get_int32(c->settings, (int32_t *)(&type))) {
	    sxi_jparse_cancel(J, "Failed to get cluster setting key and type");
	    return;
	}
	switch(type) {
	case SX_SETTING_TYPE_INT: {
	    int64_t v;
	    if(sx_blob_get_int64(c->settings, &v)) {
		sxi_jparse_cancel(J, "Failed to obtain integer value of %s", key);
		return;
	    }
	    if(sx_hashfs_cluster_settings_set_int64(hashfs, key, v)) {
		sxi_jparse_cancel(J, "Failed to modify cluster settings: %s", msg_get_reason());
		return;
	    }
	    break;
	}
	case SX_SETTING_TYPE_UINT: {
	    uint64_t v;
	    if(sx_blob_get_uint64(c->settings, &v)) {
		sxi_jparse_cancel(J, "Failed to obtain unsigned integer value of %s", key);
		return;
	    }
	    if(sx_hashfs_cluster_settings_set_uint64(hashfs, key, v)) {
		sxi_jparse_cancel(J, "Failed to modify cluster settings: %s", msg_get_reason());
		return;
	    }
	    break;
	}
	case SX_SETTING_TYPE_BOOL: {
	    int v;
	    if(sx_blob_get_bool(c->settings, &v)) {
		sxi_jparse_cancel(J, "Failed to obtain boolean value of %s", key);
		return;
	    }
	    if(sx_hashfs_cluster_settings_set_bool(hashfs, key, v)) {
		sxi_jparse_cancel(J, "Failed to modify cluster settings: %s", msg_get_reason());
		return;
	    }
	    break;
	}
	case SX_SETTING_TYPE_FLOAT: {
	    double v;
	    if(sx_blob_get_float(c->settings, &v)) {
		sxi_jparse_cancel(J, "Failed to obtain float value of %s", key);
		return;
	    }
	    if(sx_hashfs_cluster_settings_set_double(hashfs, key, v)) {
		sxi_jparse_cancel(J, "Failed to modify cluster settings: %s", msg_get_reason());
		return;
	    }
	    break;
	}
	case SX_SETTING_TYPE_STRING: {
	    const char *str;
	    if(sx_blob_get_string(c->settings, &str)) {
		sxi_jparse_cancel(J, "Failed to obtain string value of %s", key);
		return;
	    }
	    if(sx_hashfs_cluster_settings_set_string(hashfs, key, str)) {
		sxi_jparse_cancel(J, "Failed to modify cluster settings: %s", msg_get_reason());
		return;
	    }
	    break;
	}
	}
    }
    if(sx_hashfs_modify_cluster_settings_end(hashfs, c->timestamp, 1)) {
	sxi_jparse_cancel(J, "Failed to modify cluster settings: %s", msg_get_reason());
	return;
    }
}

void fcgi_sync_globs(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_syncusr_key, JPKEY("users"), JPANYKEY, JPKEY("key")),
		      JPACT(cb_syncusr_desc, JPKEY("users"), JPANYKEY, JPKEY("desc")),
		      JPACT(cb_syncusr_userid, JPKEY("users"), JPANYKEY, JPKEY("user")),
		      JPACT(cb_syncvol_owner, JPKEY("volumes"), JPANYKEY, JPKEY("owner")),
                      JPACT(cb_syncvol_global_id, JPKEY("volumes"), JPANYKEY, JPKEY("global_id")),
		      JPACT(cb_syncvol_meta, JPKEY("volumes"), JPANYKEY, JPKEY("meta"), JPANYKEY),
		      JPACT(cb_syncmisc_mode, JPKEY("misc"), JPKEY("mode")),
		      JPACT(cb_syncmisc_cmeta, JPKEY("misc"), JPKEY("clusterMeta"), JPARR(1), JPANYKEY),
		      JPACT(cb_syncmisc_csets, JPKEY("misc"), JPKEY("clusterSettings"), JPARR(1), JPANYKEY),
                      JPACT(cb_syncusr_meta, JPKEY("users"), JPANYKEY, JPKEY("userMeta"), JPANYKEY)
		      ),
	JPACTS_INT64(
		     JPACT(cb_syncusr_quota, JPKEY("users"), JPANYKEY, JPKEY("quota")),
		     JPACT(cb_syncvol_size, JPKEY("volumes"), JPANYKEY, JPKEY("size")),
		     JPACT(cb_syncmisc_timestamp, JPKEY("misc"), JPKEY("clusterMeta"), JPARR(0)),
		     JPACT(cb_syncmisc_timestamp, JPKEY("misc"), JPKEY("clusterSettings"), JPARR(0))
		     ),
	JPACTS_INT32(
		     JPACT(cb_syncvol_replica, JPKEY("volumes"), JPANYKEY, JPKEY("replica")),
		     JPACT(cb_syncvol_revs, JPKEY("volumes"), JPANYKEY, JPKEY("revs")),
		     JPACT(cb_syncperms, JPKEY("perms"), JPANYKEY, JPANYKEY)
		     ),
	JPACTS_BOOL(
		    JPACT(cb_syncusr_role, JPKEY("users"), JPANYKEY, JPKEY("admin"))
		    ),
	JPACTS_MAP_BEGIN(
			 JPACT(cb_syncusr_init, JPKEY("users"), JPANYKEY),
			 JPACT(cb_syncvol_init, JPKEY("volumes"), JPANYKEY)
			 ),
	JPACTS_MAP_END(
		       JPACT(cb_syncusr_create, JPKEY("users"), JPANYKEY),
		       JPACT(cb_syncvol_create, JPKEY("volumes"), JPANYKEY)
		       ),
	JPACTS_ARRAY_BEGIN(
			   JPACT(cb_syncmisc_cmetainit, JPKEY("misc"), JPKEY("clusterMeta")),
			   JPACT(cb_syncmisc_csetsinit, JPKEY("misc"), JPKEY("clusterSettings"))
			   ),
	JPACTS_ARRAY_END(
			 JPACT(cb_syncmisc_cmetadone, JPKEY("misc"), JPKEY("clusterMeta")),
			 JPACT(cb_syncmisc_csetsdone, JPKEY("misc"), JPKEY("clusterSettings"))
		       )
    };
    struct cb_sync_ctx yctx;
    jparse_t *J;
    int len;

    if(!sx_storage_is_bare(hashfs))
	quit_errmsg(400, "Node already initialized");

    yctx.settings = sx_blob_new();
    if(!yctx.settings)
        quit_errmsg(500, "Cannot allocate data store");

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J) {
	sx_blob_free(yctx.settings);
	quit_errmsg(503, "Cannot create JSON parser");
    }

    if(sx_hashfs_syncglobs_begin(hashfs)) {
	sxi_jparse_destroy(J);
	sx_blob_free(yctx.settings);
	quit_errmsg(503, "Failed to prepare object synchronization");
    }

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
        if(sxi_jparse_digest(J, hashbuf, len))
            break;

    if(len || sxi_jparse_done(J)) {
	send_error(400, sxi_jparse_geterr(J));
	CRIT("Global object sync failed: %s", sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	sx_blob_free(yctx.settings);
	sx_hashfs_syncglobs_abort(hashfs);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    if(!is_authed()) {
        sx_blob_free(yctx.settings);
	sx_hashfs_syncglobs_abort(hashfs);
	send_authreq();
	return;
    }

    if(sx_hashfs_syncglobs_end(hashfs)) {
        sx_blob_free(yctx.settings);
	quit_errmsg(503, "Failed to finalize object synchronization");
    }

    sx_blob_free(yctx.settings);
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

    if(!strcmp(path, "any")) {
        s = sx_hashfs_force_volumes_replica_unlock(hashfs);
        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
    }
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
    int64_t sysjobs, usrjobs;
    const sx_nodelist_t *nodes;
    sxi_node_status_t status;
    int comma;
    rc_ty s;

    s = sx_hashfs_node_status(hashfs, &status);
    if(s != OK) {
        free(status.cpu_stat);
        free(status.network_traffic_json);
        quit_errmsg(rc2http(s), msg_get_reason());
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n{");
    CGI_PRINTF("\"osType\":\"%s\",\"osArch\":\"%s\",\"osRelease\":\"%s\",\"osVersion\":\"%s\",\"cores\":%d",
        status.os_name, status.os_arch, status.os_release, status.os_version, status.cores);
    CGI_PRINTF(",\"osEndianness\":\"%s\",\"localTime\":\"%s\",\"utcTime\":\"%s\"", status.endianness, status.localtime, status.utctime);
    CGI_PUTS(",\"hashFSVersion\":"); json_send_qstring(status.hashfs_version);
    CGI_PUTS(",\"libsxclientVersion\":"); json_send_qstring(status.libsxclient_version);
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
    CGI_PUTS(",\"memAvailable\":");
    CGI_PUTLL(status.mem_avail);
    CGI_PUTS(",\"swapTotal\":");
    CGI_PUTLL(status.swap_total);
    CGI_PUTS(",\"swapFree\":");
    CGI_PUTLL(status.swap_free);
    CGI_PRINTF(",\"statistics\":{\"processes\":%d,\"processesRunning\":%d,\"processesBlocked\":%d,\"btime\":",
        status.processes, status.processes_running, status.processes_blocked);
    CGI_PUTLL(status.btime);
    if(status.cores > 0 && status.cpu_stat) {
        int i = 0;
	comma = 0;
        CGI_PUTS(",\"processors\":{");
        for(i = 0; i < status.cores; i++) {
            if(comma)
                CGI_PUTC(',');
            comma = 1;
            CGI_PRINTF("\"%s\":{\"user\":", status.cpu_stat[i].name);
            CGI_PUTLL(status.cpu_stat[i].stat_user);
            CGI_PUTS(",\"nice\":");
            CGI_PUTLL(status.cpu_stat[i].stat_nice);
            CGI_PUTS(",\"system\":");
            CGI_PUTLL(status.cpu_stat[i].stat_system);
            CGI_PUTS(",\"idle\":");
            CGI_PUTLL(status.cpu_stat[i].stat_idle);
            CGI_PUTS(",\"iowait\":");
            CGI_PUTLL(status.cpu_stat[i].stat_iowait);
            CGI_PUTS(",\"irq\":");
            CGI_PUTLL(status.cpu_stat[i].stat_irq);
            CGI_PUTS(",\"softirq\":");
            CGI_PUTLL(status.cpu_stat[i].stat_softirq);
            CGI_PUTS(",\"steal\":");
            CGI_PUTLL(status.cpu_stat[i].stat_steal);
            CGI_PUTS(",\"guest\":");
            CGI_PUTLL(status.cpu_stat[i].stat_guest);
            CGI_PUTS(",\"guest_nice\":");
            CGI_PUTLL(status.cpu_stat[i].stat_guest_nice);
            CGI_PUTC('}');
        }
        CGI_PUTC('}');
    }
    if(status.load_stat) {
        CGI_PRINTF(",\"loadavg\":{\"1min\":%f,\"5min\":%f,\"15min\":%f,\"tasksRunning\":%u,\"tasks\":%u,\"newestPid\":%u}",
                   status.load_stat->stat_loadavg_1, status.load_stat->stat_loadavg_5, status.load_stat->stat_loadavg_15,
                   status.load_stat->stat_tasks_running, status.load_stat->stat_tasks, status.load_stat->stat_pid);
    }
    if(status.network_traffic_json && status.network_traffic_json_size)
        CGI_PRINTF(",\"traffic\":%.*s", (unsigned)status.network_traffic_json_size, status.network_traffic_json);
    CGI_PRINTF("},\"heal\":\"%s\",", status.heal_status);
    CGI_PUTS("\"queueStatus\":{");
    if(sx_hashfs_stats_jobq(hashfs, &sysjobs, &usrjobs) == OK) {
	CGI_PUTS("\"eventQueue\":{\"systemJobs\":"); CGI_PUTLL(sysjobs);
	CGI_PUTS(",\"userJobs\":"); CGI_PUTLL(usrjobs); CGI_PUTC('}');
	comma = 1;
    } else
	comma = 0;

    nodes = sx_hashfs_all_nodes(hashfs, NL_NEXTPREV);
    if(nodes) {
	int64_t ready, held, unbumps;
	const sx_node_t *node;
	unsigned int i;
	CGI_PRINTF("%s\"transferQueue\":{", comma ? "," : "");
	for(i=0; i<sx_nodelist_count(nodes); i++) {
	    const sx_uuid_t *nuuid;
	    node = sx_nodelist_get(nodes, i);
	    nuuid = sx_node_uuid(node);
	    if(sx_hashfs_stats_blockq(hashfs, nuuid, &ready, &held, &unbumps) != OK)
		break;
	    CGI_PRINTF("%s\"%s\":{", i ? "," : "", nuuid->string);
	    CGI_PUTS("\"ready\":"); CGI_PUTLL(ready);
	    CGI_PUTS(",\"held\":"); CGI_PUTLL(held);
	    CGI_PUTS(",\"unbumps\":"); CGI_PUTLL(unbumps);
	    CGI_PUTC('}');
	}
	CGI_PUTC('}');
    }
 
    CGI_PRINTF("}}");

    free(status.cpu_stat);
    free(status.network_traffic_json);
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
    int64_t term;
    int64_t last_log_index;
    int64_t last_log_term;
    sx_uuid_t candidate_uuid;
    int64_t hdist_version;
    sx_hashfs_version_t remote_version;
    char libsxclient_version[128];
    int have_candidate, have_hasfhs_ver;
};

static void cb_votereq_candidate(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;
    char uuid_str[UUID_STRING_SIZE+1];

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid candidate UUID");
	return;
    }
    memcpy(uuid_str, string, UUID_STRING_SIZE);
    uuid_str[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&c->candidate_uuid, uuid_str)) {
	sxi_jparse_cancel(J, "Invalid candidate UUID");
	return;
    }
    c->have_candidate = 1;
}

static void cb_votereq_hashfsver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;

    if(sx_hashfs_version_parse(&c->remote_version, string, length)) {
	sxi_jparse_cancel(J, "Invalid storage version");
	return;
    }
    c->have_hasfhs_ver = 1;
}

static void cb_votereq_libsxver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;

    if(length >= sizeof(c->libsxclient_version)) {
	sxi_jparse_cancel(J, "Invalid client library version");
	return;
    }
    memcpy(c->libsxclient_version, string, length);
    c->libsxclient_version[length] = '\0';
}

static void cb_votereq_term(jparse_t *J, void *ctx, int64_t num) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid term");
	return;
    }
    c->term = num;
}

static void cb_votereq_distver(jparse_t *J, void *ctx, int64_t num) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid distribution version");
	return;
    }
    c->hdist_version = num;
}

static void cb_votereq_logidx(jparse_t *J, void *ctx, int64_t num) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid last log index");
	return;
    }
    c->last_log_index = num;
}

static void cb_votereq_logterm(jparse_t *J, void *ctx, int64_t num) {
    struct cb_request_vote_ctx *c = (struct cb_request_vote_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid last log term");
	return;
    }
    c->last_log_term = num;
}

void fcgi_raft_request_vote(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_votereq_candidate, JPKEY("candidateID")),
		      JPACT(cb_votereq_hashfsver, JPKEY("hashFSVersion")),
		      JPACT(cb_votereq_libsxver, JPKEY("libsxclientVersion"))
		      ),
	JPACTS_INT64(
		     JPACT(cb_votereq_term, JPKEY("term")),
		     JPACT(cb_votereq_distver, JPKEY("distributionVersion")),
		     JPACT(cb_votereq_logidx, JPKEY("lastLogIndex")),
		     JPACT(cb_votereq_logterm, JPKEY("lastLogTerm"))
		     )
    };
    const sx_hashfs_version_t *local_version;
    struct cb_request_vote_ctx ctx;
    sx_raft_state_t state;
    int len, success = 0, state_changed = 0;
    jparse_t *J;

    memset(&ctx, 0, sizeof(ctx));
    ctx.term = -1;
    ctx.hdist_version = -1;
    ctx.last_log_index = -1;
    ctx.last_log_term = -1;
    local_version = sx_hashfs_version(hashfs);

    J = sxi_jparse_create(&acts, &ctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(400, sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    if(!is_authed()) {
        send_authreq();
        return;
    }

    /* NOTE: ctx.last_log_index and ctx.last_log_term are optional */
    if(!ctx.have_candidate || !ctx.have_hasfhs_ver || !ctx.libsxclient_version[0] ||
       ctx.term < 0 || ctx.hdist_version < 0)
	quit_errmsg(400, "One or more required fields are missing");

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
	      local_version->str, ctx.remote_version.str);
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

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"raftResponse\":{\"success\":%s,\"term\":", success ? "true" : "false");
    CGI_PUTLL(state.current_term.term);
    CGI_PRINTF(",\"distributionVersion\":");
    CGI_PUTLL(sx_hashfs_hdist_getversion(hashfs));
    CGI_PUTS(",\"hashFSVersion\":"); json_send_qstring(local_version->str);
    CGI_PUTS(",\"libsxclientVersion\":"); json_send_qstring(sxc_get_version());
    CGI_PUTS("}}");
    sx_hashfs_raft_state_empty(hashfs, &state);
}

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

struct cb_appendent_ctx {
    int64_t term;
    int64_t prev_log_index;
    int64_t prev_log_term;
    int64_t leader_commit;
    int64_t hdist_version;
    sx_uuid_t leader_uuid;
    sx_hashfs_version_t remote_version;
    char libsxclient_version[128];
    int have_leader, have_hasfhs_ver;
    struct raft_log_entry {
	int64_t index;
	uint8_t data[MAX_RAFT_LOG_ENTRY_LEN];
	unsigned int data_len;
	int complete;
    } entries[MAX_RAFT_LOG_ENTRIES];
};

static void cb_appendent_term(jparse_t *J, void *ctx, int64_t num) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid term index");
	return;
    }
    c->term = num;
}

static void cb_appendent_distver(jparse_t *J, void *ctx, int64_t num) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid distribution version");
	return;
    }
    c->hdist_version = num;
}

static void cb_appendent_logidx(jparse_t *J, void *ctx, int64_t num) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    if(num < -1) {
	sxi_jparse_cancel(J, "Invalid previous log index");
	return;
    }
    c->prev_log_index = num;
}

static void cb_appendent_logterm(jparse_t *J, void *ctx, int64_t num) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid previous log term");
	return;
    }
    c->prev_log_term = num;
}

static void cb_appendent_leaderci(jparse_t *J, void *ctx, int64_t num) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid previous leader commit");
	return;
    }
    c->leader_commit = num;
}

static void cb_appendent_entryidx(jparse_t *J, void *ctx, int64_t num) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    int pos = sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J)));

    if(pos < 0) {
	/* Not possible */
	WARN("Internal error detected while parsing entry");
	sxi_jparse_cancel(J, "Internal error detected while parsing log entries");
	return;
    }
    if(pos >= MAX_RAFT_LOG_ENTRIES) {
	sxi_jparse_cancel(J, "Too many log entries entries");
	return;
    }
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid index found in log entry %d", pos);
	return;
    }

    c->entries[pos].index = num;
    c->entries[pos].complete |= 1;
}


static void cb_appendent_leader(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    char uuid_str[UUID_STRING_SIZE+1];

    if(length != UUID_STRING_SIZE) {
	sxi_jparse_cancel(J, "Invalid leader UUID");
	return;
    }
    memcpy(uuid_str, string, UUID_STRING_SIZE);
    uuid_str[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&c->leader_uuid, uuid_str)) {
	sxi_jparse_cancel(J, "Invalid leader UUID");
	return;
    }
    c->have_leader = 1;
}

static void cb_appendent_hashfsver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;

    if(sx_hashfs_version_parse(&c->remote_version, string, length)) {
	sxi_jparse_cancel(J, "Invalid storage version");
	return;
    }
    c->have_hasfhs_ver = 1;
}

static void cb_appendent_libsxver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;

    if(length >= sizeof(c->libsxclient_version)) {
	sxi_jparse_cancel(J, "Invalid client library version");
	return;
    }
    memcpy(c->libsxclient_version, string, length);
    c->libsxclient_version[length] = '\0';
}


static void cb_appendent_entry(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_appendent_ctx *c = (struct cb_appendent_ctx*)ctx;
    int pos = sxi_jpath_arraypos(sxi_jpath_down(sxi_jparse_whereami(J)));

    if(pos < 0) {
	/* Not possible */
	WARN("Internal error detected while parsing entry");
	sxi_jparse_cancel(J, "Internal error detected while parsing log entries");
	return;
    }
    if(pos >= MAX_RAFT_LOG_ENTRIES) {
	sxi_jparse_cancel(J, "Too many log entries entries");
	return;
    }

    if(sxi_hex2bin(string, length, c->entries[pos].data, MAX_RAFT_LOG_ENTRY_LEN)) {
	sxi_jparse_cancel(J, "Invalid data found in log entry %d", pos);
	return;
    }
    c->entries[pos].data_len = length/2;
    c->entries[pos].complete |= 2;
}

void fcgi_raft_append_entries(void) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_appendent_leader, JPKEY("leaderID")),
		      JPACT(cb_appendent_hashfsver, JPKEY("hashFSVersion")),
		      JPACT(cb_appendent_libsxver, JPKEY("libsxclientVersion")),
		      JPACT(cb_appendent_entry, JPKEY("entries"), JPANYITM, JPKEY("entry"))
		      ),
	JPACTS_INT64(
		     JPACT(cb_appendent_term, JPKEY("term")),
		     JPACT(cb_appendent_distver, JPKEY("distributionVersion")),
		     JPACT(cb_appendent_logidx, JPKEY("prevLogIndex")),
		     JPACT(cb_appendent_logterm, JPKEY("prevLogTerm")),
		     JPACT(cb_appendent_leaderci, JPKEY("leaderCommit")),
		     JPACT(cb_appendent_entryidx, JPKEY("entries"), JPANYITM, JPKEY("index"))
		     )
    };
    const sx_hashfs_version_t *local_version;
    struct cb_appendent_ctx ctx;
    sx_raft_state_t state;
    unsigned int nentries;
    int len;
    int success = 0;
    int state_changed = 0;
    jparse_t *J;

    memset(&ctx, 0, sizeof(ctx));
    ctx.term = -1;
    ctx.hdist_version = -1;
    ctx.prev_log_index = -2;
    ctx.prev_log_term = -1;
    ctx.leader_commit = -1;
    local_version = sx_hashfs_version(hashfs);

    J = sxi_jparse_create(&acts, &ctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(400, sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    if(!is_authed()) {
        send_authreq();
        return;
    }

    /* NOTE: ctx.prev_log_index, ctx.prev_log_term and ctx.leader_commit are optional */
    if(!ctx.have_leader || !ctx.have_hasfhs_ver || !ctx.libsxclient_version[0] ||
       ctx.term < 0 || ctx.hdist_version < 0)
	quit_errmsg(400, "One or more required fields are missing");
    for(nentries=0; nentries<MAX_RAFT_LOG_ENTRIES; nentries++) {
	if(ctx.entries[nentries].complete == 0)
	    break;
	if(ctx.entries[nentries].complete != 3)
	    quit_errmsg(500, "Required field missing from log entry");
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
                local_version->str, ctx.remote_version.str);
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

    CGI_PRINTF("Content-type: application/json\r\n\r\n{\"raftResponse\":{\"success\":%s,\"term\":", success ? "true" : "false");
    CGI_PUTLL(state.current_term.term);
    CGI_PRINTF(",\"distributionVersion\":");
    CGI_PUTLL(sx_hashfs_hdist_getversion(hashfs));
    CGI_PUTS(",\"hashFSVersion\":"); json_send_qstring(local_version->str);
    CGI_PUTS(",\"libsxclientVersion\":"); json_send_qstring(sxc_get_version());
    CGI_PUTS("}}");
    sx_hashfs_raft_state_empty(hashfs, &state);
}
