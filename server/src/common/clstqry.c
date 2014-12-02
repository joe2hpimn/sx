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

#include "clstqry.h"

struct cstatus {
    sx_nodelist_t *one;
    sx_nodelist_t *two;
    yajl_handle yh;
    char *addr, *auth;
    char *int_addr;
    sx_uuid_t uuid, distid;
    uint64_t checksum;
    int64_t capa;
    int nsets, have_uuid, have_distid, op_complete;
    enum {
	OP_NONE,
	OP_REBALANCE,
	OP_REPLACE,
    } op_type;
    unsigned int version;
    char op_msg[1024];
    curlev_context_t *cbdata;

    enum cstatus_state { CS_BEGIN, CS_BASEKEY, CS_CSTATUS, CS_SKEY, CS_DISTS, CS_DIST, CS_NODES, CS_NODEKEY, CS_UUID, CS_ADDR, CS_INT_ADDR, CS_CAPA, CS_DISTID, CS_DISTVER, CS_DISTCHK, CS_AUTH, CS_INPRG, CS_INPRGKEY, CS_INPRGOP, CS_INPRGDONE, CS_INPRGMSG, CS_COMPLETE } state;
};

static int cb_cstatus_start_map(void *ctx) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(c->state == CS_BEGIN)
	c->state = CS_BASEKEY;
    else if(c->state == CS_CSTATUS)
	c->state = CS_SKEY;
    else if(c->state == CS_NODES)
	c->state = CS_NODEKEY;
    else if(c->state == CS_INPRG)
	c->state = CS_INPRGKEY;
    else
	return 0;

    return 1;
}

static int cb_cstatus_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(c->state == CS_BASEKEY) {
	if(l == lenof("clusterStatus") && !memcmp("clusterStatus", s, lenof("clusterStatus")))
	    c->state = CS_CSTATUS;
	else
	    return 0;
    } else if(c->state == CS_SKEY) {
	if(l == lenof("distributionModels") && !memcmp("distributionModels", s, lenof("distributionModels")))
	    c->state = CS_DISTS;
	else if(l == lenof("distributionUUID") && !memcmp("distributionUUID", s, lenof("distributionUUID")))
	    c->state = CS_DISTID;
	else if(l == lenof("distributionVersion") && !memcmp("distributionVersion", s, lenof("distributionVersion")))
	    c->state = CS_DISTVER;
	else if(l == lenof("distributionChecksum") && !memcmp("distributionChecksum", s, lenof("distributionChecksum")))
	    c->state = CS_DISTCHK;
	else if(l == lenof("clusterAuth") && !memcmp("clusterAuth", s, lenof("clusterAuth")))
	    c->state = CS_AUTH;
	else if(l == lenof("opInProgress") && !memcmp("opInProgress", s, lenof("opInProgress")))
	    c->state = CS_INPRG;
	else
	    return 0;
    } else if(c->state == CS_NODEKEY) {
	if(l == lenof("nodeUUID") && !memcmp("nodeUUID", s, lenof("nodeUUID")))
	    c->state = CS_UUID;
	else if(l == lenof("nodeAddress") && !memcmp("nodeAddress", s, lenof("nodeAddress")))
	    c->state = CS_ADDR;
	else if(l == lenof("nodeInternalAddress") && !memcmp("nodeInternalAddress", s, lenof("nodeInternalAddress")))
	    c->state = CS_INT_ADDR;
	else if(l == lenof("nodeCapacity") && !memcmp("nodeCapacity", s, lenof("nodeCapacity")))
	    c->state = CS_CAPA;
	else
	    return 0;
    } else if(c->state == CS_INPRGKEY) {
	if(l == lenof("opType") && !memcmp("opType", s, lenof("opType")))
	    c->state = CS_INPRGOP;
	else if(l == lenof("isComplete") && !memcmp("isComplete", s, lenof("isComplete")))
	    c->state = CS_INPRGDONE;
	else if(l == lenof("opInfo") && !memcmp("opInfo", s, lenof("opInfo")))
	    c->state = CS_INPRGMSG;
	else
	    return 0;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_end_map(void *ctx) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(c->state == CS_NODEKEY) {
	sx_node_t *node;
	if(!c->have_uuid || !c->addr || c->capa <= 0 || c->nsets < 0 || c->nsets > 1)
	    return 0;
	node = sx_node_new(&c->uuid, c->addr, c->int_addr, c->capa);
	if(sx_nodelist_add(c->nsets ? c->two : c->one, node))
	    return 0;
	free(c->addr);
	free(c->int_addr);
	c->addr = NULL;
	c->int_addr = NULL;
	c->capa = 0;
	c->have_uuid = 0;
	c->state = CS_NODES;
    } else if(c->state == CS_SKEY)
	c->state = CS_BASEKEY;
    else if(c->state == CS_INPRGKEY)
	c->state = CS_SKEY;
    else if(c->state == CS_BASEKEY)
	c->state = CS_COMPLETE;
    else
	return 0;

    return 1;
}

static int cb_cstatus_start_array(void *ctx) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(c->state == CS_DISTS)
	c->state = CS_DIST;
    else if(c->state == CS_DIST) {
	if(c->nsets < 0 || c->nsets > 1)
	    return 0;
	if(c->nsets < 0 || c->nsets > 1)
	    return 0;
	c->state = CS_NODES;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_end_array(void *ctx) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(c->state == CS_NODES) {
	c->nsets++;
	c->state = CS_DIST;
    } else if(c->state == CS_DIST)
	c->state = CS_SKEY;
    else
	return 0;

    return 1;
}


static int cb_cstatus_string(void *ctx, const unsigned char *s, size_t l) {
    struct cstatus *c = (struct cstatus *)ctx;
    char uuid[UUID_STRING_SIZE + 1];

    if(c->state == CS_UUID) {
	if(c->have_uuid || l != UUID_STRING_SIZE)
	    return 0;
	memcpy(uuid, s, UUID_STRING_SIZE);
	uuid[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&c->uuid, uuid))
	    return 0;
	c->have_uuid = 1;
	c->state = CS_NODEKEY;
    } else if(c->state == CS_DISTID) {
	if(c->have_distid || l != UUID_STRING_SIZE)
	    return 0;
	memcpy(uuid, s, UUID_STRING_SIZE);
	uuid[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&c->distid, uuid))
	    return 0;
	c->have_distid = 1;
	c->state = CS_SKEY;
    } else if(c->state == CS_ADDR) {
	if(c->addr)
	    return 0;
	c->addr = malloc(l+1);
	if(!c->addr)
	    return 0;
	memcpy(c->addr, s, l);
	c->addr[l] = '\0';
	c->state = CS_NODEKEY;
    } else if(c->state == CS_INT_ADDR) {
	if(c->int_addr)
	    return 0;
	c->int_addr = malloc(l+1);
	if(!c->int_addr)
	    return 0;
	memcpy(c->int_addr, s, l);
	c->int_addr[l] = '\0';
	c->state = CS_NODEKEY;
    } else if(c->state == CS_AUTH) {
	if(c->auth)
	    return 0;
	c->auth = malloc(l+1);
	if(!c->auth)
	    return 0;
	memcpy(c->auth, s, l);
	c->auth[l] = '\0';
	c->state = CS_SKEY;
    } else if(c->state == CS_INPRGOP) {
	if(l == lenof("rebalance") && !memcmp("rebalance", s, lenof("rebalance")))
	    c->op_type = OP_REBALANCE;
	else if(l == lenof("replace") && !memcmp("replace", s, lenof("replace")))
	    c->op_type = OP_REPLACE;
	else
	    c->op_type = OP_NONE;
	c->state = CS_INPRGKEY;
    } else if(c->state == CS_INPRGMSG) {
	unsigned int ml = MIN(l, sizeof(c->op_msg) - 1);
	memcpy(c->op_msg, s, ml);
	c->op_msg[ml] = '\0';
	c->state = CS_INPRGKEY;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_number(void *ctx, const char *s, size_t l) {
    struct cstatus *c = (struct cstatus *)ctx;
    char number[24], *eon;
    int64_t lld;

    if(c->state != CS_CAPA && c->state != CS_DISTVER && c->state != CS_DISTCHK)
	return 0;

    if(c->capa || l<1 || l>20)
	return 0;

    memcpy(number, s, l);
    number[l] = '\0';
    lld = strtoll(number, &eon, 10);
    if(*eon)
	return 0;

    if(c->state == CS_CAPA) {
	if(lld < 0)
	    return 0;
	c->capa = lld;
	c->state = CS_NODEKEY;
    } else if(c->state == CS_DISTVER) {
	if(lld < 0 || lld >0xffffffff)
	    return 0;
	c->version = (unsigned int)(lld & 0xffffffff);
	c->state = CS_SKEY;
    } else {
	c->checksum = (uint64_t)lld;
	c->state = CS_SKEY;
    }

    return 1;
}

int cb_cstatus_boolean(void *ctx, int boolean) {
    struct cstatus *c = (struct cstatus *)ctx;

    if(c->state != CS_INPRGDONE)
	return 0;

    c->op_complete = boolean;
    c->state = CS_INPRGKEY;
    return 1;
}

static const yajl_callbacks cstatus_parser = {
    cb_fail_null,
    cb_cstatus_boolean,
    NULL,
    NULL,
    cb_cstatus_number,
    cb_cstatus_string,
    cb_cstatus_start_map,
    cb_cstatus_map_key,
    cb_cstatus_end_map,
    cb_cstatus_start_array,
    cb_cstatus_end_array
};

static int cstatus_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cstatus *yactx = (struct cstatus *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&cstatus_parser, NULL, yactx))) {
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

    free(yactx->auth);
    free(yactx->addr);
    free(yactx->int_addr);
    yactx->auth = NULL;
    yactx->addr = NULL;
    yactx->int_addr = NULL;
    yactx->have_uuid = 0;
    yactx->have_distid = 0;
    yactx->nsets = 0;
    yactx->version = 0;
    yactx->checksum = 0;
    yactx->capa = 0;
    yactx->op_type = OP_NONE;
    yactx->op_complete = -1;
    yactx->op_msg[0] = '\0';
    yactx->state = CS_BEGIN;
    yactx->cbdata = cbdata;

    return 0;
}

static int cstatus_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cstatus *yactx = (struct cstatus *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok)
	return 1;
    return 0;
}


void clst_destroy(clst_t *st) {
    if(!st)
	return;
    sx_nodelist_delete(st->one);
    sx_nodelist_delete(st->two);
    free(st->auth);
    free(st->addr);
    free(st->int_addr);
    if(st->yh)
	yajl_free(st->yh);
    free(st);
}

clst_t *clst_query(sxi_conns_t *conns, sxi_hostlist_t *hlist) {
    struct cstatus *yctx = NULL;

    if(!conns)
	return NULL;

    if(!(yctx = calloc(1, sizeof(*yctx))))
	return NULL;

    if(sxi_cluster_query(conns, hlist, REQ_GET, "?clusterStatus", NULL, 0, cstatus_setup_cb, cstatus_cb, yctx) != 200) {
	clst_destroy(yctx);
	return NULL;
    }

    if(yajl_complete_parse(yctx->yh) != yajl_status_ok || yctx->state != CS_COMPLETE || yctx->nsets < 0 || yctx->nsets > 2) {
	clst_destroy(yctx);
	return NULL;
    }

    yajl_free(yctx->yh);
    free(yctx->addr);
    free(yctx->int_addr);
    yctx->yh = NULL;
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

