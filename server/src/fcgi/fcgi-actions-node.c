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

/* {"nodeList":[{"nodeUUID":"%s","nodeAddress":"%s","nodeInternalAddress":"%s","nodeCapacity":%llu}]} */
struct cb_nodes_ctx {
    enum cb_nodes_state { CB_NODES_START, CB_NODES_ROOT, CB_NODES_ARRAY, CB_NODES_LIST, CB_NODES_NODE, CB_NODES_UUID, CB_NODES_ADDR, CB_NODES_INTADDR, CB_NODES_CAPA, CB_NODES_COMPLETE } state;
    sx_uuid_t id;
    char *addr;
    char *intaddr;
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
	sx_nodelist_delete(yctx.nodes);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    quit_unless_authed();

    if(has_arg("replace"))
	s = sx_hashfs_hdist_replace_req(hashfs, yctx.nodes, &job);
    else
	s = sx_hashfs_hdist_change_req(hashfs, yctx.nodes, &job);

    sx_nodelist_delete(yctx.nodes);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());
    send_job_info(job);
}

/* {"newDistribution":"HEX(blob_cfg)", "faultyNodes":["uuid1", "uuiid2"]} */
/* MODHDIST: maybe add revision here */
struct cb_updist_ctx {
    enum cb_updist_state { CB_UPDIST_START, CB_UPDIST_KEY, CB_UPDIST_CFG, CB_UPDIST_FAULTY, CB_UPDIST_FAULTYNODE, CB_UPDIST_COMPLETE } state;
    void *cfg;
    sx_nodelist_t *faulty;
    unsigned int cfg_len, nfaulty;
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
    rc_ty s;
    int len;

    yctx.cfg = NULL;
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
	free(yctx.cfg);
	send_authreq();
	return;
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
            "admin":{"key":"xxxxx","admin":true},
            "luser":{"key":"yyyyy","admin":false}
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
*/

struct cb_sync_ctx {
    enum cb_sync_state { CB_SYNC_START, CB_SYNC_MAIN, CB_SYNC_USERS, CB_SYNC_VOLUMES, CB_SYNC_PERMS, CB_SYNC_INUSERS, CB_SYNC_INVOLUMES, CB_SYNC_INPERMS, CB_SYNC_USR, CB_SYNC_VOL, CB_SYNC_PRM, CB_SYNC_USRKEY, CB_SYNC_VOLKEY, CB_SYNC_PRMKEY, CB_SYNC_USRAUTH, CB_SYNC_USRROLE, CB_SYNC_VOLOWNR, CB_SYNC_VOLREP, CB_SYNC_VOLREVS, CB_SYNC_VOLSIZ, CB_SYNC_VOLMETA, CB_SYNC_VOLMETAKEY, CB_SYNC_VOLMETAVAL, CB_SYNC_PRMVAL, CB_SYNC_OUTRO, CB_SYNC_COMPLETE } state;
    int64_t size;
    char name[MAX(SXLIMIT_MAX_VOLNAME_LEN, SXLIMIT_MAX_USERNAME_LEN) + 1];
    char mkey[SXLIMIT_META_MAX_KEY_LEN+1];
    uint8_t key[AUTH_KEY_LEN];
    sx_uid_t uid;
    int admin, have_key;
    unsigned int replica, revs;
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
    } else if(c->state == CB_SYNC_VOLOWNR) {
	uint8_t usr[AUTH_UID_LEN];
	if(l != AUTH_UID_LEN * 2)
	    return 0;
	if(hex2bin(s, l, usr, sizeof(usr)))
	    return 0;
	if(sx_hashfs_get_user_info(hashfs, usr, &c->uid, NULL, NULL))
	    return 0;
	c->state = CB_SYNC_VOLKEY;
    } else if(c->state == CB_SYNC_PRMVAL) {
	sx_priv_t priv = 0;
	if(l < 1 || l >2)
	    return 0;
	if(l == lenof("rw") && !strncmp("rw", s, lenof("rw")))
	    priv = PRIV_READ | PRIV_WRITE;
	else if(*s == 'r')
	    priv = PRIV_READ;
	else if(*s == 'w')
	    priv = PRIV_WRITE;
	else
	    return 0;
	sx_hashfs_revoke(hashfs, c->uid, c->name, PRIV_READ | PRIV_WRITE);
	if(sx_hashfs_grant(hashfs, c->uid, c->name, priv))
	    return 0;
	c->state = CB_SYNC_PRMKEY;
    } else if(c->state == CB_SYNC_VOLMETAVAL) {
	uint8_t val[SXLIMIT_META_MAX_VALUE_LEN];
	if(!l || (l & 1) || l > sizeof(val) * 2)
	    return 0;
	if(hex2bin(s, l, val, sizeof(val)))
	    return 0;
	if(sx_hashfs_volume_new_addmeta(hashfs, c->mkey, val, l/2))
	    return 0;
	c->state = CB_SYNC_VOLMETAKEY;
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

    if(c->state != CB_SYNC_VOLREP && c->state != CB_SYNC_VOLSIZ && c->state != CB_SYNC_VOLREVS)
	return 0;

    if(l<1 || l>20)
	return 0;
    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &eon, 10);
    if(*eon || n <= 0)
	return 0;

    if(c->state == CB_SYNC_VOLSIZ)
	c->size = n;
    else if(n > 0xffffffff)
	return 0;
    else if(c->state == CB_SYNC_VOLREP)
	c->replica = (unsigned int)n;
    else 
	c->revs = (unsigned int)n;

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

    else if(c->state == CB_SYNC_USR)
	c->state = CB_SYNC_USRKEY;
    else if(c->state == CB_SYNC_VOL)
	c->state = CB_SYNC_VOLKEY;
    else if(c->state == CB_SYNC_PRM)
	c->state = CB_SYNC_PRMKEY;

    else if(c->state == CB_SYNC_VOLMETA)
	c->state = CB_SYNC_VOLMETAKEY;

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
	else if(l == lenof("admin") && !strncmp("admin", s, lenof("admin")))
	    c->state = CB_SYNC_USRROLE;
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
	if(sx_hashfs_get_user_info(hashfs, usr, &c->uid, NULL, NULL))
	    return 0;
	c->state = CB_SYNC_PRMVAL;
    } else if(c->state == CB_SYNC_VOLMETAKEY) {
	if(l >= sizeof(c->mkey))
	    return 0;
	memcpy(c->mkey, s, l);
	c->mkey[l] = '\0';
	c->state = CB_SYNC_VOLMETAVAL;
    } else
	return 0;

    return 1;
}

static int cb_sync_end_map(void *ctx) {
    struct cb_sync_ctx *c = (struct cb_sync_ctx *)ctx;

    if(c->state == CB_SYNC_USRKEY) {
	if(!c->have_key || c->admin < 0)
	    return 0;
	if(sx_hashfs_create_user(hashfs, c->name, NULL, 0, c->key, sizeof(c->key), c->admin != 0))
	    return 0;
	if(sx_hashfs_user_onoff(hashfs, c->name, 1))
	    return 0;
	c->state = CB_SYNC_INUSERS;
    } else if(c->state == CB_SYNC_VOLKEY) {
	if(c->uid < 0 || c->size <= 0 || !c->replica)
	    return 0;
	if(!c->revs)
	    c->revs = 1;
	if(sx_hashfs_volume_new_finish(hashfs, c->name, c->size, c->replica, c->revs, c->uid))
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
    } else if(c->state == CB_SYNC_VOLMETAKEY) {
	c->state = CB_SYNC_VOLKEY;	
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
    if(!sx_storage_is_bare(hashfs))
	quit_errmsg(400, "Node already initialized");

    struct cb_sync_ctx yctx;
    memset(&yctx, 0, sizeof(yctx));
    yctx.state = CB_SYNC_START;

    yajl_handle yh = yajl_alloc(&sync_parser, NULL, &yctx);
    if(!yh)
	quit_errmsg(500, "Cannot allocate json parser");

    /* MODHDIST: transaction starts here */
    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;

    if(len || yajl_complete_parse(yh) != yajl_status_ok || yctx.state != CB_SYNC_COMPLETE) {
	yajl_free(yh);
	/* MODHDIST: rollback here */
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    /* MODHDIST: commit if authed, rollback if unauthed */
    quit_unless_authed();

    CGI_PUTS("\r\n");
}


void fcgi_node_jlock(void) {
    rc_ty s = sx_hashfs_job_lock(hashfs, path);
    if(s != OK)
	quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}


void fcgi_node_junlock(void) {
    rc_ty s = sx_hashfs_job_unlock(hashfs, path);
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
