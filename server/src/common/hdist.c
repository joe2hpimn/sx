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
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <limits.h>

#include "hdist.h"
#include "isaac.h"
#include "utils.h"
#include "log.h"
#include "nodes.h"
#include "zlib.h"
#include "../libsx/src/vcrypto.h"

#ifdef WORDS_BIGENDIAN
uint32_t swapu32(uint32_t v)
{
    v = ((v << 8) & 0xff00ff00) | ((v >> 8) & 0xff00ff);
    return (v << 16) | (v >> 16);
}
#else
#define swapu32(x) (x)
#endif

#define CFG_PREALLOC	4096
#define MAX_RDIV	5

struct hdist_point {
    uint64_t point;
    uint64_t rnd;
    unsigned int num;
    unsigned int node_points;
    unsigned int node_id;
};

struct hdist_node {
    sx_node_t *sxn;
    unsigned int id;
    uint64_t capacity;
};

struct _sxi_hdist_t {
    unsigned int state, builds, version;
    unsigned int max_builds;
    unsigned int last_id; /* internal */
    uint64_t *capacity_total;
    isaac_ctx rctx;
    unsigned int seed;
    uint64_t checksum;
    sx_uuid_t uuid;

    char *cfg;
    unsigned int cfg_size, cfg_alloced, cfg_blob_size;
    unsigned char *cfg_blob;

    struct hdist_node **node_list;
    sx_nodelist_t **sxnl;
    unsigned int *node_count;
    struct hdist_point **circle;
    unsigned int *circle_points;
};

sxi_hdist_t *sxi_hdist_new(unsigned int seed, unsigned int max_builds, sx_uuid_t *uuid)
{
	sxi_hdist_t *model;
    
    if(max_builds < 1) {
	CRIT("max_builds < 1");
	return NULL;
    }

    model = calloc(1, sizeof(struct _sxi_hdist_t));
    if(!model) {
	CRIT("Can't allocate hdist");
	return NULL;
    }

    model->max_builds = max_builds;
    model->last_id = 1;

    model->node_list = (struct hdist_node **) wrap_calloc(sizeof(struct hdist_node *), max_builds);
    if(!model->node_list) {
	CRIT("Can't allocate memory for model->node_list");
	free(model);
	return NULL;
    }

    model->sxnl = (sx_nodelist_t **) wrap_calloc(sizeof(sx_nodelist_t *), max_builds);
    if(!model->sxnl) {
	CRIT("Can't allocate memory for model->sxnl");
	free(model);
	return NULL;
    }

    model->node_count = (unsigned int *) wrap_calloc(sizeof(unsigned int), max_builds);
    if(!model->node_count) {
	CRIT("Can't allocate memory for model->node_count");
	free(model->node_list);
	free(model);
	return NULL;
    }

    model->capacity_total = (uint64_t *) wrap_calloc(sizeof(uint64_t), max_builds);
    if(!model->capacity_total) {
	CRIT("Can't allocate memory for model->capacity_total");
	free(model->node_list);
	free(model->node_count);
	free(model);
	return NULL;
    }

    model->circle = (struct hdist_point **) wrap_malloc(sizeof(struct hdist_point *) * max_builds);
    if(!model->circle) {
	CRIT("Can't allocate memory for model->circle");
	free(model->node_list);
	free(model->node_count);
	free(model->capacity_total);
	free(model);
	return NULL;
    }

    model->circle_points = (unsigned int *) wrap_calloc(sizeof(unsigned int), max_builds);
    if(!model->circle_points) {
	CRIT("Can't allocate memory for model->circle_points");
	free(model->node_list);
	free(model->node_count);
	free(model->circle);
	free(model->capacity_total);
	free(model);
	return NULL;
    }

    if(!uuid)
	uuid_generate(&model->uuid);
    else
	memcpy(&model->uuid, uuid, sizeof(*uuid));

    model->cfg = (char *) wrap_malloc(sizeof(char) * CFG_PREALLOC);
    if(!model->cfg) {
	CRIT("Can't allocate memory for model->circle_points");
	free(model->node_list);
	free(model->node_count);
	free(model->circle);
	free(model->capacity_total);
	free(model->circle_points);
	free(model);
	return NULL;
    }
    model->cfg_alloced = CFG_PREALLOC;
    model->cfg_size = sprintf(model->cfg, "HDIST:%s:%u:%u", model->uuid.string, seed, max_builds);

    model->seed = seed;
    isaac_seed(&model->rctx, seed);
    model->state = 0xcafe;
    return model;
}

static char *gettoken(const char *str, unsigned int *pos, char *buf, size_t bufsize)
{
	size_t len, stored = 0;

    if(!str || !buf || *pos >= strlen(str))
	return NULL;
    len = strlen(&str[*pos]);
    if(str[*pos] == ':') {
	(*pos)++;
	len--;
    }
    while(len) {
	if(str[*pos] == ':') {
	    (*pos)++;
	    break;
	} else {
	    if(stored + 1 >= bufsize) {
		CRIT("provided buffer too small");
		return NULL;
	    }
	    buf[stored++] = str[(*pos)++];
	    len--;
	}
    }
    if(stored + 1 >= bufsize) {
	CRIT("provided buffer too small");
	return NULL;
    }
    buf[stored] = 0;
    return stored ? buf : NULL;
}

sxi_hdist_t *sxi_hdist_from_cfg(const void *cfg, unsigned int cfg_len)
{
	char *cs;
	char token[128], *pt;
	unsigned int pos = 0, seed, max_builds;
	uLongf destlen, got;
	sx_uuid_t uuid;
	sxi_hdist_t *model;
	rc_ty ret = 1;

    destlen = swapu32(*(uint32_t *) cfg);
    cs = malloc(destlen);
    if(!cs) {
	CRIT("Can't allocate memory to uncompress cfg blob");
	return NULL;
    }
    got = destlen;
    if(uncompress((Bytef *) cs, &got, (const Bytef *) cfg + 4, cfg_len - 4) != Z_OK || got != destlen) {
	CRIT("Can't uncompress cfg blob");
	free(cs);
	return NULL;
    }

    if(got < 30) {
	CRIT("Invalid configuration data (too short)");
	free(cs);
	return NULL;
    }

    /* magic */
    pt = gettoken(cs, &pos, token, sizeof(token));
    if(!pt || strcmp(pt, "HDIST")) {
	CRIT("Invalid configuration data (magic)");
	free(cs);
	return NULL;
    }

    /* UUID */
    pt = gettoken(cs, &pos, token, sizeof(token));
    if(uuid_from_string(&uuid, pt)) {
	CRIT("Invalid configuration data (UUID = %s)", pt);
	free(cs);
	return NULL;
    }

    /* seed */
    pt = gettoken(cs, &pos, token, sizeof(token));
    if(!pt || !isdigit(*pt)) {
	CRIT("Invalid configuration data (seed)");
	free(cs);
	return NULL;
    }
    seed = atoi(pt);

    /* max_builds */
    pt = gettoken(cs, &pos, token, sizeof(token));
    if(!pt || !isdigit(*pt)) {
	CRIT("Invalid configuration data (max_builds)");
	free(cs);
	return NULL;
    }
    max_builds = atoi(pt);

    model = sxi_hdist_new(seed, max_builds, &uuid);
    if(!model) {
	free(cs);
	return NULL;
    }

    while((pt = gettoken(cs, &pos, token, sizeof(token)))) {
	if(!strcmp(pt, "BUILD") || !strcmp(pt, "REBALANCED")) {
		long long int checksum;

	    if(!strcmp(pt, "BUILD"))
		ret = sxi_hdist_build(model);
	    else
		ret = sxi_hdist_rebalanced(model);

	    if(ret)
		break;

	    /* checksum */
	    pt = gettoken(cs, &pos, token, sizeof(token));
	    if(!pt || (!isdigit(*pt) && *pt != '-')) {
		CRIT("Invalid configuration data (checksum)");
		ret = EINVAL;
		break;
	    }
	    checksum = strtoll(pt, NULL, 0);
	    if(checksum == LLONG_MAX) {
		CRIT("Invalid configuration data (checksum conversion)");
		ret = EINVAL;
		break;
	    }
	    if(model->checksum != (uint64_t) checksum) {
		CRIT("Invalid checksum of new model");
		ret = EINVAL;
		break;
	    };

	} else {
		char addr[40], addr_int[40];
		long long int capacity;
		char *prev_uuid;
		sx_uuid_t puuid;

	    /* UUID + (optional) prev_uuid */
	    if((prev_uuid = strchr(pt, '@'))) {
		*prev_uuid++ = 0;
		if(uuid_from_string(&puuid, prev_uuid)) {
		    CRIT("Invalid configuration data (prev_uuid = %s)", prev_uuid);
		    ret = EINVAL;
		    break;
		}
	    }
	    if(uuid_from_string(&uuid, pt)) {
		CRIT("Invalid configuration data (UUID = %s)", pt);
		ret = EINVAL;
		break;
	    }

	    /* addr */
	    pt = gettoken(cs, &pos, addr, sizeof(addr));
	    if(!pt) {
		CRIT("Invalid configuration data (addr)");
		ret = EINVAL;
		break;
	    }

	    /* addr_int */
	    pt = gettoken(cs, &pos, addr_int, sizeof(addr_int));
	    if(!pt) {
		CRIT("Invalid configuration data (addr_int)");
		ret = EINVAL;
		break;
	    }

	    /* capacity + prev_uuid */
	    pt = gettoken(cs, &pos, token, sizeof(token));
	    if(!pt || !isdigit(*pt)) {
		CRIT("Invalid configuration data (capacity)");
		ret = EINVAL;
		break;
	    }
	    capacity = strtoll(pt, NULL, 0);
	    if(capacity <= 0 || capacity == LLONG_MAX) {
		CRIT("Invalid configuration data (capacity conversion)");
		ret = EINVAL;
		break;
	    }

	    if(model->state == 0xbabe && (ret = sxi_hdist_newbuild(model))) {
		CRIT("Can't create new build");
		break;
	    }

	    ret = sxi_hdist_addnode(model, &uuid, addr, addr_int, capacity, prev_uuid ? &puuid : NULL);
	    if(ret)
		break;
	}
    }
    free(cs);

    if(ret) {
	sxi_hdist_free(model);
	return NULL;
    }

    if(model->state != 0xbabe) {
	CRIT("Invalid model state after loading cfg");
	sxi_hdist_free(model);
	return NULL;
    }

    return model;
}

rc_ty sxi_hdist_get_cfg(const sxi_hdist_t *model, const void **cfg, unsigned int *cfg_len)
{
    if(!model)
	return EINVAL;

    if(model->state != 0xbabe) {
	CRIT("Invalid model state - can't get cfg");
	return EINVAL;
    }

    *cfg = model->cfg_blob;
    *cfg_len = model->cfg_blob_size;

    return OK;
}

static int get_node_idx(const sxi_hdist_t *model, unsigned int bidx, unsigned int node_id)
{
	unsigned int i;

    for(i = 0; i < model->node_count[bidx]; i++)
	if(model->node_list[bidx][i].id == node_id)
	    return i;
    return -1;
}

static rc_ty hdist_addnode(sxi_hdist_t *model, unsigned int id, uint64_t capacity, sx_node_t *sxn, unsigned int hashes_stored, unsigned int replicas_stored, uint64_t *hashes, uint8_t *replica_cnt, const sx_uuid_t *prev_uuid)
{
	struct hdist_node *node_list_new;

    if(!model || !capacity)
	return EINVAL;

    if(model->state != 0xcafe) {
	CRIT("Model not initialized");
	return EINVAL;
    }

    node_list_new = (struct hdist_node *) wrap_realloc(model->node_list[0], (model->node_count[0] + 1) * sizeof(struct hdist_node));
    if(!node_list_new) {
	CRIT("Can't add new node - realloc() failed");
	return ENOMEM;
    }
    model->node_list[0] = node_list_new;
    node_list_new[model->node_count[0]].id = id;
    if(sxn) {
	node_list_new[model->node_count[0]].sxn = sx_node_dup(sxn);
	if(!node_list_new[model->node_count[0]].sxn) {
	    CRIT("sx_node_dup failed");
	    return ENOMEM;
	}
    } else {
	node_list_new[model->node_count[0]].sxn = NULL;
    }
    node_list_new[model->node_count[0]].capacity = capacity;
    model->node_count[0]++;

    if(model->cfg_size + 180 > model->cfg_alloced) {
	model->cfg_alloced += CFG_PREALLOC;
	model->cfg = (char *) wrap_realloc_or_free(model->cfg, sizeof(char) * model->cfg_alloced);
	if(!model->cfg) {
	    CRIT("Can't realloc model->cfg");
	    return ENOMEM;
	}
    }
    if(sxn)
	model->cfg_size += sprintf(model->cfg + model->cfg_size, ":%s%s%s:%s:%s:%llu", sx_node_uuid_str(sxn), prev_uuid ? "@" : "", prev_uuid ? prev_uuid->string : "", sx_node_addr(sxn), sx_node_internal_addr(sxn), (unsigned long long) sx_node_capacity(sxn));

    return OK;
}

rc_ty sxi_hdist_addnode(sxi_hdist_t *model, const sx_uuid_t *uuid, const char *addr, const char *internal_addr, int64_t capacity, const sx_uuid_t *prev_uuid)
{
	unsigned int i, id = 0;
	sx_node_t *sxn;
	rc_ty rc;

    if(!model || !uuid || !addr || !capacity)
	return EINVAL;

    /* retain the internal ID if possible */
    if(model->builds) {
	for(i = 0; i < model->node_count[1]; i++)
	    if(model->node_list[1][i].sxn && (!memcmp(sx_node_uuid(model->node_list[1][i].sxn), uuid, sizeof(*uuid)) || (prev_uuid && !memcmp(sx_node_uuid(model->node_list[1][i].sxn), prev_uuid, sizeof(*prev_uuid)))))
		id = model->node_list[1][i].id;
    }

    if(!id)
	id = model->last_id++;

    sxn = sx_node_new(uuid, addr, internal_addr, capacity);
    if(!sxn)
	return EINVAL;

    rc = hdist_addnode(model, id, capacity, sxn, 0, 0, NULL, NULL, prev_uuid);
    if(rc) {
	sx_node_delete(sxn);
	return rc;
    }

    if(!model->sxnl[0]) {
	model->sxnl[0] = sx_nodelist_new();
	if(!model->sxnl[0]) {
	    sx_node_delete(sxn);
	    return ENOMEM;
	}
    }

    if(sx_nodelist_add(model->sxnl[0], sxn))
	return ENOMEM;

    return rc;
}

static int circle_cmp_point(const void *a, const void *b)
{
	const struct hdist_point *ca = a;
	const struct hdist_point *cb = b;
	uint64_t aa = ca->point;
	uint64_t bb = cb->point;

    if(aa < bb)
	return -1;
    if(aa > bb)
	return 1;
    return 0;
}

static int circle_cmp_rnd(const void *a, const void *b)
{
	const struct hdist_point *ca = a;
	const struct hdist_point *cb = b;
	uint64_t aa = ca->rnd;
	uint64_t bb = cb->rnd;

    if(aa < bb)
	return -1;
    if(aa > bb)
	return 1;
    return 0;
}

static int node_cmp(const void *a, const void *b)
{
	const struct hdist_node *na = a;
	const struct hdist_node *nb = b;

    if(na->capacity > nb->capacity)
	return -1;
    if(na->capacity < nb->capacity)
	return 1;
    return 0;
}

rc_ty sxi_hdist_newbuild(sxi_hdist_t *model)
{
	unsigned int i;

    if(model->state != 0xbabe) {
	CRIT("Invalid hash distribution model");
	return EINVAL;
    }

    if(model->builds + 1 > model->max_builds) {
	CRIT("Too many builds already (max: %u)", model->max_builds);
	return EINVAL;
    }

    for(i = model->builds; i > 0; i--) {
	model->node_list[i] = model->node_list[i - 1];
	model->sxnl[i] = model->sxnl[i - 1];
	model->node_count[i] = model->node_count[i - 1];
	model->capacity_total[i] = model->capacity_total[i - 1];
	model->circle[i] = model->circle[i - 1];
	model->circle_points[i] = model->circle_points[i - 1];
    }

    model->node_list[0] = NULL;
    model->sxnl[0] = NULL;
    model->node_count[0] = 0;
    model->state = 0xcafe;
    return OK;
}

rc_ty static update_cfg(sxi_hdist_t *model)
{
	uint32_t osize;
	uLongf destLen;

    if(model->cfg_blob)
	free(model->cfg_blob);
    osize = model->cfg_size + 1;
    destLen = compressBound(osize);
    model->cfg_blob = malloc(destLen + 4);
    if(!model->cfg_blob) {
	CRIT("Can't allocate model->cfg_blob");
	return ENOMEM;
    }
    osize = swapu32(osize);
    memcpy(model->cfg_blob, &osize, 4);
    if(compress2((Bytef *) model->cfg_blob + 4, &destLen, (const Bytef *) model->cfg, model->cfg_size + 1, 9) != Z_OK) {
	CRIT("Can't compress cfg blob");
	return ENOMEM;
    }
    model->cfg_blob_size = destLen + 4;
    return OK;
}

static int hchecksum(sxi_hdist_t *model)
{
	uint64_t v;
	unsigned char sdig[SXI_SHA1_BIN_LEN];
	unsigned int i, j;
	const char *pt;
        sxi_md_ctx *sctx = sxi_md_init();

    if(!sctx)
	return 1;
    v = model->builds + model->node_count[0] + model->circle[0][0].point + model->state + model->max_builds + model->seed;
    if(!sxi_sha1_init(sctx)) {
        sxi_md_cleanup(&sctx);
        return 1;
    }
    for(i = 0; i < model->builds; i++) {
	for(j = 0; j < model->node_count[i]; j++) {
	    if(!model->node_list[i][j].sxn)
		continue;
            if (!sxi_sha1_update(sctx, sx_node_uuid(model->node_list[i][j].sxn), 16)) {
                sxi_md_cleanup(&sctx);
                return 1;
            }
	    pt = sx_node_addr(model->node_list[i][j].sxn);
	    if(pt) {
                if(!sxi_sha1_update(sctx, pt, strlen(pt))) {
                    sxi_md_cleanup(&sctx);
                    return 1;
                }
            }
	    pt = sx_node_internal_addr(model->node_list[i][j].sxn);
	    if(pt) {
                if(!sxi_sha1_update(sctx, pt, strlen(pt))) {
                    sxi_md_cleanup(&sctx);
                    return 1;
                }
            }
	    v += sx_node_capacity(model->node_list[i][j].sxn);
	}
	if(model->circle_points[i])
	    v ^= model->circle[i][model->circle_points[i] - 1].rnd;
    }
    if(!sxi_sha1_final(sctx, sdig, NULL)) {
        sxi_md_cleanup(&sctx);
        return 1;
    }
    sxi_md_cleanup(&sctx);
    model->checksum = MurmurHash64(sdig, sizeof(sdig), model->seed) ^ v;
    return 0;
}

rc_ty sxi_hdist_rebalanced(sxi_hdist_t *model)
{
	unsigned int i, j;

    if(!model)
	return EINVAL;

    if(model->state != 0xbabe) {
	CRIT("Invalid hash distribution model");
	return EINVAL;
    }

    if(model->builds < 2) {
	CRIT("Invalid number of builds (%u)", model->builds);
	return EINVAL;
    }

    for(i = 1; i < model->builds; i++) {
	for(j = 0; j < model->node_count[i]; j++)
	    sx_node_delete(model->node_list[i][j].sxn);
	free(model->node_list[i]);
	model->node_list[i] = NULL;
	sx_nodelist_delete(model->sxnl[i]);
	model->sxnl[i] = NULL;
	free(model->circle[i]);
	model->circle[i] = NULL;
    }

    model->builds = 1;
    model->version++;
    if(hchecksum(model)) {
        CRIT("Can't allocate memory for digest");
        return ENOMEM;
    }

    if(model->cfg_size + 33 > model->cfg_alloced) {
	model->cfg_alloced += CFG_PREALLOC;
	model->cfg = (char *) wrap_realloc_or_free(model->cfg, sizeof(char) * model->cfg_alloced);
	if(!model->cfg) {
	    CRIT("Can't realloc model->cfg");
	    return ENOMEM;
	}
    }
    model->cfg_size += sprintf(model->cfg + model->cfg_size, ":REBALANCED:%lld", (long long int) model->checksum);
    return update_cfg(model);
}

static int node_in_set(unsigned int *nodes, struct hdist_node *node_list, unsigned int count, unsigned int id)
{
	unsigned int i;

    if(nodes) {
	for(i = 0; i < count; i++)
	    if(nodes[i] == id)
		return 1;
    } else {
	for(i = 0; i < count; i++)
	    if(node_list[i].id == id)
		return 1;
    }

    return 0;
}

rc_ty sxi_hdist_build(sxi_hdist_t *model)
{
	unsigned int i, j, p;
	unsigned int points_total;

    if(!model || model->state != 0xcafe) {
	CRIT("Invalid hash distribution model");
	return EINVAL;
    }

    if(!model->node_count[0]) {
	CRIT("Node count is 0");
	return EINVAL;
    }

    /* Total number of points */
    points_total = MIN(model->node_count[0] * SXI_HDIST_MAX_NODE_POINTS, SXI_HDIST_MAX_TOTAL_POINTS);

    /* Cluster capacity */
    model->capacity_total[0] = 0;
    for(i = 0; i < model->node_count[0]; i++)
	model->capacity_total[0] += model->node_list[0][i].capacity;

    qsort(model->node_list[0], model->node_count[0], sizeof(struct hdist_node), node_cmp);

    model->circle[0] = (struct hdist_point *) wrap_malloc(points_total * sizeof(struct hdist_point));
    if(!model->circle[0]) {
	CRIT("Can't allocate model->circle[0]");
	return ENOMEM;
    }

    p = 0;
    if(!model->builds) {
	for(i = 0; i < model->node_count[0]; i++) {
		unsigned int node_points = (model->node_list[0][i].capacity / (float) model->capacity_total[0]) * points_total;

	    if(!node_points) {
		node_points++;
		model->circle[0] = wrap_realloc_or_free(model->circle[0], ++points_total * sizeof(struct hdist_point));
		if(!model->circle[0]) {
		    CRIT("Can't realloc model->circle[0]");
		    return ENOMEM;
		}
	    }

	    for(j = 0; j < node_points; j++) {
		if(p >= points_total) {
		    CRIT("p >= points_total (1)");
		    return FAIL_EINTERNAL;
		}
		model->circle[0][p].node_id = model->node_list[0][i].id;
		model->circle[0][p].rnd = isaac_rand(&model->rctx);
		model->circle[0][p].node_points = node_points;
		model->circle[0][p++].point = isaac_rand(&model->rctx);
	    }
	}
    } else {
	qsort(model->circle[1], model->circle_points[1], sizeof(struct hdist_point), circle_cmp_rnd);
	for(i = 0; i < model->node_count[0]; i++) {
		    unsigned int node_points = (model->node_list[0][i].capacity / (float) model->capacity_total[0]) * points_total;
		    unsigned int node_points_cnt;

		if(!node_points) {
		    node_points++;
		    model->circle[0] = wrap_realloc_or_free(model->circle[0], ++points_total * sizeof(struct hdist_point));
		    if(!model->circle[0]) {
			CRIT("Can't realloc model->circle[0]");
			return ENOMEM;
		    }
		}

		node_points_cnt = node_points;
		if(node_in_set(NULL, model->node_list[1], model->node_count[1], model->node_list[0][i].id)) {
		    for(j = 0; j < model->circle_points[1] && node_points_cnt; j++) {
			if(model->circle[1][j].node_id == model->node_list[0][i].id) {
			    if(p >= points_total) {
				CRIT("p >= points_total (2)");
				return FAIL_EINTERNAL;
			    }
			    model->circle[0][p].node_id = model->node_list[0][i].id;
			    model->circle[0][p].node_points = node_points;
			    model->circle[0][p].rnd = model->circle[1][j].rnd;
			    model->circle[0][p++].point = model->circle[1][j].point;
			    node_points_cnt--;
			}
		    }
		}
		for(j = 0; j < node_points_cnt; j++) {
		    if(p >= points_total) {
			CRIT("p >= points_total (3)");
			return FAIL_EINTERNAL;
		    }
		    model->circle[0][p].node_id = model->node_list[0][i].id;
		    model->circle[0][p].node_points = node_points;
		    model->circle[0][p].point = isaac_rand(&model->rctx);
		    model->circle[0][p++].rnd = isaac_rand(&model->rctx);
		}
	}
	qsort(model->circle[1], model->circle_points[1], sizeof(struct hdist_point), circle_cmp_point);
    }

    /*
    qsort(model->circle[0], p, sizeof(struct hdist_point), circle_cmp_rnd);
    nums = (unsigned int *) calloc(model->last_id, sizeof(unsigned int));
    if(!nums) {
        CRIT("Can't allocate memory (nums)");
        return ENOMEM;
    }
    for(i = 0; i < p; i++)
	model->circle[0][i].num = nums[model->circle[0][i].node_id - 1]++;
    free(nums);
    */

    qsort(model->circle[0], p, sizeof(struct hdist_point), circle_cmp_point);
    model->circle_points[0] = p;

    model->state = 0xbabe;
    model->builds++;
    model->version++;
    if(hchecksum(model)) {
        CRIT("Can't allocate memory for digest");
        return ENOMEM;
    }

    if(model->cfg_size + 28 > model->cfg_alloced) {
	model->cfg_alloced += CFG_PREALLOC;
	model->cfg = (char *) wrap_realloc_or_free(model->cfg, sizeof(char) * model->cfg_alloced);
	if(!model->cfg) {
	    CRIT("Can't realloc model->cfg");
	    return ENOMEM;
	}
    }
    model->cfg_size += sprintf(model->cfg + model->cfg_size, ":BUILD:%lld", (long long int) model->checksum);
    return update_cfg(model);
}

void sxi_hdist_free(sxi_hdist_t *model)
{
	unsigned int i, j;

    if(!model || !model->state)
	return;

    if(model->state != 0xcafe && model->state != 0xbabe) {
	CRIT("Corrupted hash distribution model");
	return;
    }
    free(model->capacity_total);
    free(model->circle_points);
    for(i = 0; i < model->builds; i++) {
	for(j = 0; j < model->node_count[i]; j++)
	    sx_node_delete(model->node_list[i][j].sxn);
	free(model->node_list[i]);
	sx_nodelist_delete(model->sxnl[i]);
	free(model->circle[i]);
    }
    free(model->node_count);
    free(model->node_list);
    free(model->sxnl);
    free(model->circle);
    free(model->cfg);
    free(model->cfg_blob);
    free(model);
}

/*
 * replica_count: number (>= 1) of copies to be stored on different nodes
 * dest_nodes: array of size replica_count that will be filled with node IDs
 */
static rc_ty hdist_hash(const sxi_hdist_t *model, uint64_t hash, unsigned int replica_count, unsigned int *dest_nodes, unsigned int bidx, int store)
{
	unsigned int i, j, l = 0, h, m, rdiv;
	int node_idx;

    if(!model || model->state != 0xbabe) {
	CRIT("Invalid hash distribution model");
	return EINVAL;
    }

    if(!dest_nodes) {
	CRIT("Invalid argument (dest_nodes == NULL)");
	return EINVAL;
    }

    if(bidx >= model->builds) {
	CRIT("Invalid build index (%u >= %u)", bidx, model->builds);
	return EINVAL;
    }

    if(replica_count > model->node_count[bidx]) {
	CRIT("replica_count > model->node_count[bidx]");
	return EINVAL;
    }

    h = model->circle_points[bidx] - 1;
    while(l + 1 < h) {
	m = (l + h) / 2;
	if(hash == model->circle[bidx][m].point) {
	    l = h = m;
	    break;
	}
	if(hash < model->circle[bidx][m].point)
	    h = m;
	else
	    l = m;
    }
    if(hash - model->circle[bidx][l].point > model->circle[bidx][h].point - hash)
	m = h;
    else
	m = l;

    node_idx = get_node_idx(model, bidx, model->circle[bidx][m].node_id);
    if(node_idx < 0) {
	CRIT("Node with ID %d not found", model->circle[bidx][m].node_id);
	return FAIL_EINTERNAL;
    }

    dest_nodes[0] = model->circle[bidx][m].node_id;

    rdiv = MAX_RDIV;
    for(i = 1; i < replica_count; i++) {
	node_idx = -1;
	for(j = 0; j < 2; j++) {
	    for(h = m + 1; h < model->circle_points[bidx]; h++) {
		    struct hdist_point *p = &model->circle[bidx][h];
		if(!node_in_set(dest_nodes, NULL, i, p->node_id)) {
		    /*
		    if(!j && p->num > (p->node_points / rdiv)) {
			node_idx = -1;
			continue;
		    }
		    */
		    node_idx = get_node_idx(model, bidx, p->node_id);
		    m = h;
		    break;
		}
	    }
	    if(h == model->circle_points[bidx] && m != h) {
		for(h = 0; h < m; h++) {
		    struct hdist_point *p = &model->circle[bidx][h];
		    if(!node_in_set(dest_nodes, NULL, i, p->node_id)) {
			/*
			if(!j && p->num > (p->node_points / rdiv)) {
			    node_idx = -1;
			    continue;
			}
			*/
			node_idx = get_node_idx(model, bidx, p->node_id);
			m = h;
			break;
		    }
		}
	    }
	    if(node_idx != -1)
		break;
	}
	if(node_idx == -1) {
	    CRIT("Can't replicate data");
	    return FAIL_EINTERNAL;
	}
	dest_nodes[i] = model->circle[bidx][h].node_id;
	if(rdiv >= 2)
	    rdiv--;
    }

    return 0;
}

sx_nodelist_t *sxi_hdist_locate(const sxi_hdist_t *model, uint64_t hash, unsigned int replica_count, int bidx)
{
	unsigned int *dest_nodes, i, j;
	rc_ty ret;
	sx_nodelist_t *nodelist = NULL;
	const sx_node_t *node;

    if(!model)
	return NULL;

    dest_nodes = (unsigned int *) malloc(sizeof(unsigned int) * replica_count);
    if(!dest_nodes) {
	CRIT("ERROR: Can't allocate dest_nodes");
	return NULL;
    }

    ret = hdist_hash(model, hash, replica_count, dest_nodes, bidx, 0);
    if(!ret) {
	nodelist = sx_nodelist_new();
	if(!nodelist) {
	    free(dest_nodes);
	    return NULL;
	}
	for(i = 0; i < replica_count; i++) {
	    node = NULL;
	    for(j = 0; j < model->node_count[bidx]; j++) {
		if(model->node_list[bidx][j].id == dest_nodes[i]) {
		    node = model->node_list[bidx][j].sxn;
		    break;
		}
	    }
	    if(!node) {
		CRIT("ERROR: Can't map internal node id -> sx_node_t");
		free(dest_nodes);
		sx_nodelist_delete(nodelist);
		return NULL;
	    }
	    if(sx_nodelist_add(nodelist, sx_node_dup(node))) {
		free(dest_nodes);
		sx_nodelist_delete(nodelist);
		return NULL;
	    }
	}
    }

    free(dest_nodes);
    return nodelist;
}

const sx_nodelist_t *sxi_hdist_nodelist(const sxi_hdist_t *model, int bidx)
{
    if(!model)
	return NULL;

    if((model->state == 0xcafe && bidx > model->builds) || (model->state != 0xcafe && bidx >= model->builds)) {
	CRIT("Invalid build index (%u >= %u)", bidx, model->builds);
	return NULL;
    }

    return model->sxnl[bidx];
}

unsigned int sxi_hdist_buildcnt(const sxi_hdist_t *model)
{
    return model ? model->builds : 0;
}

unsigned int sxi_hdist_version(const sxi_hdist_t *model)
{
    return model ? model->version : 0;
}

uint64_t sxi_hdist_checksum(const sxi_hdist_t *model)
{
    return model ? model->checksum : 0;
}

const sx_uuid_t *sxi_hdist_uuid(const sxi_hdist_t *model)
{
    return model ? &model->uuid : NULL;
}

int sxi_hdist_same_origin(const sxi_hdist_t *model1, const sxi_hdist_t *model2)
{
    if(!model1 || !model2)
	return 0;

    return !memcmp(&model1->uuid, &model2->uuid, sizeof(sx_uuid_t));
}
