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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include "cmdline.h"
#include "hdist.h"
#include "utils.h"
#include "linenoise.h"
#include "../../../../libsx/src/vcrypto.h"
#include "../../../../libsx/src/misc.h"

#define MBVAL 1048576
#define MINSIZE (10 * MBVAL)
#define BLKPREALLOC 1000
#define MAGIC 0xACABBACA
#define MAXBUILDS 2
#define RABALANCE_BATCH_SIZE 100
#define SEED 1337

#define IA  0
#define CL  1

struct gengetopt_args_info args;

struct sxnode {
    char host[128];
    uint64_t capacity;
    uint64_t stored;
    unsigned int del_flag;
    sx_uuid_t uuid;

    unsigned int block_cnt;
    unsigned int block_avail;
    struct sxblock *block;
};

struct sxblock {
    uint64_t hash;
    unsigned int replica_cnt;
    unsigned int origin;
    unsigned int bs;
    unsigned int ds;
    unsigned int links;
    unsigned int tid;
};

struct sxcluster {
    uint32_t magic;
    sxi_hdist_t *hdist;
    unsigned int bsize_cnt[3];
    unsigned int node_cnt;
    struct sxnode *node;
    unsigned int need_update, tid;

    uint64_t capacity;
    uint64_t read;
    uint64_t stored;
    uint64_t deduped;
};

static int dedup(struct sxcluster *cluster);
static void print_cluster(struct sxcluster *cluster);
static void print_debug(struct sxcluster *cluster);
static void print_blkstats(struct sxcluster *cluster);
static int addnode(struct sxcluster *cluster, const char *host, uint64_t capacity, sx_uuid_t *uuid);
static int store_block(struct sxcluster *cluster, uint64_t hash, int bs, int ds, int replicas, unsigned int tid, unsigned int links);
static int process_data(struct sxcluster *cluster, const char *path, unsigned int replica_count, unsigned int mode);
static int execute(struct sxcluster *cluster, const char *fname);

static void free_cluster(struct sxcluster *cluster)
{
	unsigned int i;
	struct sxnode *node;

    for(i = 0; i < cluster->node_cnt; i++) {
	node = &cluster->node[i];
	if(node->block_cnt)
	    free(node->block);
    }
    free(cluster->node);
    cluster->node = NULL;
    cluster->node_cnt = 0;
    sxi_hdist_free(cluster->hdist);
}

/*
static int save_cluster(const struct sxcluster *cluster, const char *file)
{
	int fd;
	unsigned int i, j;
	int ret = 1;
	const struct sxnode *node;
	char path[1024], *newfile = NULL;
	unsigned int cfg_len;
	const void *cfg;

    if(!access(file, R_OK) || errno != ENOENT) {
	for(i = 1; i < 1000; i++) {
	    snprintf(path, sizeof(path), "%s.%u", file, i);
	    if(access(path, R_OK) && errno == ENOENT) {
		newfile = path;
		break;
	    }
	}
	if(!newfile) {
	    printf("ERROR: Can't create unique path based on %s\n", file);
	    return 1;
	}
	file = newfile;
    }

    fd = open(file, O_WRONLY|O_CREAT, 0600);
    if(fd == -1) {
	printf("ERROR: Can't open file %s for writing\n", file);
	return 1;
    }

    if(write(fd, cluster, sizeof(struct sxcluster)) != sizeof(struct sxcluster)) {
	printf("ERROR: Can't write to %s\n", file);
	goto save_err;
    }

    for(i = 0; i < cluster->node_cnt; i++) {
	node = &cluster->node[i];
	if(write(fd, node, sizeof(struct sxnode)) != sizeof(struct sxnode)) {
	    printf("ERROR: Can't write to %s\n", file);
	    goto save_err;
	}
	for(j = 0; j < node->block_cnt; j++) {
	    if(write(fd, &node->block[j], sizeof(struct sxblock)) != sizeof(struct sxblock)) {
		printf("ERROR: Can't write to %s\n", file);
		goto save_err;
	    }
	}
    }

    if(sxi_hdist_get_cfg(cluster->hdist, &cfg, &cfg_len)) {
	printf("ERROR: Can't get hdist config\n");
	goto save_err;
    }

    if(write(fd, &cfg_len, sizeof(cfg_len)) != sizeof(cfg_len)) {
	printf("ERROR: Can't write hdist size to %s\n", file);
	goto save_err;
    }

    if(write(fd, cfg, cfg_len) != cfg_len) {
	printf("ERROR: Can't write hdist config to %s\n", file);
	goto save_err;
    }

    if(write(fd, &cluster->magic, sizeof(cluster->magic)) != sizeof(cluster->magic)) {
	printf("ERROR: Can't write to %s\n", file);
	goto save_err;
    }

    ret = 0;
save_err:
    ret |= close(fd);
    if(ret)
	unlink(file);
    else
	printf("Cluster data saved to '%s'\n", file);
    return ret;
}

static int load_cluster(struct sxcluster *cluster, const char *file)
{
	int fd;
	unsigned int i, j;
	int ret = 1;
	struct sxnode *node;
	unsigned int cfg_len;
	void *cfg = NULL;

    fd = open(file, O_RDONLY);
    if(fd == -1) {
	printf("ERROR: Can't open file %s\n", file);
	return 1;
    }

    if(read(fd, cluster, sizeof(struct sxcluster)) != sizeof(struct sxcluster)) {
	printf("ERROR: Can't read %s\n", file);
	close(fd);
	memset(cluster, 0, sizeof(struct sxcluster));
	return 1;
    }

    if(cluster->magic != MAGIC || cluster->node_cnt > 10000) {
	printf("ERROR: No valid cluster data found in %s\n", file);
	close(fd);
	memset(cluster, 0, sizeof(struct sxcluster));
	return 1;
    }
    cluster->hdist = NULL;

    cluster->node = (struct sxnode *) calloc(cluster->node_cnt, sizeof(struct sxnode));
    if(!cluster->node) {
	printf("ERROR: Out of memory\n");
	close(fd);
	return 1;
    }

    for(i = 0; i < cluster->node_cnt; i++) {
	node = &cluster->node[i];
	if(read(fd, node, sizeof(struct sxnode)) != sizeof(struct sxnode)) {
	    printf("ERROR: Can't read %s\n", file);
	    node->block_cnt = 0;
	    goto load_err;
	}
	node->block_avail = 0;
	node->block = (struct sxblock *) malloc(node->block_cnt * sizeof(struct sxblock));
	if(!node->block) {
	    printf("ERROR: Out of memory\n");
	    node->block_cnt = 0;
	    goto load_err;
	}

	for(j = 0; j < node->block_cnt; j++) {
	    if(read(fd, &node->block[j], sizeof(struct sxblock)) != sizeof(struct sxblock)) {
		printf("ERROR: Can't load block from %s\n", file);
		goto load_err;
	    }
	}
    }

    if(read(fd, &cfg_len, sizeof(cfg_len)) != sizeof(cfg_len)) {
	printf("ERROR: Can't load hdist size from %s\n", file);
	goto load_err;
    }

    if(!(cfg = malloc(cfg_len))) {
	printf("ERROR: Can't allocate memoryfor hdist config\n");
	goto load_err;
    }

    if(read(fd, cfg, cfg_len) != cfg_len) {
	printf("ERROR: Can't write hdist config to %s\n", file);
	goto load_err;
    }

    cluster->hdist = sxi_hdist_from_cfg(cfg, cfg_len);
    if(!cluster->hdist) {
	printf("ERROR: Can't initialize hdist from config\n");
	goto load_err;
    }

    if(read(fd, &cluster->magic, sizeof(cluster->magic)) != sizeof(cluster->magic)) {
	printf("ERROR: Can't read from %s\n", file);
	goto load_err;
    }

    if(cluster->magic != MAGIC) {
	printf("ERROR: Broken cluster data in %s\n", file);
	goto load_err;
    }

    ret = 0;
load_err:
    close(fd);
    free(cfg);
    if(ret)
	free_cluster(cluster);
    return ret;
}
*/

static int dump_cluster(struct sxcluster *cluster, FILE *file)
{
	unsigned int i, j;
	struct sxnode *node;
	struct sxblock *block;

    if(!cluster || !file)
	return 1;

    for(i = 0; i < cluster->node_cnt; i++) {
	node = &cluster->node[i];
	if(!node->stored || node->del_flag)
	    continue;
	for(j = 0; j < node->block_cnt; j++) {
	    block = &node->block[j];
	    if(!block->hash)
		continue;
	    fprintf(file, "%s,%016llx,%u,%u,%u\n", node->host, (long long unsigned int) block->hash, block->bs, block->replica_cnt, block->links);
	}
    }

    return 0;
}

static int savecmds(const struct sxcluster *cluster, const char *file)
{
    if(linenoiseHistorySave(file)) {
	printf("ERROR: Can't save commands to %s\n", file);
	return -1;
    }
    return 0;
}

static int update(struct sxcluster *cluster)
{
	unsigned int i;

    if(!cluster->need_update)
	return 0;

    if(!cluster->hdist) {
	if(!(cluster->hdist = sxi_hdist_new(SEED, MAXBUILDS, NULL))) {
	    printf("ERROR: sxi_hdist_new failed\n");
	    return -1;
	}
    } else {
	if(sxi_hdist_buildcnt(cluster->hdist) == MAXBUILDS) {
	    printf("%u changes to cluster already, rebalance is required\n", MAXBUILDS);
	    return -1;
	}
	if(sxi_hdist_newbuild(cluster->hdist) != OK) {
	    printf("ERROR: Can't update distribution model (REBALANCE REQUIRED/FIXME)\n");
	    return -1;
	}
    }

    for(i = 0; i < cluster->node_cnt; i++) {
	if(!cluster->node[i].del_flag && sxi_hdist_addnode(cluster->hdist, &cluster->node[i].uuid, "0.0.0.0", "0.0.0.0", cluster->node[i].capacity, NULL) != OK) {
	    printf("ERROR: Can't add new node to hdist\n");
	    return -1;
	}
    }

    if(sxi_hdist_build(cluster->hdist) != OK) {
	printf("ERROR: Can't build distribution model\n");
	return -1;
    }

    cluster->need_update = 0;
    return 0;
}

static struct sxnode *getnode(struct sxcluster *cluster, const sx_uuid_t *uuid)
{
	unsigned int i;

    for(i = 0; i < cluster->node_cnt; i++)
	if(!memcmp(&cluster->node[i].uuid, uuid, sizeof(*uuid)))
	    return &cluster->node[i];

    printf("ERROR: Node UUID %s not found\n", uuid->string);
    return NULL;
}

static int rebalance(struct sxcluster *cluster)
{
	unsigned int i, j, k, cfg_len;
	struct sxnode *node;
	struct sxcluster newcluster;
	const void *cfg;

    if(!cluster->node_cnt) {
	printf("ERROR: rebalance: Null cluster\n");
	return -1;
    }

    if(update(cluster))
	return -1;

    if(sxi_hdist_buildcnt(cluster->hdist) < 2) {
	printf("No rebalance required\n");
	return 0;
    }

    if(sxi_hdist_get_cfg(cluster->hdist, &cfg, &cfg_len)) {
	printf("ERROR: Can't retrieve hdist config\n");
	return -1;
    }

    memset(&newcluster, 0, sizeof(newcluster));
    if(!(newcluster.hdist = sxi_hdist_from_cfg(cfg, cfg_len))) {
	printf("ERROR: Can't load hdist\n");
	return -1;
    }

    for(i = 0; i < cluster->node_cnt; i++) {
	if(cluster->node[i].del_flag)
	    continue;
	addnode(&newcluster, cluster->node[i].host, cluster->node[i].capacity, &cluster->node[i].uuid);
    }

    for(i = 0; i < cluster->node_cnt; i++) {
	    uint64_t datamoved = 0;
	    struct sxblock *block;
	    int stays;
	    sx_nodelist_t *nl_cur;

	node = &cluster->node[i];
	if(node->del_flag == 2 || (node->del_flag == 1 && !node->stored))
	    continue;

	if(!node->stored) {
	    printf("No data moved from node '%s' (new/empty node)\n", node->host);
	    continue;
	}
	for(j = 0; j < node->block_cnt; j++) {
	    block = &node->block[j];
	    if(!block->hash)
		continue;

	    nl_cur = sxi_hdist_locate(newcluster.hdist, block->hash, block->replica_cnt, 0);
	    if(!nl_cur) {
		printf("ERROR: rebalance: Can't calculate destination nodes (bidx: 0)\n");
		return -1;
	    }

	    if(!block->origin) {
		stays = 0;
		for(k = 0; k < block->replica_cnt; k++) {
		    const sx_node_t *n = sx_nodelist_get(nl_cur, k);
		    if(!memcmp(&node->uuid, sx_node_uuid(n), sizeof(node->uuid))) {
			stays = 1;
			break;
		    }
		}
		if(!stays)
		    datamoved += block->bs;
		sx_nodelist_delete(nl_cur);
		continue;
	    }

	    if(store_block(&newcluster, block->hash, block->bs, block->ds, block->replica_cnt, 0, block->links) < 0) {
		printf("ERROR: rebalance: Can't store block\n");
		printf("--- DUMP OF PARTIALLY REBALANCED CLUSTER ---\n");
		print_cluster(&newcluster);
		printf("--- END OF DUMP ---\n");
		sx_nodelist_delete(nl_cur);
		return -1;
	    }

	    stays = 0;
	    for(k = 0; k < block->replica_cnt; k++) {
		const sx_node_t *n = sx_nodelist_get(nl_cur, k);
		if(!memcmp(&node->uuid, sx_node_uuid(n), sizeof(node->uuid))) {
		    stays = 1;
		    break;
		}
	    }
	    sx_nodelist_delete(nl_cur);
	    if(!stays)
		datamoved += block->bs;
	}
	printf("Data moved from node '%s': %llu MB (%.1f%%)\n", node->host, (long long unsigned) datamoved / MBVAL, 100.0 * datamoved / node->stored);
	if(cluster->node[i].del_flag == 1)
	    cluster->node[i].del_flag++;
    }

    newcluster.read = cluster->read;
    newcluster.deduped = cluster->deduped;
    dedup(&newcluster);
    free_cluster(cluster);
    memcpy(cluster, &newcluster, sizeof(newcluster));
    cluster->need_update = 0;

    return sxi_hdist_rebalanced(cluster->hdist);
}

/*
static int rebalanceV2(struct sxcluster *cluster)
{
	unsigned int i, j, k, p, points_total, *block_idx;
	sxi_hdist_t *oldmod;
	struct sxnode *node, *newnode;
	unsigned int *repchain_new, *repchain_old;
	struct sxcluster newcluster;

    oldmod = cluster->hdist;
    if(oldmod->state != 0xbabe) {
	printf("ERROR: rebalance: Invalid hash distribution model\n");
	return -1;
    }

    if(!cluster->node_cnt) {
	printf("ERROR: rebalance: Null cluster\n");
	return -1;
    }

    memset(&newcluster, 0, sizeof(newcluster));
    sxi_hdist_init(newcluster.hdist, oldmod->seed, oldmod->max_builds);
    memcpy(&newcluster.bsize_cnt, &cluster->bsize_cnt, sizeof(newcluster.bsize_cnt));
    memcpy(newcluster.hdist.rctx, cluster->hdist.rctx, sizeof(newcluster.hdist.rctx));
    newcluster.last_node_id = cluster->last_node_id;

    for(i = 0; i < cluster->node_cnt; i++) {
	if(cluster->node[i].del_flag)
	    continue;
	addnode(&newcluster, cluster->node[i].host, cluster->node[i].capacity, cluster->node[i].id);
	sxi_hdist_addnode(newcluster.hdist, cluster->node[i].id, cluster->node[i].capacity);
    }

    if(!newcluster.hdist.node_count[0]) {
	printf("ERROR: rebalance: No nodes in hdist\n");
	free_cluster(&newcluster);
	return -1;
    }

    points_total = MIN(cluster->node_cnt * 10000, SXI_HDIST_MAX_POINTS);

    for(i = 0; i < newcluster.hdist.node_count[0]; i++)
	newcluster.hdist.capacity_total[0] += newcluster.hdist.node_list[0][i].capacity;
    qsort(newcluster.hdist.node_list[0], newcluster.hdist.node_count[0], sizeof(struct sxi_hdist_node), hdist_node_cmp);

    newcluster.hdist.circle[0] = (struct sxi_hdist_point *) calloc(points_total, sizeof(struct sxi_hdist_point));
    if(!newcluster.hdist.circle[0]) {
	printf("ERROR: rebalance: Can't allocate newcluster.hdist.circle[0]\n");
	free_cluster(&newcluster);
	return -1;
    }

    qsort(oldmod->circle[0], oldmod->circle_points[0], sizeof(struct sxi_hdist_point), circle_cmp_rnd);
    p = 0;
    for(i = 0; i < newcluster.hdist.node_count[0]; i++) {
	    unsigned int node_points = (newcluster.hdist.node_list[0][i].capacity / (float) newcluster.hdist.capacity_total[0]) * points_total;

	for(j = 0; j < oldmod->circle_points[0] && node_points; j++) {
	    if(oldmod->circle[0][j].node_id == newcluster.hdist.node_list[0][i].id) {
		if(p >= points_total) {
		    printf("ERROR: rebalance: p >= points_total (1)\n");
		    free_cluster(&newcluster);
		    return -1;
		}
		newcluster.hdist.circle[0][p].node_id = newcluster.hdist.node_list[0][i].id;
		newcluster.hdist.circle[0][p].point = oldmod->circle[0][j].point;
		newcluster.hdist.circle[0][p++].rnd = oldmod->circle[0][j].rnd;
		node_points--;
	    }
	}

	for(j = 0; j < node_points; j++) {
	    if(p >= points_total) {
		printf("ERROR: rebalance: p >= points_total (2)\n");
		free_cluster(&newcluster);
		return -1;
	    }
	    newcluster.hdist.circle[0][p].node_id = newcluster.hdist.node_list[0][i].id;
	    isaac(newcluster.hdist.rctx);
	    newcluster.hdist.circle[0][p].point = MurmurHash64(newcluster.hdist.rctx.randrsl, sizeof(newcluster.hdist.rctx.randrsl), newcluster.hdist.seed);
	    isaac(newcluster.hdist.rctx);
	    newcluster.hdist.circle[0][p++].rnd = MurmurHash64(newcluster.hdist.rctx.randrsl, sizeof(newcluster.hdist.rctx.randrsl), newcluster.hdist.seed);
	}
    }
    qsort(newcluster.hdist.circle[0], p, sizeof(struct sxi_hdist_point), circle_cmp_point);
    newcluster.hdist.circle_points[0] = p;

    newcluster.hdist.state = 0xbabe;
    newcluster.hdist.builds++;

    qsort(oldmod->circle[0], oldmod->circle_points[0], sizeof(struct sxi_hdist_point), circle_cmp_point);

    repchain_new = malloc(sizeof(unsigned int) * newcluster.hdist.node_count[0]);
    if(!repchain_new) {
	printf("ERROR: rebalance: Can't allocate repchain_new\n");
	free_cluster(&newcluster);
	return -1;
    }
    repchain_old = malloc(sizeof(unsigned int) * oldmod->node_count[0]);
    if(!repchain_old) {
	printf("ERROR: rebalance: Can't allocate repchain_old\n");
	free(repchain_new);
	free_cluster(&newcluster);
	return -1;
    }

    block_idx = malloc(sizeof(unsigned int) * oldmod->node_count[0]);
    if(!repchain_old) {
	printf("ERROR: rebalance: Can't allocate block_idx\n");
	free(repchain_new);
	free(repchain_old);
	free_cluster(&newcluster);
	return -1;
    }

    for(i = 0; i < cluster->node_cnt; i++)
	block_idx[i] = cluster->node[i].block_cnt;

    i = 0;
    while(1) {
	    uint64_t datamoved = 0;
	    struct sxblock *block;
	    unsigned int bcnt = 0;

	for(j = 0; j < cluster->node_cnt; j++)
	    bcnt += block_idx[j];

	if(!bcnt)
	    break;

	i %= cluster->node_cnt;
	if(!block_idx[i]) {
	    i++;
	    continue;
	}
	node = &cluster->node[i];
	if(!node->stored) {
	    printf("No data moved from node '%s' (new/empty node)\n", node->host);
	    i++;
	    continue;
	}

	bcnt = 0;
	for(j = block_idx[i] - 1; (int) j >= 0; j--, block_idx[i]--) {
	    block = &node->block[j];
	    if(!block->hash)
		continue;

	    if(!block->origin) {
		    int stays = 0;
		if(sxi_hdist_hash(newcluster.hdist, block->hash, block->replica_cnt, repchain_new) != OK) {
		    printf("ERROR: rebalance: Can't calculate destination nodes\n");
		    free(repchain_new);
		    free(repchain_old);
		    free(block_idx);
		    free_cluster(&newcluster);
		    return -1;
		}
		for(k = 0; k < block->replica_cnt; k++) {
		    newnode = getnode(&newcluster, repchain_new[k]);
		    if(node->id == newnode->id) {
			stays = 1;
			break;
		    }
		}
		if(!stays)
		    datamoved += block->bs;
		continue;
	    }

	    if(store_block(&newcluster, block->hash, block->bs, block->ds, block->replica_cnt, repchain_new, 0, block->links) < 0) {
		printf("ERROR: rebalance: Can't store block\n");
		free(repchain_new);
		free(repchain_old);
		free(block_idx);
		printf("--- DUMP OF PARTIALLY REBALANCED CLUSTER ---\n");
		print_cluster(&newcluster);
		printf("--- END OF DUMP ---\n");
		free_cluster(&newcluster);
		return -1;
	    }

	    if(sxi_hdist_hash_bidx(oldmod, block->hash, block->replica_cnt, repchain_old, 0) < 0) {
		printf("ERROR: rebalance: Can't calculate location of existing replicas\n");
		free(repchain_new);
		free(repchain_old);
		free(block_idx);
		free_cluster(&newcluster);
		return -1;
	    }

	    newnode = getnode(&newcluster, *repchain_new);
	    if(newnode->id != node->id)
		datamoved += block->bs;

	    if(++bcnt >= RABALANCE_BATCH_SIZE)
		break;
	}
	i++;
    }

    free(repchain_new);
    free(repchain_old);
    free(block_idx);
    newcluster.read = cluster->read;
    newcluster.deduped = cluster->deduped;
    free_cluster(cluster);
    memcpy(cluster, &newcluster, sizeof(newcluster));
    cluster->need_update = 0;
    return 0;
}
*/

int64_t str2size(const char *str)
{
	const char *suffixes = "kKmMgGtT", *ptr;
	int64_t size;

    size = strtoll(str, (char **) &ptr, 0);
    if(size <= 0 || size == LLONG_MAX) {
	printf("Invalid size %s\n", str);
	return -1;
    }

    if(*ptr) {
	unsigned int shl;
	ptr = strchr(suffixes, *ptr);
	if(!ptr) {
	    printf("Invalid size %s (bad suffix)\n", str);
	    return -1;
	}
	shl = (((ptr-suffixes)/2) + 1) * 10;
	size <<= shl;
    } else { /* default is M */
	size <<= 20;
    }

    return size;
}

static int addnode(struct sxcluster *cluster, const char *host, uint64_t capacity, sx_uuid_t *uuid)
{
	struct sxnode *node_new;
	unsigned int i;

    for(i = 0; i < cluster->node_cnt; i++) {
	if(!strcmp(cluster->node[i].host, host) && !cluster->node[i].del_flag) {
	    printf("Node '%s' already exists\n", host);
	    return -1;
	}
    }

    if(capacity < MINSIZE) {
	printf("ERROR: Minimum node size is %u bytes\n", MINSIZE);
	return -1;
    }

    node_new = (struct sxnode *) realloc(cluster->node, (cluster->node_cnt + 1) * sizeof(struct sxnode));
    if(!node_new) {
	printf("ERROR: Out of memory\n");
	return -1;
    }
    cluster->node = node_new;
    memset(&cluster->node[cluster->node_cnt], 0, sizeof(struct sxnode));
    sxi_strlcpy(cluster->node[cluster->node_cnt].host, host, sizeof(cluster->node[cluster->node_cnt].host));
    cluster->node[cluster->node_cnt].capacity = capacity;
    cluster->capacity += capacity;
    if(!uuid)
	uuid_generate(&cluster->node[cluster->node_cnt].uuid);
    else
	memcpy(&cluster->node[cluster->node_cnt].uuid, uuid, sizeof(*uuid));

    cluster->node_cnt++;
    return 0;
}

static int read_nodes(struct sxcluster *cluster)
{
	FILE *fh;
	char buff[128];
	unsigned int line = 0;
	int ret = 0;

    fh = fopen(args.node_list_arg, "r");
    if(!fh) {
	printf("Can't open file %s\n", args.node_list_arg);
	return -1;
    }

    while(fgets(buff, sizeof(buff), fh)) {
	    char host[128], size1[128], size2[128];
	    int64_t s1 = 0, s2 = 0;
	    int len = strlen(buff);

	line++;
	if(!len)
	    break;
	if(sscanf(buff, "%[^@]@%s:%s", host, size1, size2) == 3) {
	    s1 = str2size(size1);
	    s2 = str2size(size2);
	    if(s1 == -1 || s2 == -1) {
		printf("ERROR: Invalid node size at line %u\n", line);
		ret = -1;
		break;
	    }
	    if(s2 > s1) {
		printf("ERROR: Used space > capacity for %s at line %u\n", host, line);
		ret = -1;
		break;
	    }
	    s1 -= s2;
	} else if(sscanf(buff, "%[^@]@%s", host, size1) == 2) {
	    s1 = str2size(size1);
	    if(s1 == -1) {
		printf("ERROR: Invalid node size at line %u\n", line);
		ret = -1;
		break;
	    }
	} else {
	    printf("ERROR: Can't parse line %u in %s\n", line, args.node_list_arg);
	    ret = -1;
	    break;
	}

	if(addnode(cluster, host, s1, NULL) < 0) {
	    ret = -1;
	    break;
	}
    }
    fclose(fh);

    if(ret < 0)
	free_cluster(cluster);

    return ret;
}

static int store_block(struct sxcluster *cluster, uint64_t hash, int bs, int ds, int replicas, unsigned int tid, unsigned int links)
{
	struct sxnode *node;
	unsigned int i;
	sx_nodelist_t *nl;

    nl = sxi_hdist_locate(cluster->hdist, hash, replicas, 0);
    if(!nl) {
	printf("ERROR: store_block: Can't calculate destination nodes (bidx: 0)\n");
	return -1;
    }

    for(i = 0; i < replicas; i++) {
	const sx_node_t *n = sx_nodelist_get(nl, i);
	node = getnode(cluster, sx_node_uuid(n));
	if(!node) {
	    sx_nodelist_delete(nl);
	    return -1;
	}

	if(node->stored + bs > node->capacity) {
	    if(!tid)
		dedup(cluster);
	    if(node->stored + bs > node->capacity) {
		printf("Not enough space on node '%s'\n", node->host);
		sx_nodelist_delete(nl);
		return -2;
	    }
	}

	if(!node->block_avail) {
		struct sxblock *block;
	    block = realloc(node->block, sizeof(struct sxblock) * (node->block_cnt + BLKPREALLOC));
	    if(!block) {
		printf("ERROR: Out of memory (node->block)\n");
		sx_nodelist_delete(nl);
		return -1;
	    }
	    node->block = block;
	    node->block_avail = BLKPREALLOC;
	}
	node->block[node->block_cnt].hash = hash;
	node->block[node->block_cnt].bs = bs;
	node->block[node->block_cnt].ds = ds;
	node->block[node->block_cnt].origin = !i;
	node->block[node->block_cnt].replica_cnt = replicas;
	node->block[node->block_cnt].links = links ? links : 1;
	node->block[node->block_cnt++].tid = tid;
	node->block_avail--;

	node->stored += bs;
	cluster->stored += bs;

	if(!i) {
		unsigned int blkidx;

	    if(bs == args.autobs_small_arg)
		blkidx = 0;
	    else if(bs == args.autobs_big_arg)
		blkidx = 2;
	    else
		blkidx = 1;
	    cluster->bsize_cnt[blkidx]++;
	    cluster->read += ds;
	}
    }
    sx_nodelist_delete(nl);
    return 0;
}

static int block_cmp(const void *a, const void *b)
{
	const struct sxblock *ba = a;
	const struct sxblock *bb = b;

    if(ba->hash > bb->hash)
	return 1;
    if(ba->hash < bb->hash)
	return -1;
    if(ba->origin > bb->origin)
	return 1;
    if(ba->origin < bb->origin)
	return -1;
    return 0;
}

static int dedup(struct sxcluster *cluster)
{
	struct sxnode *n;
	unsigned int i, j, blkidx;

    for(i = 0; i < cluster->node_cnt; i++) {
	n = &cluster->node[i];
	qsort(n->block, n->block_cnt, sizeof(struct sxblock), block_cmp);
	for(j = 1; j < n->block_cnt; j++) {
	    if(n->block[j - 1].hash && n->block[j - 1].hash == n->block[j].hash) {
		cluster->deduped += n->block[j - 1].bs;
		cluster->stored -= n->block[j - 1].bs;
		n->stored -= n->block[j - 1].bs;
		n->block[j].replica_cnt = MAX(n->block[j].replica_cnt, n->block[j - 1].replica_cnt);
		n->block[j].links += n->block[j - 1].links;
		n->block[j - 1].hash = 0;
		if(n->block[j - 1].origin) {
		    if(n->block[j - 1].bs == args.autobs_small_arg)
			blkidx = 0;
		    else if(n->block[j - 1].bs == args.autobs_big_arg)
			blkidx = 2;
		    else
			blkidx = 1;
		    cluster->bsize_cnt[blkidx]--;
		}
	    }
	}
    }

    return 0;
}

static uint64_t hashcalc(struct sxcluster *cluster, const void *buffer, unsigned int len) {
    unsigned char d[20];

    if (sxi_sha1_calc(NULL, 0, buffer, len, d)) {
	printf("ERROR: Cannot compute hash: crypto library failure\n");
	return 0;
    }

    return MurmurHash64(d, sizeof(d), SEED);
}

static void shutdown(struct sxcluster *cluster, int ret)
{
    free_cluster(cluster);
    cmdline_parser_free(&args);
    sxi_vcrypto_cleanup();
    exit(ret);
}

static unsigned int auto_addnode_id = 1;

static int autoupgrade(struct sxcluster *cluster)
{
	int needupd = 0;

    if(args.on_lowspace_addnode_given) {
	    char host[128], newhost[128], cap[128];
	    int64_t size;
	if(sscanf(args.on_lowspace_addnode_arg, "%[^@]@%s", host, cap) == 2) {
	    size = str2size(cap);
	    if(size == -1)
		return -1;
	    snprintf(newhost, sizeof(newhost), "%s-%u", host, auto_addnode_id);
	    if(addnode(cluster, newhost, size, NULL))
		return -1;
	    printf("AUTO UPGRADE: Added new node '%s' with capacity of %lld MB\n", newhost, (long long) size);
	    auto_addnode_id++;
	    needupd = 1;
	} else return -1;

    } else if(args.on_lowspace_addspace_given) {
	    struct sxnode *node;
	    unsigned int i;
	for(i = 0; i < cluster->node_cnt; i++) {
	    node = &cluster->node[i];
	    if(node->stored + args.autobs_big_arg >= node->capacity) {
		    int64_t size;
		size = str2size(args.on_lowspace_addspace_arg);
		if(size == -1)
		    return -1;
		printf("AUTO UPGRADE: Resizing node '%s': %llu MB -> %llu MB\n", node->host, (long long unsigned) node->capacity / MBVAL, (long long unsigned) (node->capacity + size) / MBVAL);
		node->capacity += size;
		cluster->capacity += size;
		needupd = 1;
	    }
	}
    }

    if(args.on_upgrade_rebalance_flag) {
	printf("AUTO UPGRADE: Forcing rebalance\n");
	return needupd ? rebalance(cluster) : -1;
    } else if(sxi_hdist_buildcnt(cluster->hdist) == MAXBUILDS) {
	printf("AUTO UPGRADE: Rebalance required - running\n");
	return rebalance(cluster);
    }

    return needupd ? rebalance(cluster) : -1;
}

void manage_completion(const char *line, linenoiseCompletions *lc)
{
	unsigned int len, i;
	char *commands[] = { "addnode", "help", "info", "debug", "blkstats", "resize",
			     "rebalance", /* "rebalanceV2", */ "continue", "save",
			     "savecmds", "dump", "exit" };

    while(*line == ' ')
	line++;
    len = strlen(line);
    for(i = 0; i < sizeof(commands) / sizeof(*commands); i++)
	if(!strncmp(line, commands[i], len < strlen(commands[i]) ? len : strlen(commands[i])))
	    linenoiseAddCompletion(lc, commands[i]);
}

void interactive_completion(const char *line, linenoiseCompletions *lc)
{
	unsigned int len, i;
	char *commands[] = { "addnode", "delnode", "help", "info", "debug", "blkstats", "resize",
			     "rebalance", /* "rebalanceV2", */ "store", "save", "savecmds",
			     "load", "dump", "reset", "execute", "exit" };

    while(*line == ' ')
	line++;
    len = strlen(line);
    for(i = 0; i < sizeof(commands) / sizeof(*commands); i++)
	if(!strncmp(line, commands[i], len < strlen(commands[i]) ? len : strlen(commands[i])))
	    linenoiseAddCompletion(lc, commands[i]);
}

static int runcmd(struct sxcluster *cluster, int mode, char *line)
{

    if(!strncmp(line, "help", 4)) {
	printf("List of commands:\n");
	printf("  help		-> display this help\n");
	printf("  info		-> display cluster information\n");
	printf("  debug		-> display debug info\n");
	printf("  blkstats	-> display block stats for input data\n");
	printf("\n");
	printf("  addnode	-> add new node\n");
	printf("  delnode	-> delete existing node\n");
	printf("  resize	-> resize single node\n");
	printf("  rebalance	-> force cluster rebalance\n");
	/* printf("  rebalanceV2	-> force cluster rebalance (V2 - testing)\n"); */
	printf("\n");
	if(mode == IA)
	printf("  store		-> store data from PATH with optional replica count N\n");
	printf("  dump		-> dump cluster content to file in CSV format\n");
	printf("  savecmds	-> save commands executed in this session to file\n");
	if(mode == IA)
	printf("  reset		-> reset cluster\n");
	if(mode == CL)
	printf("  continue	-> exit management mode and continue data processing\n");
	if(mode == IA)
	printf("  execute	-> execute commands from batch file\n");
	printf("  exit		-> exit sxsim\n");

    } else if(!strncmp(line, "info", 4)) {
	if(mode == IA && !cluster->node_cnt)
	    printf("Null cluster, use 'addnode' to add new nodes\n");
	else
	    print_cluster(cluster);

    } else if(!strncmp(line, "debug", 5)) {
	print_debug(cluster);

    } else if(!strncmp(line, "blkstats", 8)) {
	if(mode == IA && !cluster->node_cnt)
	    printf("Null cluster, use 'addnode' to add new nodes\n");
	else
	    print_blkstats(cluster);

    } else if(!strncmp(line, "addnode", 7)) {
	    char host[128], cap[128];
	    unsigned int len = strlen(line);
	    int64_t size;

	if(len < 10 || strlen(line) >= 128 || sscanf(&line[8], "%[^@]@%s", host, cap) != 2) {
	    printf("Usage: addnode NODE@CAPACITY\n");
	    printf("       CAPACITY allows K, M, G, T suffixes; default is M\n");
	} else {
	    size = str2size(cap);
	    if(size != -1 && !addnode(cluster, host, size, NULL))
		cluster->need_update = 1;
	}

    } else if(mode == IA && !strncmp(line, "delnode", 7)) {
	    struct sxnode *node;
	    unsigned int i, found = 0;
	    const char *host = &line[8], ret = 0;

	if(strlen(line) < 9) {
	    printf("Usage: delnode HOST\n");
	    return 0;
	}
	for(i = 0; i < cluster->node_cnt; i++) {
	    node = &cluster->node[i];
	    if(!strcmp(node->host, host)) {
		if(cluster->stored > cluster->capacity - node->capacity) {
		    printf("ERROR: Not enough free space in cluster to delete node '%s'\n", node->host);
		    return 1;
		}
		found = 1;
		node->del_flag = 1;
		cluster->need_update = 1;
		if(!node->stored) {
		    cluster->capacity -= node->capacity;
		} else {
		    if(!sxi_hdist_version(cluster->hdist)) {
			printf("Updating distribution model...\n");
			update(cluster);
		    }
		    rebalance(cluster);
		}
		break;
	    }
	}
	if(!found) {
	    printf("Node '%s' doesn't exist\n", host);
	    return 1;
	}

	if(ret)
	    printf("ERROR: Couldn't delete node '%s'\n", host);
	else
	    printf("Node '%s' deleted\n", host);

	return ret;

    } else if(!strncmp(line, "resize", 6)) {
	    char host[128], cap[128];
	    unsigned int len = strlen(line), i, found = 0;
	    int64_t size;
	    struct sxnode *node;

	if(len < 10 || strlen(line) >= 128 || sscanf(&line[7], "%[^@]@%s", host, cap) != 2) {
	    printf("Usage: resize NODE@NEW_CAPACITY\n");
	    printf("       NEW_CAPACITY allows K, M, G, T suffixes; default is M\n");
	} else {
	    size = str2size(cap);
	    if(size == -1)
		return 0;
	    for(i = 0; i < cluster->node_cnt; i++) {
		node = &cluster->node[i];
		if(!strcmp(cluster->node[i].host, host)) {
		    found = 1;
		    if(size < node->stored) {
			printf("FIXME: resize to less than stored not supported yet\n");
		    } else {
			    int64_t diff = size - node->capacity;
			printf("Resizing node '%s': %llu MB -> %llu MB (%s%lld MB)\n", node->host, (unsigned long long) node->capacity / MBVAL, (unsigned long long) size / MBVAL, diff > 0 ? "+" : "", (long long) diff / MBVAL);
			node->capacity += diff;
			cluster->capacity += diff;
			cluster->need_update = 1;
		    }
		}
	    }
	    if(!found)
		printf("Node '%s' doesn't exist\n", host);
	}

/*
    } else if(!strncmp(line, "rebalanceV2", 11)) {
	if(mode == IA) {
	    if(!cluster->node_cnt) {
		printf("Null cluster, use 'addnode' to add new nodes\n");
		return 0;
	    }
	    if(!sxi_hdist_version(cluster->hdist) || cluster->loaded) {
		printf("Updating distribution model...\n");
		update(cluster);
	    }
	}
	rebalanceV2(cluster);
*/
    } else if(!strncmp(line, "rebalance", 9)) {
	if(mode == IA) {
	    if(!cluster->node_cnt) {
		printf("Null cluster, use 'addnode' to add new nodes\n");
		return 0;
	    }
	    if(!sxi_hdist_version(cluster->hdist)) {
		printf("Updating distribution model...\n");
		update(cluster);
	    }
	}
	rebalance(cluster);

    } else if(mode == IA && !strncmp(line, "store", 5)) {
	    char *path;
	    unsigned int p, replica_count = 1;

	if(strlen(line) < 7) {
	    printf("Usage: store [N:]PATH\n");
	    printf("       PATH can be a directory or file\n");
	    printf("       N is an optional replica count, default is 1\n");
	    return 0;
	}
	path = &line[6];

	if(!cluster->node_cnt) {
	    printf("Null cluster, use 'addnode' to add new nodes\n");
	    return 0;
	}

	for(p = 0; p < strlen(path) - 1; p++) {
	    if(isdigit(path[p]))
		continue;
	    if(p && path[p] == ':') {
		path[p] = 0;
		replica_count = atoi(path);
		path = &path[p + 1];
	    }
	    break;
	}

	if(replica_count > cluster->node_cnt) {
	    printf("ERROR: Invalid replica count %u (> number of nodes (%u))\n", replica_count, cluster->node_cnt);
	    return 0;
	}

	if(!sxi_hdist_version(cluster->hdist) || cluster->need_update) {
	    printf("Updating distribution model...\n");
	    update(cluster);
	}

	printf("Processing data in %s (replica count = %u)\n", path, replica_count);
	if(process_data(cluster, path, replica_count, IA) == -2)
	    printf("Not enough space - please add more space/nodes and try again\n");

/*
    } else if(mode == IA && !strncmp(line, "load", 4)) {
	    struct sxcluster newcluster;

	if(strlen(line) < 6) {
	    printf("Usage: load FILE\n");
	    return 0;
	}

	if(!load_cluster(&newcluster, &line[5])) {
	    free_cluster(cluster);
	    memcpy(cluster, &newcluster, sizeof(newcluster));
	    printf("Cluster data loaded from '%s'\n", &line[5]);
	}
*/
    } else if(!strncmp(line, "savecmds", 8)) {
	if(strlen(line) < 10)
	    printf("Usage: savecmds FILE\n");
	else
	    savecmds(cluster, &line[9]);
/*
    } else if(!strncmp(line, "save", 4)) {
	if(strlen(line) < 6)
	    printf("Usage: save FILE\n");
	else {
	    if(!cluster->node_cnt)
		printf("Null cluster, use 'addnode' to add new nodes\n");
	    else {
		cluster->magic = MAGIC;
		save_cluster(cluster, &line[5]);
	    }
	}
*/
    } else if(!strncmp(line, "dump", 4)) {
	if(strlen(line) < 6) {
	    printf("Usage: dump FILE/-\n");
	} else {
	    if(!cluster->stored)
		printf("Empty cluster, nothing to dump\n");
	    else {
		if(!strcmp(&line[5], "-")) {
		    dump_cluster(cluster, stdout);
		} else {
			FILE *file = fopen(&line[5], "w");
		    if(!file) {
			printf("ERROR: Can't open '%s' for writing\n", &line[5]);
			return 0;
		    }
		    dump_cluster(cluster, file);
		    if(fclose(file))
			printf("ERROR: Failed to close file '%s'\n", &line[5]);
		    else
			printf("Cluster data dumped to '%s'\n", &line[5]);
		}
	    }
	}

    } else if(!strncmp(line, "reset", 5)) {
	if(strlen(line) != 9 || strcmp(line, "reset all")) {
	    printf("Usage: reset all\n");
	} else {
	    free_cluster(cluster);
	    memset(cluster, 0, sizeof(struct sxcluster));
	}

    } else if(mode == CL && !strncmp(line, "continue", 8)) {
	if(cluster->need_update) {
	    if(args.on_upgrade_rebalance_flag) {
		printf("Forcing rebalance\n");
		rebalance(cluster);
	    } else
		update(cluster);
	}
	return 2;

    } else if(!strncmp(line, "execute", 7)) {
	if(strlen(line) < 9)
	    printf("Usage: execute FILE\n");
	else
	    execute(cluster, &line[8]);

    } else if(!strncmp(line, "exit", 4)) {
	shutdown(cluster, 0);

    } else {
	printf("Unknown command '%s'\n", line);
    }

    return 0;
}

static int execute(struct sxcluster *cluster, const char *fname)
{
	char buff[256];
	FILE *file = fopen(fname, "r");

    if(!file) {
	printf("ERROR: Can't open file '%s'\n", fname);
	return 1;
    }
    printf("Executing commands from '%s'\n", fname);
    while(fgets(buff, sizeof(buff), file)) {
	    char *cmd = buff;
	if(buff[strlen(buff) - 1] == '\n')
	    buff[strlen(buff) - 1] = 0;
	while(*cmd == ' ')
	    cmd++;
	printf("COMMAND: %s\n", cmd);
	runcmd(cluster, IA, cmd);
    }
    fclose(file);
    linenoiseHistoryLoad(fname);
    return 0;
}

static int interactive(struct sxcluster *cluster, int mode)
{
	char *line, *linept;

    if(mode == IA) { /* interactive */
	linenoiseSetCompletionCallback(interactive_completion);
	printf("Interactive mode, type \"help\" to display available options\n");
    } else { /* management in cmdline mode */
	linenoiseSetCompletionCallback(manage_completion);
	printf("Entering cluster management mode, type \"help\" to display available options\n");
    }
    while((line = linept = linenoise("command> "))) {
	if(*line) {
	    linenoiseHistoryAdd(line);
	    while(*line == ' ')
		line++;

	    if(runcmd(cluster, mode, line) == 2)
		break;
        }
        free(linept);
    }

    return 0;
}

static int read_hash_list(struct sxcluster *cluster)
{
	FILE *fh;
	char buff[128];
	unsigned int hash[64];
	int line = 0;
	int ret = 0;

    if(!(fh = fopen(args.hash_list_arg, "r"))) {
	printf("ERROR: Can't open file %s\n", args.hash_list_arg);
	return -1;
    }

    while(fgets(buff, sizeof(buff), fh)) {
	    char *repcnt;
	    unsigned int hreps = args.replica_count_arg;
	    int buflen;

	line++;
	repcnt = strrchr(buff, ',');
	if(repcnt) {
	    *repcnt++ = 0;
	    if(!args.replica_count_given) {
		hreps = atoi(repcnt);
		if(!hreps || hreps > cluster->node_cnt) {
		    printf("ERROR: Invalid replica count for hash at line %d (replicas: %u, nodes: %u)\n", line, hreps, cluster->node_cnt);
		    ret = -1;
		    break;
		}
	    }
	}

	buflen = strlen(buff);
	if(buff[buflen - 1] == '\n') {
	    buff[buflen - 1] = 0;
	    buflen--;
	}
	if(buflen % 2) {
	    printf("ERROR: Invalid hexstring at line %u\n", line);
	    ret = -1;
	    break;
	}

	if(hex2bin(buff, buflen, (uint8_t *) hash, buflen / 2) == -1) {
	    printf("ERROR: Can't decode hexstring at line %u\n", line);
	    ret = -1;
	    break;
	}

	ret = store_block(cluster, MurmurHash64(hash, buflen / 2, SEED), args.block_size_arg, args.block_size_arg,  hreps, 0, 0);
	if(ret == -2) {
	    if((ret = autoupgrade(cluster)))
		ret = interactive(cluster, CL);
	    if(!ret)
		ret = store_block(cluster, MurmurHash64(hash, buflen / 2, SEED), args.block_size_arg, args.block_size_arg, hreps, 0, 0);
	}
	if(ret < 0) {
	    printf("ERROR: Can't store data\n");
	    break;
	}
    }
    fclose(fh);
    return ret;
}

static int process_file(struct sxcluster *cluster, const char *file, unsigned int replica_count, unsigned int tid)
{
	FILE *fh;
	char *blk;
	unsigned int blksize = args.block_size_arg;
	size_t bread;
	uint64_t hash;
	struct stat sb;
	int ret;


    if(stat(file, &sb) < 0) {
	printf("ERROR: Can't access file %s\n", file);
	return 1;
    }

    if(!args.block_size_given) { /* autobs */
	if(sb.st_size <= args.autobs_small_limit_arg) {
	    blksize = args.autobs_small_arg;
	} else if(sb.st_size >= args.autobs_big_limit_arg) {
	    blksize = args.autobs_big_arg;
	} else {
	    blksize = args.autobs_medium_arg;
	}
    }

    blk = malloc(blksize);
    if(!blk) {
	printf("ERROR: Out of memory (process_file)\n");
	return 1;
    }

    fh = fopen(file, "rb");
    if(!fh) {
	printf("ERROR: Can't open file %s\n", file);
	free(blk);
	return 1;
    }

    while((bread = fread(blk, 1, blksize, fh)) > 0) {
	hash = hashcalc(cluster, blk, bread);
	if(!hash) {
	    printf("ERROR: Can't calculate hash for block in %s\n", file);
	    fclose(fh);
	    free(blk);
	    return 1;
	}
	ret = store_block(cluster, hash, blksize, bread, replica_count ? replica_count : args.replica_count_arg, tid, 0);
	if(ret == -2 && !tid) {
	    if((ret = autoupgrade(cluster)))
		ret = interactive(cluster, CL);
	    if(!ret)
		ret = store_block(cluster, hash, blksize, bread, replica_count ? replica_count : args.replica_count_arg, tid, 0);
	}

	if(ret < 0) {
	    if(!tid)
		printf("ERROR: Can't store block of %s\n", file);
	    fclose(fh);
	    free(blk);
	    return ret;
	}
    }
    free(blk);
    fclose(fh);
    return 0;
}

static int process_dir(struct sxcluster *cluster, const char *dirname, unsigned int replica_count, unsigned int tid)
{
	DIR *dir;
	struct dirent *dent;
	struct stat sb;
	char path[2048];
	int ret = 0;

    if(!(dir = opendir(dirname))) {
	printf("ERROR: Can't open directory %s\n", dirname);
	return 1;
    }

    while((dent = readdir(dir))) {
	if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
	    sprintf(path, "%s/%s", dirname, dent->d_name);
	    if(lstat(path, &sb) == -1)
		continue;

	    if(S_ISDIR(sb.st_mode)) {
		ret = process_dir(cluster, path, replica_count, tid);
	    } else if(S_ISREG(sb.st_mode)) {
		ret = process_file(cluster, path, replica_count, tid);
	    }
	    if(ret == -2)
		break;
	}
    }
    closedir(dir);
    return ret;
}

static int gc(struct sxcluster *cluster, unsigned int tid)
{
	struct sxnode *n;
	unsigned int i, j, blkidx;

    for(i = 0; i < cluster->node_cnt; i++) {
	n = &cluster->node[i];
	for(j = 0; j < n->block_cnt; j++) {
	    if(n->block[j].tid == tid) {
		cluster->stored -= n->block[j].bs;
		n->stored -= n->block[j].bs;
		n->block[j].hash = 0;
		n->block[j].tid = 0;
		if(n->block[j].origin) {
		    if(n->block[j].bs == args.autobs_small_arg)
			blkidx = 0;
		    else if(n->block[j].bs == args.autobs_big_arg)
			blkidx = 2;
		    else
			blkidx = 1;
		    cluster->bsize_cnt[blkidx]--;
		    cluster->read -= n->block[j].ds;
		}
	    }
	}
    }

    return 0;
}

static int process_data(struct sxcluster *cluster, const char *path, unsigned int replica_count, unsigned int mode)
{
	struct stat sb;
	int ret = 1;

    if(stat(path, &sb) == -1) {
	printf("ERROR: Can't access path %s\n", path);
	return 1;
    }

    if(S_ISDIR(sb.st_mode)) {
	ret = process_dir(cluster, path, replica_count, mode == IA ? ++cluster->tid : 0);
    } else if(S_ISREG(sb.st_mode)) {
	ret = process_file(cluster, path, replica_count, mode == IA ? ++cluster->tid : 0);
    } else {
	printf("ERROR: Not supported file type\n");
    }

    if(mode == IA && ret == -2) {
	printf("Reverting transaction\n");
	gc(cluster, cluster->tid);
	return ret;
    }

    dedup(cluster);
    return ret;
}

static void print_debug(struct sxcluster *cluster)
{
    printf("* Cluster:\n");
    printf(" - magic: 0x%x\n", cluster->magic);
    printf(" - nodes: %u\n", cluster->node_cnt);
    printf(" - need update: %u\n", cluster->need_update);
    printf(" - transaction ID: %u\n", cluster->tid);
    printf(" - capacity: %llu\n", (unsigned long long) cluster->capacity);
    printf(" - read: %llu\n", (unsigned long long) cluster->read);
    printf(" - stored: %llu\n", (unsigned long long) cluster->stored);
    printf(" - deduped: %llu\n", (unsigned long long) cluster->deduped);
    printf("* Distribution model:\n");
    printf(" - Version: %u\n", sxi_hdist_version(cluster->hdist));
    printf(" - Number of builds: %u, max: %u\n", sxi_hdist_buildcnt(cluster->hdist), MAXBUILDS);
    printf(" - Checksum: %llu\n", (unsigned long long) sxi_hdist_checksum(cluster->hdist));
    printf(" - Seed: 0x%x\n", SEED);
}

static void print_blkstats(struct sxcluster *cluster)
{
    printf("Block stats for input data (excl. replicas):\n");
    if(args.block_size_given) {
	printf(" - block size: %u\n", args.block_size_arg);
	printf(" - block count: %u\n", cluster->bsize_cnt[0]);
    } else {
	    unsigned int bcount = cluster->bsize_cnt[0] + cluster->bsize_cnt[1] + cluster->bsize_cnt[2];
	printf(" - block size: auto (%u|%u|%u)\n", args.autobs_small_arg, args.autobs_medium_arg, args.autobs_big_arg);
	printf(" - total block count: %u\n", bcount);
	if(!bcount)
	    bcount++;
	printf(" - small (%u) block count: %u (%.1f%%) data size: %.1f MB\n", args.autobs_small_arg, cluster->bsize_cnt[0], 100.0 * cluster->bsize_cnt[0] / bcount, (uint64_t) args.autobs_small_arg * cluster->bsize_cnt[0] / (float) MBVAL);
	printf(" - medium (%u) block count: %u (%.1f%%) data size: %.1f MB\n", args.autobs_medium_arg, cluster->bsize_cnt[1], 100.0 * cluster->bsize_cnt[1] / bcount, (uint64_t) args.autobs_medium_arg * cluster->bsize_cnt[1] / (float) MBVAL);
	printf(" - big (%u) block count: %u (%.1f%%) data size: %.1f MB\n", args.autobs_big_arg, cluster->bsize_cnt[2], 100.0 * cluster->bsize_cnt[2] / bcount, (uint64_t) args.autobs_big_arg * cluster->bsize_cnt[2] / (float) MBVAL);
    }
}

static void print_cluster(struct sxcluster *cluster)
{
	unsigned int i;
	struct sxnode *n;

    if(cluster->read) {
	/* bsize = (unsigned long long) args.autobs_small_arg * cluster->bsize_cnt[0] + (unsigned long long) args.autobs_medium_arg * cluster->bsize_cnt[1] + (unsigned long long) args.autobs_big_arg * cluster->bsize_cnt[2]; */
	printf("Data read from disk: %.1f MB\n", cluster->read / (float) MBVAL);
    }
    printf("Deduplicated data: %.1f MB / %.1f MB (%.1f%%)\n", cluster->deduped / (float) MBVAL, (cluster->stored + cluster->deduped) / (float) MBVAL, 100.0 * cluster->deduped / (cluster->deduped + cluster->stored + 1));
    printf("Total space usage: %.1f MB / %llu MB (%.1f%%)\n", cluster->stored / (float) MBVAL, (unsigned long long) cluster->capacity / MBVAL, 100.0 * cluster->stored / (cluster->capacity + 1));

    for(i = 0; i < cluster->node_cnt; i++) {
	n = &cluster->node[i];
	if(n->del_flag)
	    continue;
	printf("Node %s: %.1f MB / %llu MB (%.1f%%)\n", n->host, n->stored / (float) MBVAL, (unsigned long long) n->capacity / MBVAL, 100.0 * n->stored / (n->capacity + 1));
    }
}

int main(int argc, char **argv)
{
	struct sxcluster cluster;
	int i, ret = 0;

    if(cmdline_parser(argc, argv, &args))
	return 1;

    if (ssl_version_check())
        return 1;

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, src_version());
	cmdline_parser_free(&args);
	return 0;
    }

    if(argc == 1 || args.execute_given) {
	if(!isatty(fileno(stdin))) {
	    printf("ERRNO: stdin is not a terminal. Please use --execute if you want to pass commands to sxsim.\n");
	    cmdline_parser_free(&args);
	    return 1;
	}
	memset(&cluster, 0, sizeof(cluster));
	if(args.execute_given && execute(&cluster, args.execute_arg))
	    shutdown(&cluster, 1);
	return interactive(&cluster, IA);
    }

    if(args.on_lowspace_addnode_given) {
	    const char *arg = args.on_lowspace_addnode_arg;
	    char host[128], cap[128];
	if(args.on_lowspace_addspace_given) {
	    printf("ERROR: --on-lowspace-addnode and --on-lowspace-addspace cannot be used both at the same time\n");
	    cmdline_parser_free(&args);
	    return 1;
	}
	if(strlen(arg) < 3 || strlen(arg) >= 128 || sscanf(arg, "%[^@]@%s", host, cap) != 2 || str2size(cap) == -1) {
	    printf("ERROR: Invalid argument for --on-lowspace-addnode\n");
	    cmdline_parser_free(&args);
	    return 1;
	}
    }

    if(args.on_lowspace_addspace_given) {
	if(str2size(args.on_lowspace_addspace_arg) == -1) {
	    printf("ERROR: Invalid argument for --on-lowspace-addspace\n");
	    cmdline_parser_free(&args);
	    return 1;
	}
    }

    memset(&cluster, 0, sizeof(cluster));

    if(args.dump_cluster_given) {
	/*
	if(load_cluster(&cluster, args.dump_cluster_arg))
	    shutdown(&cluster, 1);
	*/
	ret = dump_cluster(&cluster, stdout);
	shutdown(&cluster, ret ? 1 : 0);
    }
/*
    if(args.load_cluster_given)
	if(load_cluster(&cluster, args.load_cluster_arg))
	    shutdown(&cluster, 1);
*/
    if(args.node_list_given)
	if(read_nodes(&cluster) < 0)
	    shutdown(&cluster, 1);

    if(!cluster.node_cnt) {
	printf("Cluster not initialized (see --help)\n");
	shutdown(&cluster, 1);
    }

    cluster.magic = MAGIC;

    if(!args.replica_count_arg || args.replica_count_arg > cluster.node_cnt) {
	printf("ERROR: Invalid replica count %d (must be > 0 and < number of nodes)\n", args.replica_count_arg);
	shutdown(&cluster, 1);
    }

    if(!(cluster.hdist = sxi_hdist_new(SEED, MAXBUILDS, NULL))) {
	printf("ERROR: sxi_hdist_new failed\n");
	shutdown(&cluster, 1);
    }

    for(i = 0; i < cluster.node_cnt; i++) {
	if(sxi_hdist_addnode(cluster.hdist, &cluster.node[i].uuid, "0.0.0.0", "0.0.0.0", cluster.node[i].capacity, NULL) != OK) {
	    printf("ERROR: Can't add new node to hdist\n");
	    shutdown(&cluster, 1);
	}
    }

    if(sxi_hdist_build(cluster.hdist) != OK) {
	printf("ERROR: Can't build distribution model\n");
	shutdown(&cluster, 1);
    }

    if(args.hash_list_given)
	ret = read_hash_list(&cluster);
    else if(args.store_data_given) {
	for(i = 0; i < args.store_data_given; i++) {
		char *path = args.store_data_arg[i];
		unsigned int p, replica_count = 0; /* 0 -> use args.replica_count_arg */

	    for(p = 0; p < strlen(path) - 1; p++) {
		if(isdigit(path[p]))
		    continue;
		if(p && path[p] == ':') {
		    path[p] = 0;
		    replica_count = atoi(path);
		    path = &path[p + 1];
		}
		break;
	    }
	    printf("Processing data in %s (replica count = %u)\n", path, replica_count ? replica_count : args.replica_count_arg);
	    if(replica_count && replica_count > cluster.node_cnt) {
		printf("ERROR: Invalid replica count %u (> number of nodes (%u))\n", replica_count, cluster.node_cnt);
		shutdown(&cluster, 1);
	    }
	    ret = process_data(&cluster, path, replica_count, CL);
	}
    }

    dedup(&cluster);
    print_cluster(&cluster);
    if(args.blkstats_given)
	print_blkstats(&cluster);

/*
    if(args.save_cluster_given)
	save_cluster(&cluster, args.save_cluster_arg);
*/
    shutdown(&cluster, ret ? 1 : 0);
}
