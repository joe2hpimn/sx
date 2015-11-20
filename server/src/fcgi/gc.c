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

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "gc.h"
#include "log.h"
#include "hashfs.h"
#include "nodes.h"
#include "../libsxclient/src/curlevents.h"
#include "intervalset.h"
#include "jobmgr.h"
#include <arpa/inet.h>

static int terminate = 0;

static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}

struct heal_ctx {
    sx_hashfs_t *hashfs;
    sx_hashfs_volume_t *vol;
    uint8_t *data;
    unsigned len;
    unsigned pos;
    uint32_t need;
    unsigned eof;
    unsigned metadb;
    uint32_t revisions;
    int64_t count;
    sx_hash_t last_revision_id;
};

static int heal_pending_queries;
static int heal_pending_count;
static int64_t heal_received;

static rc_ty heal_wait(sx_hashfs_t *hashfs, int *terminate)
{
    rc_ty ret = FAIL_EINTERNAL;
    while (heal_pending_queries > 0 && !*terminate) {
        DEBUG("Waiting for %d pending queries", heal_pending_queries);
        if (sxi_curlev_poll(sxi_conns_get_curlev(sx_hashfs_conns(hashfs)))) {
            WARN("polling failed");
            return ret;
        }
    }
    if (*terminate)
        return EAGAIN;
    if (heal_pending_queries)
        WARN("pending queries negative: %d", heal_pending_queries);
    else
        ret = OK;
    DEBUG("%d pending revisions", heal_pending_count);
    heal_pending_queries = 0;
    return ret;
}


static int heal_data_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size) {
    struct heal_ctx *ctx = sxi_cbdata_get_context(cbdata);
    if (!ctx) {
        WARN("context is null");
        return -1;
    }
    if (ctx->eof) {
        WARN("received data after EOF marker: %ld bytes", size);
        return -1;
    }
    ctx->data = wrap_realloc_or_free(ctx->data, ctx->len + size);
    if (!ctx->data)
        return -1;
    memcpy(ctx->data + ctx->len, data, size);
    ctx->len += size;
    int ret = -1;
    while(!ctx->eof) {
        if (!ctx->need) {
            if (ctx->len < sizeof(ctx->need))
                return 0;
            memcpy(&ctx->need, ctx->data + ctx->pos, sizeof(ctx->need));
            ctx->need = ntohl(ctx->need);
            ctx->pos += sizeof(ctx->need);
        }
        DEBUG("%p: data: volume: %s, metadb: %d, pos=%d, need=%d, len=%d", (void*)cbdata, ctx->vol->name, ctx->metadb, ctx->pos, ctx->need, ctx->len);
        if (ctx->pos + ctx->need > ctx->len)
            return 0;
        sx_blob_t *b = sx_blob_from_data(ctx->data + ctx->pos, ctx->need);
        if (!b)
            return -1;
        do {
            ctx->pos += ctx->need;
            ctx->need = 0;
            ctx->len -= ctx->pos;
            memmove(ctx->data, ctx->data + ctx->pos, ctx->len);
            ctx->pos = 0;
            const sx_hash_t *revision_id;
            unsigned revision_blob_len;
            unsigned block_size;
            const char *magic = NULL;
            if (sx_blob_get_string(b, &magic)) {
                WARN("corrupt blob: no magic");
                break;
            }
            if (ctx->count == -1) {
                if (strcmp(magic,"[COUNT]") ||
                    sx_blob_get_int64(b, &ctx->count)) {
                    WARN("corrupt blob, magic: %s", magic);
                    break;
                }
                ret = 0;
                heal_pending_count += ctx->count;
                break;
            }
            if (!strcmp(magic, "EOF$")) {
                DEBUG("%p: got EOF: volume: %s, metadb: %d, count: %lld, got revisions: %d", (void*)cbdata, ctx->vol->name, ctx->metadb, (long long)ctx->count, ctx->revisions);
                ctx->eof = 1;
                if (sx_hashfs_heal_update(ctx->hashfs, ctx->vol, ctx->count ? &ctx->last_revision_id : NULL, ctx->metadb))
                    break;
                ret = 0;
                break;
            }
            if (strcmp(magic, "[REV]")) {
                WARN("corrupt blob, bad magic: %s", magic);
                break;
            }
            if (sx_blob_get_blob(b, (const void**)&revision_id, &revision_blob_len) ||
                revision_blob_len != sizeof(revision_id->b)) {
                WARN("corrupt blob, bad revision id");
                break;
            }
            if (sx_blob_get_int32(b, &block_size)) {
                WARN("corrupt blob received, no blocksize");
                break;
            }
            const sx_hash_t *hash;
            unsigned hash_blob_len;
            while (!sx_blob_get_blob(b, (const void**)&hash, &hash_blob_len) &&
                   hash_blob_len == sizeof(hash->b)) {
                DEBUG("got revision block");
                rc_ty s = sx_hashfs_hashop_perform(ctx->hashfs, block_size, ctx->vol->max_replica, HASHOP_INUSE, hash, NULL, revision_id, 0, NULL);
                if (s) {
                    WARN("Failed to add hash blob: %s", rc2str(s));
                    break;
                }
            }
            if (hash_blob_len) {
                WARN("corrupt blob received");
                break;
            }
            memcpy(&ctx->last_revision_id, revision_id, sizeof(ctx->last_revision_id));
            heal_pending_count--;
            ctx->revisions++;
            if (!(heal_received++ % 1000)) {
                char msg[128];
                DEBUG("Processing revision: %lld", (long long)ctx->revisions);
                if (sx_hashfs_heal_update(ctx->hashfs, ctx->vol, revision_id, ctx->metadb))
                    break;
                snprintf(msg, sizeof(msg), "Pending remote volume heal: %d queries, %lld revisions; Finished: %lld revisions", heal_pending_queries,
                         (long long)heal_pending_count, (long long)heal_received);
                sx_hashfs_set_progress_info(ctx->hashfs, INPRG_UPGRADE_RUNNING, msg);
            }
            DEBUG("processed  %ld bytes", size);
            ret = 0;
        } while(0);
        sx_blob_free(b);
    }
    return ret;
}

static void heal_finish_cb(curlev_context_t *cbdata, const char *url) {
    struct heal_ctx *ctx = sxi_cbdata_get_context(cbdata);
    if (!ctx) {
        DEBUG("ctx not set");
        return;
    }
    DEBUG("%p: finish callback for volume %s, metadb %d", (void*)cbdata, ctx->vol->name, ctx->metadb);
    while (ctx->len && !ctx->eof && !ctx->need)
        heal_data_cb(cbdata, "", 0);
    DEBUG("%p: finished callback for volume %s, metadb %d", (void*)cbdata, ctx->vol->name, ctx->metadb);
    free(ctx->data);
    ctx->data = NULL;
    free(ctx->vol);
    ctx->vol = NULL;
    free(ctx);
    sxi_cbdata_set_context(cbdata, NULL);
    heal_pending_queries--;
}

static int heal_cb(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const sx_hash_t *min_revision_in, int max_age, unsigned metadb)
{
/* TODO */
    int ret = -1;
    char query[1024];
    char *enc_vol = NULL;
    sx_nodelist_t *volnodes = NULL;
    char min_rev_hex[SXI_SHA1_TEXT_LEN+1];
    const char *for_node_uuid = sx_node_uuid_str(sx_hashfs_self(h));
    sxi_conns_t *clust = sx_hashfs_conns(h);
    sxc_client_t *sx = sx_hashfs_client(h);

    sxi_hostlist_t hlist;
    curlev_context_t *cbdata = NULL;
    unsigned blocksize;
    ret = -1;
    sxi_hostlist_init(&hlist);
    DEBUG("IN");
    do {
        cbdata = sxi_cbdata_create_generic(clust, heal_finish_cb, NULL);
        if (!cbdata) {
            WARN("failed to allocate query context");
            break;
        }
        struct heal_ctx *ctx = wrap_calloc(1, sizeof(*ctx));
        if (!ctx) {
            WARN("failed to allocate context");
            break;
        };
        ctx->vol = wrap_malloc(sizeof(*ctx->vol));
        if (!ctx->vol) {
            WARN("failed to allocate context volume");
            free(ctx);
            break;
        }
        memcpy(ctx->vol, vol, sizeof(*ctx->vol));
        ctx->hashfs = h;
        ctx->metadb = metadb;
        ctx->count = -1;
        sxi_cbdata_set_context(cbdata, ctx);
        heal_pending_queries++;

        if(min_revision_in && bin2hex(min_revision_in->b, sizeof(min_revision_in->b), min_rev_hex, sizeof(min_rev_hex))) {
            WARN("revision id hex conversion failed");
            break;
        }
        /* need to make a best effort to reach the volnodes. if there are
         * multiple replicas this could exclude the tempfaulty nodes, but if
         * there is only one replica then it'd probably better to try even the
         * tempfaulty node just in case its not completely dead */
        if (sx_hashfs_all_volnodes(h, NL_NEXTPREV, vol, SXLIMIT_MIN_FILE_SIZE, &volnodes, &blocksize)) {
            WARN("volnodes query failed");
            break;
        }
        if (!(enc_vol = sxi_urlencode(sx, vol->name, 0))) {
            WARN("failed to encode volume name");
            break;
        }
        snprintf(query, sizeof(query), "%s?o=revision_blocks&max-age=%d&min-rev=%s&metadb=%d&for-node-uuid=%s",
                enc_vol, max_age, min_revision_in ? min_rev_hex : "", metadb, for_node_uuid);
        /* must be stateless, no context param! */
        unsigned nnode, nnodes = sx_nodelist_count(volnodes);
        for (nnode=0;nnode<nnodes;nnode++) {
            if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(sx_nodelist_get(volnodes, nnode)))) {
                WARN("failed to add host");
                break;
            }
        }
        if (nnode != nnodes)
            break;
        if (sxi_cluster_query_ev_retry(cbdata, sx_hashfs_conns(h), &hlist, REQ_GET, query, NULL, 0, NULL, heal_data_cb, NULL)) {
            cbdata = NULL;/* finish cb will unref */
            WARN("failed to send query %s", query);
            break;
        }
        DEBUG("Sent query %s, ctx: %p", query, (void*)cbdata);
        ret = 0;
    } while(0);
    free(enc_vol);
    sx_nodelist_delete(volnodes);
    sxi_hostlist_empty(&hlist);
    if (cbdata && ret)
        heal_finish_cb(cbdata, NULL);
    sxi_cbdata_unref(&cbdata);
    DEBUG("callback result: %d", ret);
    /* TODO: min_revision_out */
    return ret;
}

static rc_ty process_heal(sx_hashfs_t *hashfs, int *terminate)
{
    char msg[128];
    rc_ty rc;
    heal_pending_count = 0;
    heal_received = 0;
    INFO("Checking for upgrade job");
    while (sx_hashfs_has_upgrade_job(hashfs)) {
        DEBUG("Upgrade job still running, waiting ...");
        sleep(1);
    }
    INFO("Checking for remote heal");
    while ((rc = sx_hashfs_remote_heal(hashfs, heal_cb)) == OK && !*terminate) {
        INFO("GC disabled: pending remote volume heal");
        snprintf(msg, sizeof(msg), "Pending remote volume heal: %d, %lld revisions", heal_pending_queries,
                (long long)heal_pending_count);
        DEBUG("Pending %d queries, %lld revisions", heal_pending_queries, (long long)heal_pending_count);
        if ((rc = heal_wait(hashfs, terminate)))
            return rc;
    }
    if (rc != ITER_NO_MORE)
        return rc == OK ? EAGAIN : rc;
    if (sx_hashfs_get_progress_info(hashfs, NULL) == INPRG_UPGRADE_RUNNING ||
        sx_hashfs_get_progress_info(hashfs, NULL) == INPRG_UPGRADE_COMPLETE)
        sx_hashfs_set_progress_info(hashfs, INPRG_IDLE, NULL);
    INFO("GC re-enabled: heal completed");
    return OK;
}

rc_ty hostlist_add_fallbacks(sxc_client_t *sx, sxi_hostlist_t *hl, const sx_nodelist_t *all, unsigned primary)
{
    int s;
    if (!hl || !all) {
        NULLARG();
        return EFAULT;
    }
    sxi_hostlist_init(hl);
    s = sxi_hostlist_add_host(sx, hl, sx_node_internal_addr(sx_nodelist_get(all, primary)));
    for (unsigned i=0;i<sx_nodelist_count(all) && !s;i++) {
        if (i != primary)
            s = sxi_hostlist_add_host(sx, hl, sx_node_internal_addr(sx_nodelist_get(all, i)));
    }
    if (s) {
        sxi_hostlist_empty(hl);
        return ENOMEM;
    }
    return OK;
}

static int heal_ask_data_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size)
{
    void *ctx = sxi_cbdata_get_context(cbdata);
    if (rplfiles_cb(cbdata, ctx, data, size)) {
        WARN("rplfiles_cb failed");
        return -1;
    }
    return 0;
}

static void heal_ask_finish_cb(curlev_context_t *cbdata, const char *url) {
    if (!cbdata)
        return;
    void *ctx = sxi_cbdata_get_context(cbdata);
    free(ctx);
    heal_pending_queries--;
    DEBUG("finished");
}

static rc_ty heal_ask(sx_hashfs_t *h, const sxi_hostlist_t *targets, const sx_uuid_t *node, unsigned mdb, int64_t start, int64_t stop)
{
    rc_ty ret = FAIL_EINTERNAL;
    heal_pending_queries++;
    curlev_context_t *cbdata = sxi_cbdata_create_generic(sx_hashfs_conns(h), heal_ask_finish_cb, NULL);
    if (!cbdata)
        return ENOMEM;
    char *query = NULL;
    const sx_uuid_t *self = sx_node_uuid(sx_hashfs_self(h));
    if (!self) {
        WARN("Cannot retrieve own uuid");
        return FAIL_EINTERNAL;
    }
    do {
        unsigned n = lenof(".rejoin/?mdb=&node=&start=&?stop=&dest=") + 2 + 2*UUID_STRING_SIZE + 2*COUNTER_LEN;
        query = wrap_malloc(n);
        if (!query)
            break;
        snprintf(query, n, ".rejoin/?mdb=%u&node=%s&start=%lld&stop=%lld&dest=%s", mdb, node->string, (long long)start, (long long)stop, self->string);
        DEBUG("Asking %s", query);
        struct rplfiles *ctx = wrap_calloc(1, sizeof(*ctx));
        if (!ctx) {
            ret = ENOMEM;
            break;
        }
	ctx->hashfs = h;
	ctx->b = NULL;
	ctx->pos = 0;
	ctx->ngood = 0;
	ctx->needend = 0;
	ctx->state = RPL_HDRSIZE;
        ctx->mode = MODE_HEAL;
        sxi_cbdata_set_context(cbdata, ctx);

        if (sxi_cluster_query_ev_retry(cbdata, sx_hashfs_conns(h), targets, REQ_GET, query, NULL, 0, NULL, heal_ask_data_cb, NULL)) {
            cbdata = NULL;
            break;
        }
        ret = OK;
    } while(0);
    /* will be freed when request completes */
    sxi_cbdata_unref(&cbdata);
    free(query);
    return ret;
}

rc_ty process_file_heal(sx_hashfs_t *h, int *terminate)
{
    /* this assumes that a node is only removed after all its files have been synchronized to all relevant nodes,
       i.e. you cannot remove nodes while you have faulty/pending flushes/unsynchronized nodes */
    const sx_nodelist_t *all = sx_hashfs_all_nodes(h, NL_PREVNEXT);
    unsigned nnodes = sx_nodelist_count(all);
    /* TODO: better batching */
    /*  build a nodelist with source node as first node, and all the rest as fallback nodes:
       we'll need to make the difference between an op id that is:
       - present on the remote node's interval set, with associated file => sync file, check which blocks need to be synced
        - present on the remote node's interval set, but not file => file was deleted, add opid locally nothing else to sync
        - absent on remote node's interval set => either remote node is not authoritative (i.e. a fallback node), or there is an
        upload in progress
        file / vol will be checked whether t belongs on this node, if not only blocks are checked
    */
    unsigned i;
    for (i = 0; i < nnodes && !*terminate; i++) {
        const sx_uuid_t *node = sx_node_uuid(sx_nodelist_get(all, i));
        sxi_iset_t *iset;
        DEBUG("Processing node %s", node->string);
        sxi_hostlist_t targets;
        if (hostlist_add_fallbacks(sx_hashfs_client(h), &targets, all, i))
            return ENOMEM;
        for (unsigned mdb=0;(iset = sx_hashfs_intervals(h, mdb)) && !*terminate; mdb++) {
            if (sxi_iset_iter_begin(iset, node))
                break;
            int64_t last_stop = -1;
            int64_t start, stop;
            rc_ty s;
            while ((s = sxi_iset_iter_next(iset, &start, &stop)) == OK && !*terminate) {
                int64_t m_start = last_stop + 1;
                int64_t m_stop = start - 1;
                if (m_start <= m_stop) {
                    if (heal_ask(h, &targets, node, mdb, m_start, m_stop))
                        break;
                }
            }
            /* always ask for (last_stop, +Inf) */
            if (heal_ask(h, &targets, node, mdb, last_stop + 1, INT64_MAX))
                s = FAIL_EINTERNAL;
            sxi_iset_iter_done(iset);
            if (s != ITER_NO_MORE)
                break;
        }
        sxi_hostlist_empty(&targets);
        if (iset)
            break;
    }
    if (i != nnodes)
        return FAIL_EINTERNAL;
    return heal_wait(h, terminate);
}

/* TODO: move to common header */
#define DEBUGHASH(MSG, X) do {                                          \
        char _debughash[sizeof(sx_hash_t)*2+1];                         \
        if (UNLIKELY(sxi_log_is_debug(&logger))) {                      \
            bin2hex((X)->b, sizeof(*X), _debughash, sizeof(_debughash)); \
            DEBUG("%s: #%s#", MSG, _debughash);                         \
        }                                                               \
    } while(0)



struct source {
    sx_hash_t hashes[DOWNLOAD_MAX_BLOCKS];
    unsigned n;
    const sx_node_t *node;
    unsigned replica;
};

struct fetch_ctx {
    sx_hashfs_t *h;
    char *block;
    unsigned blocksize;
    unsigned pos;
    unsigned replica;
};

static void heal_save_finish_cb(curlev_context_t *cbdata, const char *url) {
    struct fetch_ctx *ctx = sxi_cbdata_get_context(cbdata);
    if (!ctx) {
        DEBUG("ctx not set");
        return;
    }
    free(ctx->block); ctx->block = NULL;
    free(ctx);
    sxi_cbdata_set_context(cbdata, NULL);
    heal_pending_queries--;
}


static int heal_save_block_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size)
{
    struct fetch_ctx *ctx = sxi_cbdata_get_context(cbdata);
    if (!ctx) {
        DEBUG("ctx not set");
        return -1;
    }
    if (!ctx->block) {
        NULLARG();
        return -1;
    }
    int remaining = ctx->pos + size > ctx->blocksize ? ctx->blocksize - ctx->pos : size;
    memcpy(ctx->block + ctx->pos, data, remaining);
    ctx->pos += remaining;
    if (ctx->pos == ctx->blocksize) {
        if (sx_hashfs_block_put(ctx->h, ctx->block, ctx->blocksize, ctx->replica))
            return -1;
        DEBUG("saved block");
        ctx->pos = 0;
    }

    return 0;
}

static rc_ty fetch_from(sx_hashfs_t *h, struct source *source, unsigned int blocksize)
{
    rc_ty ret = OK;
    if (!h || !source) {
        NULLARG();
        return EFAULT;
    }
    if (!source->n)
        return OK;
    unsigned len = lenof(".data/1048576/") + source->n*SXI_SHA1_TEXT_LEN + 1;
    char *url = wrap_malloc(len);
    if (!url)
        return ENOMEM;
    int n = snprintf(url, len, ".data/%d/", blocksize);
    if (n < 0) {
        WARN("bad url length");
        return EINVAL;
    }
    char *c = url + n;
    for (unsigned i=0;i<source->n;i++) {
        bin2hex(source->hashes[i].b, sizeof(source->hashes[i].b), c, SXI_SHA1_TEXT_LEN+1);
        c += SXI_SHA1_TEXT_LEN;
    }
    url[len-1] = '\0';

    heal_pending_queries++;
    curlev_context_t *cbdata = sxi_cbdata_create_generic(sx_hashfs_conns(h), heal_save_finish_cb, NULL);
    do {
        if (!cbdata) {
            WARN("failed to allocate query context");
            break;
        }
        struct fetch_ctx *ctx = wrap_malloc(sizeof(*ctx));
        if (!ctx) {
            WARN("Failed to allocate fetch context");
            break;
        }
        ctx->h = h;
        ctx->blocksize = blocksize;
        ctx->block = wrap_malloc(blocksize);
        if (!ctx->block) {
            WARN("failed to allocate block");
            break;
        }
        ctx->pos = 0;
        ctx->replica = source->replica;
        sxi_cbdata_set_context(cbdata, ctx);
        if (sxi_cluster_query_ev(cbdata, sx_hashfs_conns(h), sx_node_internal_addr(source->node),
                                 REQ_GET, url, NULL, 0, NULL, heal_save_block_cb)) {
            WARN("failed to send query");
            cbdata = NULL;/* finish cb will unref */
            ret = FAIL_EINTERNAL;
        }
    } while(0);
    sxi_cbdata_unref(&cbdata);
    free(url);
    return ret;
}

rc_ty process_block_heal(sx_hashfs_t *h, int *terminate)
{
    rc_ty s;
    const sx_node_t *self = sx_hashfs_self(h);
    const sx_nodelist_t *all = sx_hashfs_all_nodes(h, NL_NEXT);
    unsigned max_replica = sx_nodelist_count(all);
    unsigned replica = 0;
    for (int i=0;i<SIZES && !*terminate;i++) {
        struct source *sources = wrap_calloc(max_replica, sizeof(*sources));
        if (!sources)
            return ENOMEM;
        for (int j=0;j<HASHDBS && !*terminate;j++) {
            s = sx_hashfs_heal_block_begin(h, i, j);
            if (s != OK)
                return s;
            sx_hash_t hash;
            sx_nodelist_t *nl = NULL;
            while ((s = sx_hashfs_heal_block_next(h, i, j, &hash)) == OK && !*terminate) {
                DEBUGHASH("needs to heal hash", &hash);
                /* TODO: should have separate heal reservations per replica? */
                nl = sx_hashfs_all_hashnodes(h, NL_NEXTPREV, &hash, max_replica);
                if (!nl) {
                    WARN("cannot allocate hashnodes");
                    break;
                }
                const sx_node_t *sourcenode = sx_nodelist_get(nl, replica);
                if (sx_node_cmp(sourcenode, self)) {
                    /* fetch from other node */
                    unsigned int idx;
                    const sx_node_t *node = sx_nodelist_lookup_index(all, sx_node_uuid(sourcenode), &idx);
                    if (!node) {
                        WARN("bad node in hashlist: %s", sx_node_uuid(sourcenode)->string);
                        break;
                    }
                    struct source *source = &sources[idx];
                    source->node = node;
                    source->replica = max_replica;
                    if (source->n < DOWNLOAD_MAX_BLOCKS)
                        memcpy(&source->hashes[source->n++], &hash, sizeof(hash));
                    else if (fetch_from(h, source, bsz[i]))
                            break;
                }
                sx_nodelist_delete(nl); nl = NULL;
            }
            sx_nodelist_delete(nl);
            sx_hashfs_heal_block_end(h, i, j);
            if (s != ITER_NO_MORE)
                return s;
        }
        for (unsigned j=0;j<max_replica && !*terminate;j++)
            if (fetch_from(h, &sources[j], bsz[i]))
                break;
        free(sources);
    }
    return heal_wait(h, terminate);
}

int gc(sxc_client_t *sx, const char *dir, int pipe, int pipe_expire) {
    struct sigaction act;
    sx_hashfs_t *hashfs;
    rc_ty rc;
    struct timeval tv0, tv1, tv2;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    hashfs = sx_hashfs_open(dir, sx);
    if (!hashfs) {
        CRIT("Failed to initialize the hash server interface");
        return EXIT_FAILURE;
    }

    INFO("GC slow check is : %s", gc_slow_check ? "enabled" : "disabled");
    memset(&tv0, 0, sizeof(tv0));
    while(!terminate) {
        int forced_awake = 0, force_expire = 0;
        /* this MUST run periodically even if we don't want to
         * GC any hashes right now */
        if (wait_trigger(pipe, gc_interval, &forced_awake))
            break;
        if (forced_awake)
            INFO("GC triggered by user");
        if (wait_trigger(pipe_expire, 0, &force_expire))
            break;
        if (force_expire)
            INFO("GC force expire is set");
        if (terminate)
            break;
        msg_new_id();

        gettimeofday(&tv1, NULL);
        sx_hashfs_distcheck(hashfs);

        INFO("file heal starting");
        rc = process_file_heal(hashfs, &terminate);
        INFO("file heal finished: %s", rc2str(rc));
        INFO("block healing starting");
        rc = process_block_heal(hashfs, &terminate);
        INFO("block healing finished: %s", rc2str(rc));
        rc = sx_hashfs_heal_reset(hashfs);
        INFO("block healing reset: %s", rc2str(rc));

        /* TODO: phase dependency (only after local upgrade completed) */
        rc = process_heal(hashfs, &terminate);
        if (rc) {
            WARN("Heal failed: %s", rc2str(rc));
            continue;
        }
        /* TODO: restrict GC until upgrade finishes locally */
        gettimeofday(&tv2, NULL);
        INFO("GC periodic completed in %.1f sec", timediff(&tv1, &tv2));
        if (rc) {
            WARN("GC error: %s", rc2str(rc));
        } else {
            if (terminate)
                break;
            if (force_expire)
                sx_hashfs_gc_periodic(hashfs, &terminate, -1);
            if (!forced_awake)
                sleep(1);
            gettimeofday(&tv1, NULL);
            if (timediff(&tv0, &tv1) > gc_interval || forced_awake) {
                INFO("Starting GC");
                sx_hashfs_gc_periodic(hashfs, &terminate, GC_GRACE_PERIOD);
                sx_hashfs_gc_run(hashfs, &terminate);
                gettimeofday(&tv2, NULL);
                INFO("GC run completed in %.1f sec", timediff(&tv1, &tv2));
                sx_hashfs_checkpoint_idle(hashfs);
                sx_hashfs_gc_info(hashfs, &terminate);
                INFO("GC completed");
                memcpy(&tv0, &tv1, sizeof(tv0));
            }
        }
        if (terminate)
            break;
        sx_hashfs_checkpoint_idle(hashfs);
    }
    sx_hashfs_close(hashfs);

    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}
