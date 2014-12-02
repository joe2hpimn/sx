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

#include "hashfs.h"
#include "log.h"
#include "blockmgr.h"

static int terminate = 0;

static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}

struct blockmgr_hlist_t {
    int64_t ids[DOWNLOAD_MAX_BLOCKS];
    sx_hash_t binhs[DOWNLOAD_MAX_BLOCKS];
    uint8_t havehs[DOWNLOAD_MAX_BLOCKS];
    unsigned int nblocks;
};

static int hcb(const char *hash, unsigned int index, int code, void *context) {
    struct blockmgr_hlist_t *list = (struct blockmgr_hlist_t *)context;

    if(!hash || !list)
	return -1;

    if(code != 200)
	return 0;

    if(index >= list->nblocks) {
	WARN("Index out of bounds");
	return -1;
    }

    list->havehs[index] = 1;
    return 0;
}

struct blockmgr_data_t {
    sx_hashfs_t *hashfs;
    sqlite3_stmt *qprune, *qlist, *qdel, *qbump;
};

static void blockmgr_del_xfer(struct blockmgr_data_t *q, int64_t xfer_id) {
    sqlite3_reset(q->qdel);
    if(sx_hashfs_blkrb_release(q->hashfs, xfer_id) != OK)
	WARN("Failed to release block %lld", (long long)xfer_id);
    else if(qbind_int64(q->qdel, ":id", xfer_id) ||
       qstep_noret(q->qdel))
	WARN("Failed to delete transfer %lld", (long long)xfer_id);
    sqlite3_reset(q->qdel);
}

static void blockmgr_reschedule_xfer(struct blockmgr_data_t *q, int64_t xfer_id) {
    sqlite3_reset(q->qbump);
    if(qbind_int64(q->qbump, ":id", xfer_id) ||
       qstep_noret(q->qbump))
	WARN("Failed to delete transfer %lld", (long long)xfer_id);
    sqlite3_reset(q->qbump);
}

static uint8_t upbuffer[UPLOAD_CHUNK_SIZE];
void blockmgr_process_queue(struct blockmgr_data_t *q) {
    sxc_client_t *sx = sx_hashfs_client(q->hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(q->hashfs);
    const sx_node_t *me = sx_hashfs_self(q->hashfs);
    sxi_hostlist_t uploadto;

    sxi_hostlist_init(&uploadto);
    sqlite3_reset(q->qlist);

    while(!terminate) {
	struct blockmgr_hlist_t hlist;
	int r = qstep(q->qlist), bs;
	unsigned int hlen, nlen, i, j, trigger_jobmgr = 0;
	const sx_node_t *node;
	sx_uuid_t node_uuid;
	const void *h, *n;
	int64_t xfer_id;
	sxi_hashop_t hc;
	uint8_t *curb;
        const char *token = NULL;

	if(r == SQLITE_DONE) {
	    DEBUG("No more pending transfers");
	    break;
	}
	if(r != SQLITE_ROW) {
	    WARN("Cannot list queued transfers");
	    break;
	}

	xfer_id = sqlite3_column_int64(q->qlist, 0);
	h = sqlite3_column_blob(q->qlist, 1);
	hlen = sqlite3_column_bytes(q->qlist, 1);
	bs = sqlite3_column_int(q->qlist, 2);
        n = sqlite3_column_blob(q->qlist, 3);
	nlen = sqlite3_column_bytes(q->qlist, 3);
	if(!h || hlen != SXI_SHA1_BIN_LEN || /* Bad hash */
	   !n || nlen != sizeof(node_uuid.binary) || /* Bad node */
	   sx_hashfs_check_blocksize(bs)) { /* Bad blocksize */
	    WARN("Removing bad transfer");
	    sqlite3_reset(q->qlist);
	    blockmgr_del_xfer(q, xfer_id);
	    continue;
	}
	uuid_from_binary(&node_uuid, n);

	/* MODHDIST: no point in transfering to _prev set */
	if(!(node = sx_nodelist_lookup(sx_hashfs_nodelist(q->hashfs, NL_NEXT), &node_uuid))) {
	    WARN("Removing transfer to non existing node %s", node_uuid.string);
	    sqlite3_reset(q->qlist);
	    blockmgr_del_xfer(q, xfer_id);
	    continue;
	}

	if(!sx_node_cmp(node, me)) {
	    WARN("Removing transfer to self");
	    sqlite3_reset(q->qlist);
	    blockmgr_del_xfer(q, xfer_id);
	    continue;
	}

        const char *host = sx_node_internal_addr(node);
	sxi_hostlist_empty(&uploadto);
	if(sxi_hostlist_add_host(sx, &uploadto, host)) {
	    WARN("Cannot generate hostlist");
	    break;
	}

	memset(&hlist, 0, sizeof(hlist));
        if(sx_hashfs_make_token(q->hashfs, CLUSTER_USER, NULL, 0, time(NULL) + JOB_FILE_MAX_TIME, &token)) {
            WARN("Cannot create blockmgr token");
            break;
        }
        /* just check for presence, reservation was already done by the failed
         * INUSE */
	sxi_hashop_begin(&hc, clust, hcb, HASHOP_CHECK, 0, NULL, NULL, &hlist, 0);
        for(hlist.nblocks = 0; r == SQLITE_ROW; hlist.nblocks++) {
	    /* Some preliminary extra checks; broken entries will be wiped on the next (outer) loop */
	    h = sqlite3_column_blob(q->qlist, 1);
	    hlen = sqlite3_column_bytes(q->qlist, 1);
	    n = sqlite3_column_blob(q->qlist, 3);
	    nlen = sqlite3_column_bytes(q->qlist, 3);
	    if(!h || hlen != SXI_SHA1_BIN_LEN) {
                WARN("Bad hash");
		break;
            }
	    if(!n || nlen != sizeof(node_uuid.binary)) {
                WARN("Bad node");
		break;
            }
	    if(memcmp(n, node_uuid.binary, sizeof(node_uuid.binary))) {
                WARN("Inconsistent node");
		break;
            }
	    if(bs != sqlite3_column_int(q->qlist, 2)) {
                WARN("Inconsistent bs");
		break;
            }

	    hlist.ids[hlist.nblocks] = sqlite3_column_int64(q->qlist, 0);
            memcpy(&hlist.binhs[hlist.nblocks], h, SXI_SHA1_BIN_LEN);
            if(sxi_hashop_batch_add(&hc, host, hlist.nblocks, h, bs) != 0) {
                WARN("Cannot verify block presence: %s", sxc_geterrmsg(sx));
                blockmgr_reschedule_xfer(q, hlist.ids[hlist.nblocks]);
            }

	    r = qstep(q->qlist);
	}

	if(r != SQLITE_DONE || !hlist.nblocks) {
	    WARN("Failed to retrieve the transfer list");
	    break;
	}

	sqlite3_reset(q->qlist);

	if(sxi_hashop_end(&hc) == -1) {
	    WARN("Cannot verify block presence on node %s: %s", node_uuid.string, sxc_geterrmsg(sx));
	    for(j=0; j<hlist.nblocks; j++)
		blockmgr_reschedule_xfer(q, hlist.ids[j]);
	    continue;
	}

	curb = upbuffer;
	for(i=0; i<hlist.nblocks; i++) {
	    const uint8_t *b;
	    if(hlist.havehs[i]) {
                /* TODO: print actual hash */
		DEBUG("Block %d was found remotely", i);
		blockmgr_del_xfer(q, hlist.ids[i]);
	    } else if(sx_hashfs_block_get(q->hashfs, bs, &hlist.binhs[i], &b)) {
		INFO("Block %ld was not found locally", hlist.ids[i]);
		blockmgr_reschedule_xfer(q, hlist.ids[i]);
	    } else {
		memcpy(curb, b, bs);
		curb += bs;
	    }
	    if(sizeof(upbuffer) - (curb - upbuffer) < bs || i == hlist.nblocks - 1) {
		/* upload chunk */
		if(sxi_upload_block_from_buf(clust, &uploadto, token, upbuffer, bs, curb-upbuffer)) {
		    WARN("Block transfer failed");
		    for(j=0; j<=i; j++)
			if(!hlist.havehs[j])
			    blockmgr_reschedule_xfer(q, hlist.ids[j]);
		    break;
		}
		curb = upbuffer;
		for(j=0; j<=i; j++) {
                    char debughash[sizeof(sx_hash_t)*2+1];
                    const sx_hash_t *hash = &hlist.binhs[j];
		    if(hlist.havehs[j])
			continue;
                    bin2hex(hash->b, sizeof(hash->b), debughash, sizeof(debughash));
		    DEBUG("Block %ld #%s# was transferred successfuly", hlist.ids[j], debughash);
		    blockmgr_del_xfer(q, hlist.ids[j]);
		    hlist.havehs[j] = 1;
		    trigger_jobmgr = 1;
		}
	    }
	}

	if(trigger_jobmgr)
	    sx_hashfs_job_trigger(q->hashfs);
        sx_hashfs_checkpoint_passive(q->hashfs);
    }
    sxi_hostlist_empty(&uploadto);
    sqlite3_reset(q->qlist); /* Better safe than deadlocked */
}

int blockmgr(sxc_client_t *sx, const char *self, const char *dir, int pipe) {
    struct blockmgr_data_t q;
    struct sigaction act;
    sxi_db_t *xferdb;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    act.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);

    memset(&q, 0, sizeof(q));

    q.hashfs = sx_hashfs_open(dir, sx);
    if(!q.hashfs) {
	CRIT("Failed to initialize the hash server interface");
	goto blockmgr_err;
    }

    xferdb = sx_hashfs_xferdb(q.hashfs);

    if(qprep(xferdb, &q.qprune, "DELETE FROM topush WHERE id IN (SELECT id FROM topush LEFT JOIN onhold ON block = hblock AND size = hsize AND node = hnode WHERE hid IS NULL) AND sched_time > expiry_time")) /* If you touch this query, please double check index usage! */
	goto blockmgr_err;
    if(qprep(xferdb, &q.qlist, "SELECT a.id, a.block, a.size, a.node FROM topush AS a LEFT JOIN (SELECT size, node FROM topush ORDER BY sched_time ASC LIMIT 1) AS b ON a.node = b.node AND a.size = b.size WHERE b.node IS NOT NULL AND b.size IS NOT NULL AND sched_time <= strftime('%Y-%m-%d %H:%M:%f') ORDER BY sched_time ASC LIMIT "STRIFY(DOWNLOAD_MAX_BLOCKS)))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qdel, "DELETE FROM topush WHERE id = :id"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qbump, "UPDATE topush SET sched_time = strftime('%Y-%m-%d %H:%M:%f', sched_time, '"STRIFY(BLOCKMGR_RESCHEDULE)" seconds') WHERE id = :id"))
	goto blockmgr_err;

    while(!terminate) {
	int dc;
        if (wait_trigger(pipe, blockmgr_delay, NULL))
            break;

	DEBUG("Start processing block queue");

	dc = sx_hashfs_distcheck(q.hashfs);
	if(dc < 0) {
	    CRIT("Failed to reload distribution");
	    goto blockmgr_err;
	} else if(dc > 0) {
	    /* MODHDIST: the model has changed, what do ? */
	    INFO("Distribution reloaded");
	}

	qstep_noret(q.qprune);
	blockmgr_process_queue(&q);
	DEBUG("Done processing block queue");
        sx_hashfs_checkpoint_xferdb(q.hashfs);
        sx_hashfs_checkpoint_gc(q.hashfs);
        sx_hashfs_checkpoint_passive(q.hashfs);
    }

 blockmgr_err:
    sqlite3_finalize(q.qbump);
    sqlite3_finalize(q.qprune);
    sqlite3_finalize(q.qlist);
    sqlite3_finalize(q.qdel);
    sx_hashfs_close(q.hashfs);
    close(pipe);
    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}
