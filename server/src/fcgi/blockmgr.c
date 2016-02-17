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
    struct blockmgr_hlist_t hashlist;
    sx_hashfs_t *hashfs;
    sqlite3_stmt *qprune, *qdel, *qbump;
    sqlite3_stmt *qget_first_hi, *qget_first_lo, *qget_next_lo, *qget_next_hi;
    sqlite3_stmt *qwipesched, *qaddsched;
    const sx_node_t *target;
    int64_t last_flowid; /* this may be uninitialized and that's ok */
    unsigned int blocksize;
};

static void blockmgr_del_xfer(struct blockmgr_data_t *q, int64_t xfer_id) {
    sx_uuid_t target;
    sx_hash_t block;
    int64_t flowid = FLOW_DEFAULT_UID;
    rc_ty s;

    if(verbose_rebalance) {
	sqlite3_stmt *qinfo = NULL;
	const void *tptr, *bptr;
	if(!qprep(sx_hashfs_xferdb(q->hashfs), &qinfo, "SELECT flow, block, node FROM topush WHERE id = :id") &&
	   !qbind_int64(qinfo, ":id", xfer_id) &&
	   qstep(qinfo) == SQLITE_ROW &&
	   (flowid = sqlite3_column_int64(qinfo, 0)) == FLOW_BULK_UID &&
	   (bptr = sqlite3_column_blob(qinfo, 1)) &&
	   sqlite3_column_bytes(qinfo, 1) == sizeof(block) &&
	   (tptr = sqlite3_column_blob(qinfo, 2)) &&
	   sqlite3_column_bytes(qinfo, 2) == sizeof(target.binary)) {
	    uuid_from_binary(&target, tptr);
	    memcpy(&block, bptr, sizeof(block));
	} else
	    flowid = FLOW_DEFAULT_UID;
	sqlite3_finalize(qinfo);
    }

    s = sx_hashfs_blkrb_release(q->hashfs, xfer_id);
    if(s != OK && s != ENOENT) {
	WARN("Failed to release block %lld", (long long)xfer_id);
	if(flowid == FLOW_BULK_UID)
	    rbl_log(&block, "blkrb_release", 0, "Error %d (%s)", s,  msg_get_reason());
    } else {
	if(flowid == FLOW_BULK_UID)
	    rbl_log(&block, "blkrb_release", 1, s == OK ? "Block released" : "Block not locked");
	sqlite3_reset(q->qdel);
	if(qbind_int64(q->qdel, ":id", xfer_id) ||
	   qstep_noret(q->qdel))
	WARN("Failed to delete transfer %lld", (long long)xfer_id);
	sqlite3_reset(q->qdel);
    }
}

static void blockmgr_reschedule_xfer(struct blockmgr_data_t *q, int64_t xfer_id) {
    sqlite3_reset(q->qbump);
    if(qbind_int64(q->qbump, ":id", xfer_id) ||
       qstep_noret(q->qbump))
	WARN("Failed to reschedule transfer %lld", (long long)xfer_id);
    sqlite3_reset(q->qbump);
}

static int schedule_blocks_sfq(struct blockmgr_data_t *q) {
    sx_uuid_t target_uuid;
    sqlite3_stmt *qget;
    int ret = 0, r;

    DEBUG("in %s", __func__);
    qget = q->qget_first_hi;
    if(qbind_int64(qget, ":flow", q->last_flowid)) {
	WARN("Error retrieving master block from queue");
	return -1;
    }
    r = qstep(qget);
    if(r == SQLITE_DONE) {
	qget = q->qget_first_lo;
	if(qbind_int64(qget, ":flow", q->last_flowid)) {
	    WARN("Error retrieving master block from queue");
	    return -1;
	}
	r = qstep(qget);
    }
    if(r == SQLITE_DONE) {
	DEBUG("No blocks in the queue");
	return 0;
    }
    if(r != SQLITE_ROW) {
	WARN("Error retrieving master block from queue");
	return -1;
    }

    do {
	int64_t push_id;
	const void *p;
	int i;

	/* SELECT id, flow, block[, size, node] */
	push_id = sqlite3_column_int64(qget, 0);
	q->last_flowid = sqlite3_column_int64(qget, 1);

	if(!ret) {
	    /* First block is the "master" and dictates blocksize and target node */
	    q->blocksize = sqlite3_column_int(qget, 3);
	    if(sx_hashfs_check_blocksize(q->blocksize)) {
		WARN("Removing block with invalid blocksize %u", q->blocksize);
		sqlite3_reset(qget);
		blockmgr_del_xfer(q, push_id);
		return schedule_blocks_sfq(q);
	    }

	    p = sqlite3_column_blob(qget, 4);
	    if(sqlite3_column_bytes(qget, 4) != sizeof(target_uuid.binary)) {
		WARN("Removing block with invalid target node UUID");
		sqlite3_reset(qget);
		blockmgr_del_xfer(q, push_id);
		return schedule_blocks_sfq(q);
	    }
	    uuid_from_binary(&target_uuid, p);
	    if(!(q->target = sx_nodelist_lookup(sx_hashfs_effective_nodes(q->hashfs, NL_NEXT), &target_uuid))) {
		DEBUG("Removing transfer to non existing (possibly ignored) node %s", target_uuid.string);
		sqlite3_reset(qget);
		blockmgr_del_xfer(q, push_id);
		return schedule_blocks_sfq(q);
	    }
	    if(!sx_node_cmp(q->target, sx_hashfs_self(q->hashfs))) {
		WARN("Removing transfer to self");
		sqlite3_reset(qget);
		blockmgr_del_xfer(q, push_id);
		return schedule_blocks_sfq(q);
	    }

	    DEBUG("Selected master block for transfer bs: %u, node: %s", q->blocksize, target_uuid.string);
	}

	p = sqlite3_column_blob(qget, 2);
	if(sqlite3_column_bytes(qget, 2) != SXI_SHA1_BIN_LEN) {
	    if(!ret) {
		/* Remove "master" block from queue */
		WARN("Removing block with invalid hash");
		sqlite3_reset(qget);
		blockmgr_del_xfer(q, push_id);
		return schedule_blocks_sfq(q);
	    } else /* Or silently skip slaves (they'll be pruned in the subsequent loops) */
		continue;
	}

	q->hashlist.ids[ret] = push_id;
	q->hashlist.havehs[ret] = 0;
	memcpy(&q->hashlist.binhs[ret], p, SXI_SHA1_BIN_LEN);
	sqlite3_reset(qget);

	if(!ret && qstep_noret(q->qwipesched)) {
	    sqlite3_reset(qget);
	    WARN("Failed to wipe schedule");
	    return -1;
	}
	if(qbind_int64(q->qaddsched, ":pushid", push_id) ||
	   qstep_noret(q->qaddsched)) {
	    WARN("Failed to schedule block transfer");
	    return -1;
	}

	/*
	do {
	    char hexh[SXI_SHA1_BIN_LEN * 2 + 1];
	    sxi_bin2hex(&q->hashlist.binhs[ret], SXI_SHA1_BIN_LEN, hexh);
	    INFO("Block %s scheduled for transfer", hexh);
	} while(0);
	*/

	ret++;
	if(ret >= DOWNLOAD_MAX_BLOCKS)
	    break;

	for(i = 0; i<2; i++) {
	    /* Failure is not severe here: we just ship what we have scheduled so far and call it a day */
	    qget = (i == 0) ? q->qget_next_hi : q->qget_next_lo;
	    if(qbind_int64(qget, ":flow", q->last_flowid) ||
	       qbind_int(qget, ":size", q->blocksize) ||
	       qbind_blob(qget, ":node", target_uuid.binary, sizeof(target_uuid.binary))) {
		WARN("Error retrieving next slave block from queue");
		r = SQLITE_DONE;
		break;
	    }
	    r = qstep(qget);
	    if(r == SQLITE_ROW)
		break;
	    if(r != SQLITE_DONE) {
		WARN("Error retrieving next slave block from queue");
		break;
	    }
	}
    } while(r == SQLITE_ROW);

    q->hashlist.nblocks = ret;
    DEBUG("Successfully scheduled %d blocks for transfer", ret);
    return ret;
}


static uint8_t upbuffer[UPLOAD_CHUNK_SIZE];
static void blockmgr_process_queue(struct blockmgr_data_t *q) {
    sxc_client_t *sx = sx_hashfs_client(q->hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(q->hashfs);
    sxi_hostlist_t uploadto;

    sxi_hostlist_init(&uploadto);

    while(!terminate) {
	unsigned int i, trigger_jobmgr = 0;
        const char *host, *token = NULL;
	sxi_hashop_t hc;
	uint8_t *curb;
	int r;

	r = schedule_blocks_sfq(q);
	if(r <= 0) {
	    /* no blocks(0) or error (<1) */
	    break;
	}

	sxi_hostlist_empty(&uploadto);
        host = sx_node_internal_addr(q->target);
	if(sxi_hostlist_add_host(sx, &uploadto, host)) {
	    WARN("Cannot generate hostlist");
	    break;
	}

        if(sx_hashfs_make_token(q->hashfs, CLUSTER_USER, NULL, 0, time(NULL) + JOB_FILE_MAX_TIME, &token)) {
            WARN("Cannot create upload token");
            break;
        }

        /* just check for presence, reservation was already done by the failed INUSE */
	sxi_hashop_begin(&hc, clust, hcb, HASHOP_CHECK, 0, NULL, NULL, &q->hashlist, 0);
	for(i=0; i<q->hashlist.nblocks; i++) {
            if(sxi_hashop_batch_add(&hc, host, i, q->hashlist.binhs[i].b, q->blocksize) != 0) {
                WARN("Cannot verify block presence: %s", sxc_geterrmsg(sx));
                blockmgr_reschedule_xfer(q, q->hashlist.ids[i]);
            }
	}
	if(sxi_hashop_end(&hc) == -1) {
	    WARN("Cannot verify block presence on node %s (%s): %s", sx_node_uuid_str(q->target), host, sxc_geterrmsg(sx));
	    for(i=0; i<q->hashlist.nblocks; i++)
		blockmgr_reschedule_xfer(q, q->hashlist.ids[i]);
	    continue;
	}

	curb = upbuffer;
	for(i=0; i<q->hashlist.nblocks; i++) {
	    const uint8_t *b;
	    if(q->hashlist.havehs[i]) {
                /* TODO: print actual hash */
		DEBUG("Block %d was found remotely", i);
		blockmgr_del_xfer(q, q->hashlist.ids[i]);
	    } else if(sx_hashfs_block_get(q->hashfs, q->blocksize, &q->hashlist.binhs[i], &b)) {
		INFO("Block %ld was not found locally", q->hashlist.ids[i]);
		blockmgr_reschedule_xfer(q, q->hashlist.ids[i]);
	    } else {
		memcpy(curb, b, q->blocksize);
		curb += q->blocksize;
	    }
	    if(sizeof(upbuffer) - (curb - upbuffer) < q->blocksize || i == q->hashlist.nblocks - 1) {
		/* upload chunk */
		int j;
		if(sxi_upload_block_from_buf(clust, &uploadto, token, upbuffer, q->blocksize, curb-upbuffer)) {
		    WARN("Block transfer failed");
		    for(j=0; j<=i; j++)
			if(!q->hashlist.havehs[j])
			    blockmgr_reschedule_xfer(q, q->hashlist.ids[j]);
		    break;
		}
		curb = upbuffer;
		for(j=0; j<=i; j++) {
                    char debughash[sizeof(sx_hash_t)*2+1];
                    const sx_hash_t *hash = &q->hashlist.binhs[j];
		    if(q->hashlist.havehs[j])
			continue;
                    bin2hex(hash->b, sizeof(hash->b), debughash, sizeof(debughash));
		    DEBUG("Block %ld #%s# was transferred successfully", q->hashlist.ids[j], debughash);
		    blockmgr_del_xfer(q, q->hashlist.ids[j]);
		    q->hashlist.havehs[j] = 1;
		    trigger_jobmgr = 1;
		}
	    }
	}

	if(trigger_jobmgr)
	    sx_hashfs_job_trigger(q->hashfs);
        sx_hashfs_checkpoint_idle(q->hashfs);
    }
    sxi_hostlist_empty(&uploadto);
}

int blockmgr(sxc_client_t *sx, const char *dir, int pipe) {
    struct blockmgr_data_t q;
    struct sigaction act;
    sqlite3_stmt *qsched = NULL;
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

    if(qprep(xferdb, &qsched, "CREATE TEMPORARY TABLE scheduled (push_id INTEGER NOT NULL PRIMARY KEY)") || qstep_noret(qsched)) {
	qnullify(qsched);
	goto blockmgr_err;
    }
    qnullify(qsched);
    if(qprep(xferdb, &q.qprune, "DELETE FROM topush WHERE id IN (SELECT id FROM topush LEFT JOIN onhold ON block = hblock AND size = hsize AND node = hnode WHERE hid IS NULL) AND sched_time > expiry_time")) /* If you touch this query, please double check index usage! */
	goto blockmgr_err;
    if(qprep(xferdb, &q.qdel, "DELETE FROM topush WHERE id = :id"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qbump, "UPDATE topush SET sched_time = strftime('%Y-%m-%d %H:%M:%f', sched_time, '"STRIFY(BLOCKMGR_RESCHEDULE)" seconds') WHERE id = :id"))
	goto blockmgr_err;

    if(qprep(xferdb, &q.qget_first_hi, "SELECT id, flow, block, size, node FROM topush WHERE strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow > :flow ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qget_first_lo, "SELECT id, flow, block, size, node FROM topush WHERE strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow <= :flow ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qget_next_hi, "SELECT id, flow, block FROM topush WHERE id NOT IN (SELECT push_id FROM scheduled) AND strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow > :flow AND node = :node AND size = :size ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qget_next_lo, "SELECT id, flow, block FROM topush WHERE id NOT IN (SELECT push_id FROM scheduled) AND strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow <= :flow AND node = :node AND size = :size ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qwipesched, "DELETE FROM scheduled"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qaddsched, "INSERT INTO scheduled (push_id) VALUES (:pushid)"))
	goto blockmgr_err;

    while(!terminate) {
	int dc;
        if (wait_trigger(pipe, blockmgr_delay, NULL))
            break;

	DEBUG("Start processing block queue");
        msg_new_id();

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
        sx_hashfs_checkpoint_idle(q.hashfs);
    }

 blockmgr_err:
    sqlite3_finalize(q.qbump);
    sqlite3_finalize(q.qprune);
    sqlite3_finalize(q.qdel);

    sqlite3_finalize(q.qget_first_hi);
    sqlite3_finalize(q.qget_first_lo);
    sqlite3_finalize(q.qget_next_lo);
    sqlite3_finalize(q.qget_next_hi);
    sqlite3_finalize(q.qwipesched);
    sqlite3_finalize(q.qaddsched);

    sx_hashfs_close(q.hashfs);
    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}
