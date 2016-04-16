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
	sxi_hashop_begin(&hc, clust, hcb, HASHOP_CHECK, 0, NULL, NULL, NULL, &q->hashlist, 0);
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
    }
    sxi_hostlist_empty(&uploadto);
}


/* Stack alloc'd! */
#define MAX_UNBUMPS 1024
struct revunbump_data_t {
    sx_hashfs_t *hashfs;
    sqlite3_stmt *quget_lo, *quget_hi, *qudel;
    sx_uuid_t last_target; /* this may be uninitialized and that's ok */
};

static int unbump_unq(struct revunbump_data_t *unb, int64_t unbid) {
    if(qbind_int64(unb->qudel, ":unbid", unbid) ||
       qstep_noret(unb->qudel)) {
	WARN("Unable to delete unbid %lld", (long long)unbid);
	return -1; /* Error */
    }
    return 0; /* Work complete */
}

static int unbump_revs(struct revunbump_data_t *unb) {
    int64_t revs[MAX_UNBUMPS];
    sqlite3_stmt *q;
    char *qry = NULL;
    const void *tgt;
    unsigned int i, qlen = 0, qat = 0;
    int64_t unbid;
    const sx_node_t *target, *me;
    int r, err = 0, remote;

    q = unb->quget_hi;
    sqlite3_reset(q);
    if(qbind_blob(q, ":oldtarget", (const void *)&unb->last_target, sizeof(unb->last_target)))
	return -1; /* Error */
    r = qstep(q);
    if(r == SQLITE_DONE) {
	q = unb->quget_lo;
	sqlite3_reset(q);
	if(qbind_blob(q, ":oldtarget", (const void *)&unb->last_target, sizeof(unb->last_target)))
	    return -1; /* Error */
	r = qstep(q);
	if(r == SQLITE_DONE)
	    return 0; /* Work complete */
    }
    if(r != SQLITE_ROW)
	return -1; /* Error */

    unbid = sqlite3_column_int64(q, 0);
    tgt = sqlite3_column_blob(q, 3);
    if(!tgt || sqlite3_column_bytes(q, 3) != sizeof(unb->last_target.binary)) {
	WARN("Removing unbid %lld with bogus target", (long long)unbid);
	sqlite3_reset(q);
	return unbump_unq(unb, unbid);
    }
    uuid_from_binary(&unb->last_target, tgt);

    target = sx_nodelist_lookup(sx_hashfs_all_nodes(unb->hashfs, NL_NEXTPREV), &unb->last_target);
    if(!target) {
	DEBUG("Removing unbid %lld for target node %s which is no longer a member", (long long)unbid, unb->last_target.string);
	sqlite3_reset(q);
	return unbump_unq(unb, unbid);
    }

    if(sx_hashfs_is_node_ignored(unb->hashfs, &unb->last_target)) {
	/* These will be sent once there is a replacement */
	DEBUG("Skipping requests for unbid %lld for target node %s which is no longer a member", (long long)unbid, unb->last_target.string);
	sqlite3_reset(q);
	return 0; /* Work complete */
    }

    me = sx_hashfs_self(unb->hashfs);
    remote = sx_node_cmp(me, target);
    if(!remote && sx_hashfs_revision_op_begin(unb->hashfs)) {
	WARN("Failed to start revision operation: %s", msg_get_reason());
	sqlite3_reset(q);
	return -1; /* Error */
    }
    for(i=0; i<MAX_UNBUMPS;) {
	const sx_hash_t *revid;
	unsigned int bs = sqlite3_column_int(q, 2);

	if(sx_hashfs_check_blocksize(bs))
	    WARN("Removing unbid %lld with invalid block size %u", (long long)unbid, bs);
	else if(!(revid = sqlite3_column_blob(q, 1)) || sqlite3_column_bytes(q, 1) != sizeof(*revid))
	    WARN("Removing unbid %lld with bogus revision ID", (long long)unbid);
	else if(!(tgt = sqlite3_column_blob(q, 3)) || sqlite3_column_bytes(q, 3) != sizeof(unb->last_target.binary))
	    WARN("Removing unbid %lld with bogus target", (long long)unbid);
        else if(memcmp(tgt, &unb->last_target.binary, sizeof(unb->last_target.binary)))
	    break;
	else if(remote) {
	    /* Remote target */
	    if(qlen - qat < sizeof(*revid) * 2 + sizeof(",\"\":") + 32) {
		/* Make room for hex encoded rev, size and json glue */
		qlen += 1024;
		qry = wrap_realloc_or_free(qry, qlen);
		if(!qry) {
		    WARN("Unable to allocate query");
		    err = 1;
		    break;
		}
	    }
	    
	    qry[qat] = qat ? ',' : '{';
	    qry[qat+1] = '"';
	    qat += 2;
	    bin2hex(revid, sizeof(*revid), &qry[qat], qlen - qat);
	    qat += sizeof(*revid)*2;
	    qat += snprintf(&qry[qat], qlen - qat,"\":%u", bs);
	} else {
	    /* Local target */
	    if(sx_hashfs_revision_op(unb->hashfs, bs, revid, -1) != OK) {
		WARN("Failed to unbump local revision");
		err = 1;
		break;
	    }
	}
	revs[i++] = sqlite3_column_int64(q, 0);

	r = qstep(q);
	if(r == SQLITE_ROW)
	    continue;
	else if(r != SQLITE_DONE) {
	    WARN("Failed to retrieve next revision");
	    err = 1;
	}
	break;
    }

    sqlite3_reset(q);

    if(!remote) {
	/* Commit local revision ops... */
	if(!err && sx_hashfs_revision_op_commit(unb->hashfs)) {
	    WARN("Failed to commit revision operation: %s", msg_get_reason());
	    err = 1;
	}
	/* ... or rollback on error */
	if(err)
	    sx_hashfs_revision_op_rollback(unb->hashfs);
    }

    if(err) {
	free(qry);
	return -1; /* Error */
    }

    if(remote && qry) {
	sxi_conns_t *clust = sx_hashfs_conns(unb->hashfs);
	sxc_client_t *sx = sx_hashfs_client(unb->hashfs);
	sxi_hostlist_t hlist;
	int qret;

	sxi_hostlist_init(&hlist);
	if(qlen - qat < 2) {
	    qry = wrap_realloc_or_free(qry, qlen + 2);
	    if(!qry) {
		WARN("Unable to allocate query");
		return -1; /* Error */
	    }
	}
	qry[qat] = '}';
	qry[qat+1] = '\0';

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(target))) {
	    WARN("Unable to allocate hostlist");
	    free(qry);
	    return -1; /* Error */
	}

	qret = sxi_cluster_query(clust, &hlist, REQ_PUT, ".blockrevs/remove", qry, strlen(qry), NULL, NULL, NULL);
	free(qry);
	qry = NULL;
	sxi_hostlist_empty(&hlist);
	if(qret != 200) {
	    WARN("Unbump request failed for %s (%s): HTTP status %d", unb->last_target.string, sx_node_internal_addr(target), qret);
	    return -1;
	}
    }

    free(qry);
    while(i--)
	unbump_unq(unb, revs[i]);

    return 1; /* Some work done */

}

int blockmgr(sxc_client_t *sx, const char *dir, int pipe) {
    struct blockmgr_data_t q;
    struct revunbump_data_t unb;
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
    memset(&unb, 0, sizeof(unb));

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
    /* Slightly slower version:
       DELETE FROM topush WHERE id IN (SELECT id FROM topush LEFT JOIN onhold ON block = hblock AND size = hsize AND node = hnode WHERE hid IS NULL) AND sched_time > expiry_time */
    if(qprep(xferdb, &q.qprune, "DELETE FROM topush WHERE NOT EXISTS (SELECT 1 FROM onhold WHERE block = hblock AND size = hsize AND node = hnode) AND sched_time > expiry_time"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qdel, "DELETE FROM topush WHERE id = :id"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qbump, "UPDATE topush SET sched_time = strftime('%Y-%m-%d %H:%M:%f', sched_time, '"STRIFY(BLOCKMGR_RESCHEDULE)" seconds') WHERE id = :id"))
	goto blockmgr_err;

    if(qprep(xferdb, &q.qget_first_hi, "SELECT id, flow, block, size, node FROM topush WHERE strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow > :flow ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qget_first_lo, "SELECT id, flow, block, size, node FROM topush WHERE strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow <= :flow ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    /* Using index on 'node' is explicitly disabled here because despite being more efficient in the WHERE clause,
     * it adds extremely higher extra costs in the for of a temp b-tree used for the ORDER BY clause */
    if(qprep(xferdb, &q.qget_next_hi, "SELECT id, flow, block FROM topush WHERE id NOT IN (SELECT push_id FROM scheduled) AND strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow > :flow AND +node = :node AND size = :size ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qget_next_lo, "SELECT id, flow, block FROM topush WHERE id NOT IN (SELECT push_id FROM scheduled) AND strftime('%Y-%m-%d %H:%M:%f') >= sched_time AND flow <= :flow AND +node = :node AND size = :size ORDER BY flow ASC, sched_time ASC LIMIT 1"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qwipesched, "DELETE FROM scheduled"))
	goto blockmgr_err;
    if(qprep(xferdb, &q.qaddsched, "INSERT INTO scheduled (push_id) VALUES (:pushid)"))
	goto blockmgr_err;

    unb.hashfs = q.hashfs;
    if(qprep(xferdb, &unb.quget_hi, "SELECT unbid, revid, revsize, target FROM unbumps WHERE target > :oldtarget ORDER BY target LIMIT "STRIFY(MAX_UNBUMPS)))
	goto blockmgr_err;
    if(qprep(xferdb, &unb.quget_lo, "SELECT unbid, revid, revsize, target FROM unbumps WHERE target <= :oldtarget ORDER BY target LIMIT "STRIFY(MAX_UNBUMPS)))
	goto blockmgr_err;
    if(qprep(xferdb, &unb.qudel, "DELETE FROM unbumps WHERE unbid = :unbid"))
	goto blockmgr_err;

    while(!terminate) {
	int dc;
        if (wait_trigger(pipe, blockmgr_delay, NULL))
            break;

	while(1) {
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

	    DEBUG("Start processing unbump queue");
	    dc = unbump_revs(&unb);
	    DEBUG("Done processing block queue");

	    /* Fast loop unless unbump complete or failed */
	    if(dc <= 0)
		break;
	}
	
        sx_hashfs_checkpoint_xferdb(q.hashfs);
        sx_hashfs_checkpoint_idle(q.hashfs);
    }

 blockmgr_err:
    sqlite3_finalize(unb.quget_lo);
    sqlite3_finalize(unb.quget_hi);
    sqlite3_finalize(unb.qudel);

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
