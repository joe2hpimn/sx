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

/* temporary work-around for OS X: to be investigated.
 * 2 issues: BIND_8_COMPAT required for nameser_compat.h
 * and sth from default.h messing with the endian stuff
 */
#if __APPLE__ 
# define BIND_8_COMPAT
# ifdef WORDS_BIGENDIAN
#  undef LITTLE_ENDIAN
#  define BIG_ENDIAN 1
#  define BYTE_ORDER BIG_ENDIAN
# else
#  undef BIG_ENDIAN
#  define LITTLE_ENDIAN 1
#  define BYTE_ORDER LITTLE_ENDIAN
# endif
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "../libsxclient/src/sxproto.h"
#include "../libsxclient/src/misc.h"
#include "../libsxclient/src/curlevents.h"
#include "hashfs.h"
#include "hdist.h"
#include "job_common.h"
#include "log.h"
#include "jobmgr.h"
#include "blob.h"
#include "nodes.h"
#include "version.h"
#include "clstqry.h"

static int current_job_status = 0;

typedef enum _act_result_t {
    ACT_RESULT_UNSET = 0,
    ACT_RESULT_OK = 1,
    ACT_RESULT_TEMPFAIL = -1,
    ACT_RESULT_PERMFAIL = -2,

    /* Heavy/aggressive jobs willingly giving up before completion:
     * same as ACT_RESULT_TEMPFAIL except it's rescheduled without delay */
    ACT_RESULT_NOTFAILED = -3,
} act_result_t;

typedef struct _job_data_t {
    void *ptr;
    unsigned int len;
    uint64_t op_expires_at;
    sx_uid_t owner;
} job_data_t;

typedef act_result_t (*job_action_t)(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *node, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl);

#define action_set_fail(retcode, failcode, failmsg)	    \
    do {						    \
	ret = (retcode);				    \
	*fail_code = (failcode);			    \
        current_job_status = (failcode);                    \
	sxi_strlcpy(fail_msg, (failmsg), JOB_FAIL_REASON_SIZE); \
        DEBUG("fail set to: %s\n", fail_msg); \
    } while(0)

#define action_error(retcode, failcode, failmsg)	    \
    do {						    \
	action_set_fail((retcode), (failcode), (failmsg));  \
	goto action_failed;				    \
    } while(0)

#define CRITCOND CRIT("A critical condition has occurred (see messages above): please check the health and reachability of all cluster nodes")

#define DEBUGHASH(MSG, X) do {				\
    char _debughash[sizeof(sx_hash_t)*2+1];		\
    if (UNLIKELY(sxi_log_is_debug(&logger))) {          \
        bin2hex((X)->b, sizeof(*X), _debughash, sizeof(_debughash));	\
        DEBUG("%s: #%s#", MSG, _debughash); \
    }\
    } while(0)
static act_result_t http2actres(int code) {
    int ch = code / 100;
    if (code < 0)
        return ACT_RESULT_PERMFAIL;
    if(ch == 2)
	return ACT_RESULT_OK;
    if(ch == 4)
	return ACT_RESULT_PERMFAIL;
    if(code == 503 || ch != 5)
	return ACT_RESULT_TEMPFAIL;
    return ACT_RESULT_PERMFAIL;
}

static act_result_t rc2actres(rc_ty rc) {
    return http2actres(rc2http(rc));
}

/* A convenience function to get all targets of a job: intended (almost)
 * exclusively for the case when cleanup is required for parent actions.
 * It subverts the normal 2PC mechanics. Please do not misuse/abuse. */
static sx_nodelist_t *get_all_job_targets(sx_hashfs_t *hashfs, job_t job_id) {
    sxi_db_t *eventdb = sx_hashfs_eventdb(hashfs);
    sx_nodelist_t *ret = NULL;
    sqlite3_stmt *q = NULL;
    int r;

    ret = sx_nodelist_new();
    if(!ret) {
	WARN("Failed to allocate nodelist");
	goto alltgt_fail;
    }
    if(qprep(eventdb, &q, "SELECT id, target, addr, internaladdr, capacity FROM actions WHERE job_id = :jobid") ||
       qbind_int64(q, ":jobid", job_id)) {
	CRIT("Failed to prepare query");
	goto alltgt_fail;
    }
    while((r = qstep(q)) == SQLITE_ROW) {
	const void *id = sqlite3_column_blob(q, 1);
	unsigned int idlen = sqlite3_column_bytes(q, 1);
	const char *addr = sqlite3_column_text(q, 2);
	const char *intaddr = sqlite3_column_text(q, 3);
	int64_t capa = sqlite3_column_int64(q, 4);
	sx_uuid_t uuid;
	
	if(!id || idlen != sizeof(uuid.binary) || !addr || !intaddr) {
	    WARN("Found invalid data in action %lld", (long long)sqlite3_column_int64(q, 0));
	    continue; /* best effort */
	}
	uuid_from_binary(&uuid, id);
	if(sx_nodelist_add(ret, sx_node_new(&uuid, addr, intaddr, capa))) {
	    WARN("Failed to add target to list");
	    goto alltgt_fail;
	}
    }

    if(r != SQLITE_DONE)
	WARN("Failed to collect all targets");

 alltgt_fail:
    sqlite3_finalize(q);
    return ret;
}

static void send_unlock(sx_hashfs_t *hashfs, const sx_nodelist_t *nodes);

typedef struct {
	curlev_context_t *cbdata;
	int query_sent;
} query_list_t;

static void query_list_free(query_list_t *qrylist, unsigned nnodes)
{
    unsigned i;
    if (!qrylist)
        return;
    for (i=0;i<nnodes;i++) {
        sxi_cbdata_unref(&qrylist[i].cbdata);
    }

    free(qrylist);
}

static act_result_t force_phase_success(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    return ACT_RESULT_OK;
}

static rc_ty volonoff_common(sx_hashfs_t *hashfs, job_t job_id, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, const sx_hash_t *global_vol_id, int enable) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    char *query = NULL;
    rc_ty s;
    char volid_hex[SXI_SHA1_TEXT_LEN+1]; /* Volume onoff query path is a hex of the global ID */
    bin2hex(global_vol_id->b, sizeof(global_vol_id->b), volid_hex, sizeof(volid_hex));

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	INFO("%s volume with ID '%s' on %s", enable ? "Enabling" : "Disabling", volid_hex, sx_node_uuid_str(node));

	if(!sx_node_cmp(me, node)) {
	    if(enable) {
		if((s = sx_hashfs_volume_enable(hashfs, global_vol_id))) {
		    WARN("Failed to enable volume with ID '%s' job %lld: %s", volid_hex, (long long)job_id, msg_get_reason());
		    action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to enable volume");
		}
	    } else {
		if((s = sx_hashfs_volume_disable(hashfs, global_vol_id))) {
		    WARN("Failed to disable volume with ID '%s' job %lld: %s", volid_hex, (long long)job_id, msg_get_reason());
		    action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to disable volume");
		}
	    }
	    succeeded[nnode] = 1;
	} else {
	    if(!query) {
		query = wrap_malloc(strlen(volid_hex) + sizeof("?o=disable")); /* fits "enable" and "disable" with termination */
		if(!query) {
		    WARN("Cannot allocate query");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		sprintf(query, "%s?o=%s", volid_hex, enable ? "enable" : "disable");

		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_PUT, query, NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    if(query) {
	for(nnode=0; qrylist && nnode<nnodes; nnode++) {
	    int rc;
            long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if(http_status == 200 || http_status == 410) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
	}
        query_list_free(qrylist, nnodes);
	free(query);
    }

    return ret;
}


static act_result_t voldelete_common(sx_hashfs_t *hashfs, job_t job_id, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, const sx_hash_t *global_vol_id, int force) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    char *query = NULL;
    rc_ty s;
    char volid_hex[SXI_SHA1_TEXT_LEN+1];
    bin2hex(global_vol_id->b, sizeof(global_vol_id->b), volid_hex, sizeof(volid_hex));

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	INFO("Deleting volume with ID %s on %s", volid_hex, sx_node_uuid_str(node));

	if(!sx_node_cmp(me, node)) {
	    if((s = sx_hashfs_volume_delete(hashfs, global_vol_id, force)) != OK && s != ENOENT) {
		WARN("Failed to delete volume with ID '%s' for job %lld", volid_hex, (long long)job_id);
		action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to enable volume");
	    }
	    succeeded[nnode] = 1;
	} else {
	    if(!query) {
		query = malloc(lenof(volid_hex) + lenof("?force") + 1);
		if(!query) {
		    WARN("Cannot encode path");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
                sprintf(query, "%s%s", volid_hex, force ? "?force" : "");
		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_DELETE, query, NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    if(query) {
	for(nnode=0; qrylist && nnode<nnodes; nnode++) {
	    int rc;
            long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if (http_status == 200 || http_status == 410 || http_status == 404) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
	}
        query_list_free(qrylist, nnodes);
	free(query);
    }

    return ret;
}

static act_result_t createvol_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const char *volname, *owner;
    int64_t volsize, owner_uid;
    unsigned int nnode, nnodes;
    int i, replica, revisions, nmeta, bumpttl;
    sx_blob_t *b = NULL;
    act_result_t ret = ACT_RESULT_OK;
    sxi_query_t *proto = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxc_meta_t *vmeta = NULL;
    query_list_t *qrylist = NULL;
    rc_ty s;
    const sx_hash_t *global_id = NULL;
    unsigned int global_id_size = 0;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) ||
       sx_blob_get_blob(b, (const void**)&global_id, &global_id_size) || global_id_size != sizeof(global_id->b) ||
       sx_blob_get_string(b, &owner) ||
       sx_blob_get_int64(b, &volsize) ||
       sx_blob_get_int32(b, &replica) ||
       sx_blob_get_int32(b, &revisions) ||
       sx_blob_get_int32(b, &nmeta) ||
       sx_blob_get_int32(b, &bumpttl)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if((s = sx_hashfs_get_uid(hashfs, owner, &owner_uid))) {
	WARN("Cannot find owner '%s' for job %lld", owner, (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Invalid user");
    }

    sx_blob_savepos(b);

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	INFO("Making volume %s - owner: %s, size: %lld, replica: %d, revs: %u, meta: %d on %s", volname, owner, (long long)volsize, replica, revisions, nmeta, sx_node_uuid_str(node));

	if(!sx_node_cmp(me, node)) {
	    sx_hashfs_volume_new_begin(hashfs);

	    if(nmeta) {
		sx_blob_loadpos(b);
		for(i=0; i<nmeta; i++) {
		    const char *mkey;
		    const void *mval;
		    unsigned int mval_len;
		    if(sx_blob_get_string(b, &mkey) ||
		       sx_blob_get_blob(b, &mval, &mval_len)) {
			WARN("Cannot get volume metadata from blob for job %lld", (long long)job_id);
			action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
		    }
		    if((s = sx_hashfs_volume_new_addmeta(hashfs, mkey, mval, mval_len))) {
			WARN("Cannot add meta data to volume for job %lld", (long long)job_id);
			action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Invalid volume metadata");
		    }
		}
	    }

	    s = sx_hashfs_volume_new_finish(hashfs, volname, global_id, volsize, replica, revisions, owner_uid, 1);
	    if(s != OK) {
                const char *msg = (s == EINVAL || s == EEXIST) ? msg_get_reason() : rc2str(s);
		action_error(rc2actres(s), rc2http(s), msg);
            }
	    succeeded[nnode] = 1;
	    *adjust_ttl = bumpttl;
	} else {
	    if(!proto) {
		if(nmeta) {
		    sx_blob_loadpos(b);
		    if(!(vmeta = sxc_meta_new(sx))) {
			WARN("Cannot build a list of volume metadata for job %lld", (long long)job_id);
			action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		    }

		    for(i=0; i<nmeta; i++) {
			const char *mkey;
			const void *mval;
			unsigned int mval_len;
			if(sx_blob_get_string(b, &mkey) ||
			   sx_blob_get_blob(b, &mval, &mval_len)) {
			    WARN("Cannot get volume metadata from blob for job %lld", (long long)job_id);
			    action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
			}
			if(sxc_meta_setval(vmeta, mkey, mval, mval_len)) {
			    WARN("Cannot build a list of volume metadata for job %lld", (long long)job_id);
			    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
			}
		    }
		}

		proto = sxi_volumeadd_proto(sx, volname, owner, volsize, replica, revisions, vmeta, global_id->b, sizeof(global_id->b));
		if(!proto) {
		    WARN("Cannot allocate proto for job %lld", (long long)job_id);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}

		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    sx_blob_free(b);
    if(proto) {
	for(nnode=0; qrylist && nnode<nnodes; nnode++) {
	    int rc;
            long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if(http_status == 200 || http_status == 410) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
	}
        query_list_free(qrylist, nnodes);
	sxi_query_free(proto);
    }
    sxc_meta_free(vmeta);
    return ret;
}

static act_result_t createvol_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const char *volname;
    sx_blob_t *b = NULL;
    act_result_t ret;
    const sx_hash_t *global_id = NULL;
    unsigned int global_id_len = 0;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_blob(b, (const void**)&global_id, &global_id_len) ||
       global_id_len != sizeof(global_id->b)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = volonoff_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg, global_id, 1);

 action_failed:
    sx_blob_free(b);

    return ret;
}

static act_result_t createvol_abort_and_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const char *volname;
    const sx_hash_t *global_id = NULL;
    unsigned int global_id_len = 0;
    sx_blob_t *b = NULL;
    act_result_t ret;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_blob(b, (const void**)&global_id, &global_id_len) ||
       global_id_len != sizeof(global_id->b)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = voldelete_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg, global_id, 1);

 action_failed:
    sx_blob_free(b);

    return ret;
}


static act_result_t deletevol_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;
    sx_blob_t *b = NULL;
    act_result_t ret;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || !global_vol_id || global_id_len != sizeof(global_vol_id->b)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = volonoff_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg, global_vol_id, 0);

 action_failed:
    sx_blob_free(b);

    return ret;
}

static act_result_t deletevol_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hash_t *global_vol_id = NULL;
    unsigned int global_id_len = 0;
    sx_blob_t *b = NULL;
    act_result_t ret;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || !global_vol_id || global_id_len != sizeof(global_vol_id->b)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = voldelete_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg, global_vol_id, 0);

 action_failed:
    sx_blob_free(b);

    return ret;
}

static act_result_t deletevol_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;
    sx_blob_t *b = NULL;
    act_result_t ret;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || !global_vol_id || global_id_len != sizeof(global_vol_id->b)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = volonoff_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg, global_vol_id, 1);

 action_failed:
    sx_blob_free(b);

    return ret;
}

static act_result_t deletevol_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;
    sx_blob_t *b = NULL;
    act_result_t ret;
    char volid_hex[SXI_SHA1_TEXT_LEN+1];

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || !global_vol_id || global_id_len != sizeof(global_vol_id->b)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }
    bin2hex(global_vol_id->b, sizeof(global_vol_id->b), volid_hex, sizeof(volid_hex));

    CRIT("Volume with ID '%s' may have been left in an inconsistent state after a failed removal attempt", volid_hex);
    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Volume removal failed: the volume may have been left in an inconsistent state");

 action_failed:
    sx_blob_free(b);

    return ret;
}

static act_result_t job_twophase_execute(const job_2pc_t *spec, jobphase_t phase, sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    sxi_query_t *proto = NULL;
    rc_ty rc;
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sx_blob_t *b = sx_blob_from_data(job_data->ptr, job_data->len);

    if (!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
        sx_blob_reset(b);

	if(!sx_node_cmp(me, node)) {
            /* execute locally */
            rc = spec->execute_blob(hashfs, b, phase, 0);
            if (rc != OK) {
                const char *msg = msg_get_reason();
                if (!msg)
                    msg = rc2str(rc);
                action_error(rc2actres(rc), rc2http(rc), msg);
            }
	    succeeded[nnode] = 1;
	    *adjust_ttl = spec->timeout(sx_hashfs_client(hashfs), nnodes);
        } else {
            /* execute remotely */
            if (!proto) {
                proto = spec->proto_from_blob(sx_hashfs_client(hashfs), b, phase);
                if (!proto) {
                    WARN("Cannot allocate proto for job %lld", (long long)job_id);
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }
                qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
                if(!qrylist) {
                    WARN("Cannot allocate result space");
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }
            }
            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
        }
    }

 action_failed: /* or succeeded */
    sx_blob_free(b);
    if(proto) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc;
            long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
                *adjust_ttl = 0;
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if(http_status == 200 || http_status == 410) {
		succeeded[nnode] = 1;
	    } else {
                *adjust_ttl = 0;
		act_result_t newret;
                if (!http_status && phase == JOBPHASE_REQUEST) {
                    /* request can be safely aborted, so abort asap when
                     * a node is down */
                    http_status = 502;/* can't connect */
                    newret = ACT_RESULT_PERMFAIL;
                } else
                    newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
        }
        query_list_free(qrylist, nnodes);
	sxi_query_free(proto);
    }
    return ret;
}

static act_result_t acl_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&acl_spec, JOBPHASE_REQUEST, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t acl_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&acl_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t acl_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&acl_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t acl_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&acl_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t createuser_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_spec, JOBPHASE_REQUEST, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t createuser_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t createuser_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t createuser_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t deleteuser_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&userdel_spec, JOBPHASE_REQUEST, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t deleteuser_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&userdel_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t deleteuser_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&userdel_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t deleteuser_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&userdel_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t usermodify_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_modify_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t usermodify_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_modify_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t usermodify_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&user_modify_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_mode_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_mode_spec, JOBPHASE_REQUEST, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_mode_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_mode_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_setmeta_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_setmeta_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_setmeta_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_setmeta_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_setmeta_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_setmeta_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_settings_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_settings_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_settings_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_settings_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t cluster_settings_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return job_twophase_execute(&cluster_settings_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static int req_append(char **req, unsigned int *req_len, const char *append_me) {
    unsigned int current_len, append_len;

    if(!*req_len) {
	*req = NULL;
	current_len = 0;
    } else
	current_len = strlen(*req);
    append_len = strlen(append_me) + 1;
    if(current_len + append_len > *req_len) {
	*req_len += MAX(1024, append_len);
	*req = wrap_realloc_or_free(*req, *req_len);
    }
    if(!*req) {
        WARN("Failed to append string to request");
        return 1;
    }

    memcpy(*req + current_len, append_me, append_len);
    return 0;
}

static rc_ty filerev_from_jobdata_rev(sx_hashfs_t *hashfs, job_data_t *job_data, sx_hashfs_file_t *filerev)
{
    char revision[REV_LEN+1];

    if(job_data->len != REV_LEN) {
	CRIT("Bad job data");
        return FAIL_EINTERNAL;
    }
    memcpy(revision, job_data->ptr, REV_LEN);
    revision[REV_LEN] = 0;
    return sx_hashfs_getinfo_by_revision(hashfs, revision, filerev);
}

static rc_ty filerev_from_jobdata_tmpfileid(sx_hashfs_t *hashfs, job_data_t *job_data, sx_hashfs_file_t *filerev)
{
    int64_t tmpfile_id;
    rc_ty s;

    if(job_data->len != sizeof(tmpfile_id)) {
        CRIT("Bad job data");
        return FAIL_EINTERNAL;
    }
    sx_hashfs_tmpinfo_t *tmpinfo;
    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));
    s = sx_hashfs_tmp_getinfo(hashfs, tmpfile_id, &tmpinfo, 0);
    if (s) {
        WARN("Failed to lookup tmpfileid: %s", rc2str(s));
        return s;
    }
    filerev->volume_id = tmpinfo->volume_id;
    filerev->block_size = tmpinfo->block_size;
    sxi_strlcpy(filerev->name, tmpinfo->name, sizeof(filerev->name));
    sxi_strlcpy(filerev->revision, tmpinfo->revision, sizeof(filerev->revision));
    memcpy(filerev->revision_id.b, tmpinfo->revision_id.b, SXI_SHA1_BIN_LEN);

    free(tmpinfo);
    return OK;
}

static act_result_t revision_job_from(sx_hashfs_t *hashfs, job_t job_id, const sx_hashfs_file_t *filerev, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, int op, jobphase_t phase) {
    sx_revision_op_t revision_op;
    const sx_hashfs_volume_t *volume;
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;
    sx_blob_t *blob = NULL;
    job_data_t new_job_data;
    s = sx_hashfs_volume_by_id(hashfs, filerev->volume_id, &volume);
    if (s)
        action_error(rc2actres(s), rc2http(s), "Failed to retrieve volume info");
    revision_op.lock = NULL;
    revision_op.blocksize = filerev->block_size;
    revision_op.op = op;
    memcpy(revision_op.revision_id.b, filerev->revision_id.b, SXI_SHA1_BIN_LEN);

    blob = sx_blob_new();
    if (!blob)
        action_error(ACT_RESULT_TEMPFAIL, 500, "Cannot allocate blob");
    if (revision_spec.to_blob(sx_hashfs_client(hashfs), sx_nodelist_count(nodes), &revision_op, blob)) {
        const char *msg = msg_get_reason();
        if(!msg || !*msg)
            msg_set_reason("Cannot create job blob");
        action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    sx_blob_to_data(blob, (const void**)&new_job_data.ptr, &new_job_data.len);
    new_job_data.op_expires_at = 0;
    ret = job_twophase_execute(&revision_spec, phase, hashfs, job_id, &new_job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
action_failed:
    sx_blob_free(blob);
    return ret;
}

static act_result_t revision_job_from_tmpfileid(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, int op, jobphase_t phase) {
    sx_hashfs_file_t filerev;
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s = filerev_from_jobdata_tmpfileid(hashfs, job_data, &filerev);
    if (s)
        action_error(rc2actres(s), rc2http(s), "Failed to lookup file by tmpfile id");
    ret = revision_job_from(hashfs, job_id, &filerev, nodes, succeeded, fail_code, fail_msg, adjust_ttl, op, phase);
action_failed:
    return ret;
}

static act_result_t revision_job_from_rev(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, int op, jobphase_t phase)
{
    sx_hashfs_file_t filerev;
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s = filerev_from_jobdata_rev(hashfs, job_data, &filerev);
    if (s)
        action_error(rc2actres(s), rc2http(s), "Failed to lookup file by revision");
    ret = revision_job_from(hashfs, job_id, &filerev, nodes, succeeded, fail_code, fail_msg, adjust_ttl, op, phase);
    CRIT("File %s (rev %s) on volume %lld was left in an inconsistent state after a failed deletion attempt", filerev.name, filerev.revision, (long long)filerev.volume_id);
    action_error(ACT_RESULT_PERMFAIL, 500, "File was left in an inconsistent state after a failed deletion attempt");
action_failed:
    return ret;
}


static act_result_t replicateblocks_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    /* bump block revision */
    return revision_job_from_tmpfileid(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, 1, JOBPHASE_COMMIT);
}

static act_result_t replicateblocks_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    unsigned int i, j, worstcase_rpl, nqueries = 0, giveup = 0;
    act_result_t ret = ACT_RESULT_OK;
    sx_hashfs_tmpinfo_t *mis = NULL;
    query_list_t *qrylist = NULL;
    int64_t tmpfile_id;
    rc_ty s;

    if(job_data->len != sizeof(tmpfile_id)) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));
    DEBUG("replocateblocks_request for file %lld", (long long)tmpfile_id);
    s = sx_hashfs_tmp_getinfo(hashfs, tmpfile_id, &mis, 1);
    if(s == EFAULT || s == EINVAL) {
	CRIT("Error getting tmpinfo: %s", msg_get_reason());
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == ENOENT) {
	WARN("Token %lld could not be found", (long long)tmpfile_id);
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == EAGAIN)
	action_error(ACT_RESULT_TEMPFAIL, 500, "Job data temporary unavailable");

    if(s == EINPROGRESS)
	giveup = 1;
    else if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to check missing blocks");

    worstcase_rpl = mis->replica_count;

    /* Loop through all blocks to check availability */
    for(i=0; i<MIN(mis->nuniq, DOWNLOAD_MAX_BLOCKS); i++) {
	unsigned int ndone = 0, ndone_or_pending = 0, pushingidx = 0, blockno = mis->uniq_ids[i];

	/* For DEBUG()ging purposes */
	char blockname[SXI_SHA1_TEXT_LEN + 1];
	bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), blockname, sizeof(blockname));

	/* Compute the current replica level for this block */
	for(j=0; j<mis->replica_count; j++) {
	    int8_t avlbl = mis->avlblty[blockno * mis->replica_count + j];
	    if(avlbl == 1) {
		ndone++;
		ndone_or_pending++;
		pushingidx = mis->nidxs[blockno * mis->replica_count + j];
		DEBUG("Block %s is available on set %u (node %u)", blockname, j, mis->nidxs[blockno * mis->replica_count + j]);
	    } else if(avlbl > 0) {
		ndone_or_pending++;
		DEBUG("Block %s pending upload on set %u (node %u)", blockname, j, mis->nidxs[blockno * mis->replica_count + j]);
	    } else {
		DEBUG("Block %s is NOT available on set %u (node %u)", blockname, j, mis->nidxs[blockno * mis->replica_count + j]);
	    }
	}

	DEBUG("Block %s has got %u replicas (%u including pending xfers) out of %u", blockname, ndone, ndone_or_pending, mis->replica_count);

	/* Update the worst case replica */
	if(ndone < worstcase_rpl)
	    worstcase_rpl = ndone;

	/* If the replica is already satisfied, then there is nothing to do for this block */
	if(ndone_or_pending == mis->replica_count)
	    continue;

	/* No node has got this block: job failed */
	if(!ndone) {
	    if(giveup)
		continue;
	    else {
		char missing_block[SXI_SHA1_TEXT_LEN + 1];
		bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), missing_block, sizeof(missing_block));
		WARN("Early flush on job %lld: hash %s could not be located ", (long long)tmpfile_id, missing_block);
		action_error(ACT_RESULT_PERMFAIL, 400, "Some block is missing");
	    }
	}

	/* We land here IF at least one node has got the block AND at least one node doesn't have the block */
	/* NOTE:
	 * If the pushing node is the local node then a transfer request is added to the local block queue
	 * If the pushing node is not the local node, then we submit the request via HTTP
	 * This unfortunately makes the following code a little bit more convoluted than it could be */

	/* Variables used for both remote and local mode */
	const sx_node_t *pusher = sx_nodelist_get(mis->allnodes, pushingidx);
	int remote = (sx_node_cmp(pusher, me) != 0);
	unsigned int current_hash_idx;

	/* Variables used in remote mode only */
	unsigned int req_len = 0;
	char *req = NULL;

	if(remote) {
	    /* query format: { "hash1":["target_node_id1","target_node_id2"],"hash2":["target_node_id3","target_node_id4"] } */
	    if(req_append(&req, &req_len, "{"))
		action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	}

	DEBUG("Selected pusher is %s node %u (%s)", remote ? "remote" : "local", pushingidx, sx_node_internal_addr(pusher));

	/* Look ahead a little (not too much to avoid congesting the pusher) and collect all blocks
	 * that are available on the selected pusher and unavailable on some other replica nodes */
	for(j=0, current_hash_idx = i; j < DOWNLOAD_MAX_BLOCKS && current_hash_idx < mis->nuniq; current_hash_idx++) {
	    unsigned int current_replica, have_pusher = 0, have_junkies = 0, current_blockno = mis->uniq_ids[current_hash_idx];

	    bin2hex(&mis->all_blocks[current_blockno], sizeof(mis->all_blocks[0]), blockname, sizeof(blockname));
	    DEBUG("Considering block %s for pusher %u...", blockname, pushingidx);

	    /* Scan the replica set of the current block... */
	    for(current_replica = 0; current_replica < mis->replica_count; current_replica++) {
		/* ...checking for some node in need of this block...  */
		if(mis->avlblty[current_blockno * mis->replica_count + current_replica] <= 0) {
		    DEBUG("Followup block %s is NOT available on set %u (node %u)", blockname, current_replica, mis->nidxs[current_blockno * mis->replica_count + current_replica]);
		    have_junkies = 1;
		    continue;
		} else if(mis->avlblty[current_blockno * mis->replica_count + current_replica] == 2)
		    DEBUG("Followup block %s is pending upload on set %u (node %u)", blockname, current_replica, mis->nidxs[current_blockno * mis->replica_count + current_replica]);
		else
		    DEBUG("Followup block %s is available on set %u (node %u)", blockname, current_replica, mis->nidxs[current_blockno * mis->replica_count + current_replica]);

		/* ...and checking if the selected pusher is in possession of the block */
		if(mis->avlblty[current_blockno * mis->replica_count + current_replica] == 1 &&
		   mis->nidxs[current_blockno * mis->replica_count + current_replica] == pushingidx)
		    have_pusher = 1;
	    }

	    if(have_junkies && have_pusher)
		DEBUG("Followup block %s needs to be replicated and CAN be replicated by %s pusher %u", blockname, remote ? "remote" : "local", pushingidx);
	    else if(have_junkies)
		DEBUG("Followup block %s needs to be replicated but CANNOT be replicated by %s pusher %u", blockname, remote ? "remote" : "local", pushingidx);
	    else
		DEBUG("Followup block %s needs NOT to be replicated", blockname);

	    /* If we don't have both, then move on to the next block */
	    if(!have_pusher || !have_junkies)
		continue;

	    j++; /* This acts as a look-ahead limiter */

	    sx_hash_t *current_hash = &mis->all_blocks[current_blockno];
            DEBUGHASH("asking hash to be pushed", current_hash);
	    sx_nodelist_t *xfertargets = NULL; /* used in local mode only */

	    if(remote) {
		char key[SXI_SHA1_TEXT_LEN + sizeof("\"\":[")];
		key[0] = '"';
		bin2hex(current_hash, sizeof(mis->all_blocks[0]), key+1, SXI_SHA1_TEXT_LEN+1);
		memcpy(&key[1+SXI_SHA1_TEXT_LEN], "\":[", sizeof("\":["));
		if(req_append(&req, &req_len, key))
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	    } else {
		xfertargets = sx_nodelist_new();
		if(!xfertargets)
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory for local block transfer");
	    }

	    /* Go through the replica set again */
	    for(current_replica = 0; current_replica < mis->replica_count; current_replica++) {
		const sx_node_t *target;

		/* Skip all nodes that have the block already */
		if(mis->avlblty[current_blockno * mis->replica_count + current_replica] > 0)
		    continue;

		DEBUG("Block %s is set to be transfered to node %u", blockname, mis->nidxs[current_blockno * mis->replica_count + current_replica]);

		/* Mark the block as being transferred so it's not picked up again later */
		mis->avlblty[current_blockno * mis->replica_count + current_replica] = 2;
		target = sx_nodelist_get(mis->allnodes, mis->nidxs[current_blockno * mis->replica_count + current_replica]);
		if(!target) {
		    WARN("Target no longer exists");
		    if(remote)
			free(req);
		    else
			sx_nodelist_delete(xfertargets);
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Internal error looking up target nodes");
		}

		/* Add this node as a transfer target */
		if(remote) {
		    const sx_uuid_t *target_uuid;
		    target_uuid = sx_node_uuid(target);
		    if(req_append(&req, &req_len, "\"") ||
		       req_append(&req, &req_len, target_uuid->string) ||
		       req_append(&req, &req_len, "\","))
			action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
		} else {
		    if(sx_nodelist_add(xfertargets, sx_node_dup(target))) {
			sx_nodelist_delete(xfertargets);
			action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory for local block transfer");
		    }
		}
		DEBUG("Block %s added to %s push queue for target %s", blockname, remote ? "remote" : "local", sx_node_internal_addr(target));
	    }

	    if(remote) {
		req[strlen(req)-1] = '\0';
		if(req_append(&req, &req_len, "],"))
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	    } else {
		/* Local xfers are flushed at each block */
		s = sx_hashfs_xfer_tonodes(hashfs, current_hash, mis->block_size, xfertargets, job_data->owner);
		sx_nodelist_delete(xfertargets);
		if(s)
		    action_error(rc2actres(s), rc2http(s), "Failed to request local block transfer");
	    }
	}

	if(remote) {
	    /* Remote xfers are flushed at each pushing node */
	    char url[sizeof(".pushto/") + 64 + AUTH_UID_LEN*2];
	    uint8_t pushuser[AUTH_UID_LEN];

	    req[strlen(req)-1] = '}';

	    if(!(nqueries % 64)) {
		query_list_t *nuqlist = realloc(qrylist, sizeof(*qrylist) * (nqueries+64));
		if(!nuqlist) {
		    free(req);
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
		}
		memset(nuqlist + nqueries, 0, sizeof(*qrylist) * 64);
		qrylist = nuqlist;
	    }
            qrylist[nqueries].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    sxi_cbdata_set_context(qrylist[nqueries].cbdata, req);

	    snprintf(url, sizeof(url), ".pushto/%u/", mis->block_size);
	    if(sx_hashfs_get_user_by_uid(hashfs, job_data->owner, pushuser, 0) == OK) {
		unsigned int urlen;
		urlen = strlen(url);
		url[urlen++] = '/';
		bin2hex(pushuser, AUTH_UID_LEN, &url[urlen], AUTH_UID_LEN*2+1);
	    }

	    if(sxi_cluster_query_ev(qrylist[nqueries].cbdata, clust, sx_node_internal_addr(pusher), REQ_PUT, url, req, strlen(req), NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(pusher), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		nqueries++;
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nqueries].query_sent = 1;
	    nqueries++;
	} else
	    sx_hashfs_xfer_trigger(hashfs);
    }

    DEBUG("Job id %lld - current replica %u out of %u", (long long)job_id, worstcase_rpl, mis->replica_count);

    if(giveup || i<mis->nuniq) /* Incomplete presence check or remote xfers */
	action_error(ACT_RESULT_NOTFAILED, 500, "Replica not completely verified");

    if(worstcase_rpl < mis->replica_count)
	action_error(ACT_RESULT_TEMPFAIL, 500, "Replica not yet completed");

 action_failed:
    if(qrylist) {
	for(i=0; i<nqueries; i++) {
	    if(qrylist[i].query_sent) {
                long http_status = 0;
		int rc = sxi_cbdata_wait(qrylist[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
		if(rc != -2) {
		    if(rc == -1) {
			WARN("Query failed with %ld", http_status);
			if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else if(http_status == 404) {
			/* Syntactically invalid request (bad token or block size, etc) */
			action_set_fail(ACT_RESULT_PERMFAIL, 400, "Internal error: replicate block request failed");
		    } else if(http_status != 200) {
			act_result_t newret = http2actres(http_status);
			if(newret < ret) /* Severity shall only be raised */
			    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    }
		} else {
		    CRIT("Failed to wait for query");
		    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		}
	    }
	    free(sxi_cbdata_get_context(qrylist[i].cbdata));
	}
        query_list_free(qrylist, nqueries);
    }

    free(mis);

    if(ret == ACT_RESULT_OK) {
        unsigned i;
        for (i=0;i<sx_nodelist_count(nodes);i++) {
    	    succeeded[i] = 1;
        }
    }

    return ret;
}

static act_result_t fileflush_remote(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    unsigned int i, nnodes;
    act_result_t ret = ACT_RESULT_OK;
    sx_hashfs_tmpinfo_t *mis = NULL;
    query_list_t *qrylist = NULL;
    sxi_query_t *proto = NULL;
    int64_t tmpfile_id;
    const sx_hashfs_volume_t *volume;
    rc_ty s;

    if(job_data->len != sizeof(tmpfile_id)) {
       CRIT("Bad job data");
       action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }
    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));
    DEBUG("fileflush_remote for file %lld", (long long)tmpfile_id);
    s = sx_hashfs_tmp_getinfo(hashfs, tmpfile_id, &mis, 0);
    if(s == EFAULT || s == EINVAL) {
	CRIT("Error getting tmpinfo: %s", msg_get_reason());
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == ENOENT) {
	WARN("Token %lld could not be found", (long long)tmpfile_id);
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == EAGAIN)
	action_error(ACT_RESULT_TEMPFAIL, 500, "Job data temporary unavailable");

    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to check missing blocks");

    s = sx_hashfs_volume_by_id(hashfs, mis->volume_id, &volume);
    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to lookup volume");
    nnodes = sx_nodelist_count(nodes);
    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);
        if (!sx_hashfs_is_node_volume_owner(hashfs, NL_NEXTPREV, node, volume, 0)) {
	    succeeded[i] = 1; /* not a volnode, only used by undo/abort */
            continue;
        }
	if(sx_node_cmp(me, node)) {
	    /* Remote only - local tmpfile will be handled in fileflush_local */
	    if(!proto) {
		const sx_hashfs_volume_t *volume;
		unsigned int blockno;
		sxc_meta_t *fmeta;
                char revid_hex[SXI_SHA1_TEXT_LEN+1];
                char volid_hex[SXI_SHA1_TEXT_LEN+1];

		if(!(fmeta = sxc_meta_new(sx)))
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to prepare file propagate query");

                /* TODO: the volume reference is taken in each loop step, but it has already been loaded before the loop. */
		s = sx_hashfs_volume_by_id(hashfs, mis->volume_id, &volume);
		if(s == OK)
		    s = sx_hashfs_tmp_getmeta(hashfs, tmpfile_id, fmeta);
		if(s != OK) {
		    sxc_meta_free(fmeta);
		    action_error(rc2actres(s), rc2http(s), msg_get_reason());
		}

                bin2hex(volume->global_id.b, sizeof(volume->global_id.b), volid_hex, sizeof(volid_hex));
                bin2hex(mis->revision_id.b, sizeof(mis->revision_id.b), revid_hex, sizeof(revid_hex));
		proto = sxi_fileadd_proto_begin_internal(sx, volid_hex, mis->name, mis->revision, revid_hex, 0, mis->block_size, mis->file_size);

		blockno = 0;
		while(proto && blockno < mis->nall) {
		    char hexblock[SXI_SHA1_TEXT_LEN + 1];
		    bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), hexblock, sizeof(hexblock));
		    blockno++;
		    proto = sxi_fileadd_proto_addhash(sx, proto, hexblock);
		}

		if(proto)
		    proto = sxi_fileadd_proto_end(sx, proto, fmeta);
		sxc_meta_free(fmeta);

		qrylist = calloc(nnodes, sizeof(*qrylist));
		if(!proto || ! qrylist)
		    action_error(rc2actres(ENOMEM), rc2http(ENOMEM), "Failed to prepare file propagate query");
	    }

            qrylist[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[i].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[i].query_sent = 1;
	} else
	    succeeded[i] = 1; /* Local node is handled in _local  */
    }

 action_failed:
    if(qrylist) {
	for(i=0; i<nnodes; i++) {
	    if(qrylist[i].query_sent) {
                long http_status = 0;
		int rc = sxi_cbdata_wait(qrylist[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
		if(rc != -2) {
		    if(rc == -1) {
			WARN("Query failed with %ld", http_status);
			if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else if(http_status != 200 && http_status != 410) {
			act_result_t newret = http2actres(http_status);
			if(newret < ret) /* Severity shall only be raised */
			    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else
			succeeded[i] = 1;
		} else {
		    CRIT("Failed to wait for query");
		    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		}
	    }
	}
        query_list_free(qrylist, nnodes);
    }

    sxi_query_free(proto);
    free(mis);
    return ret;
}

static act_result_t fileflush_local(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sx_hashfs_tmpinfo_t *mis = NULL;
    const sx_node_t *me, *node;
    unsigned int i, nnodes;
    int64_t tmpfile_id;
    rc_ty s;

    if(job_data->len != sizeof(tmpfile_id)) {
       CRIT("Bad job data");
       action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }
    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));

    DEBUG("fileflush_local for file %lld", (long long)tmpfile_id);
    s = sx_hashfs_tmp_getinfo(hashfs, tmpfile_id, &mis, 0);
    if(s == EFAULT || s == EINVAL) {
	CRIT("Error getting tmpinfo: %s", msg_get_reason());
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == ENOENT) {
	WARN("Token %lld could not be found", (long long)tmpfile_id);
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to check missing blocks");

    nnodes = sx_nodelist_count(nodes);
    me = sx_hashfs_self(hashfs);
    for(i=0; i<nnodes; i++) {
	node = sx_nodelist_get(nodes, i);
	if(!sx_node_cmp(me, node)) {
	    /* Local only - remote file created in fileflush_remote */
	    s = sx_hashfs_tmp_tofile(hashfs, mis);
	    if(s != OK) {
		CRIT("Error creating file: %s", msg_get_reason());
		action_error(rc2actres(s), rc2http(s), msg_get_reason());
	    }
	}
	succeeded[i] = 1;
    }

 action_failed:
    free(mis);
    return ret;
}

static act_result_t replicateblocks_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    /* undo the revision bump from the commit in replicateblocks_request */
    return revision_job_from_tmpfileid(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, 1, JOBPHASE_UNDO);
}

static act_result_t fileflush_remote_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const sx_hashfs_volume_t *volume;
    act_result_t ret = ACT_RESULT_OK;
    sx_hashfs_tmpinfo_t *tmp = NULL;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    sxi_query_t *proto = NULL;
    int64_t tmpfile_id;
    rc_ty s;
    char volid_hex[SXI_SHA1_TEXT_LEN+1];

    nnodes = sx_nodelist_count(nodes);
    if(job_data->len != sizeof(tmpfile_id)) {
       CRIT("Bad job data");
       action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }
    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));
    DEBUG("fileflush_remote for file %lld", (long long)tmpfile_id);

    s = sx_hashfs_tmp_getinfo(hashfs, tmpfile_id, &tmp, 0);
    if(s == ENOENT)
	return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
    if(s != OK) {
	WARN("Failed to retrive file info for tempfile %lld which will not be cleanly removed", (long long)tmpfile_id);
	action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    s = sx_hashfs_volume_by_id(hashfs, tmp->volume_id, &volume);
    if(s == ENOENT)
	return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to find file to delete");
    bin2hex(volume->global_id.b, sizeof(volume->global_id.b), volid_hex, sizeof(volid_hex));

    sx_hashfs_revunbump(hashfs, &tmp->revision_id, tmp->block_size); /* No point in leaving the file around if this fails */

    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	if(!sx_node_cmp(me, node)) {
	    /* Local node - only parent undo needed */
            succeeded[nnode]++;
	} else {
	    /* Remote node */
	    if(!proto) {
		proto = sxi_filedel_proto_internal(sx, volid_hex, tmp->name, tmp->revision);
		if(!proto) {
		    WARN("Cannot allocate proto for job %lld", (long long)job_id);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		qrylist = calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate querylist for job %lld", (long long)job_id);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }
	    qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    if(proto) {
	for(nnode=0; qrylist && nnode<nnodes; nnode++) {
	    int rc;
	    long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
	    rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if(http_status == 200 || http_status == 404) {
		succeeded[nnode]++;
	    } else {
		act_result_t newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
	}
	query_list_free(qrylist, nnodes);
	sxi_query_free(proto);
    }
    for(nnode=0; nnode<nnodes; nnode++) {
        /* both 'parent undo' and 'child undo' must succeeded on a node for it
         * to be successful, if one fails both are attempted again */
        succeeded[nnode] = (succeeded[nnode] == 2);
    }

    free(tmp);
    return ret;
}

static act_result_t filedelete_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const sx_hashfs_volume_t *volume;
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    sxi_query_t *proto = NULL;
    sx_hashfs_file_t filerev;
    rc_ty s;
    char volid_hex[SXI_SHA1_TEXT_LEN+1];

    s = filerev_from_jobdata_rev(hashfs, job_data, &filerev);
    if(s == ENOENT) {
	DEBUG("Cannot get revision data from blob for job %lld", (long long)job_id);
	return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
    }
    if (s)
	action_error(rc2actres(s), rc2http(s), "Failed to find file to delete");

    s = sx_hashfs_volume_by_id(hashfs, filerev.volume_id, &volume);
    if(s == ENOENT)
	return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to find file to delete");
    bin2hex(volume->global_id.b, sizeof(volume->global_id.b), volid_hex, sizeof(volid_hex));

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	if(!sx_node_cmp(me, node)) {
            /* Local node: handled in commit */
	    succeeded[nnode] += 1;
	} else {
	    /* Remote node */
	    if(!proto) {
		proto = sxi_filedel_proto_internal(sx, volid_hex, filerev.name, filerev.revision);
		if(!proto) {
		    WARN("Cannot allocate proto for job %lld", (long long)job_id);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		qrylist = calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate querylist for job %lld", (long long)job_id);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }
            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
            DEBUG("Sending file delete query");
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    if(proto) {
	for(nnode=0; qrylist && nnode<nnodes; nnode++) {
	    int rc;
            long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if(http_status == 200 || http_status == 404) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
	}
        query_list_free(qrylist, nnodes);
	sxi_query_free(proto);
    }

    return ret;
}


static act_result_t filedelete_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_node_t *me = sx_hashfs_self(hashfs);
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes;
    rc_ty s;

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	if(!sx_node_cmp(me, sx_nodelist_get(nodes, nnode))) {
            sx_hashfs_file_t filerev;
            const sx_hashfs_volume_t *volume;

            s = filerev_from_jobdata_rev(hashfs, job_data, &filerev);
            if(s == ENOENT) {
                DEBUG("Cannot get revision data from blob for job %lld", (long long)job_id);
                return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
            }
            if (s)
                action_error(rc2actres(s), rc2http(s), "Failed to retrieve fileid");
            s = sx_hashfs_volume_by_id(hashfs, filerev.volume_id, &volume);
            if (s)
                action_error(rc2actres(s), rc2http(s), "Failed to retrieve volume id");
    	    s = sx_hashfs_file_delete(hashfs, volume, filerev.name, filerev.revision);
            if (s && s != ENOENT) {
                action_error(rc2actres(s), rc2http(s), "Failed to delete file");
            }
	}
	succeeded[nnode] = 1;
    }

 action_failed:
    return ret;
}

static act_result_t filedelete_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return revision_job_from_rev(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, -1, JOBPHASE_ABORT);
}

static act_result_t filedelete_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return revision_job_from_rev(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, -1, JOBPHASE_UNDO);
}

struct cb_challenge_ctx {
    sx_hash_challenge_t chlrsp;
    unsigned int at;
};

static int challenge_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_challenge_ctx *c = (struct cb_challenge_ctx *)ctx;
    if(c->at + size > sizeof(c->chlrsp.response))
	return 1;
    memcpy(&c->chlrsp.response[c->at], data, size);
    c->at += size;
    return 0;
}

#define TARGET_SYNCFLUSH_SIZE (16*1024*1024)
struct sync_ctx {
    sx_hashfs_t *hashfs;
    const sxi_hostlist_t *hlist;
    char *buf, permvolid_hex[SXI_SHA1_TEXT_LEN+1];
    unsigned int bufsz, bufat;
    enum sync_objtype { SYNCTYPE_NONE, SYNCTYPE_USER, SYNCTYPE_VOLUME, SYNCTYPE_PERM, SYNCTYPE_MODE, SYNCTYPE_CLUSTMETA, SYNCTYPE_SETTINGS } lstobjtype;
};
const char *sysects[] = { NULL, "users", "volumes", "perms", "misc", "misc", "misc" };

FMT_PRINTF(2, 3) static int sync_printf(struct sync_ctx *sctx, const char *fmt, ...) {
    unsigned int avail, needed;
    va_list ap;

    avail = sctx->bufsz - sctx->bufat;
    va_start(ap, fmt);
    needed = vsnprintf(&sctx->buf[sctx->bufat], avail, fmt, ap); /* Assuming C99 */
    va_end(ap);

    if(needed >= avail) {
	/* Alloc (needed+1) aligned up to the next boundary */
	sctx->bufsz += needed + 1 + (~needed & 0x3ff);
	sctx->buf = wrap_realloc_or_free(sctx->buf, sctx->bufsz);
	if(!sctx->buf) {
	    CRIT("Failed to allocate buffer to syncronise cluster objects");
	    return -1;
	}
	va_start(ap, fmt);
	vsprintf(&sctx->buf[sctx->bufat], fmt, ap);
	va_end(ap);
    }

    sctx->bufat += needed;
    return 0;
}

static int sync_flush(struct sync_ctx *sctx) {
    int qret;

    if(!sctx->bufat)
	return 0;

    if(sync_printf(sctx, "}}"))
	return -1;

    qret = sxi_cluster_query(sx_hashfs_conns(sctx->hashfs), sctx->hlist, REQ_PUT, ".sync", sctx->buf, sctx->bufat, NULL, NULL, NULL);
    if(qret != 200) {
	WARN("Sync query failed with %d", qret);
	return -1;
    }

    sctx->lstobjtype = SYNCTYPE_NONE;
    sctx->bufat = 0;
    return 0;
}

static int sync_objbegin(struct sync_ctx *sctx, enum sync_objtype type) {
    int ret;
    if(sctx->lstobjtype != type || sctx->bufat >= TARGET_SYNCFLUSH_SIZE) {
	if(sync_flush(sctx))
	    return -1;
	sctx->lstobjtype = type;
    }
    if(!sctx->bufat)
	ret = sync_printf(sctx, "{\"%s\":{", sysects[type]);
    else
	ret = sync_printf(sctx, ",");

    return ret;
}

static int sync_metapairs(struct sync_ctx *sctx, const char *json_head, rc_ty (*get_next_pair_fn)(sx_hashfs_t *, const char **, const void **, unsigned int *)) {
    char hexvalue[SXLIMIT_META_MAX_VALUE_LEN * 2 + 1];
    unsigned int metaval_len, head_sent = 0;
    const char *metakey;
    const void *metaval;
    int ret;
    rc_ty s;

    while((s=get_next_pair_fn(sctx->hashfs, &metakey, &metaval, &metaval_len)) == OK) {
	char *enc_key;
	if(bin2hex(metaval, metaval_len, hexvalue, sizeof(hexvalue))) {
	    WARN("Binary value too long for %s", metakey);
	    return -1;
	}
	enc_key = sxi_json_quote_string(metakey);
	if(!enc_key) {
	    WARN("Cannot encode cluster meta key %s", metakey);
	    return -1;
	}
	if(!head_sent) {
	    ret = sync_printf(sctx, "%s{%s:\"%s\"", json_head, enc_key, hexvalue);
	    head_sent = 1;
	} else
	    ret = sync_printf(sctx, ",%s:\"%s\"", enc_key, hexvalue);
	free(enc_key);
	if(ret)
	    return -1;
    }
    if(s != ITER_NO_MORE) {
	WARN("Failed to enumerate meta pairs");
	return -1;
    }
    if(head_sent && sync_printf(sctx, "}"))
	return -1;

    return 0;
}


static int syncusers_cb(sx_hashfs_t *hashfs, sx_uid_t user_id, const char *username, const uint8_t *user, const uint8_t *key, int is_admin, const char *desc, int64_t quota, int64_t quota_used, int print_meta, int print_custom_meta, int nmeta, metacontent_t *meta, void *ctx) {
    struct sync_ctx *sctx = (struct sync_ctx *)ctx;
    char *enc_name, *enc_desc, hexkey[AUTH_KEY_LEN*2+1], hexuser[AUTH_UID_LEN*2+1];
    int ret;
    rc_ty s;

    /* User object begin */
    if(sync_objbegin(sctx, SYNCTYPE_USER))
	return -1;

    enc_name = sxi_json_quote_string(username);
    if(!enc_name) {
	WARN("Cannot quote username %s", username);
	return -1;
    }
    enc_desc = sxi_json_quote_string(desc ? desc : "");
    if (!enc_desc) {
	WARN("Cannot quote desc %s", desc);
        free(enc_name);
	return -1;
    }
    bin2hex(key, AUTH_KEY_LEN, hexkey, sizeof(hexkey));
    bin2hex(user, AUTH_UID_LEN, hexuser, sizeof(hexuser));

    /* User main body */
    ret = sync_printf(sctx, "%s:{\"user\":\"%s\",\"key\":\"%s\",\"admin\":%s,\"desc\":%s,\"quota\":%lld",
		      enc_name, hexuser, hexkey, is_admin ? "true" : "false", enc_desc, (long long)quota);
    free(enc_name);
    free(enc_desc);
    if(ret)
	return -1;

    /* User metadata */
    s = sx_hashfs_usermeta_begin(hashfs, user_id);
    if(s != OK) {
        WARN("Failed to synchronize user metadata");
        return -1;
    }
    if(sync_metapairs(sctx, ",\"userMeta\":", sx_hashfs_usermeta_next))
	return -1;

    /* User object end */
    if(sync_printf(sctx, "}"))
	return -1;

    return 0;
}

static int syncperms_cb(const char *username, int priv, int is_owner, void *ctx) {
    struct sync_ctx *sctx = (struct sync_ctx *)ctx;
    char userhex[AUTH_UID_LEN * 2 + 1];
    uint8_t user[AUTH_UID_LEN];
    int comma = 1;

    if(!(priv & (PRIV_READ | PRIV_WRITE)))
	return 0;

    if(*sctx->permvolid_hex) {
	if(sync_objbegin(sctx, SYNCTYPE_PERM) || sync_printf(sctx, "\"%s\":{", sctx->permvolid_hex))
	    return -1;
	*sctx->permvolid_hex = '\0';
	comma = 0;
    }
    
    if(sx_hashfs_get_user_by_name(sctx->hashfs, username, user, 0)) {
	WARN("Failed to lookup user %s", username);
	return -1;
    }

    bin2hex(user, sizeof(user), userhex, sizeof(userhex));
    if(sync_printf(sctx, "%s \"%s\":%d", comma ? "," : "", userhex, priv))
	return -1;
    return 0;
}

static int sync_global_objects(sx_hashfs_t *hashfs, const sxi_hostlist_t *hlist) {
    const sx_hashfs_volume_t *vol;
    struct sync_ctx *sctx;
    time_t last_mod;
    char *enc_name;
    rc_ty s;
    int mode = 0, r, ret = -1;

    if(!(sctx = wrap_calloc(1, sizeof(*sctx)))) {
	WARN("Failed to allocate sync structure");
	return -1;
    }
    sctx->hashfs = hashfs;
    sctx->hlist = hlist;

    if(sx_hashfs_list_users(hashfs, NULL, syncusers_cb, 1, 1, 1, 1, sctx))
	goto sync_global_err;

    for(s = sx_hashfs_volume_first(hashfs, &vol, 0); s == OK; s = sx_hashfs_volume_next(hashfs)) {
	uint8_t user[AUTH_UID_LEN];
	char userhex[AUTH_UID_LEN * 2 + 1];
        char global_id_hex[SXI_SHA1_TEXT_LEN+1];

	/* Volume object begins */
	if(sx_hashfs_get_user_by_uid(hashfs, vol->owner, user, 0)) {
	    WARN("Cannot find user %lld (owner of %s)", (long long)vol->owner, vol->name);
	    goto sync_global_err;
	}
	bin2hex(user, AUTH_UID_LEN, userhex, sizeof(userhex));
        bin2hex(vol->global_id.b, sizeof(vol->global_id.b), global_id_hex, sizeof(global_id_hex));

	if(sync_objbegin(sctx, SYNCTYPE_VOLUME))
	    goto sync_global_err;

	enc_name = sxi_json_quote_string(vol->name);
	if(!enc_name) {
	    WARN("Failed to encode volume name %s", vol->name);
	    goto sync_global_err;
	}
	/* Volume main body */
	r = sync_printf(sctx, "%s:{\"owner\":\"%s\",\"size\":%lld,\"replica\":%u,\"revs\":%u,\"global_id\":\"%s\"",
			  enc_name, userhex, (long long)vol->size, vol->max_replica, vol->revisions, global_id_hex);
	free(enc_name);
	if(r)
	    goto sync_global_err;

	/* Volume metadata */
	s = sx_hashfs_volumemeta_begin(hashfs, vol);
	if(s != OK) {
	    WARN("Failed to enumaerate metadata for volume %s: %d", vol->name, s);
	    goto sync_global_err;
	}
	if(sync_metapairs(sctx, ",\"meta\":", sx_hashfs_volumemeta_next))
	    goto sync_global_err;

	/* User object end */
	if(sync_printf(sctx, "}"))
	    goto sync_global_err;
    }
    if(s != ITER_NO_MORE) {
	WARN("Volume enumeration failed with %d", s);
	goto sync_global_err;
    }

    s = sx_hashfs_volume_first(hashfs, &vol, 0);
    if(s == OK) {
	do {
	    bin2hex(vol->global_id.b, sizeof(vol->global_id.b), sctx->permvolid_hex, sizeof(sctx->permvolid_hex));
	    if(sx_hashfs_list_acl(hashfs, vol, 0, PRIV_ADMIN, syncperms_cb, sctx)) {
		WARN("Failed to list permissions for %s: %s", vol->name, msg_get_reason());
		goto sync_global_err;
	    }
	    if(*sctx->permvolid_hex) /* The volume was ignored by the cb */
		*sctx->permvolid_hex = '\0';
	    else if(sync_printf(sctx, "}")) /* The volume was not ignored */
		goto sync_global_err;

	    s = sx_hashfs_volume_next(hashfs);
	} while(s == OK);
	if(s != ITER_NO_MORE) {
	    WARN("Failed to list volume permissions: %d", s);
	    goto sync_global_err;
	}
    }

    if(sx_hashfs_cluster_get_mode(hashfs, &mode)) {
        WARN("Failed to get cluster operating mode");
	goto sync_global_err;
    }

    /* Syncing misc globs */
    if(sync_objbegin(sctx, SYNCTYPE_MODE) ||
       sync_printf(sctx, "\"mode\":\"%s\"", mode ? "ro" : "rw")) {
	goto sync_global_err;
    }

    /* Synchronize cluster meta */
    if(sx_hashfs_clustermeta_last_change(hashfs, &last_mod)) {
        WARN("Failed to get last cluster meta modification time");
	goto sync_global_err;
    }
    if(sync_objbegin(sctx, SYNCTYPE_CLUSTMETA) ||
       sync_printf(sctx, "\"clusterMeta\":[%ld", last_mod))
	goto sync_global_err;

    s = sx_hashfs_clustermeta_begin(hashfs);
    if(s != OK) {
	WARN("Failed to retrieve cluster metadata");
	goto sync_global_err;
    }
    if(sync_metapairs(sctx, ",", sx_hashfs_clustermeta_next))
	goto sync_global_err;
    if(sync_printf(sctx, "]"))
	goto sync_global_err;

    /* Synchronize cluster settings */
    if(sx_hashfs_cluster_settings_last_change(hashfs, &last_mod)) {
        WARN("Failed to get last cluster settings modification time");
	goto sync_global_err;
    } else {
	const char *setkey, *setval;
	s = sx_hashfs_cluster_settings_first(hashfs, &setkey, NULL, &setval);
	if(s == OK) {
	    if(sync_objbegin(sctx, SYNCTYPE_SETTINGS) ||
	       sync_printf(sctx, "\"clusterSettings\":[%ld,{", last_mod))
		goto sync_global_err;

	    do {
		char hexvalue[SXLIMIT_META_MAX_VALUE_LEN * 2 + 1];
		if(bin2hex(setval, strlen(setval), hexvalue, sizeof(hexvalue))) {
		    WARN("Cannot encode cluster settings value %s", setval);
		    goto sync_global_err;
		}
		enc_name = sxi_json_quote_string(setkey);
		if(!enc_name) {
		    WARN("Cannot encode cluster settings key %s", setkey);
		    goto sync_global_err;
		}
		r = sync_printf(sctx, "%s:\"%s\"", enc_name, hexvalue);
		free(enc_name);
		if(r)
		    goto sync_global_err;

		s = sx_hashfs_cluster_settings_next(hashfs);
		if(s == OK && sync_printf(sctx, ","))
		    goto sync_global_err;

	    } while(s == OK);
	    if(s == ITER_NO_MORE) {
		if(sync_printf(sctx, "}]"))
		    goto sync_global_err;
		s = OK;
	    }
	}
	if(s != OK) {
	    WARN("Failed to retrieve cluster settings: %d", s);
	    goto sync_global_err;
	}
    }

    if(sync_flush(sctx))
	goto sync_global_err;

    ret = 0; /* Success */

 sync_global_err:
    if(sctx) {
	free(sctx->buf);
	free(sctx);
    }
    return ret;
}

static int challenge_and_sync(sx_hashfs_t *hashfs, const sx_node_t *node, int *fail_code, char *fail_msg) {
    sx_hash_challenge_t chlrsp;
    char challenge[lenof(".challenge/") + sizeof(chlrsp.challenge) * 2 + 1];
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    struct cb_challenge_ctx ctx;
    sxi_query_t *initproto;
    sxi_hostlist_t hlist;
    int qret, ret = 1;

    sxi_hostlist_init(&hlist);
    ctx.at = 0;
    if(sx_hashfs_challenge_gen(hashfs, &chlrsp, 1)) {
	WARN("Failed to generate challenge %s: %s",  sx_node_uuid_str(node), msg_get_reason());
	ret = 1;
	goto sync_err;
    }

    if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node))) {
	WARN("Not enough memory to perform challenge request on %s", sx_node_uuid_str(node));
	ret = 1;
	goto sync_err;
    }

    strcpy(challenge, ".challenge/");
    bin2hex(chlrsp.challenge, sizeof(chlrsp.challenge), challenge + lenof(".challenge/"), sizeof(challenge) - lenof(".challenge/"));
    qret = sxi_cluster_query(clust, &hlist, REQ_GET, challenge, NULL, 0, NULL, challenge_cb, &ctx);
    if(qret != 200 || ctx.at != sizeof(chlrsp.response)) {
	WARN("Challenge query to %s failed: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
	ret = 2;
	goto sync_err;
    }

    if(memcmp(chlrsp.response, ctx.chlrsp.response, sizeof(chlrsp.response))) {
	WARN("Bad challenge response from %s", sx_node_uuid_str(node));
	ret = 2;
	goto sync_err;
    }	

    initproto = sxi_nodeinit_proto(sx,
				   sx_hashfs_cluster_name(hashfs),
				   sx_node_uuid_str(node),
				   sx_hashfs_http_port(hashfs),
				   sx_hashfs_uses_secure_proto(hashfs),
				   sx_hashfs_ca_file(hashfs));
    if(!initproto) {
	WARN("Not enough memory to perform node initialise request on %s", sx_node_uuid_str(node));
	ret = 1;
	goto sync_err;
    }

    qret = sxi_cluster_query(clust, &hlist, initproto->verb, initproto->path, initproto->content, initproto->content_len, NULL, NULL, NULL);
    sxi_query_free(initproto);
    if(qret != 200) {
	WARN("Initialise query to %s failed: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
	ret = 2;
	goto sync_err;
    }

    /* MOHDIST: Create users and volumes */
    if(sync_global_objects(hashfs, &hlist)) {
	WARN("Failed to synchronize objects on node %s", sx_node_uuid_str(node));
	ret = 2;
	goto sync_err;
    }	

    ret = 0;

 sync_err:
    sxi_hostlist_empty(&hlist);
    return ret;
}

static act_result_t distribution_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hashfs_version_t *swver = sx_hashfs_version(hashfs);
    sxi_hdist_t *hdist;
    const sx_nodelist_t *prev, *next;
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes;
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxi_query_t *proto = NULL;
    sxi_hostlist_t hlist;
    int qret;
    rc_ty s;

    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    hdist = sxi_hdist_from_cfg(job_data->ptr, job_data->len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	s = ENOMEM;
	action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	return ret;
    }

    sxi_hostlist_init(&hlist);

    if(sxi_hdist_buildcnt(hdist) != 2) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    prev = sxi_hdist_nodelist(hdist, 1);
    next = sxi_hdist_nodelist(hdist, 0);
    if(!prev || !next) {
	WARN("Invalid distribution found");
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    proto = sxi_distribution_proto_begin(sx, job_data->ptr, job_data->len, swver->str);
    if(proto)
	proto = sxi_distribution_proto_end(sx, proto);
    if(!proto) {
	WARN("Cannot allocate proto for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }
    nnodes = sx_nodelist_count(nodes);

    /* Sync newly added nodes first - failure is always PERM */
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	int was_in = sx_nodelist_lookup(prev, sx_node_uuid(node)) != NULL;
	int is_in = sx_nodelist_lookup(next, sx_node_uuid(node)) != NULL;

	if(!was_in) {
	    if(!is_in) {
		WARN("Node %s is not part of either the old and the new distributions", sx_node_uuid_str(node));
		action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
	    }
	    
	    if(!sx_node_cmp(me, node)) {
		WARN("This node cannot be both a distribution change initiator and a new node");
		action_error(ACT_RESULT_PERMFAIL, 500, "Something is really out of place");
	    }

	    /* Challenge new node */
	    switch(challenge_and_sync(hashfs, node, fail_code, fail_msg)) {
	    case 0:
		break;
	    case 1:
		action_error(ACT_RESULT_PERMFAIL, 500, "Failed to join new node due to local errors");
	    default:
		action_error(ACT_RESULT_PERMFAIL, 500, "Failed to join new node due to remote errors");
	    }
	}
    }

    /* Set distribution on newly added nodes first */
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	int was_in = sx_nodelist_lookup(prev, sx_node_uuid(node)) != NULL;

	if(was_in)
	    continue;

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
	    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform challenge request");

	qret = sxi_cluster_query(clust, &hlist, proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL, NULL);
	if(qret != 200)
	    action_error(http2actres(qret), qret, sxc_geterrmsg(sx));

	sxi_hostlist_empty(&hlist);
	succeeded[nnode] = 1;
    }

    /* Finally set distribution on existing nodes */
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	int was_in = sx_nodelist_lookup(prev, sx_node_uuid(node)) != NULL;

	if(!was_in)
	    continue;

	if(sx_node_cmp(me, node)) {
	    if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
		action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform challenge request");
	    qret = sxi_cluster_query(clust, &hlist, proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL, NULL);
	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	    sxi_hostlist_empty(&hlist);
	} else {
	    s = sx_hashfs_hdist_change_add(hashfs, job_data->ptr, job_data->len);
	    if(s)
		action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	}

	succeeded[nnode] = 1;
    }


action_failed:
    sxi_query_free(proto);
    sxi_hostlist_empty(&hlist);
    sxi_hdist_free(hdist);

    if(ret == ACT_RESULT_PERMFAIL) {
	sx_nodelist_t *lockednodes = get_all_job_targets(hashfs, job_id);
	send_unlock(hashfs, lockednodes);
	sx_nodelist_delete(lockednodes);
    }
    return ret;
}


static act_result_t commit_dist_common(sx_hashfs_t *hashfs, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int is_replacemnt_dist) {
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes;
    sxi_hostlist_t hlist;
    rc_ty s;

    sxi_hostlist_init(&hlist);
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
	    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform the enable distribution request");

	if(sx_node_cmp(me, node)) {
	    int qret = sxi_cluster_query(clust, &hlist, REQ_PUT, is_replacemnt_dist ? ".dist?replaceNodes" : ".dist", NULL, 0, NULL, NULL, NULL);
	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	} else {
	    s = sx_hashfs_hdist_change_commit(hashfs, is_replacemnt_dist);
	    if(s)
		action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	}

	sxi_hostlist_empty(&hlist);
	succeeded[nnode] = 1;
    }

action_failed:
    sxi_hostlist_empty(&hlist);

    return ret;
}

static act_result_t distribution_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sxi_hdist_t *hdist = NULL;

    if(!job_data) {
	NULLARG();
	action_error(ACT_RESULT_PERMFAIL, 500, "Null job");
    }

    hdist = sxi_hdist_from_cfg(job_data->ptr, job_data->len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	action_error(rc2actres(ENOMEM), rc2http(ENOMEM), msg_get_reason());
    }

    if(sxi_hdist_buildcnt(hdist) != 2) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    ret = commit_dist_common(hashfs, nodes, succeeded, fail_code, fail_msg, 0);

action_failed:
    sxi_hdist_free(hdist);
    return ret;
}

static act_result_t revoke_dist_common(sx_hashfs_t *hashfs, job_t job_id, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes;
    sx_nodelist_t *lockednodes;
    sxi_hostlist_t hlist;
    rc_ty s;

    /* Extra force unlock in case of timeouts */
    lockednodes = get_all_job_targets(hashfs, job_id);
    send_unlock(hashfs, lockednodes);
    sx_nodelist_delete(lockednodes);

    sxi_hostlist_init(&hlist);
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
	    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform the revoke distribution request");

	if(sx_node_cmp(me, node)) {
	    int qret = sxi_cluster_query(clust, &hlist, REQ_DELETE, ".dist", NULL, 0, NULL, NULL, NULL);
	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	} else {
	    s = sx_hashfs_hdist_change_revoke(hashfs);
	    if(s)
		action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	}

	sxi_hostlist_empty(&hlist);
	succeeded[nnode] = 1;
    }

action_failed:
    sxi_hostlist_empty(&hlist);
    return ret;
}

static act_result_t distribution_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sxi_hdist_t *hdist = NULL;

    if(!job_data) {
	NULLARG();
	action_error(ACT_RESULT_PERMFAIL, 500, "Null job");
    }

    hdist = sxi_hdist_from_cfg(job_data->ptr, job_data->len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	action_error(rc2actres(ENOMEM), rc2http(ENOMEM), msg_get_reason());
    }

    if(sxi_hdist_buildcnt(hdist) != 2) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    ret = revoke_dist_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg);

action_failed:
    sxi_hdist_free(hdist);
    return ret;
}

static act_result_t distribution_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret;

    CRIT("The attempt to change the cluster distribution model (i.e. nodes) resulted in a fatal failure leaving it in an inconsistent state");
    action_set_fail(ACT_RESULT_PERMFAIL, 500, "The attempt to change the cluster distribution model (i.e. nodes) resulted in a fatal failure leaving it in an inconsistent state");
    return ret;
}


static act_result_t startrebalance_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    unsigned int i, nnodes = sx_nodelist_count(nodes);
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    rc_ty s;

    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);
	if(sx_node_cmp(me, node)) {
	    /* Remote node */
	    if(!qrylist) {
		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate query");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[i].cbdata, clust, sx_node_internal_addr(node), REQ_PUT, ".rebalance", NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[i].query_sent = 1;
	} else {
	    /* Local node */
	    s = sx_hashfs_hdist_rebalance(hashfs);
	    if(s != OK)
		action_error(rc2actres(s), rc2http(s), msg_get_reason());
	    succeeded[i] = 1;
	}
    }

 action_failed:
    if(qrylist) {
	for(i=0; i<nnodes; i++) {
	    if(qrylist[i].query_sent) {
                long http_status = 0;
		int rc = sxi_cbdata_wait(qrylist[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
		if(rc != -2) {
		    if(rc == -1) {
			WARN("Query failed with %ld", http_status);
			if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else if(http_status != 200) {
			act_result_t newret = http2actres(http_status);
			if(newret < ret) /* Severity shall only be raised */
			    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else
			succeeded[i] = 1;
		} else {
		    CRIT("Failed to wait for query");
		    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		}
	    }
	}
        query_list_free(qrylist, nnodes);
    }

    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }

    return ret;
}


static act_result_t jlock_common(int lock, sx_hashfs_t *hashfs, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int unlockall) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    unsigned int i, nnodes = sx_nodelist_count(nodes);
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    char *query = NULL;
    rc_ty s;

    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);
	const char *owner = sx_node_uuid_str(me);
	if(!lock && unlockall)
	    owner = "any";
	if(sx_node_cmp(me, node)) {
	    /* Remote node */
	    if(!query) {
		query = wrap_malloc(lenof(".jlock/") + strlen(owner) + 1);
		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!query || !qrylist) {
		    WARN("Cannot allocate query");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		sprintf(query, ".jlock/%s", owner);
	    }

            qrylist[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[i].cbdata, clust, sx_node_internal_addr(node), lock ? REQ_PUT : REQ_DELETE, query, NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[i].query_sent = 1;
	} else {
	    /* Local node */
	    if(lock)
		s = sx_hashfs_job_lock(hashfs, owner);
	    else
		s = sx_hashfs_job_unlock(hashfs, unlockall ? NULL : owner);
	    if(s != OK)
		action_error(rc2actres(s), rc2http(s), msg_get_reason());
            if(!lock && unlockall) {
                s = sx_hashfs_force_volumes_replica_unlock(hashfs);
                if(s != OK)
                    action_error(rc2actres(s), rc2http(s), msg_get_reason());
            }
	    if(succeeded)
		succeeded[i] = 1;
	}
    }

 action_failed:
    if(qrylist) {
	for(i=0; i<nnodes; i++) {
	    if(qrylist[i].query_sent) {
                long http_status = 0;
		int rc = sxi_cbdata_wait(qrylist[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
		if(rc != -2) {
		    if(rc == -1) {
			WARN("Query failed with %ld", http_status);
			if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else if(http_status != 200) {
			act_result_t newret = http2actres(http_status);
			if(newret < ret) /* Severity shall only be raised */
			    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else
			if(succeeded)
			    succeeded[i] = 1;
		} else {
		    CRIT("Failed to wait for query");
		    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		}
	    }
	}
        query_list_free(qrylist, nnodes);
    }

    free(query);
    return ret;
}

static act_result_t jlock_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return jlock_common(1, hashfs, nodes, succeeded, fail_code, fail_msg, 0);
}

static act_result_t jlock_abort_and_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return jlock_common(0, hashfs, nodes, succeeded, fail_code, fail_msg, 0);
}

static void send_unlock(sx_hashfs_t *hashfs, const sx_nodelist_t *nodes) {
    char buf[JOB_FAIL_REASON_SIZE];
    int ret;
    
    if(!nodes)
	return;
    jlock_common(0, hashfs, nodes, NULL, &ret, buf, 0);
}


static act_result_t junlockall_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    jlock_common(0, hashfs, nodes, succeeded, fail_code, fail_msg, 1);
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

#define FOREACH_BLOCK(startq)						\
    if(verbose_rebalance)						\
	for(unsigned int _qno = (startq); _qno < maxnodes && rbdata[_qno].node; _qno++) \
	    for(unsigned int _bno = 0; _bno < rbdata[_qno].nblocks; _bno++)

#define FOREACH_QUEUE_BLOCK(blockq)					\
    if(verbose_rebalance)						\
	for(unsigned int _qno = (blockq), _bno = 0; _bno < rbdata[_qno].nblocks; _bno++)


#define RB_MAX_NODES (2 /* FIXME: bump me ? */)
#define RB_MAX_BLOCKS (100 /* FIXME: should be a sane(!) multiple of DOWNLOAD_MAX_BLOCKS */)
#define RB_MAX_TRIES (RB_MAX_BLOCKS * RB_MAX_NODES)
static act_result_t blockrb_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_node_t *self = sx_hashfs_self(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_nodelist_t *next = sx_hashfs_all_nodes(hashfs, NL_NEXT);
    act_result_t ret = ACT_RESULT_OK;
    struct {
	curlev_context_t *cbdata;
	sxi_query_t *proto;
	const sx_node_t *node;
	block_meta_t *blocks[RB_MAX_BLOCKS];
	unsigned int nblocks;
	int query_sent;
    } rbdata[RB_MAX_NODES];
    unsigned int i, j, maxnodes = 0, maxtries;
    rc_ty s;

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    memset(rbdata, 0, sizeof(rbdata));

    s = sx_hashfs_br_begin(hashfs);
    if(s == ITER_NO_MORE) {
	rbl_log(NULL, "br_begin", 1, "Work complete");
	INFO("No more blocks to be relocated");
	succeeded[0] = 1;
	return ACT_RESULT_OK;
    } else if(s != OK) {
	rbl_log(NULL, "br_begin", 0, "Error %d (%s)", s,  msg_get_reason());
	action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }
    rbl_log(NULL, "br_begin", 1, NULL);

    maxnodes = MIN(RB_MAX_NODES, sx_nodelist_count(next) - (sx_nodelist_lookup(next, sx_node_uuid(self)) != NULL));
    maxtries = RB_MAX_TRIES; /* Maximum *consecutive* attempts to find a pushable block */
    rbl_log(NULL, "nqueues", 1, "Using up to %u queues", maxnodes);
    while(maxtries) {
	const sx_node_t *target;
	block_meta_t *blockmeta;
	char hstr[sizeof(blockmeta->hash) * 2 +1];

	s = sx_hashfs_br_next(hashfs, &blockmeta);
	if(s != OK) {
            if(s == ITER_NO_MORE)
		rbl_log(NULL, "br_next", 1, "Round complete");
	    else
		rbl_log(NULL, "br_next", 0, "Error %d (%s)", s,  msg_get_reason());
	    break;
	}
	rbl_log(NULL, "br_next", 1, "Block received");

	bin2hex(&blockmeta->hash, sizeof(blockmeta->hash), hstr, sizeof(hstr));

	s = sx_hashfs_new_home_for_old_block(hashfs, &blockmeta->hash, &target);
	if(s == EINVAL) {
	    /* Block homelessness (mostly triggering on blocks left over from previous rebalances) */
	    rbl_log(&blockmeta->hash, "newhome", 1, "Falure ignored: %s", msg_get_reason());
	    INFO("Failed to identify target for %s: %s", hstr, msg_get_reason());
	    sx_hashfs_blockmeta_free(&blockmeta);
	    continue;
	} else if(s != OK) {
	    /* Should never trigger */
	    rbl_log(&blockmeta->hash, "newhome", 0, "Error %d (%s)", s, msg_get_reason());
	    WARN("Failed to identify target for %s: %s", hstr, msg_get_reason());
	    sx_hashfs_blockmeta_free(&blockmeta);
	    break;
	}
	if(!sx_node_cmp(self, target)) {
	    /* Not to be moved */
	    rbl_log(&blockmeta->hash, "newhome", 1, "No migration required");
	    DEBUG("Block %s is not to be moved", hstr);
            DEBUGHASH("br_ignore", &blockmeta->hash);
	    sx_hashfs_blockmeta_free(&blockmeta);
	    continue;
	}
	rbl_log(&blockmeta->hash, "newhome", 1, "New home on %s", sx_node_uuid_str(target));
        if ((s = sx_hashfs_br_use(hashfs, blockmeta))) {
	    rbl_log(&blockmeta->hash, "br_use", 0, "Error %d (%s)", s,  msg_get_reason());
	    sx_hashfs_blockmeta_free(&blockmeta);
            break;
        }
	rbl_log(&blockmeta->hash, "br_use", 1, NULL);
	for(i=0; i<maxnodes; i++) {
	    if(!rbdata[i].node) {
		rbdata[i].node = target;
		break;
	    }
	    if(!sx_node_cmp(rbdata[i].node, target))
		break;
	}
	if(i == maxnodes) {
	    /* All target slots are taken, will target again later */
	    rbl_log(&blockmeta->hash, "enqueue", 0, "No queues to %s currently available", sx_node_uuid_str(target));
	    DEBUG("Block %s is targeted for %s(%s) to which we currently do not have a channel", hstr, sx_node_uuid_str(target), sx_node_internal_addr(target));
	    sx_hashfs_blockmeta_free(&blockmeta);
	    maxtries--;
	    continue;
	}
	if(rbdata[i].nblocks >= RB_MAX_BLOCKS) {
	    /* This target is already full */
	    rbl_log(&blockmeta->hash, "enqueue", 0, "Queue to %s is already full", sx_node_uuid_str(target));
	    DEBUG("Channel to %s (%s) have all the slots full: block %s will be moved later", sx_node_uuid_str(target), sx_node_internal_addr(target), hstr);
	    sx_hashfs_blockmeta_free(&blockmeta);
	    maxtries--;
	    continue;
	}

	rbl_log(&blockmeta->hash, "enqueue", 1, "Queued to %s in position %u", sx_node_uuid_str(target), rbdata[i].nblocks);

	rbdata[i].blocks[rbdata[i].nblocks] = blockmeta;
	rbdata[i].nblocks++;
	maxtries = RB_MAX_TRIES; /* Reset tries to the max */
	if(rbdata[i].nblocks >= RB_MAX_BLOCKS) {
	    /* Target has reached capacity, check if everyone is full */
	    for(j=0; j<maxnodes; j++)
		if(rbdata[j].nblocks < RB_MAX_BLOCKS)
		    break;
	    if(j == maxnodes) {
		DEBUG("All slots on all channels are now complete");
		break; /* All slots for all targets are full */
	    }
	}
    }

    if(s == OK || s == ITER_NO_MORE) {
	unsigned int dist_version;
	const sx_uuid_t *dist_id = sx_hashfs_distinfo(hashfs, &dist_version, NULL);
	if(!dist_id) {
	    WARN("Cannot retrieve distribution version");
	    FOREACH_BLOCK(0) {
		rbl_log(&rbdata[_qno].blocks[_bno]->hash, "distinfo", 0, "Distinfo failed");
	    }
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to retrieve distribution version");
	}
	FOREACH_BLOCK(0) {
	    rbl_log(&rbdata[_qno].blocks[_bno]->hash, "distinfo", 1, NULL);
	}
	for(i=0; i<maxnodes; i++) {
	    if(!rbdata[i].node)
		break;

            /* FIXME: proper expiration time */
	    rbdata[i].proto = sxi_hashop_proto_inuse_begin(sx, NULL);
	    for(j=0; j<rbdata[i].nblocks; j++)
		rbdata[i].proto = sxi_hashop_proto_inuse_hash(sx, rbdata[i].proto, rbdata[i].blocks[j]);
	    rbdata[i].proto = sxi_hashop_proto_inuse_end(sx, rbdata[i].proto);
	    if(!rbdata[i].proto) {
		FOREACH_BLOCK(i) {
		    rbl_log(&rbdata[_qno].blocks[_bno]->hash, "inuse_query", 0, "Query allocation failure");
		}
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }

            rbdata[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(rbdata[i].cbdata, clust, sx_node_internal_addr(rbdata[i].node), rbdata[i].proto->verb, rbdata[i].proto->path, rbdata[i].proto->content, rbdata[i].proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(rbdata[i].node), sxc_geterrmsg(sx));
		FOREACH_BLOCK(i) {
		    rbl_log(&rbdata[_qno].blocks[_bno]->hash, "inuse_query", 0, "Query to %s failed with %s", sx_node_uuid_str(rbdata[_qno].node), sxc_geterrmsg(sx));
		}
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }

	    rbdata[i].query_sent = 1;
	}
    } else
	action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to iterate blocks");


action_failed:

    for(i=0; i<maxnodes; i++) {
	if(!rbdata[i].node)
	    break;

	if(rbdata[i].query_sent) {
            long http_status = 0;
	    int rc = sxi_cbdata_wait(rbdata[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc != -2) {
		if(rc == -1) {
		    WARN("Query failed with %ld", http_status);
		    FOREACH_QUEUE_BLOCK(i) {
			rbl_log(&rbdata[_qno].blocks[_bno]->hash, "inuse_query", 0, "Remote query failed with HTTP %ld", http_status);
		    }
		    if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(rbdata[i].cbdata));
		} else if(http_status != 200) {
		    act_result_t newret = http2actres(http_status);
		    FOREACH_QUEUE_BLOCK(i) {
			rbl_log(&rbdata[_qno].blocks[_bno]->hash, "inuse_query", 0, "Remote query failed with HTTP %ld", http_status);
		    }
		    if(newret < ret) /* Severity shall only be raised */
			action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(rbdata[i].cbdata));
		} else {
		    for(j=0; j<rbdata[i].nblocks; j++) {
			rbl_log(&rbdata[i].blocks[j]->hash, "inuse_query", 1, NULL);
			if((s = sx_hashfs_blkrb_hold(hashfs, &rbdata[i].blocks[j]->hash, rbdata[i].blocks[j]->blocksize, rbdata[i].node)) != OK) {
			    WARN("Cannot hold block"); /* Unexpected but not critical, will retry later */
			    rbl_log(&rbdata[i].blocks[j]->hash, "blkrb_hold", 0, "Error %d (%s)", s,  msg_get_reason());
			} else {
			    rbl_log(&rbdata[i].blocks[j]->hash, "blkrb_hold", 1, NULL);
			    if((s = sx_hashfs_xfer_tonode(hashfs, &rbdata[i].blocks[j]->hash, rbdata[i].blocks[j]->blocksize, rbdata[i].node, FLOW_BULK_UID)) != OK) {
				WARN("Cannot add block to transfer queue"); /* Unexpected but not critical, will retry later */
				rbl_log(&rbdata[i].blocks[j]->hash, "xfer_tonode", 0, "Error %d (%s)", s,  msg_get_reason());
			    } else {
				rbl_log(&rbdata[i].blocks[j]->hash, "xfer_tonode", 1, NULL);
				if((s = sx_hashfs_br_delete(hashfs, rbdata[i].blocks[j])) != OK) {
				    WARN("Cannot delete block"); /* Unexpected but not critical, will retry later */
				    rbl_log(&rbdata[i].blocks[j]->hash, "br_delete", 0, "Error %d (%s)", s,  msg_get_reason());
				} else
				    rbl_log(&rbdata[i].blocks[j]->hash, "br_delete", 1, NULL);
			    }
			}
		    }
		}
	    } else {
		CRIT("Failed to wait for query");
		FOREACH_QUEUE_BLOCK(i) {
		    rbl_log(&rbdata[_qno].blocks[_bno]->hash, "inuse_query", 0, "Failed to wait for query result");
		}
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
	    }
	}

	for(j=0; j<rbdata[i].nblocks; j++)
	    sx_hashfs_blockmeta_free(&rbdata[i].blocks[j]);

        sxi_cbdata_unref(&rbdata[i].cbdata);
	sxi_query_free(rbdata[i].proto);

    }

    /* If some block was skipped, return tempfail so we get called again later */
    if(ret == ACT_RESULT_OK) {
	DEBUG("All blocks in this batch queued for tranfer; more to come later...");
	action_set_fail(ACT_RESULT_NOTFAILED, 503, "Block propagation in progress");
    }

    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }

    return ret;
}

static act_result_t blockrb_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    if(sx_hashfs_blkrb_is_complete(hashfs) != OK) {
	INFO("Waiting for pending block tranfers to complete");
	action_error(ACT_RESULT_TEMPFAIL, 500, "Awaiting completion of block propagation");
    }

    INFO("All blocks were migrated successfully");
    succeeded[0] = 1;

 action_failed:
    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}


static act_result_t filerb_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REBALANCE_RUNNING, "Relocating metadata (initialization)");

    if(sx_hashfs_relocs_populate(hashfs) != OK) {
	INFO("Failed to populate the relocation queue");
	action_error(ACT_RESULT_TEMPFAIL, 500, "Failed to setup file relocation");
    }

    succeeded[0] = 1;

 action_failed:
    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}

#define RB_MAX_FILES 128
static act_result_t filerb_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    struct {
	const sx_reloc_t *reloc;
	curlev_context_t *cbdata;
	sxi_query_t *proto;
	int query_sent;
    } rbdata[RB_MAX_FILES];
    unsigned int i;
    act_result_t ret;
    int64_t nrelocs;
    rc_ty r;

    memset(&rbdata, 0, sizeof(rbdata));

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    r = sx_hashfs_relocs_begin(hashfs, &nrelocs);
    if(r == ITER_NO_MORE) {
	/* ITER_NO_MORE here means that there are no more files to relocate *AT ALL* */
	ret = ACT_RESULT_OK;
    } else if(r != OK) {
	/* DB busy or something */
	action_error(ACT_RESULT_TEMPFAIL, 503, "Relocation data (temporarily) unavailable");
    } else {
	char msgbuf[128];
	snprintf(msgbuf, sizeof(msgbuf), "Relocating metadata (%lld objects remaining)", (long long)nrelocs);
	sx_hashfs_set_progress_info(hashfs, INPRG_REBALANCE_RUNNING, msgbuf);

	for(i = 0; i<RB_MAX_FILES; i++) {
	    const sx_reloc_t *rlc;
	    unsigned int blockno;
            char revid_hex[SXI_SHA1_TEXT_LEN+1];
            char volid_hex[SXI_SHA1_TEXT_LEN+1];

	    r = sx_hashfs_relocs_next(hashfs, &rlc);
	    if(r == ITER_NO_MORE) {
		/* ITER_NO_MORE *here* means that there are no more files to relocate *FOR THIS ROUND* */
		break;
	    }
	    if(r != OK)
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to lookup file to relocate");

            bin2hex(rlc->volume.global_id.b, sizeof(rlc->volume.global_id.b), volid_hex, sizeof(volid_hex));
            bin2hex(rlc->file.revision_id.b, sizeof(rlc->file.revision_id.b), revid_hex, sizeof(revid_hex));
	    rbdata[i].reloc = rlc;
	    rbdata[i].proto = sxi_fileadd_proto_begin_internal(sx,
						      volid_hex,
						      rlc->file.name,
						      rlc->file.revision,
                                                      revid_hex,
						      0,
						      rlc->file.block_size,
						      rlc->file.file_size);
	    blockno = 0;
	    while(rbdata[i].proto && blockno < rlc->file.nblocks) {
		char hexblock[SXI_SHA1_TEXT_LEN + 1];
		bin2hex(&rlc->blocks[blockno], sizeof(rlc->blocks[0]), hexblock, sizeof(hexblock));
		blockno++;
		if(rbdata[i].proto)
		    rbdata[i].proto = sxi_fileadd_proto_addhash(sx, rbdata[i].proto, hexblock);
	    }

	    if(rbdata[i].proto)
		rbdata[i].proto = sxi_fileadd_proto_end(sx, rbdata[i].proto, rlc->metadata);

	    if(!rbdata[i].proto)
		action_error(rc2actres(ENOMEM), rc2http(ENOMEM), "Failed to prepare file relocation query");

	    rbdata[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    DEBUG("File query: %u %s [ %s ]", rbdata[i].proto->verb, rbdata[i].proto->path, (char *)rbdata[i].proto->content);
	    if(sxi_cluster_query_ev(rbdata[i].cbdata, clust, sx_node_internal_addr(rlc->target), rbdata[i].proto->verb, rbdata[i].proto->path, rbdata[i].proto->content, rbdata[i].proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(rlc->target), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    rbdata[i].query_sent = 1;
	}

	action_error(ACT_RESULT_NOTFAILED, 503, "File relocation in progress");
    }


 action_failed:
    for(i = 0; i<RB_MAX_FILES; i++) {
	if(rbdata[i].query_sent) {
            long http_status = 0;
	    int rc = sxi_cbdata_wait(rbdata[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc != -2) {
		if(rc == -1) {
		    WARN("Query failed with %ld", http_status);
		    if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(rbdata[i].cbdata));
		} else if(http_status != 200) {
		    act_result_t newret = http2actres(http_status);
		    if(newret < ret) /* Severity shall only be raised */
			action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(rbdata[i].cbdata));
		} else if(sx_hashfs_relocs_delete(hashfs, rbdata[i].reloc) != OK) {
		    if(ret == ACT_RESULT_OK)
			action_set_fail(ACT_RESULT_TEMPFAIL, 503, "Failed to delete file from relocation queue");
		}
	    } else {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
	    }
	}

        sxi_cbdata_unref(&rbdata[i].cbdata);
	sxi_query_free(rbdata[i].proto);
	sx_hashfs_reloc_free(rbdata[i].reloc);
    }

    if(ret == ACT_RESULT_OK) {
	if(sx_hashfs_set_progress_info(hashfs, INPRG_REBALANCE_COMPLETE, "Relocation complete") == OK) {
	    INFO(">>>>>>>>>>>> OBJECT RELOCATION COMPLETE <<<<<<<<<<<<");
	    succeeded[0] = 1;
	} else
	    action_set_fail(ACT_RESULT_TEMPFAIL, 503, msg_get_reason());
    }

    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}


static act_result_t finishrebalance_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    unsigned int i, nnodes = sx_nodelist_count(nodes);
    act_result_t ret = ACT_RESULT_TEMPFAIL;
    sxi_hostlist_t hlist;

    sxi_hostlist_init(&hlist);

    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);
	DEBUG("Checking for rebalance completion on %s", sx_node_internal_addr(node));
	if(sx_node_cmp(me, node)) {
	    /* Remote node */
	    clst_t *clst;
	    clst_state qret;

	    if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
		action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to query rebalance status");
	    clst = clst_query(clust, &hlist);
	    if(!clst)
		action_error(ACT_RESULT_TEMPFAIL, 500, "Failed to query rebalance status");

	    qret = clst_rebalance_state(clst, NULL);
	    clst_destroy(clst);

	    if(qret == CLSTOP_COMPLETED)
		succeeded[i] = 1;
	    else if(qret == CLSTOP_INPROGRESS) {
		DEBUG("Relocation still running on node %s", sx_node_uuid_str(node));
		action_error(ACT_RESULT_TEMPFAIL, 500, "Relocation still running");
	    } else {
		WARN("Unexpected rebalance state on node %s", sx_node_uuid_str(node));
		action_error(ACT_RESULT_TEMPFAIL, 500, "Unexpected rebalance status");
	    }

	    sxi_hostlist_empty(&hlist);
	} else {
	    /* Local node */
	    sx_inprogress_t inprg = sx_hashfs_get_progress_info(hashfs, NULL);
	    if(inprg == INPRG_ERROR)
		action_error(ACT_RESULT_TEMPFAIL, 500, "Unexpected rebalance state on local node");
	    else if(inprg == INPRG_REBALANCE_COMPLETE)
		succeeded[i] = 1;
	    else
		action_error(ACT_RESULT_TEMPFAIL, 500, "Rebalance still running on local node");
	}
    }

    ret = ACT_RESULT_OK;

 action_failed:
    sxi_hostlist_empty(&hlist);

    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	/* NOTE: this block was put in here for consistency with other handler, even if it cannot be reached */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }

    return ret;
}


static act_result_t finishrebalance_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    unsigned int i, nnodes = sx_nodelist_count(nodes);
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    rc_ty s;

    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);
	DEBUG("Stopping rebalance on %s", sx_node_internal_addr(node));
	if(sx_node_cmp(me, node)) {
	    /* Remote node */
	    if(!qrylist) {
		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate query");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[i].cbdata, clust, sx_node_internal_addr(node), REQ_DELETE, ".rebalance", NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[i].query_sent = 1;
	} else {
	    /* Local node */
	    s = sx_hashfs_hdist_endrebalance(hashfs);
	    if(s != OK)
		action_error(rc2actres(s), rc2http(s), msg_get_reason());
	    succeeded[i] = 1;
	}
    }

 action_failed:
    if(qrylist) {
	for(i=0; i<nnodes; i++) {
	    if(qrylist[i].query_sent) {
                long http_status = 0;
		int rc = sxi_cbdata_wait(qrylist[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
		if(rc != -2) {
		    if(rc == -1) {
			WARN("Query failed with %ld", http_status);
			if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else if(http_status != 200) {
			act_result_t newret = http2actres(http_status);
			if(newret < ret) /* Severity shall only be raised */
			    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else
			succeeded[i] = 1;
		} else {
		    CRIT("Failed to wait for query");
		    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		}
	    }
	}
        query_list_free(qrylist, nnodes);
    }

    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}


static act_result_t cleanrb_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    if((s = sx_hashfs_hdist_set_rebalanced(hashfs))) {
	WARN("Cannot set rebalanced: %s", msg_get_reason());
	action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REBALANCE_COMPLETE, "Cleaning up relocated objects after successful rebalance");

    succeeded[0] = 1;

 action_failed:
    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}

static act_result_t cleanrb_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    if(sx_hashfs_rb_cleanup(hashfs) != OK)
	action_error(ACT_RESULT_TEMPFAIL, 503, "Cleanup failed");

    sx_hashfs_set_progress_info(hashfs, INPRG_IDLE, NULL);

    INFO(">>>>>>>>>>>> THIS NODE IS NOW FULLY REBALANCED <<<<<<<<<<<<");
    succeeded[0] = 1;

 action_failed:
    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}

/* Context used to push volume sizes */
struct volsizes_push_ctx {
    unsigned int idx; /* index of a node which query was sent to */
    unsigned int fail; /* Will be set to 0 if query has been successfully sent to all nodes */
    sxi_query_t *query; /* query reference used to send query */
};

/* Push volume sizes to particular node */
static curlev_context_t *push_volume_sizes(sx_hashfs_t *h, const sx_node_t *n, unsigned int node_index, sxi_query_t **query) {
    curlev_context_t *ret;
    struct volsizes_push_ctx *ctx;

    if(!h || !n || !query) {
        NULLARG();
        return NULL;
    }

    ret = sxi_cbdata_create_generic(sx_hashfs_conns(h), NULL, NULL);
    if(!ret) {
        WARN("Failed to allocate cbdata");
        return NULL;
    }

    /* Create context which will be added to cbdata */
    ctx = malloc(sizeof(*ctx));
    if(!ctx) {
        WARN("Failed to allocate push context");
        sxi_cbdata_unref(&ret);
        return NULL;
    }

    /* Assign index to distinguish nodes during polling */
    ctx->idx = node_index;
    /* Assign query to free it later (its content may be used in async callbacks) */
    ctx->query = *query;
    /* Avoid double free */
    *query = NULL;
    /* Set fail flag to 1 (failed), it will be assgined to 0 later */
    ctx->fail = 1;
    /* Add context to cbdata */
    sxi_cbdata_set_context(ret, ctx);

    if(sxi_cluster_query_ev(ret, sx_hashfs_conns(h), sx_node_internal_addr(n), REQ_PUT, ctx->query->path, ctx->query->content, ctx->query->content_len, NULL, NULL)) {
        WARN("Failed to push volume size to host %s: %s", sx_node_internal_addr(n), sxc_geterrmsg(sx_hashfs_client(h)));
        sxi_query_free(ctx->query);
        free(ctx);
        sxi_cbdata_unref(&ret);
        return NULL;
    }

    return ret;
}

static act_result_t replace_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hashfs_version_t *swver = sx_hashfs_version(hashfs);
    sxi_hdist_t *hdist = NULL;
    sx_nodelist_t *faulty = NULL;
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes, cfg_len;
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    sxi_query_t *proto = NULL;
    sx_blob_t *b = NULL;
    sxi_hostlist_t hlist;
    const void *cfg;
    int qret;
    rc_ty s;

    DEBUG("IN %s", __func__);
    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    sxi_hostlist_init(&hlist);
    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    faulty = sx_nodelist_from_blob(b);
    if(!faulty || sx_blob_get_blob(b, &cfg, &cfg_len)) {
	WARN("Cannot retrrieve %s from job data for job %lld", faulty ? "new distribution":"faulty nodes", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    hdist = sxi_hdist_from_cfg(cfg, cfg_len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	s = ENOMEM;
	action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    if(sxi_hdist_buildcnt(hdist) != 1) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    proto = sxi_distribution_proto_begin(sx, cfg, cfg_len, swver->str);
    nnodes = sx_nodelist_count(faulty);
    for(nnode = 0; proto && nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(faulty, nnode);
	proto = sxi_distribution_proto_add_faulty(sx, proto, sx_node_uuid_str(node));
    }
    if(proto)
	proto = sxi_distribution_proto_end(sx, proto);
    if(!proto) {
	WARN("Cannot allocate proto for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	int is_replacement = sx_nodelist_lookup(faulty, sx_node_uuid(node)) != NULL;

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
	    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform challenge request");

	if(is_replacement) {
	    if(!sx_node_cmp(me, node)) {
		WARN("This node cannot be both a distribution change initiator and a new node");
		action_error(ACT_RESULT_PERMFAIL, 500, "Something is really out of place");
	    }

	    /* Challenge new node */
	    switch(challenge_and_sync(hashfs, node, fail_code, fail_msg)) {
	    case 0:
		break;
	    case 1:
		action_error(ACT_RESULT_PERMFAIL, 500, "Failed to join new node due to local errors");
	    default:
		action_error(ACT_RESULT_PERMFAIL, 500, "Failed to join new node due to remote errors");
	    }
	}

	if(sx_node_cmp(me, node)) {
	    qret = sxi_cluster_query(clust, &hlist, proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL, NULL);
	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	} else {
	    s = sx_hashfs_hdist_replace_add(hashfs, cfg, cfg_len, faulty);
	    if(s)
		action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	}

	sxi_hostlist_empty(&hlist);
	succeeded[nnode] = 1;
    }

action_failed:
    sx_nodelist_delete(faulty);
    sx_blob_free(b);
    sxi_query_free(proto);
    sxi_hostlist_empty(&hlist);
    sxi_hdist_free(hdist);

    if(ret == ACT_RESULT_PERMFAIL) {
	sx_nodelist_t *lockednodes = get_all_job_targets(hashfs, job_id);
	send_unlock(hashfs, lockednodes);
	sx_nodelist_delete(lockednodes);
    }

    return ret;
}

static act_result_t replace_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sx_nodelist_t *faulty = NULL;
    sxi_hdist_t *hdist = NULL;
    unsigned int cfg_len;
    sx_blob_t *b = NULL;
    const void *cfg;

    DEBUG("IN %s", __func__);
    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    faulty = sx_nodelist_from_blob(b);
    if(!faulty || sx_blob_get_blob(b, &cfg, &cfg_len)) {
	WARN("Cannot retrrieve %s from job data for job %lld", faulty ? "new distribution":"faulty nodes", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    hdist = sxi_hdist_from_cfg(cfg, cfg_len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	action_error(rc2actres(ENOMEM), rc2http(ENOMEM), msg_get_reason());
    }

    if(sxi_hdist_buildcnt(hdist) != 1) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    ret = commit_dist_common(hashfs, nodes, succeeded, fail_code, fail_msg, 1);

action_failed:
    sx_nodelist_delete(faulty);
    sxi_hdist_free(hdist);
    sx_blob_free(b);
    return ret;
}

static act_result_t replace_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sx_nodelist_t *faulty = NULL;
    sxi_hdist_t *hdist = NULL;
    unsigned int cfg_len;
    sx_blob_t *b = NULL;
    const void *cfg;

    DEBUG("IN %s", __func__);
    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    faulty = sx_nodelist_from_blob(b);
    if(!faulty || sx_blob_get_blob(b, &cfg, &cfg_len)) {
	WARN("Cannot retrrieve %s from job data for job %lld", faulty ? "new distribution":"faulty nodes", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    hdist = sxi_hdist_from_cfg(cfg, cfg_len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	action_error(rc2actres(ENOMEM), rc2http(ENOMEM), msg_get_reason());
    }

    if(sxi_hdist_buildcnt(hdist) != 1) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    ret = revoke_dist_common(hashfs, job_id, nodes, succeeded, fail_code, fail_msg);

action_failed:
    sx_nodelist_delete(faulty);
    sxi_hdist_free(hdist);
    sx_blob_free(b);
    return ret;
}

static void check_distribution(sx_hashfs_t *h) {
    int dc;

    dc = sx_hashfs_distcheck(h);
    if(dc < 0) {
        CRIT("Failed to reload distribution");
        return;
    }
    if(dc > 0)
        INFO("Distribution reloaded");
}

static act_result_t replace_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret;

    CRIT("The attempt to change the cluster distribution model (i.e. nodes) resulted in a fatal failure leaving it in an inconsistent state");
    action_set_fail(ACT_RESULT_PERMFAIL, 500, "The attempt to change the cluster distribution model (i.e. nodes) resulted in a fatal failure leaving it in an inconsistent state");
    return ret;
}


static act_result_t replaceblocks_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;

    DEBUG("IN %s", __func__);
    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REPLACE_RUNNING, "Building a list of objects to heal");

    if(sx_hashfs_init_replacement(hashfs))
	action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to initialize replacement");

    succeeded[0] = 1;

 action_failed:
    return ret;
}


enum replace_state { RPL_HDRSIZE = 0, RPL_HDRDATA, RPL_DATA, RPL_END };

struct rplblocks {
    sx_hashfs_t *hashfs;
    sx_blob_t *b;
    uint8_t block[SX_BS_LARGE];
    sx_block_meta_index_t lastgood;
    unsigned int pos, itemsz, ngood;
    enum replace_state state;
};

static int rplblocks_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct rplblocks *c = (struct rplblocks *)ctx;
    uint8_t *input = (uint8_t *)data;
    unsigned int todo;

    while(size) {
	if(c->state == RPL_END) {
	    if(size)
		INFO("Spurious tail of %u bytes", (unsigned int)size);
	    return 0;
	}

	if(c->state == RPL_HDRSIZE) {
	    todo = MIN((sizeof(c->itemsz) - c->pos), size);
	    memcpy(c->block + c->pos, input, todo);
	    input += todo;
	    size -= todo;
	    c->pos += todo;
	    if(c->pos == sizeof(c->itemsz)) {
		memcpy(&todo, c->block, sizeof(todo));
		c->itemsz = htonl(todo);
		if(c->itemsz >= sizeof(c->block)) {
		    WARN("Invalid header size %u", c->itemsz);
		    return 1;
		}
		c->state = RPL_HDRDATA;
		c->pos = 0;
	    }
	}

	if(c->state == RPL_HDRDATA) {
	    todo = MIN((c->itemsz - c->pos), size);
	    memcpy(c->block + c->pos, input, todo);
	    input += todo;
	    size -= todo;
	    c->pos += todo;
	    if(c->pos == c->itemsz) {
		const char *signature;
		c->b = sx_blob_from_data(c->block, c->itemsz);
		if(!c->b) {
		    WARN("Cannot create blob of size %u", c->itemsz);
		    return 1;
		}
		if(sx_blob_get_string(c->b, &signature)) {
		    WARN("Cannot read create blob signature");
		    return 1;
		}
		if(!strcmp(signature, "$THEEND$")) {
		    if(size)
			INFO("Spurious tail of %u bytes", (unsigned int)size);
		    c->state = RPL_END;
		    return 0;
		}
		if(strcmp(signature, "$BLOCK$")) {
		    WARN("Invalid blob signature '%s'", signature);
		    return 1;
		}
		if(sx_blob_get_int32(c->b, &c->itemsz) ||
		   sx_hashfs_check_blocksize(c->itemsz)) {
		    WARN("Invalid block size");
		    return 1;
		}
		c->state = RPL_DATA;
		c->pos = 0;
	    }
	}

	if(c->state == RPL_DATA) {
	    todo = MIN((c->itemsz - c->pos), size);
	    memcpy(c->block + c->pos, input, todo);
	    input += todo;
	    size -= todo;
	    c->pos += todo;
	    if(c->pos == c->itemsz) {
		const sx_block_meta_index_t *bmi;
		sx_hash_t hash;
		const void *ptr;

		if(sx_blob_get_blob(c->b, &ptr, &todo) || todo != sizeof(hash)) {
		    WARN("Invalid block hash");
		    return 1;
		}
		memcpy(&hash, ptr, sizeof(hash));

		/* FIXME: do i hash the block and match it ? */

		if(sx_blob_get_blob(c->b, (const void **)&bmi, &todo) || todo != sizeof(*bmi)) {
		    WARN("Invalid block index");
		    return 1;
		}
		if(sx_blob_get_int32(c->b, &todo)) {
		    WARN("Invalid number of entries");
		    return 1;
		}

		while(todo--) {
                    sx_hash_t revision_id, global_vol_id;
		    unsigned int replica;
		    rc_ty s;
		    const void *ptr;
                    unsigned int blob_size;

		    if(sx_blob_get_blob(c->b, &ptr, &blob_size) ||
                       blob_size != sizeof(revision_id.b)) {
			WARN("Invalid revision id size: %d", blob_size);
			return 1;
                    }
                    memcpy(&revision_id.b, ptr, sizeof(revision_id.b));
                    if(sx_blob_get_blob(c->b, &ptr, &blob_size) ||
                       blob_size != sizeof(global_vol_id.b)) {
                        WARN("Invalid global volume id size: %d", blob_size);
                        return 1;
                    }
                    memcpy(&global_vol_id.b, ptr, sizeof(global_vol_id.b));
                    if (sx_blob_get_int32(c->b, &replica)) {
			WARN("Invalid replica: %d", replica);
			return 1;
		    }

		    s = sx_hashfs_hashop_mod(c->hashfs, &hash, &global_vol_id, NULL, &revision_id, c->itemsz, replica, 1, 0);
		    if(s != OK && s != ENOENT) {
			WARN("Failed to mod hash");
			return 1;
		    }
		}

		if(sx_hashfs_block_put(c->hashfs, c->block, c->itemsz, 0, FLOW_DEFAULT_UID)) { /* Flow is not actually used because of 0 replica */
		    WARN("Failed to mod hash");
		    return 1;
		}
		c->lastgood = *bmi;
		sx_blob_free(c->b);
		c->b = NULL;
		c->ngood++;
		c->pos = 0;
		c->state = RPL_HDRSIZE;
	    }
	}
    }
    return 0;
}


static act_result_t replaceblocks_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    act_result_t ret = ACT_RESULT_TEMPFAIL;
    sx_block_meta_index_t bmidx;
    const sx_node_t *source;
    sxi_hostlist_t hlist;
    unsigned int dist;
    int have_blkidx;
    rc_ty s;

    DEBUG("IN %s", __func__);
    sxi_hostlist_init(&hlist);

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REPLACE_RUNNING, "Healing blocks");

    s = sx_hashfs_replace_getstartblock(hashfs, &dist, &source, &have_blkidx, (uint8_t *)&bmidx);
    if(s == OK) {
	sxi_conns_t *clust = sx_hashfs_conns(hashfs);
	const sx_node_t *me = sx_hashfs_self(hashfs);
	struct rplblocks *ctx = malloc(sizeof(*ctx));
	char query[256];
	int qret;

	if(!ctx)
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory");
	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(source))) {
	    free(ctx);
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory");
	}

	if(have_blkidx) {
	    char hexidx[sizeof(bmidx)*2+1];
	    bin2hex(&bmidx, sizeof(bmidx), hexidx, sizeof(hexidx));
	    snprintf(query, sizeof(query), ".replblk?target=%s&dist=%u&idx=%s", sx_node_uuid_str(me), dist, hexidx);
	} else
	    snprintf(query, sizeof(query), ".replblk?target=%s&dist=%u", sx_node_uuid_str(me), dist);

	ctx->hashfs = hashfs;
	ctx->b = NULL;
	ctx->pos = 0;
	ctx->ngood = 0;
	ctx->state = RPL_HDRSIZE;

	qret = sxi_cluster_query(clust, &hlist, REQ_GET, query, NULL, 0, NULL, rplblocks_cb, ctx);
	sx_blob_free(ctx->b);
	if(qret != 200) {
	    free(ctx);
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Bad reply from node");
	}
	if(ctx->state == RPL_END) {
	    if(sx_hashfs_replace_setlastblock(hashfs, sx_node_uuid(source), NULL))
		WARN("Replace setnode failed");
	} else if(ctx->ngood) {
	    if(sx_hashfs_replace_setlastblock(hashfs, sx_node_uuid(source), (uint8_t *)&ctx->lastgood))
		WARN("Replace setnode failed");
	}
	free(ctx);

	action_error(ACT_RESULT_NOTFAILED, 503, "Block repopulation in progress");
    } else if(s == ITER_NO_MORE) {
	succeeded[0] = 1;
	ret = ACT_RESULT_OK;
    }

 action_failed:
    sxi_hostlist_empty(&hlist);
    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}


struct rplfiles {
    sx_hashfs_t *hashfs;
    sx_blob_t *b;
    sx_hash_t hash;
    const sx_hashfs_volume_t *vol;
    uint8_t hdr[1024 +
		  SXLIMIT_MAX_FILENAME_LEN +
		  REV_LEN +
		  ( 128 + SXLIMIT_META_MAX_KEY_LEN + SXLIMIT_META_MAX_VALUE_LEN ) * SXLIMIT_META_MAX_ITEMS];
    char volume[SXLIMIT_MAX_VOLNAME_LEN+1],
	file[SXLIMIT_MAX_FILENAME_LEN+1],
	rev[REV_LEN+1];
    unsigned int ngood, itemsz, pos, needend, allow_over_replica;
    enum replace_state state;
};

static int rplfiles_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct rplfiles *c = (struct rplfiles *)ctx;
    uint8_t *input = (uint8_t *)data;
    unsigned int todo;
    rc_ty s;

    while(size) {
	if(c->state == RPL_END) {
	    if(size)
		INFO("Spurious tail of %u bytes", (unsigned int)size);
	    return 0;
	}

	if(c->state == RPL_HDRSIZE) {
	    todo = MIN((sizeof(c->itemsz) - c->pos), size);
	    memcpy(c->hdr + c->pos, input, todo);
	    input += todo;
	    size -= todo;
	    c->pos += todo;
	    if(c->pos == sizeof(c->itemsz)) {
		memcpy(&todo, c->hdr, sizeof(todo));
		c->itemsz = htonl(todo);
		if(c->itemsz >= sizeof(c->hdr)) {
		    WARN("Invalid header size %u", c->itemsz);
		    return 1;
		}
		c->state = RPL_HDRDATA;
		c->pos = 0;
	    }
	}

	if(c->state == RPL_HDRDATA) {
	    todo = MIN((c->itemsz - c->pos), size);
	    memcpy(c->hdr + c->pos, input, todo);
	    input += todo;
	    size -= todo;
	    c->pos += todo;
	    if(c->pos == c->itemsz) {
		const char *signature;
		c->b = sx_blob_from_data(c->hdr, c->itemsz);
		if(!c->b) {
		    WARN("Cannot create blob of size %u", c->itemsz);
		    return 1;
		}
		if(sx_blob_get_string(c->b, &signature)) {
		    WARN("Cannot read create blob signature");
		    return 1;
		}
		if(!strcmp(signature, "$THEEND$")) {
		    c->state = RPL_END;
		    if(size)
			INFO("Spurious tail of %u bytes", (unsigned int)size);
		    return 0;
		}
		if(strcmp(signature, "$FILE$")) {
		    WARN("Invalid blob signature '%s'", signature);
		    return 1;
		}
		if(sx_hashfs_createfile_begin(c->hashfs)) {
		    WARN("Invalid createfile_begin failed");
		    return 1;
		}
		c->needend = 1;
		if(sx_blob_get_int32(c->b, &c->itemsz)) {
		    WARN("Invalid block size");
		    return 1;
		}
		c->state = RPL_DATA;
		c->pos = 0;
	    }
	}

	if(c->state == RPL_DATA) {
	    if(c->itemsz) {
		todo = MIN((sizeof(c->hash) - c->pos), size);
		memcpy((uint8_t *)&c->hash + c->pos, input, todo);
		input += todo;
		size -= todo;
		c->pos += todo;
		if(c->pos == sizeof(c->hash)) {
		    if(sx_hashfs_putfile_putblock(c->hashfs, &c->hash)) {
			WARN("Failed to add block");
			return 1;
		    }
		    c->pos = 0;
		    c->itemsz--;
		}
	    }
	    if(!c->itemsz) {
		const char *file_name, *file_rev;
                const sx_hash_t *file_revid;
		int64_t file_size;
                unsigned int file_revid_len;
		if(sx_blob_get_string(c->b, &file_name) ||
		   sx_blob_get_string(c->b, &file_rev) ||
                   sx_blob_get_blob(c->b, (const void**)&file_revid, &file_revid_len) ||
                   file_revid_len != SXI_SHA1_BIN_LEN ||
		   sx_blob_get_int64(c->b, &file_size)) {
		    WARN("Bad file characteristics");
		    return 1;
		}
		while(1) {
		    const char *signature, *key;
		    const void *val;
		    if(sx_blob_get_string(c->b, &signature)) {
			WARN("Bad file meta signature");
			return 1;
		    }
		    if(!strcmp(signature, "$ENDMETA$"))
			break;
		    if(strcmp(signature, "$META$") ||
		       sx_blob_get_string(c->b, &key) ||
		       sx_blob_get_blob(c->b, &val, &todo)) {
			WARN("Bad file meta");
			return 1;
		    }
		    if(sx_hashfs_putfile_putmeta(c->hashfs, key, val, todo)) {
			WARN("Failed to add file meta");
			return 1;
		    }
		}
		s = sx_hashfs_createfile_commit(c->hashfs, c->vol, file_name, file_rev, file_revid, file_size, c->allow_over_replica);
		c->needend = 0;
		if(s) {
		    WARN("Failed to create file %s:%s", file_name, file_rev);
		    return 1;
		}
		c->ngood++;
		sxi_strlcpy(c->file, file_name, sizeof(c->file));
		sxi_strlcpy(c->rev, file_rev, sizeof(c->rev));
		sx_blob_free(c->b);
		c->b = NULL;
		c->state = RPL_HDRSIZE;
	    }
	}
    }
    return 0;
}

static act_result_t replacefiles_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    act_result_t ret;
    char maxrev[REV_LEN+1];
    sxi_hostlist_t hlist;
    struct rplfiles *ctx = NULL;
    rc_ty s;

    DEBUG("IN %s", __func__);
    sxi_hostlist_init(&hlist);

    if(job_data->len || sx_nodelist_count(nodes) != 1) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REPLACE_RUNNING, "Healing files");

    ctx = malloc(sizeof(*ctx));
    if(!ctx)
	action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory allocating request context");

    while((s = sx_hashfs_replace_getstartfile(hashfs, maxrev, ctx->volume, ctx->file, ctx->rev)) == OK) {
	unsigned int nnode, nnodes, rndnode;
	const sx_node_t *source;
	sx_nodelist_t *volnodes;

	s = sx_hashfs_volume_by_name(hashfs, ctx->volume, &ctx->vol);
	if(s == ENOENT) {
	    /* Volume is gone */
	    s = sx_hashfs_replace_setlastfile(hashfs, ctx->volume, NULL, NULL);
	    if(s == OK)
		continue;
	}
	if(s != OK)
	    action_error(rc2actres(s), rc2http(s), msg_get_reason());

	s = sx_hashfs_all_volnodes(hashfs, NL_NEXT, ctx->vol, 0, &volnodes, NULL);
	if(s != OK)
	    action_error(rc2actres(s), rc2http(s), msg_get_reason());

	nnodes = sx_nodelist_count(volnodes);
	rndnode = sxi_rand();
	for(nnode = 0; nnode < nnodes; nnode++) {
	    source = sx_nodelist_get(volnodes, (nnode + rndnode) % nnodes);
	    if(!sx_hashfs_is_node_faulty(hashfs, sx_node_uuid(source)))
		break;
	}
	if(nnode == nnodes) {
	    /* All volnodes are faulty */
	    s = sx_hashfs_replace_setlastfile(hashfs, ctx->volume, NULL, NULL);
	    sx_nodelist_delete(volnodes);
	    if(s == OK)
		continue; /* Pick next volume */
	    break; /* Retry later */
	}

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(source))) {
	    sx_nodelist_delete(volnodes);
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory");
	}
	sx_nodelist_delete(volnodes);
	break; /* exit with s = OK and hlist set */
    }

    if(s == OK) {
	char *enc_vol = NULL, *enc_file = NULL, *enc_rev = NULL, *enc_maxrev = NULL, *query = NULL;
	sxi_conns_t *clust = sx_hashfs_conns(hashfs);
	int qret;

	enc_vol = sxi_urlencode(sx, ctx->volume, 0);
	enc_file = sxi_urlencode(sx, ctx->file, 0);
	enc_rev = sxi_urlencode(sx, ctx->rev, 0);
	enc_maxrev = sxi_urlencode(sx, maxrev, 0);

	if(enc_vol && enc_file && enc_rev && enc_maxrev) {
	    query = malloc(lenof(".replfl/") +
			   strlen(enc_vol) +
			   lenof("/") +
			   strlen(enc_file) +
			   lenof("?maxrev=") +
			   strlen(enc_maxrev) +
			   lenof("&startrev=") +
			   strlen(enc_rev) +
			   1);

	    if(query) {
		if(strlen(enc_file))
		    sprintf(query, ".replfl/%s/%s?maxrev=%s&startrev=%s", enc_vol, enc_file, enc_maxrev, enc_rev);
		else
		    sprintf(query, ".replfl/%s?maxrev=%s", enc_vol, enc_maxrev);
	    }
	}

	free(enc_vol);
	free(enc_file);
	free(enc_rev);
	free(enc_maxrev);

	if(!query)
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory allocating the request URL");

	ctx->hashfs = hashfs;
	ctx->b = NULL;
	ctx->pos = 0;
	ctx->ngood = 0;
	ctx->needend = 0;
        ctx->allow_over_replica = 0;
	ctx->state = RPL_HDRSIZE;

	qret = sxi_cluster_query(clust, &hlist, REQ_GET, query, NULL, 0, NULL, rplfiles_cb, ctx);
	free(query);
	sx_blob_free(ctx->b);
	if(ctx->needend)
	    sx_hashfs_putfile_end(hashfs);
	if(qret != 200)
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Bad reply from node");
	if(ctx->state == RPL_END) {
	    if(sx_hashfs_replace_setlastfile(hashfs, ctx->volume, NULL, NULL))
		WARN("Replace setlastfile failed");
	    else
		INFO("Replacement of volume %s completed", ctx->volume);
	} else if(ctx->ngood) {
	    if(sx_hashfs_replace_setlastfile(hashfs, ctx->volume, ctx->file, ctx->rev))
		WARN("Replace setlastfile failed");
	}

	action_error(ACT_RESULT_NOTFAILED, 503, "File repopulation in progress");
    } else if(s == ITER_NO_MORE) {
	succeeded[0] = 1;
	ret = ACT_RESULT_OK;
    } else
	action_error(rc2actres(s), rc2http(s), msg_get_reason());


 action_failed:
    sxi_hostlist_empty(&hlist);
    free(ctx);
    if(ret == ACT_RESULT_PERMFAIL) {
	/* Since there is no way we can recover at this point we
	 * downgrade to temp failure and try to notify about the issue.
	 * There is no timeout anyway */
	CRITCOND;
	ret = ACT_RESULT_TEMPFAIL;
	*fail_code = 503;
    }
    return ret;
}

static act_result_t replacefiles_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_nodelist_t *allnodes = sx_hashfs_all_nodes(hashfs, NL_NEXT);
    int64_t hdistver = sx_hashfs_hdist_getversion(hashfs);
    unsigned int i, nnodes = sx_nodelist_count(allnodes);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const sx_uuid_t *myuuid = sx_node_uuid(me);
    query_list_t *qrylist = NULL;
    char query[128];
    rc_ty s;
    act_result_t ret = ACT_RESULT_OK;

    DEBUG("IN %s", __func__);

    if(!sx_hashfs_is_node_faulty(hashfs, myuuid)) {
	sx_hashfs_set_progress_info(hashfs, INPRG_IDLE, NULL);
	return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REPLACE_COMPLETE, "Healing complete");

    snprintf(query, sizeof(query), ".faulty/%s?dist=%lld", myuuid->string, (long long)hdistver); 
    qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
    if(!qrylist) {
	WARN("Cannot allocate result space");
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }
    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(allnodes, i);
	if(!sx_node_cmp(me, node))
	    continue;
	/* Remote nodes first */
	qrylist[i].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	if(sxi_cluster_query_ev(qrylist[i].cbdata, clust, sx_node_internal_addr(node), REQ_DELETE, query, NULL, 0, NULL, NULL)) {
	    WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
	    action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	}
	qrylist[i].query_sent = 1;
    }


 action_failed:
    if(qrylist) {
	for(i=0; i<nnodes; i++) {
	    if(qrylist[i].query_sent) {
                long http_status = 0;
		int rc = sxi_cbdata_wait(qrylist[i].cbdata, sxi_conns_get_curlev(clust), &http_status);
		if(rc != -2) {
		    if(rc == -1) {
			WARN("Query failed with %ld", http_status);
			if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
			    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    } else if(http_status != 200 && http_status != 404) {
			act_result_t newret = http2actres(http_status);
			if(newret < ret) /* Severity shall only be raised */
			    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[i].cbdata));
		    }
		} else {
		    CRIT("Failed to wait for query");
		    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		}
	    }
	}
        query_list_free(qrylist, nnodes);
    }

    if(ret == ACT_RESULT_OK) {
	/* Local node last */
	s = sx_hashfs_set_unfaulty(hashfs, myuuid, hdistver);
	if(s == OK || s == ENOENT) {
	    INFO(">>>>>>>>>>>> THIS NODE IS NOW A PROPER REPLACEMENT  <<<<<<<<<<<<");
	    succeeded[0] = 1;
	} else
	    action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
    }
    return ret;
}

static act_result_t ignodes_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sx_nodelist_t *ignodes = NULL;
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes;
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    query_list_t *qrylist = NULL;
    char *query = NULL;
    sx_blob_t *b = NULL;
    rc_ty s;

    DEBUG("IN %s", __func__);
    if(!job_data) {
	NULLARG();
	action_error(ACT_RESULT_PERMFAIL, 500, "Null job");
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    ignodes = sx_nodelist_from_blob(b);
    if(!ignodes) {
	WARN("Cannot retrrieve list of nodes from job data for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    nnodes = sx_nodelist_count(nodes);
    qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
    if(!qrylist) {
	WARN("Cannot allocate result space");
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	if(!sx_node_cmp(me, node)) {
	    /* Local node */
	    if((s = sx_hashfs_setignored(hashfs, ignodes))) {
		WARN("Failed to mark faulty nodes for job %lld: %s", (long long)job_id, msg_get_reason());
		action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to enable volume");
	    }
	    succeeded[nnode] = 1;
	} else {
	    /* Remote node */
	    if(!query) {
		unsigned int i, nign = sx_nodelist_count(ignodes);
		char *eoq;
		query = malloc((UUID_STRING_SIZE+3) * nign + sizeof("{\"faultyNodes\":[]}"));
		if(!query)
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory allocating the request");
		sprintf(query, "{\"faultyNodes\":[");
		eoq = query + lenof("{\"faultyNodes\":[");
		for(i=0; i<nign; i++) {
		    const sx_node_t *ignode = sx_nodelist_get(ignodes, i);
		    snprintf(eoq, UUID_STRING_SIZE+3+3, "\"%s\"%s", sx_node_uuid_str(ignode), i != nign-1 ? "," : "]}");
		    eoq += strlen(eoq);
		}
	    }
	    qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_PUT, ".nodes?setfaulty", query, strlen(query), NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }


 action_failed:
    sx_nodelist_delete(ignodes);
    sx_blob_free(b);
    if(query) {
	for(nnode=0; qrylist && nnode<nnodes; nnode++) {
	    int rc;
            long http_status = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
	    if(rc == -2) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		continue;
	    }
	    if(rc == -1) {
		WARN("Query failed with %ld", http_status);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    } else if(http_status == 200) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(http_status);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
	    }
	}
	free(query);
    }
    if (qrylist)
        query_list_free(qrylist, nnodes);

    return ret;
}

static act_result_t ignodes_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    DEBUG("IN %s", __func__);
    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    return commit_dist_common(hashfs, nodes, succeeded, fail_code, fail_msg, 0);
}

static act_result_t dummy_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    DEBUG("IN %s", __func__);
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}
static act_result_t dummy_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    DEBUG("IN %s", __func__);
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}
static act_result_t dummy_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    DEBUG("IN %s", __func__);
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}
static act_result_t dummy_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    DEBUG("IN %s", __func__);
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

#define REVSCLEAN_ITER_LIMIT     64

static act_result_t revsclean_vol_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    const sx_hashfs_volume_t *vol = NULL;
    const sx_hashfs_file_t *file = NULL;
    const char *file_threshold = NULL;
    rc_ty s, t;
    unsigned int scheduled = 0;
    sx_blob_t *b;
    act_result_t ret;
    unsigned int nnodes;
    const sx_node_t *me;
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || !global_vol_id || global_id_len != sizeof(global_vol_id->b) ||
       sx_blob_get_string(b, &file_threshold)) {
        WARN("Cannot get job data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if((s = sx_hashfs_volume_by_global_id(hashfs, global_vol_id, &vol)) != OK) {
        WARN("Failed to get volume reference: %s", msg_get_reason());
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Invalid volume");
    }

    /* All volnodes that received this commit request should iterate over files and schedule delete jobs for the outdate revs */
    for(s = sx_hashfs_list_first(hashfs, vol, NULL, &file, 1, file_threshold, 0); s == OK; s = sx_hashfs_list_next(hashfs)) {
        unsigned int scheduled_per_file = 0;

        if((t = sx_hashfs_delete_old_revs(hashfs, vol, file->name+1, &scheduled_per_file)) != OK) {
            WARN("Failed to schedule deletes for file %s", file->name);
            /* This will not break the job itself and let it retry deleting old revisions */
            action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to schedule outdated revisions deletion");
        }

        scheduled += scheduled_per_file;
        if(scheduled >= REVSCLEAN_ITER_LIMIT) {
            DEBUG("Reached revisions cleaning limit: %u", scheduled);
            break;
        }
    }

    if(s != ITER_NO_MORE && s != OK) {
        WARN("Iteration failed: %s", msg_get_reason());
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to iterate over files");
    }

    /* Job is scheduled only on local node */
    nnodes = sx_nodelist_count(nodes);
    if(nnodes != 1) {
        WARN("Revsclean job scheduled to more than one (local) node, or nodes list is empty");
        action_error(ACT_RESULT_PERMFAIL, 500, "Revsclean job scheduled to more than one (local) node");
    }

    me = sx_hashfs_self(hashfs);
    if(!me) {
        WARN("Failed to get self node reference");
        action_error(ACT_RESULT_PERMFAIL, 500, "Failed to get node reference");
    }

    if(s == OK) {
        sx_blob_t *new_blob;
        job_t job;
        const void *new_job_data;
        unsigned int job_datalen;
        sx_nodelist_t *curnode_list;
        int job_timeout = 20;

        if(!(new_blob = sx_blob_new()))
            action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");

        /* Insert volume name and last cleaned up file name */
        if(sx_blob_add_blob(new_blob, global_vol_id->b, sizeof(global_vol_id->b)) || sx_blob_add_string(new_blob, file->name)) {
            sx_blob_free(new_blob);
            action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
        }

        sx_blob_to_data(new_blob, &new_job_data, &job_datalen);
        curnode_list = sx_nodelist_new();
        if(!curnode_list) {
            WARN("Failed to allocate nodeslist");
            sx_blob_free(new_blob);
            action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
        }
        if(sx_nodelist_add(curnode_list, sx_node_dup(me))) {
            WARN("Failed to add myself to nodelist");
            sx_blob_free(new_blob);
            sx_nodelist_delete(curnode_list);
            action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
        }
        s = sx_hashfs_job_new(hashfs, 0, &job, JOBTYPE_REVSCLEAN, job_timeout, vol->name, new_job_data, job_datalen, curnode_list);
        sx_blob_free(new_blob);
        sx_nodelist_delete(curnode_list);
        if(s != OK)
            action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to create next job");
    }

    succeeded[0] = 1;
    ret = ACT_RESULT_OK;

 action_failed:
    sx_blob_free(b);
    return ret;
}

/* At least some warnings should be printed when revsclean job fails */
static act_result_t revsclean_vol_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    WARN("Failed to finish backgroud revsclean job");
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t revsclean_vol_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    WARN("Failed to finish backgroud revsclean job");
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}


/* Update cbdata array with new context and send volsizes query to given node */
static rc_ty finalize_query(sx_hashfs_t *h, curlev_context_t ***cbdata, unsigned int *ncbdata, const sx_node_t *n, unsigned int node_index, sxi_query_t **query) {
    curlev_context_t *ctx;
    curlev_context_t **newptr;
    rc_ty ret = FAIL_EINTERNAL;

    if(!h || !cbdata || !ncbdata || !n || !query || !*query) {
        NULLARG();
        goto finalize_query_err;
    }

    if(!(*query = sxi_volsizes_proto_end(sx_hashfs_client(h), *query))) {
        WARN("Failed to close query proto");
        goto finalize_query_err;
    }

    newptr = realloc(*cbdata, sizeof(curlev_context_t*) * (*ncbdata + 1));
    if(!newptr) {
        WARN("Failed to allocate memory for next cbdata");
        goto finalize_query_err;
    }
    *cbdata = newptr;

    ctx = push_volume_sizes(h, n, node_index, query);
    if(!ctx) {
        WARN("Failed to push volume sizes to node %s: Failed to send query", sx_node_addr(n));
        /* Allocation of cbdata succeeded, so this pointer should be returned to handle the rest of queries,
         * but we do not want to increase a counter and set a NULL pointer */
        goto finalize_query_err;
    }

    ret = OK;
finalize_query_err:
    /* Add new cbdata context to array */
    if(ret == OK) {
        (*cbdata)[*ncbdata] = ctx;
        (*ncbdata)++;
    }
    return ret;
}

#define VOLSIZES_PUSH_INTERVAL 10.0
#define VOLSIZES_VOLS_PER_QUERY 128

static rc_ty checkpoint_volume_sizes(sx_hashfs_t *h) {
    rc_ty ret = FAIL_EINTERNAL;
    const sx_nodelist_t *nodes;
    unsigned int i;
    const sx_node_t *me;
    struct timeval now;
    sxc_client_t *sx = sx_hashfs_client(h);
    curlev_context_t **cbdata = NULL;
    unsigned int ncbdata = 0;
    unsigned int nnodes;
    unsigned int fail;
    sxi_query_t *query = NULL;

    /* Reload hashfs */
    check_distribution(h);

    me = sx_hashfs_self(h);

    /* If storage is bare, won't push volume size changes*/
    if(sx_storage_is_bare(h))
        return OK;

    /* Check if its time to push volume sizes */
    gettimeofday(&now, NULL);
    if(sxi_timediff(&now, sx_hashfs_volsizes_timestamp(h)) < VOLSIZES_PUSH_INTERVAL)
        return OK;
    memcpy(sx_hashfs_volsizes_timestamp(h), &now, sizeof(now));

    nodes = sx_hashfs_effective_nodes(h, NL_PREVNEXT);
    if(!nodes) {
        WARN("Failed to get node list");
        goto checkpoint_volume_sizes_err;
    }
    nnodes = sx_nodelist_count(nodes);

    /* Iterate over all nodes */
    for(i = 0; i < nnodes; i++) {
        int64_t last_push_time;
        int s;
        int required = 0;
        const sx_node_t *n = sx_nodelist_get(nodes, i);
        const sx_hashfs_volume_t *vol = NULL;
        int j;

        if(!n) {
            WARN("Failed to get node at index %d", i);
            goto checkpoint_volume_sizes_err;
        }

        if(!sx_node_cmp(me, n)) {
            /* Skipping myself... */
            continue;
        }

        /* Get last push time */
        last_push_time = sx_hashfs_get_node_push_time(h, n);
        if(last_push_time < 0) {
            WARN("Failed to get last push time for node %s", sx_node_addr(n));
            goto checkpoint_volume_sizes_err;
        }

        for(s = sx_hashfs_volume_first(h, &vol, 0); s == OK; s = sx_hashfs_volume_next(h)) {
            /* Check if node n is not a volnode for volume and it is this node's volume */
            if(sx_hashfs_is_volume_to_push(h, vol, n)) {
                /* Check if its about time to push current volume size */
                if((!last_push_time && vol->changed) || last_push_time <= vol->changed) {
                    char volid_hex[SXI_SHA1_TEXT_LEN+1];
                    bin2hex(vol->global_id.b, sizeof(vol->global_id.b), volid_hex, sizeof(volid_hex));
                    if(!query) {
                        query = sxi_volsizes_proto_begin(sx);
                        if(!query) {
                            WARN("Failed to prepare query for pushing volume size");
                            goto checkpoint_volume_sizes_err;
                        }
                    }

                    if(!(query = sxi_volsizes_proto_add_volume(sx, query, volid_hex, vol->usage_total, vol->usage_files, vol->nfiles))) {
                        WARN("Failed to append volume to the query string");
                        goto checkpoint_volume_sizes_err;
                    }

                    /* Increase number of required volumes */
                    required++;
                    /* Check if number of volumes is not too big, we should avoid too long json */
                    if(required >= VOLSIZES_VOLS_PER_QUERY) {
                        /* On successful call query variable will be nullified and stored in the ctx */
                        if(finalize_query(h, &cbdata, &ncbdata, n, i, &query)) {
                            WARN("Failed to finalize and send query");
                            goto checkpoint_volume_sizes_err;
                        }
                        required = 0;
                    }
                }
            }
        }

        if(required) {
            /* On successful call query variable will be nullified and stored in the ctx */
            if(finalize_query(h, &cbdata, &ncbdata, n, i, &query)) {
                WARN("Failed to finalize and send query");
                goto checkpoint_volume_sizes_err;
            }
            required = 0;
        }

        if(s != ITER_NO_MORE) {
            WARN("Failed to list volumes");
            goto checkpoint_volume_sizes_err;
        }

        /* All volumes were checked for current node, set fail flag to 0 for it */
        for(j = ncbdata-1; j >= 0; j--) {
            struct volsizes_push_ctx *ctx = sxi_cbdata_get_context(cbdata[j]);

            if(i == ctx->idx)
                ctx->fail = 0;
            else
                break; /* Index is different, stop iteration because we reach different node */
        }
    }

    ret = OK;
checkpoint_volume_sizes_err:
    /* First wait for all queries to finish */
    for(i = 0; i < ncbdata; i++) {
        struct volsizes_push_ctx *ctx;
        long status = -1;
        ctx = sxi_cbdata_get_context(cbdata[i]);

        if(sxi_cbdata_wait(cbdata[i], sxi_conns_get_curlev(sx_hashfs_conns(h)), &status)) {
            WARN("Failed to wait for query to finish: %s", sxi_cbdata_geterrmsg(cbdata[i]));
            ctx->fail = 1;
            ret = FAIL_EINTERNAL;
        } else if(status != 200) {
            WARN("Volume size update query failed: %s", sxi_cbdata_geterrmsg(cbdata[i]));
            ctx->fail = 1;
            ret = FAIL_EINTERNAL;
        }
    }

    /* Second, Update node push time if all queries for particular node succeeded */
    fail = 0;
    for(i = 0; i < ncbdata; i++) {
        struct volsizes_push_ctx *ctx = sxi_cbdata_get_context(cbdata[i]);

        if(i > 0) {
            struct volsizes_push_ctx *prevctx = sxi_cbdata_get_context(cbdata[i-1]);

            if(ctx->idx != prevctx->idx) { /* Node has changed, check for fail and update push time */
                const sx_node_t *n = sx_nodelist_get(nodes, prevctx->idx);

                if(n && !fail && sx_hashfs_update_node_push_time(h, n)) {
                    WARN("Failed to update node push time");
                    ret = FAIL_EINTERNAL;
                    break;
                }
                fail = 0;
            }
        }

        if(ctx->fail)
            fail = 1;
    }

    /* Handle last node */
    if(ncbdata && i == ncbdata && !fail) {
        struct volsizes_push_ctx *ctx = sxi_cbdata_get_context(cbdata[ncbdata-1]);
        const sx_node_t *n = sx_nodelist_get(nodes, ctx->idx);

        if(sx_hashfs_update_node_push_time(h, n)) {
            WARN("Failed to update node push time");
            ret = FAIL_EINTERNAL;
        }
    }

    /* Third, cleanup */
    for(i = 0; i < ncbdata; i++) {
        struct volsizes_push_ctx *ctx = sxi_cbdata_get_context(cbdata[i]);
        if(ctx) {
            sxi_query_free(ctx->query);
            free(ctx);
        }
        sxi_cbdata_unref(&cbdata[i]);
    }

    sxi_query_free(query);
    free(cbdata);
    return ret;
}

static rc_ty volmod_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return job_twophase_execute(&volmod_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty volmod_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return job_twophase_execute(&volmod_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty volmod_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return job_twophase_execute(&volmod_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t distlock_common(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, jobphase_t phase, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    unsigned int nnode, nnodes;
    sx_blob_t *b = NULL;
    act_result_t ret = ACT_RESULT_OK;
    sxi_query_t *proto = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    query_list_t *qrylist = NULL;
    const char *lockid = NULL;
    int32_t op = 0;
    rc_ty s;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &lockid) || sx_blob_get_int32(b, &op)) {
        WARN("Cannot get data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if(!lockid) {
        WARN("Cannot get data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if(phase == JOBPHASE_ABORT)
        op = !op; /* Revert operation in case of abort */

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
        const sx_node_t *node = sx_nodelist_get(nodes, nnode);

        if(sx_node_cmp(me, node)) {
            if(!proto) {
                proto = sxi_distlock_proto(sx, op, lockid);
                if(!proto) {
                    WARN("Cannot allocate proto for job %lld", (long long)job_id);
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }

                qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
                if(!qrylist) {
                    WARN("Cannot allocate result space");
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }
            }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
            if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
                WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
            }
            qrylist[nnode].query_sent = 1;
        } else if(phase == JOBPHASE_REQUEST) {
            succeeded[nnode] = 1; /* Locally mark as succeeded */
        } else { /* ABORT phase on local node, revert previously set distlock */
            /* op variable was previously inverted */
            if(op) { /* Lock operation */
                s = sx_hashfs_distlock_acquire(hashfs, lockid);
                if(s != OK && s != EEXIST) { /* EEXIST is not an error when we want to revert the lock */
                    WARN("Failed to acquire lock %s", lockid);
                    action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to acquire distribution lock");
                }
            } else { /* Unlock operation */
                s = sx_hashfs_distlock_release(hashfs);
                if(s != OK) {
                    WARN("Failed to release lock %s", lockid);
                    action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to release distribution lock");
                }
            }
        }
    }

 action_failed:
    sx_blob_free(b);
    if(proto) {
        for(nnode=0; qrylist && nnode<nnodes; nnode++) {
            int rc;
            long http_status = 0;
            if(!qrylist[nnode].query_sent)
                continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
            if(rc == -2) {
                CRIT("Failed to wait for query");
                action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
                continue;
            }
            if(rc == -1) {
                WARN("Query failed with %ld", http_status);
                if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
                    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else if(http_status == 200) {
                succeeded[nnode] = 1;
            } else {
                act_result_t newret = http2actres(http_status);
                if(newret < ret) /* Severity shall only be raised */
                    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            }
        }
        query_list_free(qrylist, nnodes);
        sxi_query_free(proto);
    }
    return ret;
}

static act_result_t distlock_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return distlock_common(hashfs, job_id, job_data, nodes, JOBPHASE_REQUEST, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t distlock_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
   return distlock_common(hashfs, job_id, job_data, nodes, JOBPHASE_ABORT, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty revision_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return job_twophase_execute(&revision_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty revision_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return job_twophase_execute(&revision_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty revision_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return job_twophase_execute(&revision_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t upgrade_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    INFO("Preparing to upgrade node");
    if (sx_hashfs_upgrade_1_0_or_1_1_prepare(hashfs) ||
        sx_hashfs_upgrade_1_0_or_1_1_local(hashfs))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to upgrade local node");
    ret = force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
 action_failed:
    return ret;
}

static int parse_job_id(const char *jobid, job_t *job, sx_uuid_t *uuid) {
    unsigned int uuid_len;
    char uuid_str[UUID_STRING_SIZE+1];
    const char *p;
    char *enumb;

    if(!jobid || !job || !uuid || !(p = strchr(jobid, ':')))
        return -1;

    uuid_len = p - jobid;
    if(uuid_len != UUID_STRING_SIZE)
        return -1;
    memcpy(uuid_str, jobid, UUID_STRING_SIZE);
    uuid_str[UUID_STRING_SIZE] = '\0';
    *job = strtoll(p + 1, &enumb, 10);
    if(enumb && *enumb) {
        *job = -1;
        return -1;
    }
    if(uuid_from_string(uuid, uuid_str)) {
        *job = -1;
        return -1;
    }

    return 0;
}

static act_result_t jobspawn_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;
    sx_blob_t *b = NULL, *spawn_newb = NULL, *jobids_blob = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    unsigned int nnode, nnodes;
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const void *slave_job_data;
    unsigned int slave_job_data_len;
    sxi_query_t *proto = NULL;
    jobtype_t slave_job_type;
    const void *new_job_data;
    unsigned int new_job_data_len;
    char slave_job_id[UUID_STRING_SIZE + 1 + 21];
    const char *slave_job_lockname;
    int slave_job_timeout;
    job_t child;
    int r;
    query_list_t *qrylist = NULL;
    unsigned int nsucceeded = 0;

    nnodes = sx_nodelist_count(nodes);
    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_int64(b, &child) || sx_blob_get_int32(b, (int32_t*)&slave_job_type) ||
       sx_blob_get_int32(b, &slave_job_timeout) || sx_blob_get_string(b, &slave_job_lockname) ||
       sx_blob_get_blob(b, &slave_job_data, &slave_job_data_len)) {
        WARN("Failed to get slave job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    }

    DEBUG("Slave job type: %d, child job ID: %lld", slave_job_type, (long long)child);

    spawn_newb = sx_blob_new();
    if(!spawn_newb) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    /* Clone beginning of the current job data blob */
    if(sx_blob_cat(spawn_newb, b)) {
        WARN("Failed to add slave job data");
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    /* Pick list of already scheduled and not commited job IDs */
    if((r = sx_blob_get_blob(b, &new_job_data, &new_job_data_len)) == 0) {
        const char *jobid;

        if(nnodes == 0) {
            DEBUG("Advancing spawn job %lld to the commit phase", (long long)job_id);
            goto action_failed;
        }

        jobids_blob = sx_blob_from_data(new_job_data, new_job_data_len);
        if(!jobids_blob) {
            WARN("Cannot allocate blob for job %lld", (long long)job_id);
            action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
        }

        /* Iterate through job IDs blob to move towards the blob end. Also check if job ID nodes does not
         * intersect with nodelist. */
        while((r = sx_blob_get_string(jobids_blob, &jobid)) == 0) {
            job_t job;
            sx_uuid_t uuid;
            const sx_node_t *node;

            if(parse_job_id(jobid, &job, &uuid)) {
                WARN("Corrupted node list for job %s", jobid);
                action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: invalid node list");
            }

            node = sx_nodelist_lookup_index(nodes, &uuid, &nnode);
            if(node) {
                WARN("Node %s is already stored in job ID list", sx_node_internal_addr(node));
                action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
            }
        }
        if(r < 0) {
            WARN("Failed to check job data blob");
            action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
        }
    } else if(r < 0) {
        WARN("Failed to check job data blob");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    } else {
        jobids_blob = sx_blob_new();
        if(!jobids_blob) {
            WARN("Cannot allocate blob for job %lld", (long long)job_id);
            action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
        }
    }

    proto = sxi_mass_job_proto(sx, slave_job_type, slave_job_timeout, slave_job_lockname, slave_job_data, slave_job_data_len);
    if(!proto) {
        WARN("Failed to get slave job spawn query: %s", sxc_geterrmsg(sx));
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
    if(!qrylist) {
        WARN("Cannot allocate result space");
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    for(nnode = 0; nnode<nnodes; nnode++) {
        const sx_node_t *node = sx_nodelist_get(nodes, nnode);

        if(sx_node_cmp(me, node)) {
            qrylist[nnode].cbdata = sxi_job_submit_ev(clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->path, proto->content, proto->content_len);
            if(!qrylist[nnode].cbdata) {
                WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
            }
            qrylist[nnode].query_sent = 1;
        } else {
            /* Local node */
            job_t local_slave_job_id;

            /* Schedule the job locally */
            if((s = sx_hashfs_create_local_mass_job(hashfs, 0, &local_slave_job_id, slave_job_type, slave_job_timeout, slave_job_lockname, slave_job_data, slave_job_data_len)) != OK) {
                INFO("Failed to add local slave job: %s", msg_get_reason());
                if(s == FAIL_LOCKED)
                    action_error(rc2actres(s), rc2http(s), "A complex operation is already running on the cluster");
                else
                    action_error(rc2actres(s), rc2http(s), msg_get_reason());
            }

            /* Save a string representation of local slave job id */
            snprintf(slave_job_id, sizeof(slave_job_id), "%s:%lld", sx_node_uuid_str(me), (long long)local_slave_job_id);
            if(sx_blob_add_string(jobids_blob, slave_job_id)) {
                WARN("Failed to save job id to a new job data blob");
                action_error(ACT_RESULT_PERMFAIL, 500, "Not enough memory to perform the requested action");
            }
            succeeded[nnode] = 1;
            nsucceeded++;
        }
    }

action_failed:
    if(qrylist) {
        for(nnode=0; nnode<nnodes; nnode++) {
            sxi_job_t *remote_job;
            long http_status = 0;
            if(!qrylist[nnode].query_sent)
                continue;
            remote_job = sxi_job_submit_ev_wait(qrylist[nnode].cbdata, &http_status);
            if(!remote_job) {
                act_result_t newret = http2actres(http_status);
                if(newret < ret) /* Severity shall only be raised */
                    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else {
                DEBUG("Successfully advanced remote slave job on %s", sx_node_internal_addr(sx_nodelist_get(nodes, nnode)));
                if(sx_blob_add_string(jobids_blob, sxi_job_get_id(remote_job))) {
                    WARN("Failed to save job id to a new job data blob");
                    sxi_job_free(remote_job);
                    action_set_fail(ACT_RESULT_PERMFAIL, 500, "Not enough memory to perform the requested action");
                }
                sxi_job_free(remote_job);
                succeeded[nnode] = 1;
                nsucceeded++;
            }
        }
        query_list_free(qrylist, nnodes);
    }
    sxi_query_free(proto);

    if(jobids_blob && nsucceeded) {    
        /* Append list of job IDs to spawn job data blob */
        sx_blob_to_data(jobids_blob, &new_job_data, &new_job_data_len);
        if(sx_blob_add_blob(spawn_newb, new_job_data, new_job_data_len)) {
            WARN("Failed to update spawn job data");
            action_set_fail(ACT_RESULT_PERMFAIL, 500, "Failed to update job data");
            sx_blob_free(b);
            sx_blob_free(jobids_blob);
            sx_blob_free(spawn_newb);
            return ret;
        }

        sx_blob_to_data(spawn_newb, &new_job_data, &new_job_data_len);
        DEBUG("Setting new job data for job %lld: %d", (long long)job_id, new_job_data_len);
        if(sx_hashfs_set_job_data(hashfs, job_id, new_job_data, new_job_data_len, 0, 1)) {
            WARN("Failed to update spawn job data");
            action_set_fail(ACT_RESULT_PERMFAIL, 500, "Failed to update job data");
            sx_blob_free(b);
            sx_blob_free(jobids_blob);
            sx_blob_free(spawn_newb);
            return ret;
        }
    }

    if(nnodes && nsucceeded == nnodes) {
        DEBUG("Setting new job data for job %lld, length: %d", (long long)child, new_job_data_len);
        sx_blob_to_data(jobids_blob, &new_job_data, &new_job_data_len);
        if(sx_hashfs_set_job_data(hashfs, child, new_job_data, new_job_data_len, 0, 1)) {
            WARN("Failed to update child job data");
            action_set_fail(ACT_RESULT_PERMFAIL, 500, "Failed to update job data");
            sx_blob_free(b);
            sx_blob_free(jobids_blob);
            sx_blob_free(spawn_newb);
            return ret;
        }

        /* For the commit phase restart the initial timer to avoid expiring before slave jobs */
        *adjust_ttl = MASS_JOB_DELAY_TIMEOUT;

        /* Tempfail the job to force job data being reloaded */
        action_set_fail(ACT_RESULT_NOTFAILED, 503, "Forcing job data reload");
    }

    sx_blob_free(b);
    sx_blob_free(jobids_blob);
    sx_blob_free(spawn_newb);
    return ret;
}

static act_result_t jobspawn_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sx_blob_t *b = NULL, *list_blob = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const void *slave_job_data;
    unsigned int slave_job_data_len;
    sxi_query_t *proto = NULL;
    jobtype_t slave_job_type;
    const char *slave_job_lockname;
    job_t child;
    const void *job_id_list;
    unsigned int job_id_list_len;
    int slave_job_timeout;
    const char *jobid;
    int r;
    sx_uuid_t uuid;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_int64(b, &child) || sx_blob_get_int32(b, (int32_t*)&slave_job_type) ||
       sx_blob_get_int32(b, &slave_job_timeout) || sx_blob_get_string(b, &slave_job_lockname) ||
       sx_blob_get_blob(b, &slave_job_data, &slave_job_data_len) || sx_blob_get_blob(b, &job_id_list, &job_id_list_len)) {
        WARN("Failed to get slave job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    }

    list_blob = sx_blob_from_data(job_id_list, job_id_list_len);
    if(!list_blob) {
        WARN("Failed to get slave job ID list");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    }

    nnodes = sx_nodelist_count(nodes);

    qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
    if(!qrylist) {
        WARN("Cannot allocate result space");
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    while(!(r = sx_blob_get_string(list_blob, &jobid))) {
        job_t job;
        const sx_node_t *node = NULL;
        if(parse_job_id(jobid, &job, &uuid)) {
            WARN("Corrupted node list for job %s", jobid);
            action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: invalid node list");
        }

        node = sx_nodelist_lookup_index(nodes, &uuid, &nnode);
        if(!node)
            continue; /* Node has been removed because it has failed or succeeded */

        if(!sx_node_cmp(node, me)) {
            rc_ty s = sx_hashfs_commit_local_mass_job(hashfs, job, 1);
            if(s != OK) {
                WARN("Failed to commit local mass job %lld: %s", (long long)job, msg_get_reason());
                action_error(rc2actres(s), rc2http(s), msg_get_reason());
            }
            succeeded[nnode] = 1;
        } else {
            sxi_query_free(proto);
            proto = sxi_mass_job_commit_proto(sx, jobid);
            if(!proto) {
                WARN("Failed to prepare commit query for remote job %s", jobid);
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
            }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
            if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
                WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
            }
            qrylist[nnode].query_sent = 1;
        }
    }

    if(r < 0) {
        WARN("Cannot get data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = ACT_RESULT_OK;
action_failed:
    if(qrylist) {
        for(nnode=0; nnode<nnodes; nnode++) {
            int rc;
            long http_status = 0;
            if(!qrylist[nnode].query_sent)
                continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
            if(rc == -2) {
                CRIT("Failed to wait for query");
                action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
                continue;
            }
            if(rc == -1) {
                WARN("Query failed with %ld", http_status);
                if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
                    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else if(http_status != 200) {
                act_result_t newret = http2actres(http_status);
                if(newret < ret) /* Severity shall only be raised */
                    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else {
                DEBUG("Successfully advanced remote slave job on %s", sx_node_internal_addr(sx_nodelist_get(nodes, nnode)));
                succeeded[nnode] = 1;
            }
        }
        query_list_free(qrylist, nnodes);
    }
    sxi_query_free(proto);
    sx_blob_free(b);
    sx_blob_free(list_blob);
    return ret;
}

static act_result_t delay_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    sx_blob_t *b = NULL;
    int wait = 1;

    if(sx_nodelist_count(nodes) != 1) {
        WARN("Invalid nodelist count: Delay job must be run with only one target node");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Invalid nodelist");
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_int32(b, &wait)) {
        WARN("Failed to get delay job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    }

    if(wait) {
        DEBUG("Waiting for a commit...");
        action_error(ACT_RESULT_TEMPFAIL, 200, "Waiting for a commit");
    }

    /* Wait flag has been reset, this job should succeed and allow child job to run */
    succeeded[0] = 1;
action_failed:
    sx_blob_free(b);
    return ret;
}

static act_result_t volrep_undo_common(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, jobtype_t type, jobphase_t phase, int revert_files);

static act_result_t jobspawn_abort_and_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, jobphase_t phase) {
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode;
    sx_blob_t *b = NULL;
    const void *slave_job_data;
    unsigned int slave_job_data_len;
    jobtype_t slave_job_type;
    const char *slave_job_lockname;
    int slave_job_timeout;
    job_t child;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform requested action");

    /* JOBSPAWN job data might be required to undo some mass jobs */
    if(sx_blob_get_int64(b, &child) || sx_blob_get_int32(b, (int32_t*)&slave_job_type) ||
       sx_blob_get_int32(b, &slave_job_timeout) || sx_blob_get_string(b, &slave_job_lockname) ||
       sx_blob_get_blob(b, &slave_job_data, &slave_job_data_len)) {
        WARN("Failed to get slave job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    }

    /* We have obtained the slave job data */
    if(slave_job_type == JOBTYPE_VOLREP_FILES || slave_job_type == JOBTYPE_VOLREP_BLOCKS) {
        job_data_t slave_data;
        
        /*
         * Try hard to schedule undo phases for blocks and volumes synchronization.
         *
         * In order to avoid looping the undo phases we should avoid scheduling undo phase if it is already an undo phase. */

        slave_data.len = slave_job_data_len;
        slave_data.ptr = (void*)slave_job_data;
        slave_data.owner = job_data->owner;
        slave_data.op_expires_at = job_data->op_expires_at;

        if(slave_job_type == JOBTYPE_VOLREP_FILES)
            ret = volrep_undo_common(hashfs, job_id, &slave_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBTYPE_JOBSPAWN, phase, 1);
        else /* There is no need to revert files phase, just undo for blocks */
            ret = volrep_undo_common(hashfs, job_id, &slave_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBTYPE_JOBSPAWN, phase, 0);
        sx_blob_free(b);
        return ret;
    }

    /* Succeed at this stage */
    for(nnode = 0; nnode < sx_nodelist_count(nodes); nnode++)
        succeeded[nnode] = 1;
action_failed:
    CRIT("Some files were left in an inconsistent state after a failed mass job attempt");
    sx_blob_free(b);
    return ret;
}

static act_result_t jobspawn_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return jobspawn_abort_and_undo(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBPHASE_ABORT);
}

static act_result_t jobspawn_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return jobspawn_abort_and_undo(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBPHASE_UNDO);
}

static act_result_t jobpoll_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;
    sx_blob_t *b = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    sxi_job_t **jobs = NULL;
    nnodes = sx_nodelist_count(nodes);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    int r;
    sx_uuid_t uuid;
    const char *jobid = NULL;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    /* This is a master job, poll status of children jobs */
    jobs = wrap_calloc(nnodes, sizeof(*jobs));
    if(!jobs) {
        WARN("Cannot allocate memory for jobs to poll");
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
    if(!qrylist) {
        WARN("Cannot allocate result space");
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    while(!(r = sx_blob_get_string(b, &jobid))) {
        job_status_t status;
        const char *message = NULL;
        job_t job;
        const sx_node_t *node = NULL;

        if(parse_job_id(jobid, &job, &uuid)) {
            WARN("Corrupted node list for job %s", jobid);
            action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: invalid node list");
        }

        node = sx_nodelist_lookup_index(nodes, &uuid, &nnode);
        if(!node)
            continue; /* Node has been removed because it has failed or succeeded */

        if(!sx_node_cmp(node, me)) {
            if((s = sx_hashfs_job_result(hashfs, job, 0, &status, &message)) != OK) {
                WARN("Failed to check job %lld status: %s", (long long)job, msg_get_reason());
                action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to check job status");
            }
            if(status == JOB_OK)
                succeeded[nnode] = 1;
            else if(status == JOB_PENDING)
                action_error(ACT_RESULT_TEMPFAIL, 503, "Local job is pending");
            else {
                DEBUG("Local job has failed: message: %s", message);
                action_error(ACT_RESULT_PERMFAIL, rc2http(s), message);
            }
        } else {
            jobs[nnode] = sxi_job_new(sx_hashfs_conns(hashfs), jobid, REQ_DELETE, sx_node_internal_addr(node));
            if(!jobs[nnode]) {
                WARN("Cannot allocate memory for job %lld to poll", (long long)job);
                action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
            }

            qrylist[nnode].cbdata = sxi_job_cbdata(jobs[nnode]);
            if(sxi_job_query_ev(sx_hashfs_conns(hashfs), jobs[nnode], NULL)) {
                WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
            }
            qrylist[nnode].query_sent = 1;
        }
    }

    if(r < 0) {
        WARN("Cannot get data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    ret = ACT_RESULT_OK;
action_failed:
    if(qrylist && jobs) {
        for(nnode=0; nnode<nnodes; nnode++) {
            int rc;
            long http_status = 0;
            if(!qrylist[nnode].query_sent)
                continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
            if(rc == -2) {
                CRIT("Failed to wait for query");
                action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
                continue;
            }
            if(rc == -1) {
                WARN("Query failed with %ld", http_status);
                if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
                    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else if (http_status == 200) {
                sxi_job_status_t status = sxi_job_status(jobs[nnode]);

                if(status == JOBST_OK)
                    succeeded[nnode] = 1;
                else if(status == JOBST_PENDING)
                    action_set_fail(ACT_RESULT_TEMPFAIL, 503, "Remote job is pending");
                else
                    action_set_fail(ACT_RESULT_PERMFAIL, 500, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else {
                act_result_t newret = http2actres(http_status);
                if(newret < ret) /* Severity shall only be raised */
                    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            }
        }
        /* cbdata stored in qrylist is owned by jobs array, therefore the query_list_free() is not used here */
        free(qrylist);
    }
    if(jobs) {
        for(nnode = 0; nnode < nnodes; nnode++)
            sxi_job_free(jobs[nnode]);
        free(jobs);
    }
    sx_blob_free(b);
    return ret;
}

static act_result_t jobpoll_abort_and_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, jobphase_t phase) {
    rc_ty s;
    job_t parent;
    jobtype_t parent_type;
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode;
    sx_blob_t *b = NULL;
    const void *slave_job_data;
    unsigned int slave_job_data_len;
    jobtype_t slave_job_type;
    const char *slave_job_lockname;
    int slave_job_timeout;
    job_t child;

    s = sx_hashfs_get_parent_job(hashfs, job_id, &parent, &parent_type, &b);
    if(s != OK || !b) {
        WARN("Failed to check parent job");
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to check parent job");
    }

    if(parent_type != JOBTYPE_JOBSPAWN) {
        WARN("Invalid parent job type: got %d, expected %d", parent_type, JOBTYPE_JOBSPAWN);
        action_error(ACT_RESULT_PERMFAIL, 503, "Invalid job configuration");
    }

    /* JOBSPAWN job data might be required to undo some mass jobs */
    if(sx_blob_get_int64(b, &child) || child != job_id || sx_blob_get_int32(b, (int32_t*)&slave_job_type) ||
       sx_blob_get_int32(b, &slave_job_timeout) || sx_blob_get_string(b, &slave_job_lockname) ||
       sx_blob_get_blob(b, &slave_job_data, &slave_job_data_len)) {
        WARN("Failed to get slave job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: Corrupt job data");
    }

    /* We have obtained the slave job data */
    if(slave_job_type == JOBTYPE_VOLREP_FILES || slave_job_type == JOBTYPE_VOLREP_BLOCKS) {
        job_data_t slave_data;
        
        /*
         * Try hard to schedule undo phases for blocks and volumes synchronization.
         *
         * In order to avoid looping the undo phases we should avoid scheduling undo phase if it is already an undo phase. */

        slave_data.len = slave_job_data_len;
        slave_data.ptr = (void*)slave_job_data;
        slave_data.owner = job_data->owner;
        slave_data.op_expires_at = job_data->op_expires_at;

        if(slave_job_type == JOBTYPE_VOLREP_FILES)
            ret = volrep_undo_common(hashfs, job_id, &slave_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBTYPE_JOBPOLL, phase, 1);
        else /* There is no need to revert files phase, just undo for blocks */
            ret = volrep_undo_common(hashfs, job_id, &slave_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBTYPE_JOBPOLL, phase, 0);
        sx_blob_free(b);
        return ret;
    }

    /* Succeed at this stage */
    for(nnode = 0; nnode < sx_nodelist_count(nodes); nnode++)
        succeeded[nnode] = 1;
action_failed:
    CRIT("Some files were left in an inconsistent state after a failed mass job attempt");
    sx_blob_free(b);
    return ret;
}

static act_result_t jobpoll_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return jobpoll_abort_and_undo(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBPHASE_ABORT);
}

static act_result_t jobpoll_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return jobpoll_abort_and_undo(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBPHASE_UNDO);
}

#define MAX_BATCH_ITER  2048
static act_result_t massdelete_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;
    struct timeval timestamp;
    sx_blob_t *b = NULL;
    const char *pattern = NULL;
    const sx_hashfs_volume_t *vol = NULL;
    const sx_hashfs_file_t *file = NULL;
    unsigned int i = 0;
    int recursive = 0;
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;
    char timestamp_str[REV_TIME_LEN+1];

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }
    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || sx_blob_get_int32(b, &recursive) ||
       sx_blob_get_string(b, &pattern) || sx_blob_get_datetime(b, &timestamp)) {
        WARN("Cannot get data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }
    if(!global_vol_id || global_id_len != sizeof(global_vol_id->b) || !pattern) {
        WARN("Cannot get data from blob for job %lld: invalid global ID or pattern", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if(sx_hashfs_timeval2str(&timestamp, timestamp_str)) {
        WARN("Cannot parse timestamp");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if((s = sx_hashfs_volume_by_global_id(hashfs, global_vol_id, &vol))) {
        WARN("Failed to load volume");
        action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    /* Perform operations */
    for(s = sx_hashfs_list_first(hashfs, vol, pattern, &file, recursive, NULL, 0); s == OK && i < MAX_BATCH_ITER; s = sx_hashfs_list_next(hashfs)) {
        rc_ty t;
        const sx_hashfs_file_t *filerev = NULL;
        char name[SXLIMIT_MAX_FILENAME_LEN+2];
        sxi_strlcpy(name, file->name, sizeof(name));

        for(t = sx_hashfs_revision_first(hashfs, vol, name+1, &filerev, 0); t == OK; t = sx_hashfs_revision_next(hashfs, 0)) {
            rc_ty u;
            if(strncmp(filerev->revision, timestamp_str, REV_TIME_LEN) > 0) {
                DEBUG("Skipping %s: %.*s > %s", filerev->name, (int)REV_TIME_LEN, filerev->revision, timestamp_str);
                continue;
            }

            /* Delete the revision */
            if((u = sx_hashfs_file_delete(hashfs, vol, filerev->name, filerev->revision)) != OK) {
                WARN("Failed to delete file revision %s: %s", filerev->revision, msg_get_reason());
                t = u;
                break;
            }

            /* File is deleted, we can unbump the revision */
	    sx_hashfs_revunbump(hashfs, &filerev->revision_id, filerev->block_size);

            i++;
        }

        if(t != ITER_NO_MORE && t != ENOENT) {
            WARN("Failed to delete all revisions of file %s: %s", file->name, msg_get_reason());
            s = t;
            break;
        }
    }
    if(s != ITER_NO_MORE) {
        if(i >= MAX_BATCH_ITER) {
            DEBUG("Sleeping job due to exceeded deletions limit");
            action_error(ACT_RESULT_NOTFAILED, 503, "Exceeded limit");
        } else {
            WARN("Failed to finish batch job: %s", rc2str(s));
            action_error(rc2actres(s), rc2http(s), rc2str(s));
        }
    }
    /* Job is done */
    ret = ACT_RESULT_OK;
action_failed:
    sx_blob_free(b);

    if(ret == ACT_RESULT_OK)
        succeeded[0] = 1;
    return ret;
}

static act_result_t massdelete_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    CRIT("Some files were left in an inconsistent state after a failed deletion attempt");
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t massdelete_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    CRIT("Some files were left in an inconsistent state after a failed deletion attempt");
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

/* Drop all stale source revisions */
static rc_ty massrename_drop_old_src_revs(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const char *filename) {
    rc_ty ret = FAIL_EINTERNAL, t;
    const sx_hashfs_file_t *filerev = NULL;

    if(!vol || !filename) {
        NULLARG();
        return EINVAL;
    }

    /* Iterate through all older revisions of the file and drop them */
    for(t = sx_hashfs_revision_first(h, vol, filename, &filerev, 0); t == OK; t = sx_hashfs_revision_next(h, 0)) {
        rc_ty u;

        /* Delete the revision */
        if((u = sx_hashfs_file_delete(h, vol, filerev->name, filerev->revision)) != OK) {
            WARN("Failed to delete file revision %s: %s", filerev->revision, msg_get_reason());
            t = u;
            break;
        }

        /* File is deleted, we can unbump the revision */
	sx_hashfs_revunbump(h, &filerev->revision_id, filerev->block_size);
    }

    if(t != ITER_NO_MORE && t != ENOENT) {
        WARN("Failed to delete all revisions of file %s: %s", filename, msg_get_reason());
        ret = t;
        goto massrename_drop_old_src_revs_err;
    }

    ret = OK;
massrename_drop_old_src_revs_err:
    return ret;
}

static act_result_t massrename_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;
    struct timeval timestamp;
    sx_blob_t *b = NULL;
    const char *source = NULL, *dest = NULL;
    const sx_hashfs_volume_t *vol = NULL;
    const sx_hashfs_file_t *file = NULL;
    unsigned int dlen, plen;
    int recursive = 0;
    char timestamp_str[REV_TIME_LEN+1];
    char newname[SXLIMIT_MAX_FILENAME_LEN+1];
    char *suffix;
    unsigned int i = 0;
    unsigned int source_slashes;
    long http_code = 0;
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || sx_blob_get_int32(b, &recursive) ||
       sx_blob_get_string(b, &source) || sx_blob_get_datetime(b, &timestamp) ||
       sx_blob_get_string(b, &dest)) {
        WARN("Cannot get data from blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if(!global_vol_id || global_id_len != sizeof(global_vol_id->b) || !source || !dest) {
        WARN("Cannot get data from blob for job %lld: invalid global ID or pattern", (long long)job_id);
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if(sx_hashfs_timeval2str(&timestamp, timestamp_str)) {
        WARN("Cannot parse timestamp");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if((s = sx_hashfs_volume_by_global_id(hashfs, global_vol_id, &vol))) {
        WARN("Failed to load volume");
        action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    source_slashes = sxi_count_slashes(source);
    dlen = strlen(dest);

    sxi_strlcpy(newname, dest, sizeof(newname));
    for(s = sx_hashfs_list_first(hashfs, vol, source, &file, recursive, NULL, 0); s == OK && i < MAX_BATCH_ITER; s = sx_hashfs_list_next(hashfs)) {
        rc_ty t;
        const sx_hashfs_file_t *filerev = NULL;
        char name[SXLIMIT_MAX_FILENAME_LEN+1];
        unsigned int name_len;

        if(strncmp(file->revision, timestamp_str, REV_TIME_LEN) > 0) {
            DEBUG("Skipping %s: %.*s > %s", name, (int)REV_TIME_LEN, filerev->revision, timestamp_str);
            /* Do not set failed flag, it is not an error, just skip the file */
            continue;
        }

        /* +1 because of preceding slash */
        sxi_strlcpy(name, file->name + 1, sizeof(name));
        name_len = strlen(name);

        if(name_len && name[name_len-1] == '/') {
            if(recursive) {
                WARN("File name ends with slash, but listing is recursive");
                s = FAIL_EINTERNAL;
                break;
            }
            DEBUG("Skipping file %s, it is a directory", name);
            continue;
        }

        /* source can contain globbing, need to find out last slash position. */
        suffix = sxi_ith_slash(name, source_slashes);
        if(source_slashes) { /* prefix len is until suffix only */
            if(!suffix) {
                WARN("File name %s did not match number of slashes from the pattern %s", name, source);
                s = FAIL_EINTERNAL;
                break;
            }
            suffix++;
            plen = suffix - name;
        } else /* File name does not contain slashes, full file name will be prefixed with dest */
            plen = 0;

        /* If dest has a trailing slash, append the suffix after it */
        if(!dlen || dest[dlen-1] == '/') {
            /* Check if appending new name suffix to the destination prefix won't exceed filename limit */
            if(strlen(name) - plen + dlen > SXLIMIT_MAX_FILENAME_LEN) {
                DEBUG("Skipping '%s': Filename too long", name);
                http_code = 400;
                continue;
            }

            /* Destination is a directory, append source without the prefix */
            sxi_strlcpy(newname + dlen, name + plen, sizeof(newname) - dlen);
        } else if(suffix && sxi_count_slashes(suffix)) {
            /* Dest does not have a trailing slash, replace it until first slash in the suffix */

            /* Get next slash position */
            suffix = sxi_ith_slash(suffix, 1);
            if(!suffix) {
                WARN("Suffix contains slash, but failed to get its string position");
                s = FAIL_EINTERNAL;
                break;
            }
            /* Check filename correctness */
            if(strlen(suffix) + dlen > SXLIMIT_MAX_FILENAME_LEN) {
                DEBUG("Skipping '%s': Filename too long", name);
                http_code = 400;
                continue;
            }
            /* Create new filename */
            sxi_strlcpy(newname + dlen, suffix, sizeof(newname) - dlen);
        }

        DEBUG("Renaming file %s to %s", name, newname);
        if(!strcmp(name, newname)) {
            DEBUG("Skipping %s: destination and source filenames are equal", name);
            /* Do not set failed flag, it is not an error, just skip the file */
            continue;
        }

        if(strlen(newname) < SXLIMIT_MIN_FILENAME_LEN || strlen(newname) > SXLIMIT_MAX_FILENAME_LEN || sxi_utf8_validate_len(newname) < 0) {
            DEBUG("Skipping '%s': Invalid filename", name);
            http_code = 400;
            continue;
        }

        /* Rename the youngest revision */
        if((t = sx_hashfs_file_rename(hashfs, vol, &timestamp, name, file->revision, newname)) != OK) {
            WARN("Failed to rename file revision %s: %s", file->revision, msg_get_reason());
            s = t;
            break;
        }

        if((t = massrename_drop_old_src_revs(hashfs, vol, name)) != OK) {
            WARN("Failed to drop old %s revisions: %s", name, msg_get_reason());
            if(t == ENOMEM || t == EAGAIN)
                action_error(ACT_RESULT_TEMPFAIL, 503, msg_get_reason());
            else
                action_error(rc2actres(t), rc2http(t), "Failed to remove old source revisions");
        }
        i++;
    }

    if(s != ITER_NO_MORE) {
        if(i >= MAX_BATCH_ITER) {
            DEBUG("Sleeping job due to exceeded deletions limit");
            action_error(ACT_RESULT_NOTFAILED, 503, "Exceeded limit");
        } else {
            INFO("Failed to finish mass job: %s", rc2str(s));
            action_error(rc2actres(s), rc2http(s), rc2str(s));
        }
    } else if(http_code) {
        /* If we reached the end of the list and http_code is set, then we should fail the job. */
        action_error(ACT_RESULT_PERMFAIL, http_code, "Some files could not be renamed");
    }

    /* Job is done */
    ret = ACT_RESULT_OK;
action_failed:
    sx_blob_free(b);

    if(ret == ACT_RESULT_OK)
        succeeded[0] = 1;
    return ret;
}

static act_result_t massrename_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    if(current_job_status / 100 != 4)
        CRIT("Some files were left in an inconsistent state after a failed rename attempt");
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t massrename_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    CRIT("Some files were left in an inconsistent state after a failed rename attempt");
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static act_result_t volrep_common(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, jobphase_t phase) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    const sx_node_t *me = sx_hashfs_self(hashfs);
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    sxi_query_t *proto = NULL;
    rc_ty s;
    const char *volname;
    unsigned int prev_replica = 0, next_replica = 0;
    const sx_hashfs_volume_t *vol;
    sx_blob_t *b = NULL;

    if(phase != JOBPHASE_COMMIT && phase != JOBPHASE_UNDO) {
        WARN("Invalid job phase");
        action_error(ACT_RESULT_PERMFAIL, 500, "Invalid job phase");
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_int32(b, (int32_t *)&prev_replica) || sx_blob_get_int32(b, (int32_t *)&next_replica)) {
        WARN("Corrupted job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Corrupted job data");
    }

    if((s = sx_hashfs_volume_by_name(hashfs, volname, &vol))) {
        WARN("Failed to load volume %s", volname);
        action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    if(phase == JOBPHASE_UNDO) {
        /* Set both prev and next replica to the same value */
        next_replica = prev_replica;
    }

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
        const sx_node_t *node = sx_nodelist_get(nodes, nnode);

        DEBUG("Changing volume %s replica: %u -> %u", vol->name, prev_replica, next_replica);

        if(!sx_node_cmp(me, node)) {
            s = sx_hashfs_modify_volume_replica(hashfs, vol, prev_replica, next_replica);
            if(s != OK) {
                WARN("Failed to change volume '%s' replica: %s", vol->name, msg_get_reason());
                action_error(rc2actres(s), rc2http(s), "Failed to modify volume replica");
            }
            succeeded[nnode] = 1;
        } else {
            if(!proto) {
                proto = sxi_replica_change_proto(sx, vol->name, prev_replica, next_replica);
                if(!proto) {
                    WARN("Cannot allocate replica change query");
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }

                qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
                if(!qrylist) {
                    WARN("Cannot allocate result space");
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }
            }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
            if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_PUT, proto->path, proto->content, proto->content_len, NULL, NULL)) {
                WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
            }
            qrylist[nnode].query_sent = 1;
        }
    }

 action_failed:
    if(proto) {
        for(nnode=0; qrylist && nnode<nnodes; nnode++) {
            int rc;
            long http_status = 0;
            if(!qrylist[nnode].query_sent)
                continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), &http_status);
            if(rc == -2) {
                CRIT("Failed to wait for query");
                action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
                continue;
            }
            if(rc == -1) {
                WARN("Query failed with %ld", http_status);
                if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
                    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            } else if(http_status == 200 || http_status == 410) {
                succeeded[nnode] = 1;
            } else {
                act_result_t newret = http2actres(http_status);
                if(newret < ret) /* Severity shall only be raised */
                    action_set_fail(newret, http_status, sxi_cbdata_geterrmsg(qrylist[nnode].cbdata));
            }
        }
        query_list_free(qrylist, nnodes);
        sxi_query_free(proto);
    }
    sx_blob_free(b);
    return ret;
}

static rc_ty volrep_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return volrep_common(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBPHASE_COMMIT);
}

static rc_ty volrep_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return volrep_common(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl, JOBPHASE_UNDO);
}

#define UPGRADE_2_1_4_REVID_INSERT_LIMIT 2048
enum upgrade_2_1_4_state { UPGRADE_2_1_4_HDRSIZE = 0, UPGRADE_2_1_4_HDRDATA, UPGRADE_2_1_4_END };

struct upgrade_2_1_4_remote_ctx {
    sx_hashfs_t *hashfs;
    sx_blob_t *b;
    const sx_hashfs_volume_t *vol;
    uint8_t hdr[1024 +
                  SXLIMIT_MAX_FILENAME_LEN +
                  REV_LEN];
    /* Will hold the last file and revision which was sent in response to the query */
    char file[SXLIMIT_MAX_FILENAME_LEN+1],
        rev[REV_LEN+1];
    unsigned int ngood, itemsz, pos, has_limit /* set to 1 when last file has been received */;
    enum upgrade_2_1_4_state state;
};

static int upgrade_2_1_4_remote_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct upgrade_2_1_4_remote_ctx *c = (struct upgrade_2_1_4_remote_ctx *)ctx;
    const uint8_t *input = (const uint8_t *)data;
    unsigned int todo;
    rc_ty s;

    while(size) {
        if(c->state == UPGRADE_2_1_4_END) {
            if(size)
                INFO("Spurious tail of %u bytes", (unsigned int)size);
            return 0;
        }

        if(c->state == UPGRADE_2_1_4_HDRSIZE) {
            todo = MIN((sizeof(c->itemsz) - c->pos), size);
            memcpy(c->hdr + c->pos, input, todo);
            input += todo;
            size -= todo;
            c->pos += todo;
            if(c->pos == sizeof(c->itemsz)) {
                memcpy(&todo, c->hdr, sizeof(todo));
                c->itemsz = htonl(todo);
                if(c->itemsz >= sizeof(c->hdr)) {
                    WARN("Invalid header size %u", c->itemsz);
                    return 1;
                }
                c->state = UPGRADE_2_1_4_HDRDATA;
                c->pos = 0;
            }
        }

        if(c->state == UPGRADE_2_1_4_HDRDATA) {
            todo = MIN((c->itemsz - c->pos), size);
            memcpy(c->hdr + c->pos, input, todo);
            input += todo;
            size -= todo;
            c->pos += todo;
            if(c->pos == c->itemsz) {
                const char *signature;
                c->b = sx_blob_from_data(c->hdr, c->itemsz);
                if(!c->b) {
                    WARN("Cannot create blob of size %u", c->itemsz);
                    return 1;
                }
                if(sx_blob_get_string(c->b, &signature)) {
                    WARN("Cannot read create blob signature");
                    return 1;
                }
                if(!strcmp(signature, "$THEEND$")) {
                    c->state = UPGRADE_2_1_4_END;
                    if(size)
                        INFO("Spurious tail of %u bytes", (unsigned int)size);
                    if(!c->has_limit) /* Not critical, we should still be able to retry the iteration from the preovious limit */
                        INFO("Received batch end, but without a file limit");
                    return 0;
                } else if(!strcmp(signature, "$FILE$")) {
                    const char *file_name, *file_rev;

                    /* Process the last file processed on the pulled node */
                    if(sx_blob_get_string(c->b, &file_name) ||
                       sx_blob_get_string(c->b, &file_rev)) {
                        WARN("Bad file characteristics");
                        return 1;
                    }
                    sxi_strlcpy(c->file, file_name, sizeof(c->file));
                    sxi_strlcpy(c->rev, file_rev, sizeof(c->rev));
                    c->has_limit = 1;
                } else if(!strcmp(signature, "$REVID$")) {
                    sx_hash_t revision_id;
                    const void *revid = NULL;
                    unsigned int len = 0;

                    /* Process next revision ID */

                    if(sx_blob_get_blob(c->b, &revid, &len) || len != sizeof(revision_id.b)) {
                        WARN("Invalid revision ID");
                        return 1;
                    }
                    memcpy(revision_id.b, revid, sizeof(revision_id.b));
                    s = sx_hashfs_upgrade_2_1_4_update_revid(c->hashfs, c->vol, &revision_id);
                    if(s != OK) {
                        WARN("Failed store revision ID");
                        return 1;
                    }
                    c->ngood++;
                } else {
                    WARN("Invalid blob signature '%s'", signature);
                    return 1;
                }
                sx_blob_free(c->b);
                c->b = NULL;
                c->state = UPGRADE_2_1_4_HDRSIZE;
                c->pos = 0;
            }
        }
    }
    return 0;
}

struct upgrade_2_1_4_local_ctx {
    sx_hashfs_file_t lastfile;
    unsigned int nfiles;
    sx_hashfs_t *hashfs;
};

static int upgrade_2_1_4_local_cb(const sx_hashfs_volume_t *vol, const sx_hashfs_file_t *file, const sx_hash_t *contents, unsigned int nblocks, void *ctx) {
    struct upgrade_2_1_4_local_ctx *c = (struct upgrade_2_1_4_local_ctx *)ctx;

    if(c->nfiles >= UPGRADE_2_1_4_REVID_INSERT_LIMIT)
        return 0;
    if(sx_hashfs_upgrade_2_1_4_update_revid(c->hashfs, vol, &file->revision_id)) {
        WARN("Failed to store revision ID for local file %s", file->name);
        return 1;
    }
    memcpy(c->lastfile.name, file->name, sizeof(c->lastfile.name));
    memcpy(c->lastfile.revision, file->revision, sizeof(c->lastfile.revision));
    c->nfiles++;
    return 1;
}

/* Store revision IDs locally in order to be able to pull blocks from all the non-volnodes. */
static rc_ty upgrade_2_1_3_to_2_1_4_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;

    DEBUG("IN %s", __func__);

    if(sx_nodelist_count(nodes) > 1) {
        action_set_fail(ACT_RESULT_PERMFAIL, 500, "Upgrade job can only be scheduled on one node");
        return ret;
    }

    if(sx_hashfs_is_rebalancing(hashfs) || sx_nodelist_count(sx_hashfs_faulty_nodes(hashfs)))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Waiting for rebalance to finish");

    /* Only initialize the iteration */
    if(sx_hashfs_upgrade_2_1_4_init(hashfs))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to initialize 2_1_4 upgrade job");

    succeeded[0] = 1;
action_failed:
    return ret;
}

static rc_ty upgrade_2_1_3_to_2_1_4_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_NOTFAILED;
    rc_ty s;
    const sx_hashfs_volume_t *vol;
    sx_nodelist_t *volnodes = NULL;
    unsigned int nvolnodes;
    const sx_node_t *me = sx_hashfs_self(hashfs);
    char maxrev[REV_LEN+1];
    char startvol[SXLIMIT_MAX_VOLNAME_LEN+1], startfile[SXLIMIT_MAX_FILENAME_LEN+1], startrev[REV_LEN+1];
    sxi_hostlist_t hlist;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    int is_volnode;
    sxi_query_t *query = NULL;

    DEBUG("IN %s", __func__);

    if(sx_nodelist_count(nodes) > 1) {
        action_set_fail(ACT_RESULT_PERMFAIL, 500, "Upgrade job can only be scheduled on one node");
        return ret;
    }

    sxi_hostlist_init(&hlist);

    if(sx_hashfs_is_rebalancing(hashfs) || sx_nodelist_count(sx_hashfs_faulty_nodes(hashfs)))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Waiting for rebalance to finish");

    sx_hashfs_set_progress_info(hashfs, INPRG_UPGRADE_RUNNING, "Building a list of objects to heal");

    while((s = sx_hashfs_replace_getstartfile(hashfs, maxrev, startvol, startfile, startrev)) == OK) {
        const sx_node_t *source;

        if((s = sx_hashfs_volume_by_name(hashfs, startvol, &vol)) != OK)
            action_error(rc2actres(s), rc2http(s), msg_get_reason());

        if((s = sx_hashfs_all_volnodes(hashfs, NL_NEXTPREV, vol, 0, &volnodes, NULL)) != OK)
            action_error(rc2actres(s), rc2http(s), msg_get_reason());

        if(sx_nodelist_lookup(volnodes, sx_node_uuid(me)))
            is_volnode = 1;
        else
            is_volnode = 0;

        nvolnodes = sx_nodelist_count(volnodes);

        if(!is_volnode) {
            /* Randomize the source node for the query because the volnodes list is constant for for all the files in the volume. */
            source = sx_nodelist_get(volnodes, sxi_rand() % nvolnodes);

            if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(source)))
                action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory");
        }

        break;
    }

    if(s == OK) {
        int finished = 0;

        /* We have picked a volume to process */
        if(is_volnode) {
            struct upgrade_2_1_4_local_ctx ctx;

            /* Volnodes update revision IDs locally */
            memset(&ctx, 0, sizeof(ctx));
            ctx.hashfs = hashfs;

            if(strcmp(startfile, ""))
                s = sx_hashfs_file_find(hashfs, vol, startfile, startrev, maxrev, upgrade_2_1_4_local_cb, &ctx);
            else
                s = sx_hashfs_file_find(hashfs, vol, NULL, NULL, maxrev, upgrade_2_1_4_local_cb, &ctx);
            if(s != FAIL_ETOOMANY && s != ITER_NO_MORE)
                action_error(rc2actres(s), rc2http(s), "Failed to store local revision ID list");
            else if(s == FAIL_ETOOMANY) {
                memcpy(startfile, ctx.lastfile.name, sizeof(startfile));
                memcpy(startrev, ctx.lastfile.revision, sizeof(startrev));
            } else if(s == ITER_NO_MORE)
                finished = 1;
        } else {
            int qret;
            struct upgrade_2_1_4_remote_ctx ctx;
            sxi_conns_t *clust = sx_hashfs_conns(hashfs);
            /* Non-volnodes should send the revision ID pull query */

            ctx.hashfs = hashfs;
            ctx.b = NULL;
            ctx.pos = 0;
            ctx.ngood = 0;
            ctx.has_limit = 0;
            ctx.state = UPGRADE_2_1_4_HDRSIZE;
            ctx.vol = vol;

            query = sxi_2_1_4_upgrade_proto(sx, startvol, maxrev, startfile, startrev);
            if(!query)
                action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory allocating revision ID pull query");
            qret = sxi_cluster_query(clust, &hlist, query->verb, query->path, query->content, query->content_len, NULL, upgrade_2_1_4_remote_cb, &ctx);
            sx_blob_free(ctx.b);
            if(qret != 200)
                action_error(ACT_RESULT_TEMPFAIL, 503, "Bad reply from node");

            if(ctx.state == UPGRADE_2_1_4_END)
                finished = 1;
            else if(ctx.ngood) {
                memcpy(startfile, ctx.file, sizeof(startfile));
                memcpy(startrev, ctx.rev, sizeof(startrev));
            } else
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to obtain revision ID list");
        }

        if(finished) {
            if(sx_hashfs_replace_setlastfile(hashfs, startvol, NULL, NULL))
                WARN("Volume replica change files relocation failed");
        } else {
            if(sx_hashfs_replace_setlastfile(hashfs, startvol, startfile, startrev))
                WARN("Volume replica change files relocation failed");
        }
    } else if(s == ITER_NO_MORE) {
        s = sx_hashfs_remote_upgrade_finished(hashfs);
        if(s != OK)
            action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to finish remote upgrade job");
        succeeded[0] = 1;
        ret = ACT_RESULT_OK;
    } else
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

action_failed:
    if(ret == ACT_RESULT_OK && succeeded[0] == 1)
        INFO("<<<< 2.1.3 TO 2.1.4 UPGRADE FINISHED SUCCESSFULLY ON THIS NODE >>>>");
    sx_nodelist_delete(volnodes);
    sxi_hostlist_empty(&hlist);
    sxi_query_free(query);

    return ret;
}

static rc_ty upgrade_2_1_3_to_2_1_4_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty upgrade_2_1_3_to_2_1_4_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
}

static rc_ty volrep_blocks_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_OK;
    rc_ty s;
    sx_blob_t *b = NULL;
    const char *volname = NULL;
    const sx_hashfs_volume_t *vol;
    unsigned int prev_replica = 0, next_replica = 0, is_undoing = 0;

    DEBUG("IN %s", __func__);
    if(!job_data || !job_data->len || !job_data->ptr) {
        NULLARG();
        action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
        return ret;
    }

    if(sx_nodelist_count(nodes) > 1) {
        action_set_fail(ACT_RESULT_PERMFAIL, 500, "JOBTYPE_VOLREP_BLOCKS can only be scheduled on one node");
        return ret;
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_int32(b, (int32_t *)&prev_replica) ||
       sx_blob_get_int32(b, (int32_t *)&next_replica) || sx_blob_get_int32(b, (int32_t *)&is_undoing)) {
        WARN("Corrupted job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    if((s = sx_hashfs_volume_by_name(hashfs, volname, &vol)) != OK)
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

    if(vol->prev_max_replica != prev_replica || vol->max_replica != next_replica) {
        WARN("Invalid volume state, replica limits mismatch");
        action_error(ACT_RESULT_PERMFAIL, 500, "Replica mismatch");
    }

    if((s = sx_hashfs_volrep_init(hashfs, vol, is_undoing)) != OK)
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

    sx_hashfs_set_progress_info(hashfs, INPRG_VOLREP_RUNNING, "Preparing local blocks to replica change");

    if((s = sx_hashfs_volrep_update_revid_replica(hashfs, vol, is_undoing)) != OK)
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

    succeeded[0] = 1;
action_failed:
    sx_blob_free(b);

    return ret;
}

#define MAX_VOLREP_BLOCKS_RELEASE_LIMIT 2048

static rc_ty volrep_blocks_release(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, int is_undoing) {
    rc_ty ret = FAIL_EINTERNAL, s;
    unsigned int count = 0;
    const sx_node_t *node = NULL;
    int have_blkidx = 0;
    sx_block_meta_index_t blkidx;

    sx_hashfs_set_progress_info(h, INPRG_REPLACE_RUNNING, "Releasing over-replica blocks");

    s = sx_hashfs_volrep_getstartblock(h, &node, &have_blkidx, (uint8_t *)&blkidx);
    if(s != OK && s != ITER_NO_MORE) {
        WARN("Failed to get start block");
        goto volrep_blocks_release_err;
    } else if(s == ITER_NO_MORE) {
        ret = s;
        goto volrep_blocks_release_err;
    }

    if(!have_blkidx)
        memset(&blkidx, 0, sizeof(blkidx));

    while((s = sx_hashfs_volrep_release_blocks(h, vol, is_undoing, !have_blkidx, &blkidx)) == OK) {
        count++;
        if(count >= MAX_VOLREP_BLOCKS_RELEASE_LIMIT)
            break; /* OK is returned */
        have_blkidx = 1;
    }

    if(s != OK && s != ITER_NO_MORE) {
        WARN("Failed to release over-replica blocks");
        goto volrep_blocks_release_err;
    }

    /* Set a return point for the next iteration, after the job is woken up */
    if(s == ITER_NO_MORE) {
        if(sx_hashfs_volrep_setlastblock(h, sx_node_uuid(sx_hashfs_self(h)), NULL))
            WARN("Failed to set last block for a volume replica modification");
    } else {
        /* More blocks to be dropped, set a proper blockmeta index */
        if(sx_hashfs_volrep_setlastblock(h, sx_node_uuid(sx_hashfs_self(h)), (uint8_t *)&blkidx))
            WARN("Failed to set last block for a volume replica modification");
    }

    ret = s;
volrep_blocks_release_err:
    return ret;
}

static rc_ty volrep_blocks_pull(sx_hashfs_t *hashfs, const sx_hashfs_volume_t *vol, int is_undoing) {
    rc_ty ret = FAIL_EINTERNAL, s;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sx_block_meta_index_t bmidx;
    const sx_node_t *source;
    sxi_hostlist_t hlist;
    int have_blkidx;
    char *enc_vol = NULL;

    if(!vol) {
        NULLARG();
        return FAIL_EINTERNAL;
    }

    sxi_hostlist_init(&hlist);
    enc_vol = sxi_urlencode(sx, vol->name, 1);
    if(!enc_vol) {
        msg_set_reason("Not enough memory to perform the requested action");
        goto volrep_blocks_pull_err;
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_REPLACE_RUNNING, "Pulling under-replica blocks");

    s = sx_hashfs_volrep_getstartblock(hashfs, &source, &have_blkidx, (uint8_t *)&bmidx);
    if(s == OK) {
        sxi_conns_t *clust = sx_hashfs_conns(hashfs);
        const sx_node_t *me = sx_hashfs_self(hashfs);
        struct rplblocks *ctx = malloc(sizeof(*ctx));
        char query[256];
        int qret;
        char hexidx[sizeof(bmidx)*2+1];

        if(!ctx) {
            msg_set_reason("Out of memory");
            goto volrep_blocks_pull_err;
        }
        if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(source))) {
            free(ctx);
            msg_set_reason("Out of memory");
            goto volrep_blocks_pull_err;
        }

        if(have_blkidx)
            bin2hex(&bmidx, sizeof(bmidx), hexidx, sizeof(hexidx));

        snprintf(query, sizeof(query), ".volrepblk?volume=%s&target=%s%s%s%s", enc_vol, sx_node_uuid_str(me),
                have_blkidx ? "&idx=" : "", have_blkidx ? hexidx : "", is_undoing ? "&undo" : "");

        ctx->hashfs = hashfs;
        ctx->b = NULL;
        ctx->pos = 0;
        ctx->ngood = 0;
        ctx->state = RPL_HDRSIZE;
        qret = sxi_cluster_query(clust, &hlist, REQ_GET, query, NULL, 0, NULL, rplblocks_cb, ctx);
        sx_blob_free(ctx->b);
        if(qret != 200) {
            free(ctx);
            msg_set_reason("Bad reply from node");
            goto volrep_blocks_pull_err;
        }

        if(ctx->state == RPL_END) {
            if(sx_hashfs_volrep_setlastblock(hashfs, sx_node_uuid(source), NULL))
                WARN("Failed to set last block for a volume replica modification");
        } else if(ctx->ngood) {
            if(sx_hashfs_volrep_setlastblock(hashfs, sx_node_uuid(source), (uint8_t *)&ctx->lastgood))
                WARN("Failed to set last block for a volume replica modification");
        }
        free(ctx);
    } else if(s != ITER_NO_MORE) {
        ret = s;
        WARN("Failed to get start block: %s", msg_get_reason());
        goto volrep_blocks_pull_err;
    }

    ret = s;
volrep_blocks_pull_err:
    sxi_hostlist_empty(&hlist);
    free(enc_vol);
    return ret;
}

static rc_ty volrep_blocks_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_NOTFAILED;
    sxi_hostlist_t hlist;
    rc_ty s;
    sx_blob_t *b = NULL;
    const char *volname = NULL;
    unsigned int prev_replica = 0, next_replica = 0, is_undoing = 0;
    const sx_hashfs_volume_t *vol = NULL;

    DEBUG("IN %s", __func__);
    sxi_hostlist_init(&hlist);

    if(sx_nodelist_count(nodes) != 1) {
        CRIT("Bad job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "JOBTYPE_VOLREP_FILES can only be scheduled on one node");
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_int32(b, (int32_t *)&prev_replica) ||
       sx_blob_get_int32(b, (int32_t *)&next_replica) || sx_blob_get_int32(b, (int32_t *)&is_undoing)) {
        WARN("Corrupted job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    if((s = sx_hashfs_volume_by_name(hashfs, volname, &vol)) != OK)
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

    if(vol->prev_max_replica != prev_replica || vol->max_replica != next_replica) {
        WARN("Invalid volume state, replica limits mismatch");
        action_error(ACT_RESULT_PERMFAIL, 500, "Replica mismatch");
    }

    if(is_undoing) {
        WARN("Undoing volume replica change blocks relocation phase");
        unsigned int tmp = next_replica;
        next_replica = prev_replica;
        prev_replica = tmp;
    }

    if(next_replica > prev_replica)
        s = volrep_blocks_pull(hashfs, vol, is_undoing);
    else if(next_replica < prev_replica)
        s = volrep_blocks_release(hashfs, vol, is_undoing);
    else /* In case replica is the same, this operation should be a no-op */
        s = ITER_NO_MORE;
    if(s != OK && s != ITER_NO_MORE) {
        if(s == FAIL_LOCKED)
            action_error(ACT_RESULT_TEMPFAIL, 503, "Resource is temporarily locked");
        else {
            WARN("Failed to perform commit phase: %s", msg_get_reason());
            action_error(rc2actres(s), rc2http(s), msg_get_reason());
        }
    } else if(s == ITER_NO_MORE) {
        succeeded[0] = 1;
        ret = ACT_RESULT_OK;
        INFO("<<<< BLOCKS %sPHASE OF VOLUME REPLICA CHANGE DONE >>>>", is_undoing ? "UNDO " : "");
    }

action_failed:
    sxi_hostlist_empty(&hlist);
    sx_blob_free(b);
    return ret;
}

static act_result_t volrep_files_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    act_result_t ret = ACT_RESULT_NOTFAILED;
    char maxrev[REV_LEN+1];
    sxi_hostlist_t hlist;
    struct rplfiles *ctx = NULL;
    sx_blob_t *b = NULL;
    unsigned int prev_replica = 0, next_replica = 0, is_undoing = 0;
    const char *volname;
    rc_ty s;
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const sx_hashfs_volume_t *vol = NULL;
    sx_nodelist_t *volnodes = NULL;
    unsigned int index = 0;
    const sx_node_t *node;

    DEBUG("IN %s", __func__);

    sxi_hostlist_init(&hlist);

    if(sx_nodelist_count(nodes) != 1) {
        CRIT("Bad job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_int32(b, (int32_t *)&prev_replica) ||
       sx_blob_get_int32(b, (int32_t *)&next_replica) || sx_blob_get_int32(b, (int32_t *)&is_undoing)) {
        WARN("Corrupted job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    if((s = sx_hashfs_volume_by_name(hashfs, volname, &vol)) != OK)
        action_error(rc2actres(s), rc2http(s), "Failed to obtain volume by name");

    if(vol->prev_max_replica != prev_replica || vol->max_replica != next_replica) {
        WARN("Invalid volume state, replica limits mismatch");
        action_error(ACT_RESULT_PERMFAIL, 500, "Replica mismatch");
    }

    if(is_undoing) {
        unsigned int tmp = next_replica;
        next_replica = prev_replica;
        prev_replica = tmp;
    }

    if(prev_replica >= next_replica) {
        DEBUG("Skipping file relocation due to next replica being less or equal to prev replica");
        ret = ACT_RESULT_OK;
        succeeded[0] = 1;
        goto action_failed;
    }

    s = sx_hashfs_all_volnodes(hashfs, NL_NEXTPREV, vol, 0, &volnodes, NULL);
    if(s != OK)
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

    /* Check if the node running this job is the node which is becoming a new volnode */
    node = sx_nodelist_lookup_index(volnodes, sx_node_uuid(me), &index);
    if(!node) {
        WARN("This node is not a volnode for %s", volname);
        action_error(ACT_RESULT_PERMFAIL, 500, "Wrong node for the action");
    }

    if(index < MIN(prev_replica,next_replica)) {
        WARN("This node is an old volnode for %s", volname);
        action_error(ACT_RESULT_PERMFAIL, 500, "Wrong node for the action");
    }

    /* When decreasing volume replica, prev > next and it is possible to call this action
     * on the node having the index < prev, but there is no need to pull files in this case. */
    if(index < prev_replica) {
        DEBUG("Skipping files pull due to current node index being less than prev replica: %d < %d", index, prev_replica);
        succeeded[0] = 1;
        ret = ACT_RESULT_OK;
        goto action_failed;
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_VOLREP_RUNNING, "Healing files");

    ctx = malloc(sizeof(*ctx));
    if(!ctx)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory allocating request context");
    ctx->vol = vol;

    while((s = sx_hashfs_volrep_getstartfile(hashfs, maxrev, ctx->volume, ctx->file, ctx->rev)) == OK) {
        const sx_node_t *source;

        /* Just in case, check if a volume obtained from replacement table matches the volume 
         * we are modifying the replica. */
        if(strcmp(ctx->volume, volname)) {
            WARN("Invalid replica change volume entry");
            action_error(ACT_RESULT_PERMFAIL, 500, "Invalid replica change volume entry");
        }

        /* Randomize the source node for the query because the volnodes list is constant for for all the files in the volume. */
        source = sx_nodelist_get(volnodes, sxi_rand() % prev_replica);

        if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(source)))
            action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory");

        break;
    }

    if(s == OK) {
        char *enc_vol = NULL, *enc_file = NULL, *enc_rev = NULL, *enc_maxrev = NULL, *query = NULL;
        sxi_conns_t *clust = sx_hashfs_conns(hashfs);
        int qret;

        enc_vol = sxi_urlencode(sx, ctx->volume, 0);
        enc_file = sxi_urlencode(sx, ctx->file, 0);
        enc_rev = sxi_urlencode(sx, ctx->rev, 0);
        enc_maxrev = sxi_urlencode(sx, maxrev, 0);

        if(enc_vol && enc_file && enc_rev && enc_maxrev) {
            query = malloc(lenof(".replfl/") +
                           strlen(enc_vol) +
                           lenof("/") +
                           strlen(enc_file) +
                           lenof("?maxrev=") +
                           strlen(enc_maxrev) +
                           lenof("&startrev=") +
                           strlen(enc_rev) +
                           1);

            if(query) {
                /* Reuse a request used for the node replacement routine, this should work for the volume replica change case. */
                if(strlen(enc_file))
                    sprintf(query, ".replfl/%s/%s?maxrev=%s&startrev=%s", enc_vol, enc_file, enc_maxrev, enc_rev);
                else
                    sprintf(query, ".replfl/%s?maxrev=%s", enc_vol, enc_maxrev);
            }
        }

        free(enc_vol);
        free(enc_file);
        free(enc_rev);
        free(enc_maxrev);

        if(!query)
            action_error(ACT_RESULT_TEMPFAIL, 503, "Out of memory allocating the request URL");

        ctx->hashfs = hashfs;
        ctx->b = NULL;
        ctx->pos = 0;
        ctx->ngood = 0;
        ctx->needend = 0;
        ctx->allow_over_replica = is_undoing;
        ctx->state = RPL_HDRSIZE;

        qret = sxi_cluster_query(clust, &hlist, REQ_GET, query, NULL, 0, NULL, rplfiles_cb, ctx);
        free(query);
        sx_blob_free(ctx->b);
        if(ctx->needend)
            sx_hashfs_putfile_end(hashfs);
        if(qret != 200)
            action_error(ACT_RESULT_TEMPFAIL, 503, "Bad reply from node");
        if(ctx->state == RPL_END) {
            if(sx_hashfs_volrep_setlastfile(hashfs, ctx->volume, NULL, NULL))
                WARN("Volume replica change files relocation failed");
        } else if(ctx->ngood) {
            if(sx_hashfs_volrep_setlastfile(hashfs, ctx->volume, ctx->file, ctx->rev))
                WARN("Volume replica change files relocation failed");
        }
    } else if(s == ITER_NO_MORE) {
        succeeded[0] = 1;
        ret = ACT_RESULT_OK;
    } else
        action_error(rc2actres(s), rc2http(s), msg_get_reason());


 action_failed:
    sxi_hostlist_empty(&hlist);
    free(ctx);
    sx_blob_free(b);
    sx_nodelist_delete(volnodes);
    return ret;
}

static act_result_t volrep_files_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl) {
    act_result_t ret = ACT_RESULT_NOTFAILED;
    sx_blob_t *b = NULL;
    unsigned int prev_replica = 0, next_replica = 0, is_undoing = 0;
    const char *volname;
    rc_ty s;
    const sx_node_t *me = sx_hashfs_self(hashfs);
    const sx_hashfs_volume_t *vol = NULL;
    sx_nodelist_t *volnodes = NULL;
    unsigned int index = 0;
    const sx_node_t *node;

    DEBUG("IN %s", __func__);

    if(sx_nodelist_count(nodes) != 1) {
        CRIT("Bad job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
        action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) || sx_blob_get_int32(b, (int32_t *)&prev_replica) ||
       sx_blob_get_int32(b, (int32_t *)&next_replica) || sx_blob_get_int32(b, (int32_t *)&is_undoing)) {
        WARN("Corrupted job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    if((s = sx_hashfs_volume_by_name(hashfs, volname, &vol)) != OK)
        action_error(rc2actres(s), rc2http(s), "Failed to obtain volume by name");

    if(vol->prev_max_replica != prev_replica || vol->max_replica != next_replica) {
        WARN("Invalid volume state, replica limits mismatch");
        action_error(ACT_RESULT_PERMFAIL, 500, "Replica mismatch");
    }

    if(is_undoing) {
        WARN("Undoing volume replica change files relocation phase");
        unsigned int tmp = next_replica;
        next_replica = prev_replica;
        prev_replica = tmp;
    }

    s = sx_hashfs_all_volnodes(hashfs, NL_NEXTPREV, vol, 0, &volnodes, NULL);
    if(s != OK)
        action_error(rc2actres(s), rc2http(s), msg_get_reason());

    /* Check if the node running this job is the node which is becoming a new volnode */
    node = sx_nodelist_lookup_index(volnodes, sx_node_uuid(me), &index);
    if(!node) {
        WARN("This node is not a volnode for %s", volname);
        action_error(ACT_RESULT_PERMFAIL, 500, "Wrong node for the action");
    }

    if(index < MIN(prev_replica,next_replica)) {
        WARN("This node is an old volnode for %s", volname);
        action_error(ACT_RESULT_PERMFAIL, 500, "Wrong node for the action");
    }

    /* At this point we only consider the transitioning volnodes */
    if(prev_replica < next_replica) {
        /* Volume replica increase
         *
         * This node becomes a volnode for new replica, we have to recalculate sizes of the files stored here,
         * previously a non-volnode stored eventually consistent values. */
        if((s = sx_hashfs_compute_volume_size(hashfs, vol)))
            action_error(rc2actres(s), rc2http(s), msg_get_reason());
    } else if(prev_replica > next_replica) {
        /* Volume replica decrease */
        INFO("Removing all files from %s which no longer belong in here", vol->name);

        if((s = sx_hashfs_volume_clean(hashfs, vol)) != OK)
            action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    sx_hashfs_set_progress_info(hashfs, INPRG_VOLREP_COMPLETE, "Healing complete");

    succeeded[0] = 1;
    ret = ACT_RESULT_OK;
 action_failed:
    if(ret == ACT_RESULT_OK && succeeded[0] == 1)
        INFO("<<<< FILES %sPHASE OF VOLUME REPLICA CHANGE DONE >>>>", is_undoing ? "UNDO " : "");
    sx_blob_free(b);
    sx_nodelist_delete(volnodes);
    return ret;
}

/* Common for abort and undo phases, called only on one node when jobpoll fails (not on undo phase for JOBTYPE_VOLREP_FILES */
static act_result_t volrep_undo_common(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg, int *adjust_ttl, jobtype_t type, jobphase_t phase, int revert_files) {
    rc_ty s;
    sx_blob_t *b = NULL, *newb = NULL;
    const sx_nodelist_t *allnodes;
    act_result_t ret = ACT_RESULT_OK;
    const void *data;
    unsigned int data_len;
    job_t job = JOB_NOPARENT; /* Used as a parent in a chain */
    const char *volname = NULL;
    unsigned int prev_replica = 0, next_replica = 0;
    unsigned int is_undoing = 0; /* Set to 1 when this function is called for already being undone job */
    unsigned int i;
    const sx_hashfs_volume_t *vol = NULL;
    sx_nodelist_t *ftargets = NULL; /* Target nodelist for files undo phase */
    const sx_nodelist_t *targets;

    allnodes = sx_hashfs_all_nodes(hashfs, NL_NEXTPREV);
    if(!allnodes)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Failed to get nodelist");
    if(type == JOBTYPE_JOBPOLL) {
        /* For the case when we fail in polling job we have to revert changes on all the nodes. The same applies when we
         * want to revert files. */
        targets = allnodes;
    } else {
        /* For the case when we fail in the spawning job we should revert mass jobs on the nodelist provided by the job manager in an undo phase.
         * Other nodes did not succeed to spawn and they are going to timeout, but do not require undoing. */
        targets = nodes;
    }

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Out of memory");

    newb = sx_blob_new();
    if(!newb)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Out of memory");

    /* Read through original job data blob */
    if(sx_blob_get_string(b, &volname) || sx_blob_get_int32(b, (int32_t *)&prev_replica) ||
       sx_blob_get_int32(b, (int32_t *)&next_replica) || sx_blob_get_int32(b, (int32_t *)&is_undoing)) {
        WARN("Corrupted job data");
        action_error(ACT_RESULT_PERMFAIL, 500, "Bad job data");
    }

    if((s = sx_hashfs_volume_by_name(hashfs, volname, &vol)) != OK)
        action_error(rc2actres(s), rc2http(s), "Failed to obtain volume by name");

    if(vol->prev_max_replica != prev_replica || vol->max_replica != next_replica) {
        WARN("Invalid volume state, replica limits mismatch");
        action_error(ACT_RESULT_PERMFAIL, 500, "Replica mismatch");
    }

    /* Target nodelist might be shorter than over-replica nodes due to the targets nodeslit being possibly shorter than all nodes. */
    s = sx_hashfs_over_replica_volnodes(hashfs, vol, prev_replica, next_replica, targets, &ftargets);
    if(s != OK)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to obtain target nodes for files undo phase");

    /* When the spawning or polling job succeeds to schedule some jobs avoid scheduling the volume replica change job during the abort phase. 
     * If all the nodes failed at the request phase (no commit suceeded), the undo phase would not be called. */
    if(phase == JOBPHASE_ABORT) {
        if((!revert_files && sx_nodelist_count(nodes) != sx_nodelist_count(allnodes)) ||
           (revert_files && sx_nodelist_count(nodes) != sx_nodelist_count(ftargets))) {
            DEBUG("Forcibly making the abort phase to succeed");
            return force_phase_success(hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg, adjust_ttl);
        }
    }

    /* Create new job data, but set the undo flag */
    if(sx_blob_add_string(newb, volname) || sx_blob_add_int32(newb, (int32_t)prev_replica) ||
       sx_blob_add_int32(newb, (int32_t)next_replica) || sx_blob_add_int32(newb, 1))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Out of memory adding data to the new blob");

    if((s = sx_hashfs_job_new_begin(hashfs)))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Failed to start transaction");

    sx_blob_to_data(newb, &data, &data_len);

    /*
     * If the jobs were already being undone skip blocks and files relocation, but try hard to stabilize the volume replica
     * to make other volume replica changes and cluster membership modifications to be able to work again.
     *
     * When this function is called by the abort callback (can be called by jobspawn_abort) and all the nodes are on the to-abort
     * list it is not necessary to undo current stage.
     *
     * Scheduling the JOBTYPE_VOLREP_CHANGE is not going to make this function to be called again, it is a regular job.
     */
    if(!is_undoing) {
        /* Abort phase can only call this code when no undo phase is to be called later */
        if(type == JOBTYPE_JOBPOLL || phase != JOBPHASE_ABORT || revert_files) {
            DEBUG("Scheduling UNDO job for BLOCKS");
            /* When we want to revert files, schedule an undo for block to all the nodes. */
            s = sx_hashfs_mass_job_new_notrigger(hashfs, job, job_data->owner, &job, JOBTYPE_VOLREP_BLOCKS, JOB_NO_EXPIRY, "VOLREP_BLOCKS", data, data_len, revert_files ? allnodes : targets);
            if(s != OK)
                action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Failed to schedule VOLREP_BLOCKS job undo");

            /* Only revert files when needed */
            if(revert_files && (type == JOBTYPE_JOBPOLL || phase != JOBPHASE_ABORT)) {
                DEBUG("Scheduling UNDO job for FILES");
                s = sx_hashfs_mass_job_new_notrigger(hashfs, job, job_data->owner, &job, JOBTYPE_VOLREP_FILES, JOB_NO_EXPIRY, "VOLREP_FILES", data, data_len, ftargets);
                if(s != OK)
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change: Failed to schedule VOLREP_FILES job undo");
            }
        }
    } else
        CRIT("Undo phase failed for volume replica change, some files may be left in an inconsistent state");

    /* For the replica change just set both replica limits to the prev */
    sx_blob_reset(newb);
    if(sx_blob_add_string(newb, volname) || sx_blob_add_int32(newb, (int32_t)prev_replica) ||
       sx_blob_add_int32(newb, (int32_t)prev_replica) || sx_blob_add_int32(newb, 1))
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change");

    sx_blob_to_data(newb, &data, &data_len);
    s = sx_hashfs_job_new_notrigger(hashfs, job, job_data->owner, &job, JOBTYPE_VOLREP_CHANGE, 20, NULL, data, data_len, allnodes);
    if(s != OK)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change");

    /* Commit the job chain */
    s = sx_hashfs_job_new_end(hashfs);
    if(s != OK)
        action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to undo volume replica change");

    for(i = 0; i < sx_nodelist_count(nodes); i++)
        succeeded[i] = 1;
 action_failed:
    if(ret != ACT_RESULT_OK) {
        if(ret != ACT_RESULT_TEMPFAIL)
            CRIT("Permanently failed to undo volume replica change, volume '%s' might be left in an inconsistent state", volname ? volname : "<unknown>");
        sx_hashfs_job_new_abort(hashfs);
    }

    sx_nodelist_delete(ftargets);
    sx_blob_free(b);
    sx_blob_free(newb);
    return ret;
}

/* TODO: upgrade from 1.0-style flush and delete jobs */
static struct {
    job_action_t fn_request;
    job_action_t fn_commit;
    job_action_t fn_abort;
    job_action_t fn_undo;
} actions[] = {
    { createvol_request, createvol_commit, createvol_abort_and_undo, createvol_abort_and_undo }, /* JOBTYPE_CREATE_VOLUME */
    { createuser_request, createuser_commit, createuser_abort, createuser_undo }, /* JOBTYPE_CREATE_USER */
    { acl_request, acl_commit, acl_abort, acl_undo }, /* JOBTYPE_VOLUME_ACL */
    { replicateblocks_request, replicateblocks_commit, replicateblocks_abort, replicateblocks_abort }, /* JOBTYPE_REPLICATE_BLOCKS */
    { force_phase_success, fileflush_remote, replicateblocks_abort, fileflush_remote_undo }, /* JOBTYPE_FLUSH_FILE_REMOTE */
    { filedelete_request, filedelete_commit, filedelete_abort, filedelete_undo }, /* JOBTYPE_DELETE_FILE */
    { distribution_request, distribution_commit, distribution_abort, distribution_undo }, /* JOBTYPE_DISTRIBUTION */
    { startrebalance_request, force_phase_success, force_phase_success, force_phase_success }, /* JOBTYPE_STARTREBALANCE */
    { finishrebalance_request, finishrebalance_commit, force_phase_success, force_phase_success }, /* JOBTYPE_FINISHREBALANCE */
    { jlock_request, force_phase_success, jlock_abort_and_undo, jlock_abort_and_undo }, /* JOBTYPE_JLOCK */
    { blockrb_request, blockrb_commit, force_phase_success, force_phase_success }, /* JOBTYPE_REBALANCE_BLOCKS */
    { filerb_request, filerb_commit, force_phase_success, force_phase_success }, /* JOBTYPE_REBALANCE_FILES */
    { cleanrb_request, cleanrb_commit, force_phase_success, force_phase_success }, /* JOBTYPE_REBALANCE_CLEANUP */
    { deleteuser_request, deleteuser_commit, deleteuser_abort, deleteuser_undo }, /* JOBTYPE_DELETE_USER */
    { deletevol_request, deletevol_commit, deletevol_abort, deletevol_undo }, /* JOBTYPE_DELETE_VOLUME */
    { force_phase_success, usermodify_commit, usermodify_abort, usermodify_undo }, /* JOBTYPE_MODIFY_USER */
    { force_phase_success, volmod_commit, volmod_abort, volmod_undo }, /* JOBTYPE_MODIFY_VOLUME */
    { replace_request, replace_commit, replace_abort, replace_undo }, /* JOBTYPE_REPLACE */
    { replaceblocks_request, replaceblocks_commit, force_phase_success, force_phase_success }, /* JOBTYPE_REPLACE_BLOCKS */
    { replacefiles_request, replacefiles_commit, force_phase_success, force_phase_success }, /* JOBTYPE_REPLACE_FILES */
    { dummy_request, dummy_commit, dummy_abort, dummy_undo }, /* JOBTYPE_DUMMY */
    { force_phase_success, revsclean_vol_commit, revsclean_vol_abort, revsclean_vol_undo }, /* JOBTYPE_REVSCLEAN */
    { distlock_request, force_phase_success, distlock_abort, force_phase_success }, /* JOBTYPE_DISTLOCK */
    { cluster_mode_request, force_phase_success, cluster_mode_abort, force_phase_success }, /* JOBTYPE_CLUSTER_MODE */
    { ignodes_request, ignodes_commit, force_phase_success, force_phase_success }, /* JOBTYPE_IGNODES */
    { force_phase_success, revision_commit, revision_abort, revision_undo }, /* JOBTYPE_BLOCKS_REVISION */
    { force_phase_success, fileflush_local, fileflush_remote_undo, force_phase_success }, /* JOBTYPE_FLUSH_FILE_LOCAL  - 1 node */
    { upgrade_request, force_phase_success, force_phase_success, force_phase_success }, /* JOBTYPE_UPGRADE_FROM_1_0_OR_1_1 */
    { force_phase_success, jobpoll_commit, jobpoll_abort, jobpoll_undo }, /* JOBTYPE_JOBPOLL */
    { force_phase_success, massdelete_commit, massdelete_abort, massdelete_undo }, /* JOBTYPE_MASSDELETE */
    { force_phase_success, massrename_commit, massrename_abort, massrename_undo }, /* JOBTYPE_MASSRENAME */
    { force_phase_success, cluster_setmeta_commit, cluster_setmeta_abort, cluster_setmeta_undo }, /* JOBTYPE_CLUSTER_SETMETA */
    { jobspawn_request, jobspawn_commit, jobspawn_abort, jobspawn_undo }, /* JOBTYPE_JOBSPAWN */
    { force_phase_success, cluster_settings_commit, cluster_settings_abort, cluster_settings_undo }, /* JOBTYPE_CLUSTER_SETTINGS */
    { junlockall_request, force_phase_success, force_phase_success, force_phase_success }, /* JOBTYPE_JUNLOCKALL */
    { delay_request, force_phase_success, force_phase_success, force_phase_success }, /* JOBTYPE_DELAY */
    { upgrade_2_1_3_to_2_1_4_request, upgrade_2_1_3_to_2_1_4_commit, upgrade_2_1_3_to_2_1_4_abort, upgrade_2_1_3_to_2_1_4_undo }, /* JOBTYPE_UPGRADE_FROM_2_1_3_TO_2_1_4 */
    { force_phase_success, volrep_commit, force_phase_success, volrep_undo }, /* JOBTYPE_VOLREP_CHANGE */
    { volrep_blocks_request, volrep_blocks_commit, force_phase_success, force_phase_success }, /* JOBTYPE_VOLREP_BLOCKS */
    { volrep_files_request, volrep_files_commit, force_phase_success, force_phase_success }, /* JOBTYPE_VOLREP_FILES */
};


static job_data_t *make_jobdata(const void *data, unsigned int data_len, uint64_t op_expires_at, sx_uid_t owner) {
    job_data_t *ret;

    if(!data && data_len)
	return NULL;
    if(!(ret = wrap_malloc(sizeof(*ret) + data_len)))
	return NULL;
    ret->ptr = (void *)(ret+1);
    ret->len = data_len;
    ret->op_expires_at = op_expires_at;
    ret->owner = owner;
    if(data_len)
	memcpy(ret->ptr, data, data_len);
    return ret;
}

static int terminate = 0;
static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}

#define JOB_PHASE_REQUEST 0
#define JOB_PHASE_COMMIT 1
#define JOB_PHASE_DONE 2
#define JOB_PHASE_FAIL 3

#define BATCH_ACT_NUM 64

struct jobmgr_data_t {
    /* The following items are filled in once by jobmgr() */
    sx_hashfs_t *hashfs;
    sxi_db_t *eventdb;
    sqlite3_stmt *qjob;
    sqlite3_stmt *qact;
    sqlite3_stmt *qfail_children;
    sqlite3_stmt *qfail_parent;
    sqlite3_stmt *qcpl;
    sqlite3_stmt *qphs;
    sqlite3_stmt *qdly;
    sqlite3_stmt *qlfe;
    sqlite3_stmt *qvbump;
    time_t next_vcheck;

    /* The following items are filled in by:
     * jobmgr_process_queue(): sets job_id, job_type, job_expired, job_failed, job_data (from the db)
     * jobmgr_run_job(): job_failed gets updated if job fails or expires
     * jobmgr_get_actions_batch(): sets act_phase and nacts then fills the targets and act_ids arrays
     * jobmgr_execute_actions_batch(): fail_reason in case of failure
     */
    sx_nodelist_t *targets;
    job_data_t *job_data;
    int64_t act_ids[BATCH_ACT_NUM];
    int job_expired, job_failed;
    job_t job_id;
    jobtype_t job_type;
    sx_uid_t user;
    unsigned int nacts;
    int act_phase;
    int adjust_ttl;
    int nodelay_reschedule;
    char fail_reason[JOB_FAIL_REASON_SIZE];
};


static act_result_t jobmgr_execute_actions_batch(int *http_status, struct jobmgr_data_t *q) {
    act_result_t act_res = ACT_RESULT_UNSET;
    unsigned int nacts = q->nacts;
    int act_succeeded[BATCH_ACT_NUM];

    memset(act_succeeded, 0, sizeof(act_succeeded));
    *http_status = 0;
    q->fail_reason[0] = '\0';
    q->nodelay_reschedule = 0;

    if(q->job_failed) {
	if(q->act_phase == JOB_PHASE_REQUEST) {
	    /* Nothing to (un)do */
	    act_res = ACT_RESULT_OK;
	} else if(q->act_phase == JOB_PHASE_COMMIT) {
	    act_res = actions[q->job_type].fn_abort(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason, &q->adjust_ttl);
	} else { /* act_phase == JOB_PHASE_DONE */
	    act_res = actions[q->job_type].fn_undo(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason, &q->adjust_ttl);
	}
	if(act_res == ACT_RESULT_NOTFAILED) {
	    WARN("Job failed with GIVEUP; using TEMPFAIL instead");
	    act_res = ACT_RESULT_TEMPFAIL;
	}
        if(act_res == ACT_RESULT_TEMPFAIL && q->job_expired) {
            CRIT("Some undo action expired for job %lld.", (long long)q->job_id);
            act_res = ACT_RESULT_OK;
        } else if(act_res == ACT_RESULT_PERMFAIL) {
	    CRIT("Some undo action permanently failed for job %lld.", (long long)q->job_id);
	    act_res = ACT_RESULT_OK;
	}
    } else {
	if(q->act_phase == JOB_PHASE_REQUEST) {
	    act_res = actions[q->job_type].fn_request(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason, &q->adjust_ttl);
	} else { /* act_phase == JOB_PHASE_COMMIT */
	    act_res = actions[q->job_type].fn_commit(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason, &q->adjust_ttl);
	}
	if(act_res == ACT_RESULT_NOTFAILED) {
	    q->nodelay_reschedule = 1;
	    act_res = ACT_RESULT_TEMPFAIL;
	}
    }
    if(act_res != ACT_RESULT_OK && act_res != ACT_RESULT_TEMPFAIL && act_res != ACT_RESULT_PERMFAIL) {
	WARN("Unknown action return code %d: changing to PERMFAIL", act_res);
	act_res = ACT_RESULT_PERMFAIL;
    }

    while(nacts--) { /* Bump phase of successful actions */
	if(act_succeeded[nacts] || (q->job_failed && act_res == ACT_RESULT_OK)) {
	    if(qbind_int64(q->qphs, ":act", q->act_ids[nacts]) ||
	       qbind_int(q->qphs, ":phase", q->job_failed ? JOB_PHASE_FAIL : q->act_phase + 1) ||
	       qstep_noret(q->qphs))
		WARN("Cannot advance action phase for %lld.%lld", (long long)q->job_id, (long long)q->act_ids[nacts]);
	    else
		DEBUG("Action %lld advanced to phase %d", (long long)q->act_ids[nacts], q->job_failed ? JOB_PHASE_FAIL : q->act_phase + 1);
	}
    }

    return act_res;
}

static int jobmgr_get_actions_batch(struct jobmgr_data_t *q) {
    const sx_node_t *me = sx_hashfs_self(q->hashfs);
    unsigned int nacts;
    int r;

    q->nacts = 0;

    if(qbind_int64(q->qact, ":job", q->job_id) ||
       qbind_int(q->qact, ":maxphase", q->job_failed ? JOB_PHASE_FAIL : JOB_PHASE_DONE)) {
	WARN("Cannot lookup actions for job %lld", (long long)q->job_id);
	return -1;
    }
    r = qstep(q->qact);
    if(r == SQLITE_DONE) {
	if(qbind_int64(q->qcpl, ":job", q->job_id) ||
	   qstep_noret(q->qcpl))
	    WARN("Cannot set job %lld to complete", (long long)q->job_id);
	else
	    DEBUG("No actions for job %lld", (long long)q->job_id);
	return 1; /* Job completed */
    } else if(r == SQLITE_ROW)
	q->act_phase = sqlite3_column_int(q->qact, 1); /* Define the current batch phase */

    for(nacts=0; nacts<BATCH_ACT_NUM; nacts++) {
	sx_node_t *target;
	int64_t act_id;
	sx_uuid_t uuid;
	const void *ptr;
	unsigned int plen;
	rc_ty rc;

	if(r == SQLITE_DONE)
	    break; /* set batch_size and return success */

	if(r != SQLITE_ROW) {
	    WARN("Failed to retrieve actions for job %lld", (long long)q->job_id);
	    return -1;
	}
	if(sqlite3_column_int(q->qact, 1) != q->act_phase)
	    break; /* set batch_size and return success */

	act_id = sqlite3_column_int64(q->qact, 0);
	ptr = sqlite3_column_blob(q->qact, 2);
	plen = sqlite3_column_bytes(q->qact, 2);
	if(plen != sizeof(uuid.binary)) {
	    WARN("Bad action target for job %lld.%lld", (long long)q->job_id, (long long)act_id);
	    sqlite3_reset(q->qact);
	    return -1;
	}
	uuid_from_binary(&uuid, ptr);
	/* node = sx_nodelist_lookup(sx_hashfs_nodelist(q->hashfs, NL_NEXTPREV), &uuid); */
	/* if(!node) */
	    target = sx_node_new(&uuid, sqlite3_column_text(q->qact, 3), sqlite3_column_text(q->qact, 4), sqlite3_column_int64(q->qact, 5));
	/* else */
	/*     target = sx_node_dup(node); */
	if(!sx_node_cmp(me, target)) {
	    rc = sx_nodelist_prepend(q->targets, target);
	    if(nacts)
		memmove(&q->act_ids[1], &q->act_ids[0], nacts * sizeof(act_id));
	    q->act_ids[0] = act_id;
	} else {
	    rc = sx_nodelist_add(q->targets, target);
	    q->act_ids[nacts] = act_id;
	}
	if(rc != OK) {
	    WARN("Cannot add action target");
	    sqlite3_reset(q->qact);
	    return -1;
	}
	DEBUG("Action %lld (phase %d, target %s) loaded", (long long)act_id, q->act_phase, uuid.string);
	r = qstep(q->qact);
    }

    sqlite3_reset(q->qact);
    q->nacts = nacts;
    return 0;
}


static int set_job_failed(struct jobmgr_data_t *q, int result, const char *reason) {
    if(qbegin(q->eventdb)) {
	CRIT("Cannot set job %lld to failed: cannot start transaction", (long long)q->job_id);
	return -1;
    }

    if(qbind_int64(q->qfail_children, ":job", q->job_id) ||
       qbind_int(q->qfail_children, ":res", result) ||
       qbind_text(q->qfail_children, ":reason", reason) ||
       qstep_noret(q->qfail_children))
	goto setfailed_error;


    if(qbind_int64(q->qfail_parent, ":job", q->job_id) ||
       qbind_int(q->qfail_parent, ":res", result) ||
       qbind_text(q->qfail_parent, ":reason", reason) ||
       qstep_noret(q->qfail_parent))
	goto setfailed_error;

    if(qcommit(q->eventdb))
	goto setfailed_error;

    return 0;

 setfailed_error:
    CRIT("Cannot mark job %lld (and children) as failed", (long long)q->job_id);
    qrollback(q->eventdb);
    return -1;
}

static rc_ty adjust_job_ttl(struct jobmgr_data_t *q) {
    if(!q)
        return EINVAL;
    if(q->adjust_ttl) {
        char lifeadj[24];

        sqlite3_reset(q->qlfe);
        snprintf(lifeadj, sizeof(lifeadj), "%d seconds", q->adjust_ttl);
        if(qbind_int64(q->qlfe, ":job", q->job_id) ||
           qbind_text(q->qlfe, ":ttldiff", lifeadj) ||
           qstep_noret(q->qlfe)) {
            return FAIL_EINTERNAL;
        } else
            DEBUG("Lifetime of job %lld adjusted by %s", (long long)q->job_id, lifeadj);
    }
    return OK;
}

static rc_ty get_failed_job_expiration_ttl(struct jobmgr_data_t *q) {
    int64_t fsize;
    if(!q)
        return EINVAL;

    /* Handle blocks replication and file delete jobs using sx_hashfs_job_file_timeout() */
    if(q->job_type == JOBTYPE_REPLICATE_BLOCKS) {
	sx_hashfs_tmpinfo_t *tmpinfo;
        int64_t tmpfile_id;
        rc_ty s;

        if(!q->job_data || !q->job_data->ptr || q->job_data->len != sizeof(tmpfile_id))
            return FAIL_EINTERNAL;

        memcpy(&tmpfile_id, q->job_data->ptr, q->job_data->len);

        /* JOBTYPE_REPLICATE_BLOCKS contains tempfile ID as job data. Use it to get tempfile entry. */
        if((s = sx_hashfs_tmp_getinfo(q->hashfs, tmpfile_id, &tmpinfo, 0)) != OK)
            return s;
	fsize = tmpinfo->file_size;
        free(tmpinfo);
    } else if(q->job_type == JOBTYPE_DELETE_FILE) {
	sx_hashfs_file_t revinfo;
        rc_ty s;
        char rev[REV_LEN+1];

        if(!q->job_data || !q->job_data->ptr || q->job_data->len != REV_LEN)
            return FAIL_EINTERNAL;

        /* Need to nul terminate string */
        memcpy(rev, q->job_data->ptr, REV_LEN);
        rev[REV_LEN] = '\0';
        /* JOBTYPE_DELETE_FILE contains revision as job data. Use it to get tempfile entry. */
        if((s = sx_hashfs_getinfo_by_revision(q->hashfs, rev, &revinfo)) != OK) {
            /* File could be deleted already, set size to 0 but do not fail and let job manager to finish */
            if(s == ENOENT)
                fsize = 0;
            else
                return s;
        }
	fsize = revinfo.file_size;
    }

    if(q->job_type == JOBTYPE_REPLICATE_BLOCKS || q->job_type == JOBTYPE_DELETE_FILE) {
        q->adjust_ttl = sx_hashfs_job_file_timeout(q->hashfs, sx_nodelist_count(q->targets), fsize);
        return OK;
    }

    if(q->job_type == JOBTYPE_JLOCK || q->job_type == JOBTYPE_DISTRIBUTION)
        q->adjust_ttl = JOB_NO_EXPIRY;

    /* Default timeout, common for all jobs besides the two above */
    q->adjust_ttl = JOBMGR_UNDO_TIMEOUT * sx_nodelist_count(q->targets);
    if(!q->adjust_ttl) /* in case sx_nodelist_count() returns 0 */
        q->adjust_ttl = JOBMGR_UNDO_TIMEOUT;

    return OK;
}

static void jobmgr_run_job(struct jobmgr_data_t *q) {
    int r;

    /* Reload distribution */
    check_distribution(q->hashfs);
    if(q->job_expired && !q->job_failed) {
	/* FIXME: we could keep a trace of the reason of the last delay
	 * which is stored in db in case of tempfail.
	 * Of limited use but maybe nice to have */
	if(set_job_failed(q, 500, "Cluster timeout"))
	    return;
	q->job_failed = 1;
        /* Bump expiration time for abort/undo actions */
        if(get_failed_job_expiration_ttl(q) != OK) {
            WARN("Failed to determine expiration time for failed job %lld", (long long)q->job_id);
            q->adjust_ttl = JOBMGR_UNDO_TIMEOUT;
        }
        DEBUG("Job %lld is now expired, bumping expiration time with %d seconds", (long long)q->job_id, q->adjust_ttl);
        q->job_expired = 0;

        if(adjust_job_ttl(q) != OK)
            WARN("Cannot adjust lifetime of expired job %lld", (long long)q->job_id);
    }

    while(!terminate) {
	act_result_t act_res;
	int http_status;

	/* Collect a batch of actions but just for the current phase */
	sx_nodelist_empty(q->targets);
	r = jobmgr_get_actions_batch(q);
	if(r > 0) /* Job complete */
	    break;
	if(r < 0) { /* Error getting actions */
	    WARN("Failed to collect actions for job %lld", (long long)q->job_id);
	    break;
	}

	/* Execute actions */
	q->adjust_ttl = 0;
	act_res = jobmgr_execute_actions_batch(&http_status, q);

        if(adjust_job_ttl(q) != OK)
            WARN("Cannot adjust lifetime of job %lld", (long long)q->job_id);

	/* Temporary failure: mark job as to-be-retried and stop processing it for now */
	if(act_res == ACT_RESULT_TEMPFAIL) {
	    const char *delay;
	    if(q->nodelay_reschedule)
		delay = "0 seconds";
	    else if(q->job_type == JOBTYPE_FLUSH_FILE_REMOTE ||
		    q->job_type == JOBTYPE_FLUSH_FILE_LOCAL ||
		    q->job_type == JOBTYPE_REPLICATE_BLOCKS)
		delay = STRIFY(JOBMGR_DELAY_MIN) " seconds";
	    else
		delay = STRIFY(JOBMGR_DELAY_MAX) " seconds";

	    if(qbind_int64(q->qdly, ":job", q->job_id) ||
	       qbind_text(q->qdly, ":reason", q->fail_reason[0] ? q->fail_reason : "Unknown delay reason") ||
	       qbind_text(q->qdly, ":delay", delay) ||
	       qstep_noret(q->qdly))
		CRIT("Cannot reschedule job %lld (you are gonna see this again!)", (long long)q->job_id);
	    else
		DEBUG("Job %lld will be retried later", (long long)q->job_id);
	    break;
	}

	/* Permanent failure: mark job as failed and go on (with cleanup actions) */
	if(act_res == ACT_RESULT_PERMFAIL) {
	    const char *fail_reason = q->fail_reason[0] ? q->fail_reason : "Unknown failure";
            if (!http_status)
                WARN("Job failed but didn't set fail code, missing action_set_fail/action_error call?");
	    if(set_job_failed(q, http_status, fail_reason))
		break;
	    DEBUG("Job %lld failed: %s", (long long)q->job_id, fail_reason);
	    q->job_failed = 1;
	}

	/* Success: go on with the next batch */
    }

    sx_nodelist_empty(q->targets); /* Explicit free, just in case */
}

static uint16_t to_u16(const uint8_t *ptr) {
    return ((uint16_t)ptr[0] << 8) | ptr[1];
}

#define DNS_QUESTION_SECT 0
#define DNS_ANSWER_SECT 1
#define DNS_SERVERS_SECT 2
#define DNS_EXTRA_SECT 3
#define DNS_MAX_SECTS 4


static void check_version(struct jobmgr_data_t *q) {
    char buf[1024], resbuf[1024], *p1, *p2;
    uint16_t rrcount[DNS_MAX_SECTS];
    const uint8_t *rd, *eom;
    time_t now = time(NULL);
    int i, vmaj, vmin, newver, secflag, len;

    if(q->next_vcheck > now)
	return;
    q->next_vcheck += 24 * 60 * 60 + (sxi_rand() % (60 * 60)) - 30 * 60;
    if(q->next_vcheck <= now)
	q->next_vcheck = now + 24 * 60 * 60 + (sxi_rand() % (60 * 60)) - 30 * 60;
    if(qbind_int(q->qvbump, ":next", q->next_vcheck) ||
       qstep_noret(q->qvbump))
	WARN("Cannot update check time");

    if(res_init()) {
	WARN("Failed to initialize resolver");
	return;
    }

    snprintf(buf, sizeof(buf), "%lld.%s.sxver.skylable.com", (long long)q->job_id, sx_hashfs_self_unique(q->hashfs));
    len = res_query(buf, C_IN, T_TXT, resbuf, sizeof(resbuf));
    if(len < 0) {
	WARN("Failed to check version: query failed");
	return;
    }

    rd = resbuf;
    eom = resbuf + len;
    do {
	if(len < sizeof(uint16_t) + sizeof(uint16_t) + DNS_MAX_SECTS * sizeof(uint16_t))
	    break;
	rd += sizeof(uint16_t) + sizeof(uint16_t); /* id + flags */
	for(i=0; i<DNS_MAX_SECTS; i++) {
	    rrcount[i] = to_u16(rd);
	    rd += 2;
	}
	if(rrcount[DNS_QUESTION_SECT] != 1 || rrcount[DNS_ANSWER_SECT] != 1)
	    break;
	/* At question section: name + type + class */
	i = dn_skipname(rd, eom);
	if(i < 0 || rd + i + sizeof(uint16_t) + sizeof(uint16_t) > eom)
	    break;
	rd += i + sizeof(uint16_t) + sizeof(uint16_t);
	/* At answer section: name + type + class + ttl + rdlen (+rdata) */
	i = dn_skipname(rd, eom);
	if(i < 0 || rd + i + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t) > eom)
	    break;
	rd += i;
	if(to_u16(rd) != T_TXT || to_u16(rd+2) != C_IN)
	    break;
	rd += sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t);
	len = to_u16(rd);
	rd += sizeof(uint16_t);
	if(len < 1 || rd + len > eom)
	    break;
	/* At rdata of the first record of the answer section: string_lenght + string */
	if(*rd != len - 1)
	    break;
	rd++;
	len = MIN(len, sizeof(buf)) - 1;
	memcpy(buf, rd, len);
	buf[len] = '\0';
	eom = NULL;
    } while(0);
    if(eom) {
	WARN("Failed to check version: bad DNS reply");
	return;
    }

    vmaj = strtol(buf, &p1, 10);
    if(p1 == buf || *p1 != '.') {
	WARN("Failed to check version: bad version received");
	return;
    }
    p1++;
    vmin = strtol(p1, &p2, 10);
    if(p2 == p1 || *p2 != '.') {
	WARN("Failed to check version: bad version received");
	return;
    }
    p2++;
    secflag = strtol(p2, &p1, 10);
    if(p2 == p1 || (*p1 != '.' && *p1 != '\0')) {
	WARN("Failed to check version: bad version received");
	return;
    }

    if(vmaj > SRC_MAJOR_VERSION)
	newver = 2;
    else if(vmaj == SRC_MAJOR_VERSION && vmin > SRC_MINOR_VERSION) {
	if(secflag || vmin > SRC_MINOR_VERSION + 1)
	    newver = 2;
	else
	    newver = 1;
    } else
	newver=0;

    if(newver) {
	if(newver > 1) {
	    CRIT("CRITICAL update found! Skylable SX %d.%d is available (this node is running version %d.%d)", vmaj, vmin, SRC_MAJOR_VERSION, SRC_MINOR_VERSION);
	    CRIT("See http://www.skylable.com/products/sx/release/%d.%d for upgrade instructions", vmaj, vmin);
	} else {
	    INFO("Skylable SX %d.%d is available (this node is running version %d.%d)", vmaj, vmin, SRC_MAJOR_VERSION, SRC_MINOR_VERSION);
	    INFO("See http://www.skylable.com/products/sx/release/%d.%d for more info", vmaj, vmin);
	}
    }

}

static void jobmgr_process_queue(struct jobmgr_data_t *q, int forced) {
    while(!terminate) {
	const void *ptr;
	unsigned int plen;
	int r;

	if(qbind_int64(q->qjob, ":prevuser", q->user) ||
	   qbind_int(q->qjob, ":prevtype", q->job_type)) {
	    WARN("Failed to bind qjob params");
	    break;
	}
	r = qstep(q->qjob);
	if(r == SQLITE_DONE && forced) {
	    unsigned int waitus = 200000;
	    do {
		usleep(waitus);
		waitus *= 2;
		r = qstep(q->qjob);
	    } while(r == SQLITE_DONE && waitus <= 800000);
	    if(r == SQLITE_DONE)
		DEBUG("Triggered run without jobs");
	}
        forced = 0;
	if(r == SQLITE_DONE) {
	    DEBUG("No more pending jobs");
	    break; /* Stop processing jobs */
	}
	if(r != SQLITE_ROW) {
	    WARN("Failed to retrieve the next job to execute");
	    break; /* Stop processing jobs */
	}

	q->job_id = sqlite3_column_int64(q->qjob, 0);
	q->job_type = sqlite3_column_int(q->qjob, 1);
	ptr = sqlite3_column_blob(q->qjob, 2);
	plen = sqlite3_column_bytes(q->qjob, 2);
	q->job_expired = sqlite3_column_int(q->qjob, 3);
	q->job_failed = (sqlite3_column_int(q->qjob, 4) != 0);
	q->user = sqlite3_column_int64(q->qjob, 6);
	q->job_data = make_jobdata(ptr, plen, sqlite3_column_int(q->qjob, 5), q->user);
	sqlite3_reset(q->qjob);
        current_job_status = 0;

	if(!q->job_data) {
	    WARN("Job %lld has got invalid data", (long long)q->job_id);
	    continue; /* Process next job */
	}

        DEBUG("Running job %lld (type %d, %s, %s)", (long long)q->job_id, q->job_type, q->job_expired?"expired":"not expired", q->job_failed?"failed":"not failed");
	jobmgr_run_job(q);
	free(q->job_data);
	DEBUG("Finished running job %lld", (long long)q->job_id);
	/* Process next job */
    }

    if(!terminate)
	check_version(q);
}


int jobmgr(sxc_client_t *sx, const char *dir, int pipe) {
    sqlite3_stmt *q_vcheck = NULL;
    struct jobmgr_data_t q;
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGPIPE, SIG_IGN);

    act.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGHUP, &act, NULL);

    memset(&q, 0, sizeof(q));
    q.hashfs = sx_hashfs_open(dir, sx);
    if(!q.hashfs) {
	CRIT("Failed to initialize the hash server interface");
	goto jobmgr_err;
    }

    q.targets = sx_nodelist_new();
    if(!q.targets) {
	WARN("Cannot create target nodelist");
	goto jobmgr_err;
    }

    q.eventdb = sx_hashfs_eventdb(q.hashfs);

    if(qprep(q.eventdb, &q.qjob, "SELECT job, type, data, expiry_time < datetime('now'), result, strftime('%s',expiry_time), user FROM jobs WHERE complete = 0 AND sched_time <= strftime('%Y-%m-%d %H:%M:%f') AND NOT EXISTS (SELECT 1 FROM jobs AS subjobs WHERE subjobs.job = jobs.parent AND subjobs.complete = 0) ORDER BY CASE WHEN user > :prevuser THEN 0 ELSE 1 END, user, CASE WHEN type > :prevtype THEN 0 ELSE 1 END, type, sched_time LIMIT 1") ||
       qprep(q.eventdb, &q.qact, "SELECT id, phase, target, addr, internaladdr, capacity FROM actions WHERE job_id = :job AND phase < :maxphase ORDER BY phase") ||
       qprep(q.eventdb, &q.qfail_children, "WITH RECURSIVE descendents_of(jb) AS (SELECT job FROM jobs WHERE parent = :job UNION SELECT job FROM jobs, descendents_of WHERE jobs.parent = descendents_of.jb) UPDATE jobs SET result = :res, reason = :reason, complete = 1, lock = NULL WHERE job IN (SELECT * FROM descendents_of) AND result = 0") ||
       qprep(q.eventdb, &q.qfail_parent, "UPDATE jobs SET result = :res, reason = :reason WHERE job = :job AND result = 0") ||
       qprep(q.eventdb, &q.qcpl, "UPDATE jobs SET complete = 1, lock = NULL WHERE job = :job") ||
       qprep(q.eventdb, &q.qphs, "UPDATE actions SET phase = :phase WHERE id = :act") ||
       qprep(q.eventdb, &q.qdly, "UPDATE jobs SET sched_time = strftime('%Y-%m-%d %H:%M:%f', 'now', :delay), reason = :reason WHERE job = :job") ||
       qprep(q.eventdb, &q.qlfe, "WITH RECURSIVE descendents_of(jb) AS (VALUES(:job) UNION SELECT job FROM jobs, descendents_of WHERE jobs.parent = descendents_of.jb) UPDATE jobs SET expiry_time = datetime(expiry_time, :ttldiff)  WHERE job IN (SELECT * FROM descendents_of)") ||
       qprep(q.eventdb, &q.qvbump, "INSERT OR REPLACE INTO hashfs (key, value) VALUES ('next_version_check', datetime(:next, 'unixepoch'))") ||
       qprep(q.eventdb, &q_vcheck, "SELECT strftime('%s', value) FROM hashfs WHERE key = 'next_version_check'"))
	goto jobmgr_err;

    if(qstep(q_vcheck) == SQLITE_ROW)
	q.next_vcheck = sqlite3_column_int(q_vcheck, 0);
    else
	q.next_vcheck = time(NULL);
    qnullify(q_vcheck);

    while(!terminate) {
	int forced_awake = 0;

        if (wait_trigger(pipe, JOBMGR_DELAY_MIN, &forced_awake))
            break;
        msg_new_id();
	DEBUG("Start processing job queue");
	jobmgr_process_queue(&q, forced_awake);
	DEBUG("Done processing job queue");
        sx_hashfs_checkpoint_eventdb(q.hashfs);
        checkpoint_volume_sizes(q.hashfs);
    }

 jobmgr_err:
    sqlite3_finalize(q.qjob);
    sqlite3_finalize(q.qact);
    sqlite3_finalize(q.qfail_children);
    sqlite3_finalize(q.qfail_parent);
    sqlite3_finalize(q.qcpl);
    sqlite3_finalize(q.qphs);
    sqlite3_finalize(q.qdly);
    sqlite3_finalize(q.qlfe);
    sqlite3_finalize(q.qvbump);
    sqlite3_finalize(q_vcheck);
    sx_nodelist_delete(q.targets);
    sx_hashfs_close(q.hashfs);
    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}
