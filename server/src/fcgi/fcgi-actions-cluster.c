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
#include <string.h>

#include "fcgi-utils.h"
#include "fcgi-actions-cluster.h"

#include "libsxclient/src/jparse.h"

static void send_distribution(sx_hashfs_nl_t which) {
    const sx_nodelist_t *nodes = sx_hashfs_all_nodes(hashfs, which);
    unsigned int i, n = sx_nodelist_count(nodes);
    const char *zonedef;

    if(!nodes)
	return;

    CGI_PUTC('[');
    for(i = 0; i < n; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);
	const sx_uuid_t *uuid = sx_node_uuid(node);
	const char *addr = sx_node_addr(node);
	const char *int_addr = sx_node_internal_addr(node);

	if(i)
	    CGI_PUTC(',');
	CGI_PRINTF("{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",", uuid->string, addr);
	if(strcmp(addr, int_addr))
	    CGI_PRINTF("\"nodeInternalAddress\":\"%s\",", int_addr);
	CGI_PUTS("\"nodeCapacity\":");
	CGI_PUTLL(sx_node_capacity(node));
	if(sx_hashfs_is_node_ignored(hashfs, uuid))
	    CGI_PUTS(",\"nodeFlags\":\"i\"");
	CGI_PUTC('}');
    }
    if(i && (zonedef = sx_hashfs_zonedef(hashfs, which))) {
	CGI_PUTS(", ");
	json_send_qstring(zonedef);
    }
    CGI_PUTC(']');
}

void fcgi_handle_cluster_requests(void) {
    int comma = 0;
    rc_ty s;

    if(has_arg("clusterStatus") && !has_priv(PRIV_ADMIN))
	quit_errnum(403);

    /* Allow caching of rarely changing hdist-based items but force
     * revalidation so we authenticate and authorize the request again */
    if(has_arg("nodeList") + has_arg("nodeMaps") + has_arg("clusterMeta") == nargs) {
	time_t lastmod = 0;
	const char *ifmod;

        if(has_arg("nodeList") || has_arg("nodeMaps"))
            lastmod = sx_hashfs_disttime(hashfs);
        if(has_arg("clusterMeta")) {
            time_t last_meta_mod;
            if(sx_hashfs_clustermeta_last_change(hashfs, &last_meta_mod))
                quit_errnum(500);
            lastmod = MAX(lastmod, last_meta_mod);
        }
	CGI_PUTS("Last-Modified: ");
	send_httpdate(lastmod);
	CGI_PUTS("\r\nCache-control: public, must-revalidate\r\n");
	if((ifmod = FCGX_GetParam("HTTP_IF_MODIFIED_SINCE", envp))) {
	    time_t modsince;
	    if(!httpdate_to_time_t(ifmod, &modsince) && lastmod <= modsince) {
		CGI_PUTS("Status: 304\r\n\r\n");
		    return;
	    }
	}
    }

    CGI_PUTS("Content-type: application/json\r\n\r\n{");

    if(has_arg("clusterStatus")) {
	sx_inprogress_t status;
	const char *progress_msg;
        unsigned int islocked = 0, maxr, effmaxr;

	status = sx_hashfs_get_progress_info(hashfs, &progress_msg);
	if(status == INPRG_ERROR)
	    quit_errmsg(500, msg_get_reason());

        if(has_arg("operatingMode")) {
            char lockid[AUTH_UID_LEN*2+32];
            s = sx_hashfs_distlock_get(hashfs, lockid, sizeof(lockid));
            if(s != OK && s != ENOENT)
                quit_errmsg(500, msg_get_reason());
            if(s == ENOENT)
                islocked = 0;
            else
                islocked = 1;
        }

	CGI_PUTS("\"clusterStatus\":{\"distributionModels\":[");

	if(!sx_storage_is_bare(hashfs)) {
	    const sx_uuid_t *dist_uuid;
	    unsigned int version;
	    uint64_t checksum;

	    send_distribution(NL_PREV);
	    if(sx_hashfs_is_rebalancing(hashfs)) {
		CGI_PUTC(',');
		send_distribution(NL_NEXT);
	    }

	    dist_uuid = sx_hashfs_distinfo(hashfs, &version, &checksum);
	    CGI_PRINTF("],\"distributionUUID\":\"%s\",\"distributionVersion\":%u,\"distributionChecksum\":", dist_uuid->string, version);
	    CGI_PUTLL(checksum);

	    if(status != INPRG_IDLE) {
		const char *op, *complete;
		if(status == INPRG_REBALANCE_RUNNING) {
		    op = "rebalance";
		    complete = "false";
		} else if(status == INPRG_REBALANCE_COMPLETE) {
		    op = "rebalance";
		    complete = "true";
		} else if(status == INPRG_REPLACE_RUNNING) {
		    op = "replace";
		    complete = "false";
		} else if(status == INPRG_REPLACE_COMPLETE) {
		    op = "replace";
		    complete = "true";
		} else if(status == INPRG_UPGRADE_RUNNING) {
                    op = "upgrade";
                    complete = "false";
		} else if(status == INPRG_UPGRADE_COMPLETE) {
                    op = "upgrade";
                    complete = "true";
                } else if(status == INPRG_VOLREP_RUNNING) {
                    op = "volume replica change";
                    complete = "false";
                } else if(status == INPRG_VOLREP_COMPLETE) {
                    op = "volume replica change";
                    complete = "true";
                } else {
                    op = "error";
                    complete = "false";
                }
		CGI_PRINTF(",\"opInProgress\":{\"opType\":\"%s\",\"isComplete\":%s,\"opInfo\":", op, complete);
		json_send_qstring(progress_msg);
		CGI_PUTC('}');
	    }
	    CGI_PRINTF(",\"clusterAuth\":\"%s\"", sx_hashfs_authtoken(hashfs));
            if(has_arg("operatingMode"))
                CGI_PRINTF(",\"operatingMode\":\"%s\",\"locked\":%s", sx_hashfs_is_readonly(hashfs) ? "read-only" : "read-write", islocked ? "true" : "false");
	} else
	    CGI_PUTC(']');

	sx_hashfs_getmaxreplica(hashfs, &maxr, &effmaxr);
	CGI_PRINTF(",\"maxReplicaCount\":%u,\"effectiveMaxReplicaCount\":%u}", maxr, effmaxr);
	comma |= 1;
    }

    if(has_arg("volumeList")) {
	const sx_hashfs_volume_t *vol;
        char owner[SXLIMIT_MAX_USERNAME_LEN+1];
	struct {
	    char key[SXLIMIT_META_MAX_KEY_LEN+1];
	    char hexval[SXLIMIT_META_MAX_VALUE_LEN * 2 + 1];
	    int custom;
	} *meta = NULL;

        if(comma) {
            CGI_PUTC(',');
            comma = 0;
        }
	CGI_PUTS("\"volumeList\":{");
        uint8_t *u = has_priv(PRIV_ADMIN) ? NULL : user;/* user = NULL: list all volumes */
	for(s = sx_hashfs_volume_first(hashfs, &vol, u); s == OK; s = sx_hashfs_volume_next(hashfs)) {
            sx_priv_t priv = 0;
            unsigned int i, nmeta = 0;
            char volid_hex[SXI_SHA1_TEXT_LEN+1];

	    if(comma)
		CGI_PUTC(',');
	    else
		comma |= 1;

	    json_send_qstring(vol->name);
            if((s = sx_hashfs_get_access(hashfs, user, vol->name, &priv)) != OK) {
                CGI_PUTS("}");
		free(meta);
                quit_itererr("Failed to get volume privs", s);
            }

            if((s = sx_hashfs_uid_get_name(hashfs, vol->owner, owner, sizeof(owner))) != OK) {
                CGI_PUTS("}");
		free(meta);
                quit_itererr("Failed to get volume owner name", s);
            }

            if(has_priv(PRIV_ADMIN))
                priv = PRIV_READ | PRIV_WRITE;

            CGI_PUTS(":{\"owner\":");
            json_send_qstring(owner);
            CGI_PRINTF(",\"replicaCount\":%u,\"effectiveReplicaCount\":%u,\"maxRevisions\":%u,\"privs\":\"%c%c\",\"usedSize\":",
                       vol->max_replica, vol->effective_replica, vol->revisions, (priv & PRIV_READ) ? 'r' : '-', (priv & PRIV_WRITE) ? 'w' : '-');
            /*
             * usedSize:         size of the files stored in the volume including file names size and metadata size,
             * filesSize:        size of the files stored in the volume (excluding file names and metadata),
             * filesCount:       number of files stored in the volume (notice: all revisions are included!),
             * sizeBytes:        the volume size
             */
	    CGI_PUTLL(vol->usage_total);
            CGI_PRINTF(",\"sizeBytes\":");
            CGI_PUTLL(vol->size);
            CGI_PRINTF(",\"filesSize\":");
            CGI_PUTLL(vol->usage_files);
            CGI_PRINTF(",\"filesCount\":");
            CGI_PUTLL(vol->nfiles);
            bin2hex(vol->global_id.b, sizeof(vol->global_id.b), volid_hex, sizeof(volid_hex));
            CGI_PRINTF(",\"globalID\":\"%s\"", volid_hex);
            if(has_arg("volumeMeta") || has_arg("customVolumeMeta")) {
                const char *metakey;
                const void *metavalue;
                unsigned int metasize;

                if((s = sx_hashfs_volumemeta_begin(hashfs, vol)) != OK) {
                    CGI_PUTS("}}");
		    free(meta);
                    quit_itererr("Cannot lookup volume metadata", s);
                }
		if(!meta)
		    meta = wrap_malloc(sizeof(*meta) * SXLIMIT_META_MAX_ITEMS);
		if(!meta) {
                    CGI_PUTS("}}");
                    quit_itererr("Out of memory looking up volume metadata", ENOMEM);
		}
		for(nmeta=0; (s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK && nmeta < SXLIMIT_META_MAX_ITEMS; nmeta++) {
		    if(strncmp(SX_CUSTOM_META_PREFIX, metakey, lenof(SX_CUSTOM_META_PREFIX))) {
			sxi_strlcpy(meta[nmeta].key, metakey, sizeof(meta[0].key));
			meta[nmeta].custom = 0;
		    } else {
			sxi_strlcpy(meta[nmeta].key, metakey + lenof(SX_CUSTOM_META_PREFIX), sizeof(meta[0].key));
			meta[nmeta].custom = 1;
		    }
		    if(bin2hex(metavalue, metasize, meta[nmeta].hexval, sizeof(meta[0].hexval)))
			break;
		}

		if(s != ITER_NO_MORE) {
		    free(meta);
                    CGI_PUTS("}}");
                    quit_itererr("Internal error enumerating volume metadata", FAIL_EINTERNAL);
		}
            }

            if(has_arg("volumeMeta")) {
		int comma2 = 0;
                CGI_PUTS(",\"volumeMeta\":{");
                for(i = 0; i < nmeta; i++) {
		    if(meta[i].custom)
			continue;
                    if(comma2)
                        CGI_PUTC(',');
                    json_send_qstring(meta[i].key);
                    CGI_PRINTF(":\"%s\"", meta[i].hexval);
		    comma2 |= 1;
                }
                CGI_PUTC('}');
            }
            if(has_arg("customVolumeMeta")) {
		int comma2 = 0;
                CGI_PUTS(",\"customVolumeMeta\":{");
                for(i = 0; i < nmeta; i++) {
		    if(!meta[i].custom)
			continue;
                    if(comma2)
                        CGI_PUTC(',');
                    json_send_qstring(meta[i].key);
                    CGI_PRINTF(":\"%s\"", meta[i].hexval);
		    comma2 |= 1;
                }
                CGI_PUTC('}');
            }
	    CGI_PUTS("}");
	}

	free(meta);

	CGI_PUTS("}");
	if(s != ITER_NO_MORE) {
            /* send valid json with 'ErrorMessage' top-level field */
            quit_itererr("Failed to list volume", s);
        }
	comma |= 1;
    }
    if(has_arg("nodeList")) {
	const sx_nodelist_t *nodes = sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV);

	if(comma) CGI_PUTC(',');
	CGI_PUTS("\"nodeList\":");

	if(!nodes) {
            CGI_PUTS("{}");
            quit_itererr("Failed to list nodes", EFAULT);
        }
	send_nodes_randomised(nodes);
	comma |= 1;
    }
    if(has_arg("nodeMaps")) {
	const sx_nodelist_t *nodes = sx_hashfs_all_nodes(hashfs, NL_NEXTPREV);
	unsigned int nnode, nnodes = sx_nodelist_count(nodes);

	if(comma) CGI_PUTC(',');
	CGI_PUTS("\"nodeMaps\":{");

	/* We only have a single map for now */
	for(nnode=0; nnode<nnodes; nnode++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	    if(strcmp(sx_node_addr(node), sx_node_internal_addr(node)))
		break;
	}
	if(nnode < nnodes) {
	    CGI_PUTS("\"InternalNetwork\":{");
	    nnode=0;
	    while(nnode<nnodes) {
		const sx_node_t *node = sx_nodelist_get(nodes, nnode);
		json_send_qstring(sx_node_addr(node));
		CGI_PUTC(':');
		json_send_qstring(sx_node_internal_addr(node));
		nnode++;
		if(nnode != nnodes)
		    CGI_PUTC(',');
	    }
	    CGI_PUTC('}'); /* "InternalNetwork" ends */
	}
	CGI_PUTC('}'); /* "nodeMaps" ends */
	comma |= 1;
    }

    if(has_arg("clusterMeta")) {
        const char *metakey;
        const void *metavalue;
        unsigned int metasize, comma_meta = 0;

        if(comma)
            CGI_PUTC(',');
        CGI_PUTS("\"clusterMeta\":{");
        if((s = sx_hashfs_clustermeta_begin(hashfs)) != OK) {
            CGI_PUTC('}');
            quit_itererr("Cannot load cluster metadata", s);
        }
        while((s = sx_hashfs_clustermeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK) {
            char hexval[SXLIMIT_META_MAX_VALUE_LEN*2+1];
            if(comma_meta)
                CGI_PUTC(',');
            else
                comma_meta |= 1;
            json_send_qstring(metakey);
            CGI_PUTS(":\"");
            bin2hex(metavalue, metasize, hexval, sizeof(hexval));
            CGI_PUTS(hexval);
            CGI_PUTC('"');
        }
        CGI_PUTC('}');
        if(s != ITER_NO_MORE)
            quit_itererr("Failed list cluster meta", s);
        comma |= 1;
    }

    if(has_arg("raftStatus")) {
        sx_raft_state_t state;
        struct timeval now;
        uint64_t hb_warntime;

        gettimeofday(&now, NULL);
        if(comma)
            CGI_PUTC(',');

        if(sx_hashfs_cluster_settings_get_uint64(hashfs, "hb_warntime", &hb_warntime))
            quit_itererr("Failed to obtain hb_warntime setting", 500);
        if(sx_hashfs_raft_state_begin(hashfs))
            quit_itererr("Failed to get raft state", 500);
        if(sx_hashfs_raft_state_get(hashfs, &state)) {
            sx_hashfs_raft_state_abort(hashfs);
            quit_itererr("Failed to get raft state", 500);
        }

        CGI_PRINTF("\"raftStatus\":{\"role\":\"%s\",\"leader\":\"%s\"", state.role == RAFT_ROLE_FOLLOWER ? "follower" : (state.role == RAFT_ROLE_CANDIDATE ? "candidate" : "leader"),
            state.current_term.has_leader && !sx_hashfs_is_node_ignored(hashfs, &state.current_term.leader) ? state.current_term.leader.string : "<nobody>");
        if(state.role == RAFT_ROLE_LEADER) {
            unsigned int i;

            CGI_PRINTF(",\"nodeStates\":{");
            for(i = 0; i < state.leader_state.nnodes && sx_nodelist_count(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV)) >= 3; i++) {
                double timediff = sxi_timediff(&now, &state.leader_state.node_states[i].last_contact);
                if(i)
                    CGI_PUTC(',');
                CGI_PRINTF("\"%s\":{\"state\":\"", state.leader_state.node_states[i].node.string);
                if(!state.leader_state.node_states[i].hbeat_success && timediff > hb_warntime)
                    CGI_PUTS("dead");
                else
                    CGI_PUTS("alive");
                CGI_PUTS("\",\"lastContact\":");
                CGI_PUTLL((long long)timediff);
                CGI_PUTC('}');
            }
            CGI_PUTC('}');
            if(*state.leader_state.msg) {
                CGI_PUTS(",\"message\":");
                json_send_qstring(state.leader_state.msg);
            }
        }
        CGI_PUTC('}');
        sx_hashfs_raft_state_abort(hashfs);
        sx_hashfs_raft_state_empty(hashfs, &state);
        comma |= 1;
    }
    /* MOAR COMMANDS HERE */

    CGI_PUTC('}');
}


void fcgi_challenge_response(void) {
    sx_hash_challenge_t c;

    if(!sx_storage_is_bare(hashfs))
	quit_errmsg(403, "This node is active");
    if(strlen(path) != sizeof(c.challenge) * 2)
	quit_errnum(404);
    if(hex2bin(path, sizeof(c.challenge) * 2, c.challenge, sizeof(c.challenge)))
	quit_errnum(404);
    if(sx_hashfs_challenge_gen(hashfs, &c, 0))
	quit_errnum(400);

    /* Forbid caching just in case we decide to clear globals here */
    CGI_PRINTF("Pragma: no-cache\r\nCache-control: no-cache\r\nContent-type: application/octet-stream\r\nContent-Length: %lu\r\n\r\n", sizeof(c.response));
    CGI_PUTD(c.response, sizeof(c.response));
}


/* JSON scheme: {"clusterMeta":{"key1":"aabbcc","key2":"ccbbaa"},"timestamp":123123123} */
struct cluster_setmeta_ctx {
    time_t ts;
    time_t oldts;
    int has_timestamp;
    sx_blob_t *meta;
    unsigned int nmeta;
    sx_blob_t *oldmeta;
    unsigned int noldmeta;
};

static void cb_setmeta_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    uint8_t value[SXLIMIT_META_MAX_VALUE_LEN];
    struct cluster_setmeta_ctx *c = ctx;

    if(c->nmeta >= SXLIMIT_META_MAX_ITEMS) {
	sxi_jparse_cancel(J, "Too many cluster matadata items");
	return;
    }
    if(strlen(key) < SXLIMIT_META_MIN_KEY_LEN || strlen(key) > SXLIMIT_META_MAX_KEY_LEN) {
	sxi_jparse_cancel(J, "Invalid key %s", key);
	return;
    }
    if(hex2bin(string, length, value, sizeof(value))) {
	sxi_jparse_cancel(J, "Invalid metadata value for %s", key);
	return;
    }
    length /= 2;
    if(sx_hashfs_check_meta(key, value, length) ||
       sx_blob_add_string(c->meta, key) ||
       sx_blob_add_blob(c->meta, value, length)) {
	sxi_jparse_cancel(J, "Out of memory processing cluster metadata");
	return;
    }
    c->nmeta++;
}
static void cb_setmeta_ts(jparse_t *J, void *ctx, int64_t num) {
    struct cluster_setmeta_ctx *c = ctx;

    if(sx_hashfs_cluster_settings_last_change(hashfs, &c->oldts)) {
	sxi_jparse_cancel(J, "Internal error retrieving current settings age");
	return;
    }
    c->ts = num;
    c->has_timestamp = 1;
}

const struct jparse_actions setmeta_acts = {
    JPACTS_STRING(JPACT(cb_setmeta_meta, JPKEY("clusterMeta"), JPANYKEY)),
    JPACTS_INT64(JPACT(cb_setmeta_ts, JPKEY("timestamp")))
};

static rc_ty cluster_setmeta_parse_complete(void *yctx)
{
    struct cluster_setmeta_ctx *c = yctx;
    rc_ty s;
    const char *metakey = NULL;
    const void *metaval = NULL;
    unsigned int metaval_len = 0;

    if(!c)
        return EINVAL;

    /* Check if timestamp has been correctly syncronised between nodes */
    if(has_priv(PRIV_CLUSTER) && !c->has_timestamp) {
        msg_set_reason("Timestamp has not been set");
        return EINVAL;
    } else if(!has_priv(PRIV_CLUSTER)) {
        if(c->has_timestamp) {
            msg_set_reason("Timestamp can only be synced in s2s communication");
            return EINVAL;
        }
        c->ts = time(NULL);
    }

    /* Prepare a backup for old metadata */
    if(!has_priv(PRIV_CLUSTER)) {
        if((s = sx_hashfs_clustermeta_begin(hashfs)) != OK) {
            msg_set_reason("Failed to get cluster meta");
            return s;
        }

        while((s = sx_hashfs_clustermeta_next(hashfs, &metakey, &metaval, &metaval_len)) == OK) {
            if(sx_blob_add_string(c->oldmeta, metakey) || sx_blob_add_blob(c->oldmeta, metaval, metaval_len)) {
                msg_set_reason("Failed to get cluster meta");
                return FAIL_EINTERNAL;
            }
            c->noldmeta++;
        }

        if(s != ITER_NO_MORE) {
            msg_set_reason("Failed to get cluster meta");
            return s;
        }
    }

    return OK;
}

static int append_meta_to_blob(sxc_client_t *sx, unsigned int nmeta, sx_blob_t *metablob, sx_blob_t *b) {
    if(!sx || !metablob || !b) {
        WARN("Invalid argument");
        msg_set_reason("Invalid argument");
        return -1;
    }

    if(sx_blob_add_int32(b, nmeta)) {
        WARN("Failed to add meta entries count to job blob");
        msg_set_reason("Cannot create job blob");
        return -1;
    }

    if(nmeta && sx_blob_cat(b, metablob)) {
        WARN("Failed to cat meta blob to job blob");
        msg_set_reason("Cannot create job blob");
        return -1;
    }

    return 0;
}

static int cluster_setmeta_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct cluster_setmeta_ctx *c = yctx;

    if(!joblb || !c->meta || !c->oldmeta) {
        msg_set_reason("Invalid argument");
        return -1;
    }

    if(sx_blob_add_int64(joblb, c->oldts) || sx_blob_add_int64(joblb, c->ts)) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }

    /* Append old and new meta to job blob */
    if(append_meta_to_blob(sx, c->nmeta, c->meta, joblb) || append_meta_to_blob(sx, c->noldmeta, c->oldmeta, joblb))
        return -1;

    return 0;
}

static unsigned cluster_setmeta_timeout(sxc_client_t *sx, int nodes)
{
    return nodes > 1 ? 50 * (nodes - 1) : 20;
}

static sxi_query_t* cluster_setmeta_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    time_t ts = 0, oldts = 0;
    sxc_meta_t *meta = NULL;
    sxi_query_t *ret = NULL;

    if(sx_blob_get_int64(b, &oldts) || sx_blob_get_int64(b, &ts)) {
        WARN("Corrupt user blob");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(sx_hashfs_blob_to_sxc_meta(sx, b, &meta, phase != JOBPHASE_COMMIT)) {
        WARN("Failed to load new cluster meta from blob");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(phase != JOBPHASE_COMMIT) {
        /* Get old meta only when aborting */
        if(sx_hashfs_blob_to_sxc_meta(sx, b, &meta, 0)) {
            WARN("Failed to load old cluster meta from blob");
            goto cluster_setmeta_proto_from_blob_err;
        }
    }

    switch(phase) {
        case JOBPHASE_COMMIT:
            ret = sxi_cluster_setmeta_proto(sx, ts, meta);
            break;
        case JOBPHASE_ABORT:
        case JOBPHASE_UNDO:
            INFO("Aborting/Undoing cluster meta change");
            ret = sxi_cluster_setmeta_proto(sx, oldts, meta);
            break;
        default:
            WARN("Invalid job phase");
    }

cluster_setmeta_proto_from_blob_err:
    sxc_meta_free(meta);
    return ret;
}

static rc_ty cluster_setmeta_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    rc_ty ret = FAIL_EINTERNAL;
    time_t ts = 0, oldts = 0;
    int i, count;
    rc_ty s;

    if(sx_blob_get_int64(b, &oldts) || sx_blob_get_int64(b, &ts)) {
        WARN("Corrupt user blob");
        return FAIL_EINTERNAL;
    }

    if(remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    sx_hashfs_clustermeta_set_begin(h);
    if(sx_blob_get_int32(b, &count)) {
        WARN("Failed to get meta entries count from job blob");
        msg_set_reason("Cannot get meta from blob");
        return FAIL_EINTERNAL;
    }

    for(i = 0; i < count; i++) {
        const char *metakey = NULL;
        const void *metaval = NULL;
        unsigned int metaval_len = 0;

        if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &metaval_len)) {
            WARN("Failed to get %dth meta entry from blob", i);
            msg_set_reason("Cannot get meta from blob");
            return FAIL_EINTERNAL;
        }

        if(phase == JOBPHASE_COMMIT) {
            /* Add cluster meta only when in commit phase, otherwise skip it,
             * it just need to travel through the blob to the old meta */
            if((s = sx_hashfs_clustermeta_set_addmeta(h, metakey, metaval, metaval_len)) != OK)
                return s;
        }
    }

    if(phase != JOBPHASE_COMMIT) {
        /* Get old meta only when aborting */
        if(sx_blob_get_int32(b, &count)) {
            WARN("Failed to get old meta entries count from job blob");
            msg_set_reason("Cannot get old meta from blob");
            return -1;
        }
        for(i = 0; i < count; i++) {
            const char *metakey = NULL;
            const void *metaval = NULL;
            unsigned int metaval_len = 0;

            if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &metaval_len)) {
                WARN("Failed to get %dth old meta entry from blob", i);
                msg_set_reason("Cannot get old meta from blob");
                return FAIL_EINTERNAL;
            }

            if(!metakey || !metaval) {
                WARN("Invalid old meta entry");
                msg_set_reason("Cannot get old meta from blob");
                return FAIL_EINTERNAL;
            }

            if(sx_hashfs_clustermeta_set_addmeta(h, metakey, metaval, metaval_len)) {
                WARN("Failed to add old meta entry");
                msg_set_reason("Cannot get old meta from blob");
                return FAIL_EINTERNAL;
            }
        }
    }

    switch(phase) {
        case JOBPHASE_COMMIT:
            DEBUG("Cluster meta change request");
            ret = sx_hashfs_clustermeta_set_finish(h, ts, 1);
            break;
        case JOBPHASE_ABORT:
            INFO("Aborting cluster meta change");
            ret = sx_hashfs_clustermeta_set_finish(h, oldts, 1);
            break;
        case JOBPHASE_UNDO:
            CRIT("Cluster may have been left in an inconsistent state after a failed cluster meta modification");
            ret = sx_hashfs_clustermeta_set_finish(h, oldts, 1);
            break;
        default:
            WARN("Invalid job phase: %d", phase);
    }

    return ret;
}

static const char *cluster_setmeta_get_lock(sx_blob_t *b)
{
    return "CLUSTER_SETMETA";
}

static rc_ty cluster_setmeta_nodes(sx_hashfs_t *h, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if(!nodes)
        return FAIL_EINTERNAL;
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
    if(!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

const job_2pc_t cluster_setmeta_spec = {
    &setmeta_acts,
    JOBTYPE_CLUSTER_SETMETA,
    cluster_setmeta_parse_complete,
    cluster_setmeta_get_lock,
    cluster_setmeta_to_blob,
    cluster_setmeta_execute_blob,
    cluster_setmeta_proto_from_blob,
    cluster_setmeta_nodes,
    cluster_setmeta_timeout
};

void fcgi_cluster_setmeta(void) {
    struct cluster_setmeta_ctx c;
    sxc_client_t *sx = sx_hashfs_client(hashfs);

    memset(&c, 0, sizeof(c));

    c.meta = sx_blob_new();
    if(!c.meta)
        quit_errmsg(500, "Out of memory");

    c.oldmeta = sx_blob_new();
    if(!c.oldmeta) {
        sx_blob_free(c.meta);
        quit_errmsg(500, "Out of memory");
    }

    job_2pc_handle_request(sx, &cluster_setmeta_spec, &c);

    sx_blob_free(c.meta);
    sx_blob_free(c.oldmeta);
}

/* Sample body:
 * {"clusterSettings":{"key1":"aabbcc","key2":"ccbbaa"},"timestamp":123123123}
 */
struct cluster_settings_ctx {
    time_t ts;
    time_t oldts;
    int has_timestamp;
    sx_blob_t *entries;
    unsigned int nentries;
};

static void cb_cluster_settings_ts(jparse_t *J, void *ctx, int64_t num) {
    struct cluster_settings_ctx *c = ctx;
    c->ts = num;
    c->has_timestamp = 1;
}

static void cb_cluster_settings(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J))), *old_value;
    char value[SXLIMIT_SETTINGS_MAX_VALUE_LEN+1];
    struct cluster_settings_ctx *c = ctx;
    sx_setting_type_t key_type;
    rc_ty rc;

    if(c->nentries >= SXLIMIT_SETTINGS_MAX_ITEMS) {
	sxi_jparse_cancel(J, "Too many cluster settings");
	return;
    }
    if(strlen(key) < SXLIMIT_SETTINGS_MIN_KEY_LEN || strlen(key) > SXLIMIT_SETTINGS_MAX_KEY_LEN) {
	sxi_jparse_cancel(J, "Invalid key %s", key);
	return;
    }
    if(hex2bin(string, length, value, sizeof(value))) {
	sxi_jparse_cancel(J, "Invalid setting value for %s", key);
	return;
    }
    if((rc = sx_hashfs_cluster_settings_get(hashfs, key, &key_type, &old_value)) != OK) {
	sxi_jparse_cancel(J, "Invalid setting %s: %s", key, msg_get_reason());
	return;
    }
    if(hex2bin(string, length, (uint8_t*)value, sizeof(value))) {
	sxi_jparse_cancel(J, "Invalid setting value for %s", key);
	return;
    }
    length /= 2;
    value[length] = '\0';
    if(sx_blob_add_string(c->entries, key) ||
       sx_blob_add_int32(c->entries, key_type)) {
	sxi_jparse_cancel(J, "Out of memory processing cluster settings");
	return;
    }
    if(sx_hashfs_parse_cluster_setting(hashfs, key, key_type, value, c->entries) ||
       sx_hashfs_parse_cluster_setting(hashfs, key, key_type, old_value, c->entries)) {
        sxi_jparse_cancel(J, "%s", msg_get_reason());
        return;
    }
    c->nentries++;
}

const struct jparse_actions cluster_settings_acts = {
    JPACTS_STRING(JPACT(cb_cluster_settings, JPKEY("clusterSettings"), JPANYKEY)),
    JPACTS_INT64(JPACT(cb_cluster_settings_ts, JPKEY("timestamp")))
};

static rc_ty cluster_settings_parse_complete(void *yctx)
{
    struct cluster_settings_ctx *c = yctx;

    if(!c)
        return EINVAL;

    /* Check if timestamp has been correctly syncronised between nodes */
    if(has_priv(PRIV_CLUSTER) && !c->has_timestamp) {
        msg_set_reason("Timestamp has not been set");
        return EINVAL;
    } else if(!has_priv(PRIV_CLUSTER)) {
        if(c->has_timestamp) {
            msg_set_reason("Timestamp can only be synced in s2s communication");
            return EINVAL;
        }
        c->ts = time(NULL);
    }

    return OK;
}

static int cluster_settings_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct cluster_settings_ctx *c = yctx;

    if(!joblb || !c->entries) {
        msg_set_reason("Invalid argument");
        return -1;
    }

    if(sx_blob_add_int64(joblb, c->oldts) || sx_blob_add_int64(joblb, c->ts)) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }

    /* Append settings to blob */
    if(append_meta_to_blob(sx, c->nentries, c->entries, joblb))
        return -1;

    return 0;
}

static unsigned cluster_settings_timeout(sxc_client_t *sx, int nodes)
{
    return nodes > 1 ? 50 * (nodes - 1) : 20;
}

static int get_sxc_meta_from_settings_blob(sxc_client_t *sx, sx_blob_t *b, sxc_meta_t *meta, int new_settings) {
    int i, count;

    if(!sx || !b || !meta) {
        WARN("Invalid argument");
        msg_set_reason("Invalid argument");
        return -1;
    }

    if(sx_blob_get_int32(b, &count)) {
        WARN("Failed to get meta entries count from job blob");
        msg_set_reason("Cannot get meta from blob");
        return -1;
    }
    for(i = 0; i < count; i++) {
        const char *key = NULL;
        char new_value[SXLIMIT_SETTINGS_MAX_VALUE_LEN+1];
        char old_value[SXLIMIT_SETTINGS_MAX_VALUE_LEN+1];
        sx_setting_type_t type;

        if(sx_blob_get_string(b, &key) || sx_blob_get_int32(b, (int*)&type)) {
            WARN("Failed to get %dth settings entry from blob", i);
            msg_set_reason("Cannot get settings entry from blob");
            return -1;
        }

        switch(type) {
            case SX_SETTING_TYPE_INT: {
                int64_t new, old;
                if(sx_blob_get_int64(b, &new) || sx_blob_get_int64(b, &old)){
                    WARN("Failed to get integer settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                sprintf(new_value, "%lld", (long long)new);
                sprintf(old_value, "%lld", (long long)old);
                break;
            }
            case SX_SETTING_TYPE_UINT: {
                uint64_t new, old;
                if(sx_blob_get_uint64(b, &new) || sx_blob_get_uint64(b, &old)){
                    WARN("Failed to get unsinged integer settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                sprintf(new_value, "%llu", (unsigned long long)new);
                sprintf(old_value, "%llu", (unsigned long long)old);
                break;
            }
            case SX_SETTING_TYPE_BOOL: {
                int new, old;
                if(sx_blob_get_bool(b, &new) || sx_blob_get_bool(b, &old)){
                    WARN("Failed to get boolean settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                sprintf(new_value, "%d", new);
                sprintf(old_value, "%d", old);
                break;
            }
            case SX_SETTING_TYPE_FLOAT: {
                double new, old;
                if(sx_blob_get_float(b, &new) || sx_blob_get_float(b, &old)){
                    WARN("Failed to get double settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                sprintf(new_value, "%lf", new);
                sprintf(old_value, "%lf", old);
                break;
            }
            case SX_SETTING_TYPE_STRING: {
                const char *new, *old;
                if(sx_blob_get_string(b, &new) || sx_blob_get_string(b, &old)){
                    WARN("Failed to get string settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }
                sxi_strlcpy(new_value, new, sizeof(new_value));
                sxi_strlcpy(old_value, old, sizeof(old_value));
                break;
            }
        }

        if(sxc_meta_setval(meta, key, new_settings ? new_value : old_value, new_settings ? strlen(new_value) : strlen(old_value))) {
            WARN("Failed to add settings entry");
            msg_set_reason("Cannot get settings entry from blob");
            return -1;
        }
    }

    return 0;
}

static sxi_query_t* cluster_settings_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    time_t ts = 0, oldts = 0;
    sxc_meta_t *meta = NULL;
    sxi_query_t *ret = NULL;

    meta = sxc_meta_new(sx);
    if(!meta) {
        WARN("Failed to allocate new settings meta");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(sx_blob_get_int64(b, &oldts) || sx_blob_get_int64(b, &ts)) {
        WARN("Corrupt user blob");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(get_sxc_meta_from_settings_blob(sx, b, meta, phase == JOBPHASE_COMMIT)) {
        WARN("Failed to load cluster settings from blob");
        goto cluster_setmeta_proto_from_blob_err;
    }

    switch(phase) {
        case JOBPHASE_COMMIT:
            ret = sxi_cluster_settings_proto(sx, ts, meta);
            break;
        case JOBPHASE_ABORT:
        case JOBPHASE_UNDO:
            INFO("Aborting/Undoing cluster settings change");
            ret = sxi_cluster_settings_proto(sx, oldts, meta);
            break;
        default:
            WARN("Invalid job phase");
    }

cluster_setmeta_proto_from_blob_err:
    sxc_meta_free(meta);
    return ret;
}

static rc_ty cluster_settings_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    rc_ty ret = FAIL_EINTERNAL;
    time_t ts = 0, oldts = 0;
    int i, count;
    rc_ty s;

    if(sx_blob_get_int64(b, &oldts) || sx_blob_get_int64(b, &ts)) {
        WARN("Corrupt user blob");
        return FAIL_EINTERNAL;
    }

    if(remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    if(sx_hashfs_modify_cluster_settings_begin(h)) {
        msg_set_reason("Failed to modify cluster settings");
        return FAIL_LOCKED;
    }
    if(sx_blob_get_int32(b, &count)) {
        WARN("Failed to get meta entries count from job blob");
        msg_set_reason("Cannot get meta from blob");
        return FAIL_EINTERNAL;
    }

    for(i = 0; i < count; i++) {
        const char *key = NULL;
        sx_setting_type_t type;

        if(sx_blob_get_string(b, &key) || sx_blob_get_int32(b, (int*)&type)) {
            WARN("Failed to get %dth settings entry from blob", i);
            msg_set_reason("Cannot get settings entry from blob");
            return -1;
        }

        switch(type) {
            case SX_SETTING_TYPE_INT: {
                int64_t new, old;
                if(sx_blob_get_int64(b, &new) || sx_blob_get_int64(b, &old)){
                    WARN("Failed to get integer settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                if((s = sx_hashfs_cluster_settings_set_int64(h, key, phase == JOBPHASE_COMMIT ? new : old)) != OK) {
                    WARN("Failed to modify cluster settings");
                    ret = s;
                    goto cluster_settings_execute_blob_err;
                }
                break;
            }
            case SX_SETTING_TYPE_UINT: {
                uint64_t new, old;
                if(sx_blob_get_uint64(b, &new) || sx_blob_get_uint64(b, &old)){
                    WARN("Failed to get unsigned integer settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                if((s = sx_hashfs_cluster_settings_set_uint64(h, key, phase == JOBPHASE_COMMIT ? new : old)) != OK) {
                    WARN("Failed to modify cluster settings");
                    ret = s;
                    goto cluster_settings_execute_blob_err;
                }
                break;
            }
            case SX_SETTING_TYPE_BOOL: {
                int new, old;
                if(sx_blob_get_bool(b, &new) || sx_blob_get_bool(b, &old)){
                    WARN("Failed to get boolean settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                if((s = sx_hashfs_cluster_settings_set_bool(h, key, phase == JOBPHASE_COMMIT ? new : old)) != OK) {
                    WARN("Failed to modify cluster settings");
                    ret = s;
                    goto cluster_settings_execute_blob_err;
                }
                break;
            }
            case SX_SETTING_TYPE_FLOAT: {
                double new, old;
                if(sx_blob_get_float(b, &new) || sx_blob_get_float(b, &old)){
                    WARN("Failed to get integer settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                if((s = sx_hashfs_cluster_settings_set_double(h, key, phase == JOBPHASE_COMMIT ? new : old)) != OK) {
                    WARN("Failed to modify cluster settings");
                    ret = s;
                    goto cluster_settings_execute_blob_err;
                }
                break;
            }
            case SX_SETTING_TYPE_STRING: {
                const char *new, *old;
                if(sx_blob_get_string(b, &new) || sx_blob_get_string(b, &old)){
                    WARN("Failed to get string settings entry from blob");
                    msg_set_reason("Cannot get settings entry from blob");
                    return -1;
                }

                if((s = sx_hashfs_cluster_settings_set_string(h, key, phase == JOBPHASE_COMMIT ? new : old)) != OK) {
                    WARN("Failed to modify cluster settings");
                    ret = s;
                    goto cluster_settings_execute_blob_err;
                }
                break;
            }
        }
    }

    ret = OK;
cluster_settings_execute_blob_err:
    if(ret != OK)
        sx_hashfs_modify_cluster_settings_abort(h);
    else {
        switch(phase) {
            case JOBPHASE_COMMIT:
                DEBUG("Cluster settings change request");
                ret = sx_hashfs_modify_cluster_settings_end(h, ts, 0);
                break;
            case JOBPHASE_ABORT:
                DEBUG("Aborting cluster settings change");
                ret = sx_hashfs_modify_cluster_settings_end(h, oldts, 0);
                break;
            case JOBPHASE_UNDO:
                CRIT("Cluster may have been left in an inconsistent state after a failed cluster settings modification");
                ret = sx_hashfs_modify_cluster_settings_end(h, oldts, 0);
                break;
            default:
                WARN("Invalid job phase: %d", phase);
        }
    }

    if(phase == JOBPHASE_REQUEST && ret == OK)
        INFO("Sucessfully modified cluster settings");
    return ret;
}

static const char *cluster_settings_get_lock(sx_blob_t *b)
{
    return "CLUSTER_SETTINGS";
}

static rc_ty cluster_settings_nodes(sx_hashfs_t *h, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if(!nodes)
        return FAIL_EINTERNAL;
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
    if(!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

const job_2pc_t cluster_settings_spec = {
    &cluster_settings_acts,
    JOBTYPE_CLUSTER_SETTINGS,
    cluster_settings_parse_complete,
    cluster_settings_get_lock,
    cluster_settings_to_blob,
    cluster_settings_execute_blob,
    cluster_settings_proto_from_blob,
    cluster_settings_nodes,
    cluster_settings_timeout
};

void fcgi_cluster_settings(void) {
    struct cluster_settings_ctx c;
    sxc_client_t *sx = sx_hashfs_client(hashfs);

    memset(&c, 0, sizeof(c));

    c.entries = sx_blob_new();
    if(!c.entries)
        quit_errmsg(500, "Out of memory");

    job_2pc_handle_request(sx, &cluster_settings_spec, &c);

    sx_blob_free(c.entries);
}

void fcgi_get_cluster_settings(void) {
    rc_ty s;
    const char *key = NULL;
    const char *value = NULL;
    sx_setting_type_t type, *t;
    int comma = 0;
    char hexval[SXLIMIT_SETTINGS_MAX_VALUE_LEN*2+1];

    if(has_arg("key")) {
        key = get_arg("key");
        s = sx_hashfs_cluster_settings_get(hashfs, key, &type, &value);
        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
    }

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"clusterSettings\":{");

    if(has_arg("key")) {
        json_send_qstring(key);
        CGI_PUTS(":\"");
        bin2hex(value, strlen(value), hexval, sizeof(hexval));
        CGI_PRINTF("%s\"}}", hexval);
        return;
    }

    for(s = sx_hashfs_cluster_settings_first(hashfs, &key, &t, &value); s == OK; s = sx_hashfs_cluster_settings_next(hashfs)) {
        if(comma)
            CGI_PUTC(',');
        else
            comma = 1;
        json_send_qstring(key);
        CGI_PUTS(":\"");
        bin2hex(value, strlen(value), hexval, sizeof(hexval));
        CGI_PUTS(hexval);
        CGI_PUTC('"');
    }
    if(s != ITER_NO_MORE) {
        CGI_PUTC('}');
        quit_itererr("Failed get cluster settings", s);
    } else
        CGI_PUTS("}}");
}

void fcgi_cluster_junlock(void) {
    job_t job_id;
    rc_ty s;

    s = sx_hashfs_job_unlock(hashfs, NULL);
    if(s == OK)
	s = sx_hashfs_job_new(hashfs, 0, &job_id, JOBTYPE_JUNLOCKALL, 90, NULL, NULL, 0, sx_hashfs_all_nodes(hashfs, NL_NEXTPREV));
    if(s == OK)
	send_job_info(job_id);
    else
	quit_errmsg(500, msg_get_reason());
}
