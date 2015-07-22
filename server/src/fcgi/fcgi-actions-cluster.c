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

static void send_distribution(const sx_nodelist_t *nodes) {
    unsigned int i, n = sx_nodelist_count(nodes);

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
    CGI_PUTC(']');
}

void fcgi_handle_cluster_requests(void) {
    int comma = 0;
    rc_ty s;

    if(has_arg("clusterStatus") && !has_priv(PRIV_ADMIN))
	quit_errnum(403);

    /* Allow caching of rarely changing hdist-based items but force
     * revalidation so we authenticate and authorize the request again */
    if(has_arg("clusterStatus") + has_arg("nodeList") + has_arg("nodeMaps") + has_arg("clusterMeta") == nargs) {
	time_t lastmod = 0;
	const char *ifmod;

        if(has_arg("clusterStatus") || has_arg("nodeList") || has_arg("nodeMaps"))
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

	status = sx_hashfs_get_progress_info(hashfs, &progress_msg);
	if(status == INPRG_ERROR)
	    quit_errmsg(500, msg_get_reason());
	CGI_PUTS("\"clusterStatus\":{\"distributionModels\":[");

	if(!sx_storage_is_bare(hashfs)) {
	    const sx_nodelist_t *nodes = sx_hashfs_all_nodes(hashfs, NL_PREV);
	    const sx_uuid_t *dist_uuid;
	    unsigned int version;
	    uint64_t checksum;

	    if(nodes) {
		send_distribution(nodes);
		if(sx_hashfs_is_rebalancing(hashfs)) {
		    CGI_PUTC(',');
		    send_distribution(sx_hashfs_all_nodes(hashfs, NL_NEXT));
		}
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
                CGI_PRINTF(",\"operatingMode\":\"%s\"", sx_hashfs_is_readonly(hashfs) ? "read-only" : "read-write");
            CGI_PUTC('}');
	} else
	    CGI_PUTS("]}");
	comma |= 1;
    }

    if(has_arg("volumeList")) {
	const sx_hashfs_volume_t *vol;
        char owner[SXLIMIT_MAX_USERNAME_LEN+1];

	CGI_PUTS("\"volumeList\":{");
        uint8_t *u = has_priv(PRIV_ADMIN) ? NULL : user;/* user = NULL: list all volumes */
	for(s = sx_hashfs_volume_first(hashfs, &vol, u); s == OK; s = sx_hashfs_volume_next(hashfs)) {
            sx_priv_t priv = 0;
            unsigned int i;
            struct {
                char key[SXLIMIT_META_MAX_KEY_LEN+1];
                uint8_t value[SXLIMIT_META_MAX_VALUE_LEN];
                int value_len;
            } custom_meta[SXLIMIT_META_MAX_ITEMS], meta[SXLIMIT_META_MAX_ITEMS];
            unsigned int nmeta = 0, ncustommeta = 0;

	    if(comma)
		CGI_PUTC(',');
	    else
		comma |= 1;

	    json_send_qstring(vol->name);
            if((s = sx_hashfs_get_access(hashfs, user, vol->name, &priv)) != OK) {
                CGI_PUTS("}");
                quit_itererr("Failed to get volume privs", s);
            }

            if((s = sx_hashfs_uid_get_name(hashfs, vol->owner, owner, sizeof(owner))) != OK) {
                CGI_PUTS("}");
                quit_itererr("Failed to get volume owner name", s);
            }

            if(has_priv(PRIV_ADMIN))
                priv = PRIV_READ | PRIV_WRITE;

	    CGI_PRINTF(":{\"owner\":\"%s\",\"replicaCount\":%u,\"maxRevisions\":%u,\"privs\":\"%c%c\",\"usedSize\":", owner,
                vol->max_replica, vol->revisions, (priv & PRIV_READ) ? 'r' : '-', (priv & PRIV_WRITE) ? 'w' : '-');

	    CGI_PUTLL(vol->cursize);
            CGI_PRINTF(",\"sizeBytes\":");
            CGI_PUTLL(vol->size);
            if(has_arg("volumeMeta") || has_arg("customVolumeMeta")) {
                const char *metakey;
                const void *metavalue;
                unsigned int metasize;

                if((s = sx_hashfs_volumemeta_begin(hashfs, vol)) != OK) {
                    CGI_PUTS("}}");
                    quit_itererr("Cannot lookup volume metadata", s);
                }
                while((s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK) {
                    if(!strncmp(SX_CUSTOM_META_PREFIX, metakey, lenof(SX_CUSTOM_META_PREFIX))) {
                        if(has_arg("customVolumeMeta")) {
                            /* Append custom meta value */
                            sxi_strlcpy(custom_meta[ncustommeta].key, metakey + lenof(SX_CUSTOM_META_PREFIX), sizeof(custom_meta[ncustommeta].key) - lenof(SX_CUSTOM_META_PREFIX));
                            memcpy(custom_meta[ncustommeta].value, metavalue, metasize);
                            custom_meta[ncustommeta].value_len = metasize;
                            ncustommeta++;
                        }
                    } else {
                        if(has_arg("volumeMeta")) {
                            /* Append regular meta value */
                            sxi_strlcpy(meta[nmeta].key, metakey, sizeof(meta[nmeta].key));
                            memcpy(meta[nmeta].value, metavalue, metasize);
                            meta[nmeta].value_len = metasize;
                            nmeta++;
                        }
                    }
                }
            }

            if(has_arg("volumeMeta")) {
                CGI_PUTS(",\"volumeMeta\":{");
                for(i = 0; i < nmeta; i++) {
                    char hexval[SXLIMIT_META_MAX_VALUE_LEN*2+1];
                    if(i)
                        CGI_PUTC(',');
                    json_send_qstring(meta[i].key);
                    CGI_PUTS(":\"");
                    bin2hex(meta[i].value, meta[i].value_len, hexval, sizeof(hexval));
                    CGI_PUTS(hexval);
                    CGI_PUTC('"');
                }
                CGI_PUTC('}');
            }
            if(has_arg("customVolumeMeta")) {
                CGI_PUTS(",\"customVolumeMeta\":{");
                for(i = 0; i < ncustommeta; i++) {
                    char hexval[SXLIMIT_META_MAX_VALUE_LEN*2+1];
                    if(i)
                        CGI_PUTC(',');
                    json_send_qstring(custom_meta[i].key);
                    CGI_PUTS(":\"");
                    bin2hex(custom_meta[i].value, custom_meta[i].value_len, hexval, sizeof(hexval));
                    CGI_PUTS(hexval);
                    CGI_PUTC('"');
                }
                CGI_PUTC('}');
            }
	    CGI_PUTS("}");
	}

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

    /* Notice: The whoami API becomes obsolete since 1.2 release and is going to be dropped in next release.
     *         Please use GET .self query instead. */
    if(has_arg("whoami")) {
        char self[SXLIMIT_MAX_USERNAME_LEN+2];
        if(comma) CGI_PUTC(',');
        CGI_PUTS("\"whoami\":");
        s = sx_hashfs_uid_get_name(hashfs, uid, self, sizeof(self));
        if (s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
        json_send_qstring(self);
        comma |= 1;

        if(has_arg("role"))
            CGI_PRINTF(",\"role\":\"%s\"", has_priv(PRIV_ADMIN) ? "admin" : "normal");
        if(has_arg("userDescription")) {
            char *desc = NULL;
            s = sx_hashfs_get_user_info(hashfs, user, NULL, NULL, NULL, &desc, NULL);
            if (s != OK) {
                free(desc);
                quit_errmsg(rc2http(s), msg_get_reason());
            }
            CGI_PUTS(",\"userDesc\":");
            json_send_qstring(desc);
            free(desc);
        }
        if(has_arg("quota")) {
            int64_t quota_used;
            /* Get total usage of volumes owned by the user and its clones */
            if((s = sx_hashfs_get_owner_quota_usage(hashfs, uid, NULL, &quota_used)) != OK)
                quit_errmsg(rc2http(s), rc2str(s));
            CGI_PRINTF(",\"userQuota\":");
            CGI_PUTLL(user_quota);
            CGI_PRINTF(",\"userQuotaUsed\":");
            CGI_PUTLL(quota_used);
        }
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
    char metakey[SXLIMIT_META_MAX_KEY_LEN+1];
    sx_blob_t *meta;
    unsigned int nmeta;
    sx_blob_t *oldmeta;
    unsigned int noldmeta;
    enum cluster_setmeta_state { CB_SM_START=0, CB_SM_KEY, CB_SM_TIMESTAMP, CB_SM_META, CB_SM_METAKEY, CB_SM_METAVALUE, CB_SM_COMPLETE } state;
};

static int cb_cluster_setmeta_string(void *ctx, const unsigned char *s, size_t l) {
    struct cluster_setmeta_ctx *c = ctx;
    uint8_t metavalue[SXLIMIT_META_MAX_VALUE_LEN];
    if(c->state == CB_SM_METAVALUE) {
        if(hex2bin((const char*)s, l, metavalue, sizeof(metavalue)))
            return 0;
        l/=2;
        if(sx_hashfs_check_meta(c->metakey, metavalue, l) ||
           sx_blob_add_string(c->meta, c->metakey) ||
           sx_blob_add_blob(c->meta, metavalue, l))
            return 0;
        c->nmeta++;
        c->state = CB_SM_METAKEY;
        return 1;
    }
    DEBUG("Invalid state %d: expected %d", c->state, CB_SM_METAVALUE);
    return 0;
}

static int cb_cluster_setmeta_number(void *ctx, const char *s, size_t l) {
    struct cluster_setmeta_ctx *c = ctx;
    if(c->state == CB_SM_TIMESTAMP) {
        char number[21], *enumb;
        if(c->has_timestamp || l<1 || l>20)
            return 0;

        memcpy(number, s, l);
        number[l] = '\0';
        c->ts = strtol(number, &enumb, 10);
        if(enumb && *enumb)
            return 0;
        c->has_timestamp = 1;
        c->state = CB_SM_KEY;
        return 1;
    }
    DEBUG("Invalid state %d: expected %d", c->state, CB_SM_TIMESTAMP);
    return 0;
}

static int cb_cluster_setmeta_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cluster_setmeta_ctx *c = ctx;
    if(c->state == CB_SM_KEY) {
        if(l == lenof("clusterMeta") && !strncmp("clusterMeta", (const char*)s, lenof("clusterMeta"))) {
            c->state = CB_SM_META;
            return 1;
        }
        if(l == lenof("timestamp") && !strncmp("timestamp", (const char*)s, lenof("timestamp"))) {
            c->state = CB_SM_TIMESTAMP;
            return 1;
        }
    } else if(c->state == CB_SM_METAKEY) {
        if(c->nmeta >= SXLIMIT_META_MAX_ITEMS || l < SXLIMIT_META_MIN_KEY_LEN || l > SXLIMIT_META_MAX_KEY_LEN)
            return 0;
        memcpy(c->metakey, s, l);
        c->metakey[l] = '\0';
        c->state = CB_SM_METAVALUE;
        return 1;
    }
    DEBUG("Invalid state %d: expected %d or %d", c->state, CB_SM_KEY, CB_SM_METAKEY);
    return 0;
}

static int cb_cluster_setmeta_start_map(void *ctx) {
    struct cluster_setmeta_ctx *c = ctx;
    if(c->state == CB_SM_START)
        c->state = CB_SM_KEY;
    else if(c->state == CB_SM_META)
        c->state = CB_SM_METAKEY;
    else
        return 0;
    return 1;
}

static int cb_cluster_setmeta_end_map(void *ctx) {
    struct cluster_setmeta_ctx *c = ctx;
    if(c->state == CB_SM_KEY)
        c->state = CB_SM_COMPLETE;
    else if(c->state == CB_SM_METAKEY)
        c->state = CB_SM_KEY;
    else
        return 0;
    return 1;
}

static const yajl_callbacks cluster_setmeta_ops_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_cluster_setmeta_number,
    cb_cluster_setmeta_string,
    cb_cluster_setmeta_start_map,
    cb_cluster_setmeta_map_key,
    cb_cluster_setmeta_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

static rc_ty cluster_setmeta_parse_complete(void *yctx)
{
    struct cluster_setmeta_ctx *c = yctx;
    rc_ty s;
    const char *metakey = NULL;
    const void *metaval = NULL;
    unsigned int metaval_len = 0;

    if(!c || c->state != CB_SM_COMPLETE)
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

static int get_sxc_meta_from_blob(sxc_client_t *sx, sx_blob_t *b, sxc_meta_t *meta, int skip) {
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
        const char *metakey = NULL;
        const void *metaval = NULL;
        unsigned int metaval_len = 0;

        if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &metaval_len)) {
            WARN("Failed to get %dth meta entry from blob", i);
            msg_set_reason("Cannot get meta from blob");
            return -1;
        }

        if(!metakey || !metaval) {
            WARN("Invalid meta entry");
            msg_set_reason("Cannot get meta from blob");
            return -1;
        }

        if(!skip && sxc_meta_setval(meta, metakey, metaval, metaval_len)) {
            WARN("Failed to add meta entry");
            msg_set_reason("Cannot get meta from blob");
            return -1;
        }
    }

    return 0;
}

static sxi_query_t* cluster_setmeta_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    time_t ts = 0, oldts = 0;
    sxc_meta_t *meta = NULL;
    sxi_query_t *ret = NULL;

    meta = sxc_meta_new(sx);
    if(!meta) {
        WARN("Failed to allocate new cluster meta");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(sx_blob_get_int64(b, &oldts) || sx_blob_get_int64(b, &ts)) {
        WARN("Corrupt user blob");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(get_sxc_meta_from_blob(sx, b, meta, phase != JOBPHASE_COMMIT)) {
        WARN("Failed to load new cluster meta from blob");
        goto cluster_setmeta_proto_from_blob_err;
    }

    if(phase != JOBPHASE_COMMIT) {
        /* Get old meta only when aborting */
        if(get_sxc_meta_from_blob(sx, b, meta, 0)) {
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
            if((s = sx_hashfs_clustermeta_set_addmeta(h, metakey, metaval, metaval_len)) != OK) {
                WARN("Failed to add meta entry");
                return s;
            }
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
    &cluster_setmeta_ops_parser,
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
