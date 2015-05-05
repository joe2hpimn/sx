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

#include "fcgi-utils.h"

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
    if(has_arg("clusterStatus") + has_arg("nodeList") + has_arg("nodeMaps") == nargs) {
	time_t lastmod = sx_hashfs_disttime(hashfs);
	const char *ifmod;
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

            if(has_arg("volumeMeta")) {
                const char *metakey;
                const void *metavalue;
                unsigned int metasize, comma_meta = 0;

                if((s = sx_hashfs_volumemeta_begin(hashfs, vol)) != OK) {
                    CGI_PUTS("}}");
                    quit_itererr("Cannot lookup volume metadata", s);
                }

                CGI_PUTS(",\"volumeMeta\":{");
                while((s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK) {
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
                if(s != ITER_NO_MORE) {
                    CGI_PUTS("}}");
                    quit_itererr("Failed to list volume metadata", s);
                }
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
    if(has_arg("whoami")) {
        char self[SXLIMIT_MAX_USERNAME_LEN+2];
        if(comma) CGI_PUTC(',');
        CGI_PUTS("\"whoami\":");
        s = sx_hashfs_uid_get_name(hashfs, uid, self, sizeof(self));
        if (s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
        json_send_qstring(self);
        comma |= 1;
    }
    if(has_arg("role")) {
        if(comma) CGI_PUTC(',');
        CGI_PRINTF("\"role\":\"%s\"", has_priv(PRIV_ADMIN) ? "admin" : "normal");
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
    CGI_PRINTF("Pragma: no-cache\r\nCache-control: no-cache\r\nContent-type: application/octet-stream\r\nContent-Length: %u\r\n\r\n", sizeof(c.response));
    CGI_PUTD(c.response, sizeof(c.response));
}
