/*
 *  Copyright (C) 2015 Skylable Ltd. <info-copyright@skylable.com>
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
#include "utils.h"
#include "log.h"
#include "../../libsxclient/src/curlevents.h"

static int terminate = 0;

static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}

typedef enum _raft_rpc_type_t { RAFT_RPC_REQUEST_VOTE, RAFT_RPC_APPEND_ENTRIES } raft_rpc_type_t;

/*
 * Sample body:
 *
 * {
 *      "term":123,
 *      "distributionVersion":3,
 *      "hashFSVersion":"SX-Storage 1.9",
 *      "libsxclientVersion":"1.2",
 *      "success":true
 * }
 *
 */

struct cb_raft_response_ctx {
    curlev_context_t *cbdata;
    yajl_handle yh;
    enum cb_raft_response_state { CB_RR_START, CB_RR_KEY, CB_RR_TERM, CB_RR_HDIST_VERSION, CB_RR_HASHFS_VERSION, CB_RR_LIB_VERSION, CB_RR_SUCCESS, CB_RR_COMPLETE } state;
    sx_raft_term_t term;
    int success;
    int64_t hdist_version;
    char hashfs_version[15];
    char libsxclient_version[128];
};

static int cb_raft_response_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx*)ctx;

    if(c->state == CB_RR_HASHFS_VERSION) {
        if(l >= sizeof(c->hashfs_version))
            return 0;
        memcpy(c->hashfs_version, s, l);
        c->hashfs_version[l] = '\0';
        c->state = CB_RR_KEY;
        return 1;
    } else if(c->state == CB_RR_LIB_VERSION) {
        if(l >= sizeof(c->libsxclient_version))
            return 0;
        memcpy(c->libsxclient_version, s, l);
        c->libsxclient_version[l] = '\0';
        c->state = CB_RR_KEY;
        return 1;
    }

    return 0;
}

static int cb_raft_response_number(void *ctx, const char *s, size_t l) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx *)ctx;
    char number[24], *eon;
    int64_t n;

    if(c->state != CB_RR_TERM && c->state != CB_RR_HDIST_VERSION)
        return 0;

    if(l<1 || l>20)
        return 0;
    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &eon, 10);
    if(*eon || n < 0)
        return 0;
    if(c->state == CB_RR_TERM)
        c->term.term = n;
    else if(c->state == CB_RR_HDIST_VERSION)
        c->hdist_version = n;
    else
        return 0;
    c->state = CB_RR_KEY;
    return 1;
}

static int cb_raft_response_start_map(void *ctx) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx*)ctx;

    if(c->state == CB_RR_START)
        c->state = CB_RR_KEY;
    else
        return 0;

    return 1;
}

static int cb_raft_response_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx*)ctx;

    if(c->state == CB_RR_KEY) {
        if(l == lenof("term") && !strncmp("term", (const char *)s, lenof("term")))
            c->state = CB_RR_TERM;
        else if(l == lenof("success") && !strncmp("success", (const char *)s, lenof("success")))
            c->state = CB_RR_SUCCESS;
        else if(l == lenof("distributionVersion") && !strncmp("distributionVersion", (const char *)s, lenof("distributionVersion")))
            c->state = CB_RR_HDIST_VERSION;
        else if(l == lenof("hashFSVersion") && !strncmp("hashFSVersion", (const char *)s, lenof("hashFSVersion")))
            c->state = CB_RR_HASHFS_VERSION;
        else if(l == lenof("libsxclientVersion") && !strncmp("libsxclientVersion", (const char *)s, lenof("libsxclientVersion")))
            c->state = CB_RR_LIB_VERSION;
        else
            return 0;
    } else
        return 0;

    return 1;
}

static int cb_raft_response_end_map(void *ctx) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx*)ctx;

    if(c->state == CB_RR_KEY)
        c->state = CB_RR_COMPLETE;
    else
        return 0;
    return 1;
}

static int cb_raft_response_boolean(void *ctx, int boolean) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx*)ctx;

    if(c->state != CB_RR_SUCCESS)
        return 0;

    c->success = boolean;
    c->state = CB_RR_KEY;
    return 1;
}

static const yajl_callbacks raft_response_parser = {
    cb_fail_null,
    cb_raft_response_boolean,
    NULL,
    NULL,
    cb_raft_response_number,
    cb_raft_response_string,
    cb_raft_response_start_map,
    cb_raft_response_map_key,
    cb_raft_response_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

static int raft_response_setup_cb(curlev_context_t *cbdata, const char *host) {
    struct cb_raft_response_ctx *c;

    if(!cbdata)
        return -1;

    c = (struct cb_raft_response_ctx*)sxi_cbdata_get_context(cbdata);
    if(!c) {
        WARN("NULL raft response context");
        return -1;
    }

    if(c->yh)
        yajl_free(c->yh);

    c->cbdata = cbdata;
    if(!(c->yh  = yajl_alloc(&raft_response_parser, NULL, c))) {
        INFO("failed to allocate yajl structure");
        sxi_cbdata_seterr(cbdata, SXE_EMEM, "List failed: Out of memory");
        return 1;
    }

    c->state = CB_RR_START;
    c->success = -1;
    c->term.term = -1;
    memset(c->hashfs_version, 0, sizeof(c->hashfs_version));
    memset(c->libsxclient_version, 0, sizeof(c->libsxclient_version));

    return 0;
}

static int raft_response_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size) {
    struct cb_raft_response_ctx *c;

    if(!cbdata)
        return -1;

    c = (struct cb_raft_response_ctx*)sxi_cbdata_get_context(cbdata);
    if(!c) {
        WARN("NULL raft response context");
        return -1;
    }

    if(yajl_parse(c->yh, data, size) != yajl_status_ok) {
        INFO("failed to parse raft response");
        return 1;
    }

    return 0;
}

static rc_ty raft_rpc_bcast(sx_hashfs_t *h, sx_raft_state_t *state, raft_rpc_type_t rpc_type, const sx_nodelist_t *nodes, unsigned int nnodes, sx_raft_term_t *max_recv_term, int64_t *max_recv_hdist_version, char *max_recv_hashfs_version, unsigned int max_recv_hashfs_version_len, unsigned int *succeeded) {
    const sx_node_t *me = sx_hashfs_self(h);
    rc_ty ret = FAIL_EINTERNAL;
    sxc_client_t *sx = sx_hashfs_client(h);
    sxi_conns_t *clust = sx_hashfs_conns(h);
    curlev_context_t **cbdata = NULL;
    struct cb_raft_response_ctx *ctx = NULL;
    unsigned int nnode;
    sxi_query_t *proto= NULL;
    struct timeval now;

    if(!state || !me || !nodes || !max_recv_term || !max_recv_hdist_version || !max_recv_hashfs_version)
        return EINVAL;

    if(nnodes < 3) {
        WARN("Requested heartbeat in less than 3 nodes cluster");
        return EINVAL;
    }

    if(state->role == RAFT_ROLE_LEADER && (state->leader_state.hdist_version != sx_hashfs_hdist_getversion(h) || state->leader_state.nnodes != nnodes)) {
        WARN("Inconsistent raft state");
        return FAIL_EINTERNAL;
    }

    memset(max_recv_term, 0, sizeof(*max_recv_term));
    *max_recv_hdist_version = 0;
    memset(max_recv_hashfs_version, 0, max_recv_hashfs_version_len);
    if(rpc_type == RAFT_RPC_REQUEST_VOTE) {
        DEBUG("Starting new election for term %lld", (long long)state->current_term.term);

        proto = sxi_raft_request_vote(sx, state->current_term.term, sx_hashfs_hdist_getversion(h), sx_hashfs_version(h), sx_node_uuid_str(me), state->last_applied, state->current_term.term);
        if(!proto) {
            INFO("Failed to allocate RequestVote query");
            goto raft_rpc_bcast_err;
        }
    } else {
        DEBUG("Sending AppendEntry query for term %lld", (long long)state->current_term.term);

        proto = sxi_raft_append_entries_begin(sx, state->current_term.term, sx_hashfs_hdist_getversion(h), sx_hashfs_version(h), sx_node_uuid_str(me), state->last_applied-1, state->current_term.term-1, state->last_applied);
        if(!proto) {
            INFO("Failed to allocate AppendEntries query");
            goto raft_rpc_bcast_err;
        }

        proto = sxi_raft_append_entries_finish(sx, proto);
        if(!proto) {
            INFO("Failed to finish AppendEntries query");
            goto raft_rpc_bcast_err;
        }
    }

    cbdata = calloc(nnodes, sizeof(*cbdata));
    if(!cbdata) {
        INFO("Failed to allocate query context array");
        goto raft_rpc_bcast_err;
    }

    ctx = calloc(nnodes, sizeof(*ctx));
    if(!ctx) {
        INFO("Failed to allocate query response context array");
        goto raft_rpc_bcast_err;
    }

    /* Iterate over nodes list and send the request */
    for(nnode = 0; nnode<nnodes; nnode++) {
        const sx_node_t *node = sx_nodelist_get(nodes, nnode);

        if(sx_node_cmp(me, node)) {
            cbdata[nnode] = sxi_cbdata_create_generic(clust, NULL, NULL);
            sxi_cbdata_set_context(cbdata[nnode], &ctx[nnode]);
            if(sxi_cluster_query_ev(cbdata[nnode], clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, raft_response_setup_cb, raft_response_cb)) {
                WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
                msg_set_reason("Failed to setup cluster communication with node %s", sx_node_internal_addr(node));
                goto raft_rpc_bcast_err;
            }
        }
    }

    ret = OK;
raft_rpc_bcast_err:
    if(cbdata && ctx) {
        gettimeofday(&now, NULL);
        for(nnode = 0; nnode < nnodes; nnode++) {
            const sx_node_t *node = sx_nodelist_get(nodes, nnode);
            int rc;
            long http_status = 0;

            if(!sx_node_cmp(node, me)) {
                if(state->role == RAFT_ROLE_LEADER) {
                    /* Save last successful contact with the node */
                    memcpy(&state->leader_state.node_states[nnode].last_contact, &now, sizeof(state->leader_state.node_states[nnode].last_contact));
                    state->leader_state.node_states[nnode].hbeat_success = 1;
                }

                continue;
            }

            /* Some nodes could be skipped during iteration. When query is sent, cbdata[i] is not NULL. */
            if(!cbdata[nnode])
                continue;

            rc = sxi_cbdata_wait(cbdata[nnode], sxi_conns_get_curlev(clust), &http_status);
            if(rc == -2) {
                CRIT("Failed to wait for query: %s", sxi_cbdata_geterrmsg(cbdata[nnode]));
                msg_set_reason("Internal error in cluster communication");
                continue;
            }
            if(rc == -1 || http_status != 200) {
                msg_set_reason("Query failed: %s", sxi_cbdata_geterrmsg(cbdata[nnode]));
                if(state->role == RAFT_ROLE_LEADER) {
                    DEBUG("Heartbeat query failed: %s", sxi_cbdata_geterrmsg(cbdata[nnode]));
                    DEBUG("Last contact with %s (%s) took place %.0lfs ago", sx_node_uuid_str(node), sx_node_internal_addr(node), sxi_timediff(&now, &state->leader_state.node_states[nnode].last_contact));
                    state->leader_state.node_states[nnode].hbeat_success = 0;
                }
            } else {
                if(state->role == RAFT_ROLE_LEADER) {
                    /* Save last successful contact with the node */
                    memcpy(&state->leader_state.node_states[nnode].last_contact, &now, sizeof(state->leader_state.node_states[nnode].last_contact));
                    state->leader_state.node_states[nnode].hbeat_success = 1;
                }
            }
            if(succeeded && ctx[nnode].success > 0)
                (*succeeded)++;
            if(ctx[nnode].term.term > max_recv_term->term)
                memcpy(max_recv_term, &ctx[nnode].term, sizeof(*max_recv_term));
            if(ctx[nnode].hdist_version > *max_recv_hdist_version)
                *max_recv_hdist_version = ctx[nnode].hdist_version;
            if(strcmp(ctx[nnode].hashfs_version, max_recv_hashfs_version) > 0)
                sxi_strlcpy(max_recv_hashfs_version, ctx[nnode].hashfs_version, max_recv_hashfs_version_len);
        }
    }

    for(nnode = 0; nnode < nnodes && cbdata; nnode++)
        if(cbdata[nnode])
            sxi_cbdata_unref(&cbdata[nnode]);
    for(nnode = 0; nnode < nnodes && ctx; nnode++) {
        if(ctx[nnode].yh)
            yajl_free(ctx[nnode].yh);
    }
    free(cbdata);
    sxi_query_free(proto);
    free(ctx);

    return ret;
}

static rc_ty raft_leader_send_heartbeat(sx_hashfs_t *h, sx_raft_state_t *state, const sx_nodelist_t *nodes, unsigned int nnodes) {
    const sx_node_t *me = sx_hashfs_self(h);
    rc_ty s;
    sx_raft_term_t max_recv_term;
    int64_t max_recv_hdist_version = 0;
    sx_raft_state_t save_state;
    unsigned int state_changed = 0;
    char max_recv_hashfs_version[15];

    if(!state || !me || !nodes)
        return EINVAL;

    memset(max_recv_hashfs_version, 0, sizeof(max_recv_hashfs_version));
    s = raft_rpc_bcast(h, state, RAFT_RPC_APPEND_ENTRIES, nodes, nnodes, &max_recv_term, &max_recv_hdist_version, max_recv_hashfs_version, sizeof(max_recv_hashfs_version), NULL);
    if(s != OK) {
        INFO("Failed to send heardbeat message to all nodes: %s", msg_get_reason());
        return s;
    }

    if(sx_hashfs_raft_state_begin(h)) {
        WARN("Failed to save new raft state: Database is locked");
        return FAIL_LOCKED;
    }

    /* Reload raft state from database, it could've changed */
    if(sx_hashfs_raft_state_get(h, &save_state)) {
        sx_hashfs_raft_state_abort(h);
        INFO("Failed to load raft state: %s", msg_get_reason());
        return FAIL_EINTERNAL;
    }

    if(save_state.current_term.term < max_recv_term.term || save_state.leader_state.hdist_version < max_recv_hdist_version || strcmp(sx_hashfs_version(h), max_recv_hashfs_version) < 0) {
        DEBUG("Stale current term: %lld, max remote term: %lld", (long long)save_state.current_term.term, (long long)max_recv_term.term);
        save_state.role = RAFT_ROLE_FOLLOWER;
        memcpy(&save_state.current_term, &max_recv_term, sizeof(save_state.current_term));
        save_state.voted = 0;
        state_changed = 1;
    }

    if(save_state.role == RAFT_ROLE_LEADER) {
        unsigned int i;

        /* If leadership has not changed, clone the last contact entries */
        for(i = 0; i < save_state.leader_state.nnodes; i++) {
            memcpy(&save_state.leader_state.node_states[i].last_contact, &state->leader_state.node_states[i].last_contact, sizeof(save_state.leader_state.node_states[i].last_contact));
            save_state.leader_state.node_states[i].hbeat_success = state->leader_state.node_states[i].hbeat_success;
        }
        state_changed = 1;
    }

    if(state_changed) {
        if((s = sx_hashfs_raft_state_set(h, &save_state)) != OK) {
            WARN("Failed to save new raft state: %s", msg_get_reason());
            sx_hashfs_raft_state_abort(h);
            sx_hashfs_raft_state_empty(h, &save_state);
            return s;
        }

        if(sx_hashfs_raft_state_end(h)) {
            WARN("Failed to save raft state");
            sx_hashfs_raft_state_empty(h, &save_state);
            return FAIL_EINTERNAL;
        }
    } else
        sx_hashfs_raft_state_abort(h);

    sx_hashfs_raft_state_empty(h, &save_state);
    return OK;
}

static void raft_node_state_init(sx_raft_node_state_t *ns, const sx_uuid_t *node, int64_t next_index, const struct timeval *last_contact) {
    ns->next_index = next_index;
    /* Clone the node uuid */
    memcpy(&ns->node, node, sizeof(sx_uuid_t));
    /* Initially assume success when no heartbead has been sent yet. */
    memcpy(&ns->last_contact, last_contact, sizeof(struct timeval));
    ns->hbeat_success = 1;
}

static rc_ty raft_election_start(sx_hashfs_t *h, sx_raft_state_t *state, const sx_nodelist_t *nodes, unsigned int nnodes) {
    const sx_node_t *me = sx_hashfs_self(h);
    rc_ty ret = FAIL_EINTERNAL, s;
    unsigned int nnode;
    unsigned int succeeded = 1; /* This node always succeeds to vote for itself */
    sx_raft_state_t save_state;
    sx_raft_node_state_t *node_states = NULL;
    sx_raft_term_t max_recv_term;
    int64_t max_recv_hdist_version;
    int state_changed = 0;
    struct timeval now;
    char max_recv_hashfs_version[15];

    if(!state || !me || !nodes) {
        sx_hashfs_raft_state_abort(h);
        return EINVAL;
    }

    /* Election starts from switching to a candidate role. */
    state->role = RAFT_ROLE_CANDIDATE;
    /* New candidate has to increment its current term */
    state->current_term.term++;
    gettimeofday(&state->last_contact, NULL);

    /* Vote for itself */
    memcpy(&state->voted_for, sx_node_uuid(me), sizeof(sx_uuid_t));
    state->voted = 1;

    memset(max_recv_hashfs_version, 0, sizeof(max_recv_hashfs_version));

    /* Save state changes (become the candidate immediately) */
    if((s = sx_hashfs_raft_state_set(h, state)) != OK) {
        sx_hashfs_raft_state_abort(h);
        WARN("Failed to save new raft state: %s", msg_get_reason());
        return s;
    }

    if(sx_hashfs_raft_state_end(h)) {
        WARN("Failed to save raft state");
        return FAIL_EINTERNAL;
    }

    /* Prepare the node states array for a new leader (in case this node won) */
    node_states = calloc(nnodes, sizeof(sx_raft_node_state_t));
    if(!node_states) {
        WARN("Failed to allocate node states for a new leader");
        return FAIL_EINTERNAL;
    }

    gettimeofday(&now, NULL);
    /* Initialize nodes uuids and next log index */
    for(nnode = 0; nnode < nnodes; nnode++) {
        const sx_node_t *node = sx_nodelist_get(nodes, nnode);
        raft_node_state_init(&node_states[nnode], sx_node_uuid(node), state->last_applied + 1, &now);
    }

    ret = raft_rpc_bcast(h, state, RAFT_RPC_REQUEST_VOTE, nodes, nnodes, &max_recv_term, &max_recv_hdist_version, max_recv_hashfs_version, sizeof(max_recv_hashfs_version), &succeeded);
    if(ret != OK) {
        WARN("Failed to request vote");
        free(node_states);
        return ret;
    }

    if(sx_hashfs_raft_state_begin(h)) {
        WARN("Failed to save raft state: Database is locked");
        free(node_states);
        return FAIL_LOCKED;
    }

    /* Need to read the raft state from database, it could've changed in the meantime */
    if((s = sx_hashfs_raft_state_get(h, &save_state)) != OK) {
        sx_hashfs_raft_state_abort(h);
        WARN("Failed to get raft state: %s", msg_get_reason());
        free(node_states);
        return s;
    }

    if(state->current_term.term < max_recv_term.term || sx_hashfs_hdist_getversion(h) < max_recv_hdist_version || strcmp(sx_hashfs_version(h), max_recv_hashfs_version) < 0) {
        DEBUG("Stale current term: %lld, max remote term: %lld", (long long)state->current_term.term, (long long)max_recv_term.term);
        save_state.role = RAFT_ROLE_FOLLOWER;
        memcpy(&save_state.current_term, &max_recv_term, sizeof(save_state.current_term));
        save_state.voted = 0;
        state_changed = 1;
    } else if(save_state.role == RAFT_ROLE_CANDIDATE && 2 * succeeded > nnodes) {
        /* Check if succeeded to vote for majority and state did not change in the meantime (should still be a candidate) */
        DEBUG("Got the majority! (%d out of %d votes), becoming a leader", succeeded, nnodes);
        save_state.role = RAFT_ROLE_LEADER;
        save_state.voted = 0;
        save_state.leader_state.node_states = node_states;
        save_state.leader_state.nnodes = nnodes;
        save_state.leader_state.hdist_version = sx_hashfs_hdist_getversion(h);
        memcpy(&save_state.current_term.leader, sx_node_uuid(me), sizeof(sx_uuid_t));
        save_state.current_term.has_leader = 1;
        state_changed = 1;
        node_states = NULL;
    }

    if(state_changed) {
        if((s = sx_hashfs_raft_state_set(h, &save_state)) != OK) {
            WARN("Failed to save new raft state: %s", msg_get_reason());
            sx_hashfs_raft_state_abort(h);
            sx_hashfs_raft_state_empty(h, &save_state);
            return s;
        }
        if(sx_hashfs_raft_state_end(h)) {
            WARN("Failed to save raft state");
            sx_hashfs_raft_state_empty(h, &save_state);
            return FAIL_EINTERNAL;
        }
    } else
        sx_hashfs_raft_state_abort(h);

    free(node_states);
    sx_hashfs_raft_state_empty(h, &save_state);
    return ret;
}

static int raft_leader_reload_nodelist(sx_hashfs_t *h, sx_raft_state_t *state, const sx_nodelist_t *nodes, unsigned int nnodes) {
    sx_raft_node_state_t *nstates;
    unsigned int i, j;
    struct timeval now;

    if(!state) {
        NULLARG();
        return -1;
    }

    gettimeofday(&now, NULL);
    /* Initialize node states to contain exactly the same nodes as in effective nodelist */
    nstates = calloc(nnodes, sizeof(sx_raft_node_state_t));
    if(!nstates) {
        WARN("Cannot allocate nodes state list");
        return -1;
    }

    /* Iterate over nodes stored in existing node states list.
     *
     * Note: In case some nodes are different than nodes in the nodelist, or the nodelist is shorter than stored
     * node states list, some of node states previously stored in database can be disregarded. */
    for(i = 0; i < nnodes; i++) {
        const sx_node_t *node = sx_nodelist_get(nodes, i);

        for(j = 0; j < state->leader_state.nnodes; j++) {
            /* Compare previously saved node uuid with a node stored in nodelist */
            if(!memcmp(&state->leader_state.node_states[j].node, sx_node_uuid(node), sizeof(sx_uuid_t))) {
                /* Node uuid matched, clone it to new node states list */
                memcpy(&nstates[i], &state->leader_state.node_states[j], sizeof(sx_raft_node_state_t));
                break;
            }
        }

        if(j == state->leader_state.nnodes) {
            /* Node stored in the nodelist is different than node stored in node states list, create new node state */
            raft_node_state_init(&nstates[i], sx_node_uuid(node), state->last_applied + 1, &now);
        }
    }

    /* Node states list has already been loaded with sx_hashfs_raft_state_get() */
    free(state->leader_state.node_states);
    state->leader_state.node_states = nstates;
    state->leader_state.nnodes = nnodes;
    state->leader_state.hdist_version = sx_hashfs_hdist_getversion(h);
    return 0;
}

static void raft_hbeat(sx_hashfs_t *h, int hdist_changed) {
    sx_raft_state_t state;
    struct timeval now;
    const sx_nodelist_t *nodes;
    unsigned int nnodes;

    /* Prepare node list */
    nodes = sx_hashfs_effective_nodes(h, NL_NEXTPREV);
    if(!nodes) {
        INFO("Failed to obtain cluster nodelist");
        return;
    }
    nnodes = sx_nodelist_count(nodes);

    if(nnodes < 3) {
        DEBUG("Raft will not operate on less than 3 nodes cluster");
        return;
    }

    if(sx_hashfs_raft_state_begin(h)) {
        INFO("Failed to load raft state: Database is locked");
        return;
    }

    if(sx_hashfs_raft_state_get(h, &state)) {
        sx_hashfs_raft_state_abort(h);
        INFO("Failed to load raft state: %s", msg_get_reason());
        return;
    }

    gettimeofday(&now, NULL);
    if(state.role == RAFT_ROLE_LEADER) {
        /* If hdist version has changed, we need to reload nodelist for the leader.
         * In case hdist_changed is false we still need to compare versions. Such a situation
         * could happen if first attempt to update nodelist failed (e.g. locked db). */
        if(hdist_changed || state.leader_state.hdist_version != sx_hashfs_hdist_getversion(h)) {
            DEBUG("Reloading nodelist due to hdist version change: %lld -> %lld", (long long)state.leader_state.hdist_version, (long long)sx_hashfs_hdist_getversion(h));
            if(raft_leader_reload_nodelist(h, &state, nodes, nnodes)) {
                INFO("Failed to reload raft leader node states list");
                sx_hashfs_raft_state_abort(h);
                goto raft_hbeat_err;
            }
            if(sx_hashfs_raft_state_set(h, &state)) {
                INFO("Failed to save raft state");
                sx_hashfs_raft_state_abort(h);
                goto raft_hbeat_err;
            }
            if(sx_hashfs_raft_state_end(h)) {
                INFO("Failed to save raft state");
                goto raft_hbeat_err;
            }
        } else
            sx_hashfs_raft_state_abort(h);
    } else if(sxi_timediff(&now, &state.last_contact) > state.election_timeout) {
        DEBUG("Election timeout elapsed, switching to CANDIDATE state");
        /* Election timeout reached, start an election */
        if(raft_election_start(h, &state, nodes, nnodes)) {
            WARN("Failed to start an election");
            goto raft_hbeat_err;
        }
    } else {
        /* Database transaction is open, no changes are made */
        sx_hashfs_raft_state_abort(h);
    }

    /* No database transaction open here */
    if(state.role == RAFT_ROLE_LEADER && raft_leader_send_heartbeat(h, &state, nodes, nnodes))
        DEBUG("Failed to send heartbeat query to all of the nodes");

raft_hbeat_err:
    sx_hashfs_raft_state_empty(h, &state);
}

#define HBEAT_INTERVAL 20.0f

int hbeatmgr(sxc_client_t *sx, const char *dir, int pipe) {
    struct sigaction act;
    sx_hashfs_t *hashfs = NULL;

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

    hashfs = sx_hashfs_open(dir, sx);
    if(!hashfs) {
	CRIT("Failed to initialize the hash server interface");
	goto hbeat_err;
    }

    DEBUG("Heartbeat manager started");

    while(!terminate) {
	int dc;

        if(wait_trigger(pipe, HBEAT_INTERVAL, NULL))
            break;

	dc = sx_hashfs_distcheck(hashfs);
	if(dc < 0) {
	    CRIT("Failed to reload distribution");
	    goto hbeat_err;
	} else if(dc > 0)
	    INFO("Distribution reloaded");

	DEBUG("Beat!");
        if(!sx_storage_is_bare(hashfs) && !sx_hashfs_is_rebalancing(hashfs) && !sx_hashfs_is_orphan(hashfs))
	    raft_hbeat(hashfs, dc > 0);
    }

 hbeat_err:
    /*****************
      DO CLEANUP HERE
    ******************/
    sx_hashfs_close(hashfs);
    DEBUG("Heartbeat manager terminated");

    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}

