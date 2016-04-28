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
#include "../../libsxclient/src/jparse.h"

static int terminate = 0;

#define version_init(ver) sx_hashfs_version_parse(ver, "0.0", -1)

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
 *      "raftResponse":
 *      {
 *          "term":123,
 *          "distributionVersion":3,
 *          "hashFSVersion":"SX-Storage 1.9",
 *          "libsxclientVersion":"1.2",
 *          "success":true
 *      }
 * }
 *
 */

struct cb_raft_response_ctx {
    const struct jparse_actions *acts;
    jparse_t *J;
    sx_raft_term_t term;
    int success;
    int64_t hdist_version;
    sx_hashfs_version_t remote_version;
    int has_rem_ver;
    int has_lib_ver;
    char libsxclient_version[128];
};

static void cb_raft_resp_hashfs_ver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx *)ctx;

    if(sx_hashfs_version_parse(&c->remote_version, string, length)) {
        sxi_jparse_cancel(J, "Invalid hashfs version");
	return;
    }
    c->has_rem_ver = 1;
}

static void cb_raft_resp_lib_ver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx *)ctx;

    if(length >= sizeof(c->libsxclient_version)) {
        sxi_jparse_cancel(J, "Invalid client library version");
        return;
    }
    memcpy(c->libsxclient_version, string, length);
    c->libsxclient_version[length] = '\0';
    c->has_lib_ver = 1;
}

static void cb_raft_resp_term(jparse_t *J, void *ctx, int64_t term) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx *)ctx;

    if(term <= 0) {
        sxi_jparse_cancel(J, "Invalid term received");
        return;
    }
    c->term.term = term;
}

static void cb_raft_resp_hdver(jparse_t *J, void *ctx, int64_t ver) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx *)ctx;

    if(ver <= 0) {
        sxi_jparse_cancel(J, "Invalid hdist_version received");
        return;
    }

    c->hdist_version = ver;
}

static void cb_raft_resp_success(jparse_t *J, void *ctx, int success) {
    struct cb_raft_response_ctx *c = (struct cb_raft_response_ctx *)ctx;

    if(success != 0 && success != 1) {
        sxi_jparse_cancel(J, "Invalid success received");
        return;
    }

    c->success = success;
}

static int raft_response_setup_cb(curlev_context_t *cbdata, const char *host) {
    struct cb_raft_response_ctx *c;

    if(!cbdata)
        return -1;

    c = (struct cb_raft_response_ctx*)sxi_cbdata_get_context(cbdata);
    if(!c) {
        WARN("NULL raft response context");
        return -1;
    }

    sxi_jparse_destroy(c->J);

    if(!(c->J  = sxi_jparse_create(c->acts, c, 0))) {
        sxi_cbdata_seterr(cbdata, SXE_EMEM, "List failed: Out of memory");
        return 1;
    }

    c->success = -1;
    c->hdist_version = -1;
    c->term.term = -1;
    c->has_lib_ver = 0;
    c->has_rem_ver = 0;
    version_init(&c->remote_version);
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

    if(sxi_jparse_digest(c->J, data, size)) {
        sxi_cbdata_seterr(cbdata, SXE_ECOMM, sxi_jparse_geterr(c->J));
        return 1;
    }

    return 0;
}

static rc_ty raft_rpc_bcast(sx_hashfs_t *h, sx_raft_state_t *state, raft_rpc_type_t rpc_type, const sx_nodelist_t *nodes, unsigned int nnodes, sx_raft_term_t *max_recv_term, int64_t *max_recv_hdist_version, sx_hashfs_version_t *max_recv_hashfs_version, unsigned int *succeeded) {
    const sx_node_t *me = sx_hashfs_self(h);
    rc_ty ret = FAIL_EINTERNAL;
    sxc_client_t *sx = sx_hashfs_client(h);
    sxi_conns_t *clust = sx_hashfs_conns(h);
    curlev_context_t **cbdata = NULL;
    struct cb_raft_response_ctx *ctx = NULL;
    unsigned int nnode;
    sxi_query_t *proto= NULL;
    struct timeval now;
    const struct jparse_actions acts = {
        JPACTS_STRING(
                      JPACT(cb_raft_resp_hashfs_ver, JPKEY("raftResponse"), JPKEY("hashFSVersion")),
                      JPACT(cb_raft_resp_lib_ver, JPKEY("raftResponse"), JPKEY("libsxclientVersion"))
                     ),
        JPACTS_INT64 (
                      JPACT(cb_raft_resp_term, JPKEY("raftResponse"), JPKEY("term")),
                      JPACT(cb_raft_resp_hdver, JPKEY("raftResponse"), JPKEY("distributionVersion"))
                     ),
        JPACTS_BOOL  (
                      JPACT(cb_raft_resp_success, JPKEY("raftResponse"), JPKEY("success"))
                     )
    };

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
    version_init(max_recv_hashfs_version);
    if(rpc_type == RAFT_RPC_REQUEST_VOTE) {
        DEBUG("Starting new election for term %lld", (long long)state->current_term.term);

        proto = sxi_raft_request_vote(sx, state->current_term.term, sx_hashfs_hdist_getversion(h), sx_hashfs_version(h)->str, sx_node_uuid_str(me), state->last_applied, state->current_term.term);
        if(!proto) {
            INFO("Failed to allocate RequestVote query");
            goto raft_rpc_bcast_err;
        }
    } else {
        DEBUG("Sending AppendEntry query for term %lld", (long long)state->current_term.term);

        proto = sxi_raft_append_entries_begin(sx, state->current_term.term, sx_hashfs_hdist_getversion(h), sx_hashfs_version(h)->str, sx_node_uuid_str(me), state->last_applied-1, state->current_term.term-1, state->last_applied);
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
            if(state->role == RAFT_ROLE_LEADER) {
                /* Node can be marked as faulty when JOBTYPE_IGNODES job is pending, skip the node, it is not gonna response anyway. */
                if(state->leader_state.node_states[nnode].is_faulty)
                    continue;
            }

            cbdata[nnode] = sxi_cbdata_create_generic(clust, NULL, NULL);
            sxi_cbdata_set_context(cbdata[nnode], &ctx[nnode]);
            ctx[nnode].acts = &acts;
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
            int rc, fail = 0;
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

            if(rc == -1 || http_status != 200 || sxi_jparse_done(ctx[nnode].J))
                fail = 1;
            else if(!ctx[nnode].has_rem_ver || !ctx[nnode].has_lib_ver || ctx[nnode].success < 0 || ctx[nnode].term.term < 0 || ctx[nnode].hdist_version < 0) {
                fail = 1;
                sxi_cbdata_seterr(cbdata[nnode], SXE_ECOMM, "One or more required fields are missing for raft response entry");
            }

            if(fail) {
                DEBUG("Raft request to %s failed: %s", sx_node_internal_addr(node), sxi_cbdata_geterrmsg(cbdata[nnode]));
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
            if(sx_hashfs_version_cmp(&ctx[nnode].remote_version, max_recv_hashfs_version) > 0)
		sx_hashfs_version_parse(max_recv_hashfs_version, ctx[nnode].remote_version.str, -1);
        }
    }

    for(nnode = 0; nnode < nnodes && cbdata; nnode++)
        if(cbdata[nnode])
            sxi_cbdata_unref(&cbdata[nnode]);
    for(nnode = 0; nnode < nnodes && ctx; nnode++)
        sxi_jparse_destroy(ctx[nnode].J);
    free(cbdata);
    sxi_query_free(proto);
    free(ctx);

    return ret;
}

/* Check node states and mark dead nodes as faulty. A node is considered dead when it is not available for more than assumed timeout.
 * If there already exist a nodes ignoring job, then only check its status and exit. Returns negative when error occured.
 *
 * Note: This function should be called inside transaction on raft state to avoid role change races. This function does not
 *       perform any remote queries, it makes an internal job and should not cause database locks being held too long.
 */
static int raft_ignore_dead_nodes(sx_hashfs_t *h, sx_raft_state_t *state, const sx_nodelist_t *nodes, unsigned int nnodes, int hdist_changed, uint64_t hb_deadtime) {
    unsigned int i;
    struct timeval now;
    sx_nodelist_t *faulty = NULL, *targets = NULL;
    unsigned min_replica;
    const sx_hashfs_volume_t *vol;
    rc_ty s;
    int ret = -1;
    const sx_node_t *me = sx_hashfs_self(h);

    if(!state || !nodes || !me)
        return -1;

    min_replica = state->leader_state.nnodes;

    if(state->leader_state.job_scheduled) {
        job_status_t job_status;
        const char *job_message;

        /* When the job is already scheduled, avoid trying to reschedule it again.
         * Check its status instead. */
        if((s = sx_hashfs_job_result(h, state->leader_state.job_id, 0, &job_status, &job_message)) != OK) {
            WARN("Failed to check job %lld status", (long long)state->leader_state.job_id);
            return -1;
        }

        /* When job finishes (with success or not) the job_scheduled field is reset.
         * Also all nodes which has is_faulty flag enabled will have it reset. This is done
         * in error handler. */
        if(job_status == JOB_OK) {
            state->leader_state.job_scheduled = 0;
            state->leader_state.job_id = -1LL;
        } else if(job_status == JOB_ERROR) {
            WARN("Job %lld failed: %s", (long long)state->leader_state.job_id, job_message);
            state->leader_state.job_scheduled = 0;
            state->leader_state.job_id = -1LL;
            return -1;
        }

        ret = 0;
        goto raft_ignore_dead_nodes_err;
    }

    if(sx_hashfs_is_changing_volume_replica(h)) {
        DEBUG("Marking dead nodes is skipped due to a volume replica modification being in progress");
        ret = 0;
        goto raft_ignore_dead_nodes_err;
    }

    /* Iterate over volumes in order to find a volume with minimum replica */
    for(s = sx_hashfs_volume_first(h, &vol, NULL); s == OK; s = sx_hashfs_volume_next(h)) {
        if(vol->effective_replica < min_replica)
            min_replica = vol->effective_replica;
    }

    if(s != ITER_NO_MORE) {
        WARN("Failed to check minimum volumes replica");
        return -1;
    }

    gettimeofday(&now, NULL);
    /* Iterate over list and find dead nodes. Do it inside transaction in order to avoid state change race. */
    for(i = 0; i < state->leader_state.nnodes; i++) {
        if(!state->leader_state.node_states[i].hbeat_success && sxi_timediff(&now, &state->leader_state.node_states[i].last_contact) > hb_deadtime) {
            sx_node_t *node;

            /* Node is dead, mark it as faulty */

            DEBUG("Node %s is dead", state->leader_state.node_states[i].node.string);
            if(!faulty) {
                /* Prepare faulty nodes list */
                faulty = sx_nodelist_new();
                if(!faulty) {
                    INFO("Out of memory allocating faulty nodes list");
                    return -1;
                }
            }

            if(!(node = sx_node_new(&state->leader_state.node_states[i].node, "127.0.0.1", "127.0.0.1", 1))) {
                INFO("Out of memory allocating faulty node %s", state->leader_state.node_states[i].node.string);
                goto raft_ignore_dead_nodes_err;
            }

            if(sx_nodelist_add(faulty, node)) {
                INFO("Failed to add node to faulty nodelist");
                goto raft_ignore_dead_nodes_err;
            }

            min_replica--;
            DEBUG("Faulty nodes count: %d, min_replica: %d", sx_nodelist_count(faulty), min_replica);
            if(min_replica == 0)
                break; /* Not enough replica */
        }
    }

    /* Check if faulty nodelist is filled and we have enough replicas reserved for volumes */
    if(min_replica && faulty) {
        sx_blob_t *b;
        const void *data;
        unsigned int data_len;

        INFO("Setting %d node(s) as faulty due to heartbeat timeout", sx_nodelist_count(faulty));

        targets = sx_nodelist_new();
        if(!targets) {
            INFO("Out of memory allocating job targets");
            goto raft_ignore_dead_nodes_err;
        }

        for(i = 0; i < state->leader_state.nnodes; i++) {
            const sx_node_t *node = sx_nodelist_get(nodes, i);
            if(sx_nodelist_lookup(faulty, sx_node_uuid(node)))
                continue;

            /* If the leader created a nodes ignoring job knowing that it had failed to contact all the healthy
             * nodes (those that has not hbeat_success flag set, but did not time out), the job would most probably fail.
             * It is better to skip creating such a job and wait for those alive nodes to become up again or time out too. */
            if(!state->leader_state.node_states[i].hbeat_success) {
                DEBUG("Not all nodes successfully received heartbeat, but are not considered dead yet");
                ret = 0;
                goto raft_ignore_dead_nodes_err;
            }

            if(sx_nodelist_add(targets, sx_node_dup(node))) {
                INFO("Out of memory preparing job targets");
                goto raft_ignore_dead_nodes_err;
            }
        }

        /* Nodelist created, the new job is gonna be created now. */
        b = sx_nodelist_to_blob(faulty);
        if(!b) {
            INFO("Out of memory allocating nodelist blob");
            goto raft_ignore_dead_nodes_err;
        }

        sx_blob_to_data(b, &data, &data_len);
        s = sx_hashfs_job_new(h, 0, &state->leader_state.job_id, JOBTYPE_IGNODES, 20 * sx_nodelist_count(targets), "IGNODES", data, data_len, targets);
        sx_blob_free(b);

        if(s != OK)
            WARN("Failed to set %d node(s) as faulty: %s", sx_nodelist_count(faulty), msg_get_reason());
        else {
            state->leader_state.job_scheduled = 1;
            DEBUG("Successfully scheduled nodes ignoring job: %lld", (long long)state->leader_state.job_id);
        }
    } else if(faulty) {/* faulty is set when at least one node is considered dead and should be ignored */
        DEBUG("Cannot mark %d nodes as faulty due to minimum volumes replica requirement not met", sx_nodelist_count(faulty));
        snprintf(state->leader_state.msg, sizeof(state->leader_state.msg), "Unable to automatically disable dead node(s) because minimum replica requirements are not met");
    }

    ret = 0;
raft_ignore_dead_nodes_err:
    if(!state->leader_state.job_scheduled) {
        for(i = 0; i < state->leader_state.nnodes; i++)
            state->leader_state.node_states[i].is_faulty = 0; /* Reset the faulty flag when job is not shceduled to allow further pings being performed */
    }
    sx_nodelist_delete(targets);
    sx_nodelist_delete(faulty);
    return ret;
}

static rc_ty raft_leader_send_heartbeat(sx_hashfs_t *h, sx_raft_state_t *state, const sx_nodelist_t *nodes, unsigned int nnodes, int hdist_changed, uint64_t hb_deadtime) {
    const sx_node_t *me = sx_hashfs_self(h);
    rc_ty s;
    sx_raft_term_t max_recv_term;
    int64_t max_recv_hdist_version = 0;
    sx_raft_state_t save_state;
    unsigned int state_changed = 0;
    sx_hashfs_version_t max_recv_hashfs_version;

    if(!state || !me || !nodes)
        return EINVAL;

    version_init(&max_recv_hashfs_version);
    s = raft_rpc_bcast(h, state, RAFT_RPC_APPEND_ENTRIES, nodes, nnodes, &max_recv_term, &max_recv_hdist_version, &max_recv_hashfs_version, NULL);
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

    if(save_state.current_term.term < max_recv_term.term || save_state.leader_state.hdist_version < max_recv_hdist_version || sx_hashfs_version_cmp(sx_hashfs_version(h), &max_recv_hashfs_version) < 0) {
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
        *save_state.leader_state.msg = '\0';

        /* Successfully called heartbeats, last contact fields are updated. Consider whether some nodes need
         * to be marked as faulty and perform this operation when safe. */
        if(hb_deadtime && raft_ignore_dead_nodes(h, &save_state, nodes, nnodes, hdist_changed, hb_deadtime))
            WARN("Failed to mark dead nodes as faulty");
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

static rc_ty raft_election_start(sx_hashfs_t *h, sx_raft_state_t *state, const sx_nodelist_t *nodes, unsigned int nnodes, uint64_t hb_keepalive, int *won_election) {
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
    sx_hashfs_version_t max_recv_hashfs_version;

    if(!state || !me || !nodes || !won_election) {
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

    version_init(&max_recv_hashfs_version);

    /* Did not win the election so far */
    *won_election = 0;

    /* Randomize new ET */
    state->election_timeout = sxi_rand() % 2 * hb_keepalive + 3 * hb_keepalive; /* inside [3*hb_keepalive,5*hb_keepalive) */

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

    ret = raft_rpc_bcast(h, state, RAFT_RPC_REQUEST_VOTE, nodes, nnodes, &max_recv_term, &max_recv_hdist_version, &max_recv_hashfs_version, &succeeded);
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

    if(state->current_term.term < max_recv_term.term || sx_hashfs_hdist_getversion(h) < max_recv_hdist_version || sx_hashfs_version_cmp(sx_hashfs_version(h), &max_recv_hashfs_version) < 0) {
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
        /* Mark the election success flag to be positive */
        *won_election = 1;
    }

    if(state_changed) {
        if((s = sx_hashfs_raft_state_set(h, &save_state)) != OK) {
            WARN("Failed to save new raft state: %s", msg_get_reason());
            sx_hashfs_raft_state_abort(h);
            sx_hashfs_raft_state_empty(h, &save_state);
            free(node_states);
            return s;
        }
        if(sx_hashfs_raft_state_end(h)) {
            WARN("Failed to save raft state");
            sx_hashfs_raft_state_empty(h, &save_state);
            free(node_states);
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
        WARN("Cannot allocate node states list");
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

static void raft_hbeat(sx_hashfs_t *h, int hdist_changed, int hb_keepalive_changed, uint64_t hb_keepalive, uint64_t hb_deadtime) {
    sx_raft_state_t state;
    struct timeval now;
    const sx_nodelist_t *nodes;
    unsigned int nnodes;
    int reload_state = 0;

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
        INFO("Failed to load raft state: %s", msg_get_reason());
        return;
    }

    if(hb_keepalive_changed) {
        DEBUG("'hb_keepalive' has recently changed, recalculating election timeout");
        /* Randomize new ET, because new hb_keepalive setting values has been set */
        state.election_timeout = sxi_rand() % 2 * hb_keepalive + 3 * hb_keepalive; /* inside [3*hb_keepalive,5*hb_keepalive) */
        reload_state = 1;
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
            reload_state = 0;
        } else
            sx_hashfs_raft_state_abort(h);
    } else if(sxi_timediff(&now, &state.last_contact) > state.election_timeout) {
        int won_election = 0;
        DEBUG("Election timeout elapsed, switching to CANDIDATE state");
        /* Election timeout reached, start an election */
        if(raft_election_start(h, &state, nodes, nnodes, hb_keepalive, &won_election)) {
            WARN("Failed to start an election");
            goto raft_hbeat_err;
        }

        if(won_election)
           reload_state = 1;
    } else {
        /* Database transaction is open, no changes are made */
        sx_hashfs_raft_state_abort(h);
    }

    if(reload_state) {
        /* Winning an election requires reloading the raft state */
        sx_hashfs_raft_state_empty(h, &state);

        if(sx_hashfs_raft_state_begin(h)) {
            INFO("Failed to load raft state: Database is locked");
            goto raft_hbeat_err;
        }

        if(sx_hashfs_raft_state_get(h, &state)) {
            INFO("Failed to load raft state: %s", msg_get_reason());
            goto raft_hbeat_err;
        }

        /* Only reloaded state, close db transaction to not hold it while waiting for heartbeat queries */
        sx_hashfs_raft_state_abort(h);
    }

    /* No database transaction open here */
    if(state.role == RAFT_ROLE_LEADER && raft_leader_send_heartbeat(h, &state, nodes, nnodes, hdist_changed, hb_deadtime))
        DEBUG("Failed to send heartbeat query to all of the nodes");

raft_hbeat_err:
    sx_hashfs_raft_state_empty(h, &state);
}

#define HB_KEEPALIVE_DEFAULT    20LL
/* Disabled by default */
#define HB_DEADTIME_DEFAULT     0LL
#define HB_INITDEAD_DEFAULT     120LL

int hbeatmgr(sxc_client_t *sx, const char *dir, int pipe) {
    struct sigaction act;
    sx_hashfs_t *hashfs = NULL;
    uint64_t hb_deadtime, hb_initdead, hb_keepalive = 0;
    struct timeval started, now;

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

    gettimeofday(&started, NULL);
    hashfs = sx_hashfs_open(dir, sx);
    if(!hashfs) {
	CRIT("Failed to initialize the hash server interface");
	goto hbeat_err;
    }

    DEBUG("Heartbeat manager started");

    while(!terminate) {
	int dc;
        uint64_t prev_hb_keepalive = hb_keepalive;

        if(sx_hashfs_cluster_settings_get_uint64(hashfs, "hb_keepalive", &hb_keepalive)) {
            WARN("Failed to get hb_keepalive setting, defaulting to %llds", HB_KEEPALIVE_DEFAULT);
            hb_keepalive = HB_KEEPALIVE_DEFAULT;
        }

        gettimeofday(&now, NULL);
        if(sx_hashfs_cluster_settings_get_uint64(hashfs, "hb_initdead", &hb_initdead)) {
            WARN("Failed to get hb_initdead setting, defaulting to %llds", HB_INITDEAD_DEFAULT);
            hb_initdead = HB_INITDEAD_DEFAULT;
        }

        /* If node has started before hb_initdead timeout is reached, do not exclude dead nodes */
        if(sxi_timediff(&now, &started) <= hb_initdead)
            hb_deadtime = 0;
        else if(sx_hashfs_cluster_settings_get_uint64(hashfs, "hb_deadtime", &hb_deadtime)) {
            WARN("Failed to get hb_deadtime setting, defaulting to %llds", HB_DEADTIME_DEFAULT);
            hb_deadtime = HB_DEADTIME_DEFAULT;
        }

        if(wait_trigger(pipe, (float)hb_keepalive, NULL))
            break;

	dc = sx_hashfs_distcheck(hashfs);
	if(dc < 0) {
	    CRIT("Failed to reload distribution");
	    goto hbeat_err;
	} else if(dc > 0)
	    INFO("Distribution reloaded");

	DEBUG("Beat!");
        if(!sx_storage_is_bare(hashfs) && !sx_hashfs_is_rebalancing(hashfs) && !sx_hashfs_is_orphan(hashfs)) {
	    raft_hbeat(hashfs, dc > 0, prev_hb_keepalive != hb_keepalive, hb_keepalive, hb_deadtime);
	    sx_hashfs_checkpoint_hbeatdb(hashfs);
	}
    }

 hbeat_err:
    /*****************
      DO CLEANUP HERE
    ******************/
    sx_hashfs_close(hashfs);
    DEBUG("Heartbeat manager terminated");

    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}

