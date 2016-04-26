/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef _SXPROTO_H
#define _SXPROTO_H

#include "sx.h"
#include "default.h"
#define EXPIRE_TEXT_LEN 18

enum sxi_cluster_verb { REQ_GET = 0, REQ_PUT, REQ_HEAD, REQ_DELETE };
typedef struct _sxi_query_t {
    enum sxi_cluster_verb verb;
    char *path;
    void *content;
    unsigned int content_len;
    unsigned int content_allocated;
    int comma;
} sxi_query_t;

enum sxi_hashop_kind {
    HASHOP_NONE = 0,
    HASHOP_RESERVE,
    HASHOP_CHECK,
    HASHOP_INUSE,
    HASHOP_SKIP
};

sxi_query_t *sxi_useradd_proto(sxc_client_t *sx, const char *username, const uint8_t *uid, const uint8_t *key, int admin, const char *desc, int64_t quota, sxc_meta_t *meta);
sxi_query_t *sxi_userclone_proto(sxc_client_t *sx, const char *existingname, const char *username, const uint8_t *uid, const uint8_t *key, const char *desc, sxc_meta_t *meta);
sxi_query_t *sxi_useronoff_proto(sxc_client_t *sx, const char *username, int enable, int all_clones);
sxi_query_t *sxi_userdel_proto(sxc_client_t *sx, const char *username, const char *newowner, int all_clones);
sxi_query_t *sxi_usermod_proto(sxc_client_t *sx, const char *username, const uint8_t *key, int64_t quota, const char *description, sxc_meta_t *custom_meta);
sxi_query_t *sxi_volumeadd_proto(sxc_client_t *sx, const char *volname, const char *owner, int64_t size, unsigned int replica, unsigned int revisions, sxc_meta_t *metadata, const void *global_id, unsigned int global_id_len);
sxi_query_t *sxi_flushfile_proto(sxc_client_t *sx, const char *token);
sxi_query_t *sxi_fileadd_proto_begin(sxc_client_t *sx, const char *volname, const char *path, const char *revision, const char *revision_id, int64_t pos, int64_t blocksize, int64_t size);
/* New file propagation, s2s only */
sxi_query_t *sxi_fileadd_proto_begin_internal(sxc_client_t *sx, const char *global_vol_id_hex, const char *path, const char *revision, const char *revision_id, int64_t pos, int64_t blocksize, int64_t size);
sxi_query_t *sxi_fileadd_proto_addhash(sxc_client_t *sx, sxi_query_t *query, const char *hexhash);
sxi_query_t *sxi_fileadd_proto_end(sxc_client_t *sx, sxi_query_t *query, sxc_meta_t *metadata);
sxi_query_t *sxi_filedel_proto(sxc_client_t *sx, const char *volname, const char *path, const char *revision);
/* File deletion propagation query, s2s only */
sxi_query_t *sxi_filedel_proto_internal(sxc_client_t *sx, const char *global_vol_id_hex, const char *path, const char *revision);

sxi_query_t *sxi_massdel_proto(sxc_client_t *sx, const char *volname, const char *pattern, int recursive);

typedef struct {
    uint8_t b[SXI_SHA1_BIN_LEN];
} sx_hash_t;

typedef struct {
    sx_hash_t revision_id;
    sx_hash_t global_vol_id;
    int has_vol_id;
    unsigned replica;
} block_meta_entry_t;

typedef struct {
    uint8_t b[1+SXI_SHA1_BIN_LEN];
} sx_block_meta_index_t;

typedef struct {
    sx_hash_t hash;
    sx_block_meta_index_t cursor;
    unsigned int blocksize;
    block_meta_entry_t *entries;
    unsigned int count;
} block_meta_t;

sxi_query_t *sxi_hashop_proto_check(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len);
sxi_query_t *sxi_hashop_proto_reserve(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, const sx_hash_t *global_vol_id, const sx_hash_t *reserve_id, const sx_hash_t *revision_id, unsigned replica, uint64_t op_expires_at);
sxi_query_t *sxi_hashop_proto_inuse_begin(sxc_client_t *sx, const sx_hash_t *reserve_id);
sxi_query_t *sxi_hashop_proto_inuse_hash(sxc_client_t *sx, sxi_query_t *query, const block_meta_t *blockmeta);
sxi_query_t *sxi_hashop_proto_inuse_end(sxc_client_t *sx, sxi_query_t *query);
sxi_query_t *sxi_hashop_proto_revision(sxc_client_t *sx, unsigned blocksize, const sx_hash_t *revision_id, int op);

sxi_query_t *sxi_nodeinit_proto(sxc_client_t *sx, const char *cluster_name, const char *node_uuid, uint16_t http_port, int ssl_flag, const char *ssl_file);
sxi_query_t *sxi_distribution_proto_begin(sxc_client_t *sx, const void *cfg, unsigned int cfg_len, const char *swver);
sxi_query_t *sxi_distribution_proto_add_faulty(sxc_client_t *sx, sxi_query_t *query, const char *node_uuid);
sxi_query_t *sxi_distribution_proto_end(sxc_client_t *sx, sxi_query_t *query);

sxi_query_t *sxi_volsizes_proto_begin(sxc_client_t *sx);
sxi_query_t *sxi_volsizes_proto_add_volume(sxc_client_t *sx, sxi_query_t *query, const char *volname, int64_t size, int64_t fsize, int64_t nfiles);
sxi_query_t *sxi_volsizes_proto_end(sxc_client_t *sx, sxi_query_t *query);

sxi_query_t *sxi_volume_mod_proto(sxc_client_t *sx, const char *volume, const char *newname, const char *newowner, int64_t newsize, int max_revs, sxc_meta_t *meta);
/* Volume modification propagation, s2s only */
sxi_query_t *sxi_volume_mod_proto_internal(sxc_client_t *sx, const char *global_vol_id_hex, const char *newname, const char *newowner, int64_t newsize, int max_revs, sxc_meta_t *meta);

/* Distribution lock proto: set lock=1 to acquire lock, 0 to release it */
sxi_query_t *sxi_distlock_proto(sxc_client_t *sx, int lock, const char *lockid);

typedef const char* (*acl_cb_t)(void *ctx);
sxi_query_t *sxi_volumeacl_proto(sxc_client_t *sx, const char *volname,
                                 acl_cb_t grant_read, acl_cb_t grant_write, acl_cb_t grant_manager,
                                 acl_cb_t revoke_read, acl_cb_t revoke_write, acl_cb_t revoke_manager,
                                 void *ctx);

sxi_query_t *sxi_cluster_mode_proto(sxc_client_t *sx, int readonly);
sxi_query_t *sxi_cluster_upgrade_proto(sxc_client_t *sx);

sxi_query_t *sxi_cluster_setmeta_proto(sxc_client_t *sx, int timestamp, sxc_meta_t *meta);
sxi_query_t *sxi_cluster_settings_proto(sxc_client_t *sx, int timestamp, sxc_meta_t *meta);

sxi_query_t *sxi_query_create(sxc_client_t *sx, const char *path, enum sxi_cluster_verb verb);
void sxi_query_free(sxi_query_t *query);

/* Raft RequestVote request.
 *
 * term: ID of the candidate's term
 * hdist_version: candidate's hdist version
 * hashfs_version: candidate's hashfs version
 * candidate_uuid: UUID of the candidate node
 * last_log_index: last index of candidate's log
 * last_log_term: ;ast index of candidate's term
 */
sxi_query_t *sxi_raft_request_vote(sxc_client_t *sx, int64_t term, int64_t hdist_version, const char *hashfs_version, const char *candidate_uuid, int64_t last_log_index, int64_t last_log_term);

/* Raft AppendEntries request.
 *
 * term: ID of the leader term
 * hdist_version: leader's hdist version
 * hashfs_version: leader's hashfs version
 * leader_uuid: leader's node UUID string representation
 * prev_log_index: previous leader log index
 * prev_log_term: previous leader term ID
 * leader_commit: index of highest log entry known to be committed
 */
sxi_query_t *sxi_raft_append_entries_begin(sxc_client_t *sx, int64_t term, int64_t hdist_version, const char *hashfs_version, const char *leader_uuid, int64_t prev_log_index, int64_t prev_log_term, int64_t leader_commit);

/* Raft AppendEntries request.
 *
 * index: Index of log entry
 * entry: binary data of the log entry
 * entry_len: length of the log entry binary data
 * comma: set to 1 if this is called more than once to properly place entries in the JSON
 */
sxi_query_t *sxi_raft_append_entries_add(sxc_client_t *sx, sxi_query_t *query, int64_t index, const void *entry, unsigned int entry_len, int comma);

/* Raft AppendEntries request.
 *
 * Use this function to properly enclose request body
 */
sxi_query_t *sxi_raft_append_entries_finish(sxc_client_t *sx, sxi_query_t *query);

/* Schedule mass job slaves on the cluster nodes, used for s2s only */
sxi_query_t *sxi_mass_job_proto(sxc_client_t *sx, unsigned int job_type, time_t job_timeout, const char *job_lockname, const void *job_data, unsigned int job_data_len);
/* Commit a mass job slave on a cluster node, used for s2s only */
sxi_query_t *sxi_mass_job_commit_proto(sxc_client_t *sx, const char *job_id);

/* 2.1.3 -> 2.1.4 upgrade proto */
sxi_query_t *sxi_2_1_4_upgrade_proto(sxc_client_t *sx, const char *volume, const char *maxrev, const char *startfile, const char *startrev);

/* Modify the volume replica value */
sxi_query_t *sxi_replica_change_proto(sxc_client_t *sx, const char *volume, unsigned int prev_replica, unsigned int next_replica);

#endif
