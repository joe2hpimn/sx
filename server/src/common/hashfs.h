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

#ifndef __HASHFS_H
#define __HASHFS_H

#include "default.h"
#include "utils.h"
#include "nodes.h"
#include "job_common.h"
#include "../libsx/src/cluster.h"
#include "sxdbi.h"
#include "hashop.h"

#define TOKEN_RAND_BYTES 16
#define REV_TIME_LEN lenof("YYYY-MM-DD hh:mm:ss.sss")
#define REV_LEN (REV_TIME_LEN + 1 + TOKEN_RAND_BYTES * 2)

/* Number of fds required to open the databases */
#define MAX_FDS 1024

/* various constants, see bug #335, all times in seconds */
/* FIXME: find a better place, make admin settable */
#define JOB_FILE_MAX_TIME (24*60*60 /* 1 day */)
#define JOBMGR_DELAY_MIN 1
#define JOBMGR_DELAY_MAX 2
#define JOBMGR_UNDO_TIMEOUT 300 /* 300 seconds per node */
#define TOPUSH_EXPIRE 900
#define BLOCKMGR_RESCHEDULE 24
#define GC_GRACE_PERIOD JOB_FILE_MAX_TIME
#define GC_UPLOAD_MINSPEED 65536 /* in bytes / s */
#define GC_MIN_LATENCY 200 /* ms */

#define SXLIMIT_MIN_NODE_SIZE (1*1024*1024)

#define SXLIMIT_MIN_VOLNAME_LEN 2
#define SXLIMIT_MAX_VOLNAME_LEN 255
#define SXLIMIT_MIN_VOLUME_SIZE (1*1024*1024)
#define SXLIMIT_MAX_VOLUME_SIZE (1LL*1024LL*1024LL*1024LL*1024LL*1024LL)

#define SXLIMIT_MIN_FILENAME_LEN 1
#define SXLIMIT_MAX_FILENAME_LEN 1024
#define SXLIMIT_MIN_FILE_SIZE 0LL
#define SXLIMIT_MAX_FILE_SIZE (10LL*1024LL*1024LL*1024LL*1024LL)

#define SXLIMIT_META_MIN_KEY_LEN 1
#define SXLIMIT_META_MAX_KEY_LEN 256
#define SXLIMIT_META_MIN_VALUE_LEN 0
#define SXLIMIT_META_MAX_VALUE_LEN 1024
#define SXLIMIT_META_MAX_ITEMS 128

#define SXLIMIT_MIN_USERNAME_LEN 2
#define SXLIMIT_MAX_USERNAME_LEN 64

#define SXLIMIT_MIN_REVISIONS 1
#define SXLIMIT_MAX_REVISIONS 64

#define METADBS 16

typedef enum {
    NL_PREV,
    NL_NEXT,
    NL_PREVNEXT,
    NL_NEXTPREV
} sx_hashfs_nl_t;

typedef int64_t sx_uid_t;

/* HashFS main actions */
rc_ty sx_storage_create(const char *dir, sx_uuid_t *cluster, uint8_t *key, int key_size);
rc_ty sx_storage_upgrade(const char *dir);
typedef struct _sx_hashfs_t sx_hashfs_t;
sx_hashfs_t *sx_hashfs_open(const char *dir, sxc_client_t *sx);
void sx_hashfs_checkpoint_passive(sx_hashfs_t *h);
void sx_hashfs_checkpoint_gc(sx_hashfs_t *h);
void sx_hashfs_checkpoint_eventdb(sx_hashfs_t *h);
void sx_hashfs_checkpoint_xferdb(sx_hashfs_t *h);
int sx_storage_is_bare(sx_hashfs_t *h);
int sx_hashfs_is_rebalancing(sx_hashfs_t *h);
int sx_hashfs_is_orphan(sx_hashfs_t *h);
const char *sx_hashfs_cluster_name(sx_hashfs_t *h);
uint16_t sx_hashfs_http_port(sx_hashfs_t *h);
const char *sx_hashfs_ca_file(sx_hashfs_t *h);
void sx_storage_usage(sx_hashfs_t *h, int64_t *allocated, int64_t *committed);
const sx_uuid_t *sx_hashfs_distinfo(sx_hashfs_t *h, unsigned int *version, uint64_t *checksum);
rc_ty sx_storage_activate(sx_hashfs_t *h, const char *name, const sx_uuid_t *node_uuid, uint8_t *admin_uid, unsigned int uid_size, uint8_t *admin_key, int key_size, uint16_t port, const char *ssl_ca_file, const sx_nodelist_t *allnodes);
rc_ty sx_hashfs_setnodedata(sx_hashfs_t *h, const char *name, const sx_uuid_t *node_uuid, uint16_t port, int use_ssl, const char *ssl_ca_crt);
int sx_hashfs_uses_secure_proto(sx_hashfs_t *h);
void sx_hashfs_set_triggers(sx_hashfs_t *h, int job_trigger, int xfer_trigger, int gc_trigger, int gc_expire_trigger);
void sx_hashfs_close(sx_hashfs_t *h);
int sx_hashfs_check(sx_hashfs_t *h, int debug);
int sx_hashfs_extract(sx_hashfs_t *h, const char *destpath);
void sx_hashfs_stats(sx_hashfs_t *h);
int sx_hashfs_analyze(sx_hashfs_t *h, int verbose);
sx_nodelist_t *sx_hashfs_all_hashnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hash_t *hash, unsigned int replica_count);
sx_nodelist_t *sx_hashfs_putfile_hashnodes(sx_hashfs_t *h, const sx_hash_t *hash);
rc_ty sx_hashfs_check_blocksize(unsigned int bs);
int sx_hashfs_distcheck(sx_hashfs_t *h);
time_t sx_hashfs_disttime(sx_hashfs_t *h);
sxi_db_t *sx_hashfs_eventdb(sx_hashfs_t *h);
sxi_db_t *sx_hashfs_xferdb(sx_hashfs_t *h);
sxc_client_t *sx_hashfs_client(sx_hashfs_t *h);
sxi_conns_t *sx_hashfs_conns(sx_hashfs_t *h);
int sx_hashfs_hash_buf(const void *salt, unsigned int salt_len, const void *buf, unsigned int buf_len, sx_hash_t *hash);

typedef struct _sx_hash_challenge_t {
    uint8_t challenge[TOKEN_RAND_BYTES];
    uint8_t response[AUTH_KEY_LEN];
} sx_hash_challenge_t;
rc_ty sx_hashfs_challenge_gen(sx_hashfs_t *h, sx_hash_challenge_t *c, int random_challenge);

int sx_hashfs_check_volume_name(const char *name);
rc_ty sx_hashfs_check_volume_settings(sx_hashfs_t *h, const char *volume, int64_t size, unsigned int replica, unsigned int revisions);
int sx_hashfs_check_meta(const char *key, const void *value, unsigned int value_len);
int sx_hashfs_check_username(const char *name);

rc_ty sx_hashfs_derive_key(sx_hashfs_t *h, unsigned char *key, int len, const char *info);

/* HashFS properties */
rc_ty sx_hashfs_modhdist(sx_hashfs_t *h, const sx_nodelist_t *list);
rc_ty sx_hashfs_hdist_change_req(sx_hashfs_t *h, const sx_nodelist_t *newdist, job_t *job_id);
rc_ty sx_hashfs_hdist_replace_req(sx_hashfs_t *h, const sx_nodelist_t *replacements, job_t *job_id);
rc_ty sx_hashfs_hdist_change_add(sx_hashfs_t *h, const void *cfg, unsigned int cfg_len);
rc_ty sx_hashfs_hdist_replace_add(sx_hashfs_t *h, const void *cfg, unsigned int cfg_len, const sx_nodelist_t *badnodes);
rc_ty sx_hashfs_setignored(sx_hashfs_t *h, const sx_nodelist_t *ignodes);
rc_ty sx_hashfs_hdist_change_commit(sx_hashfs_t *h);
rc_ty sx_hashfs_hdist_change_revoke(sx_hashfs_t *h);
rc_ty sx_hashfs_hdist_rebalance(sx_hashfs_t *h);
rc_ty sx_hashfs_hdist_endrebalance(sx_hashfs_t *h);
int64_t sx_hashfs_hdist_getversion(sx_hashfs_t *h);

const sx_nodelist_t *sx_hashfs_all_nodes(sx_hashfs_t *h, sx_hashfs_nl_t which);
const sx_nodelist_t *sx_hashfs_effective_nodes(sx_hashfs_t *h, sx_hashfs_nl_t which);
const sx_node_t *sx_hashfs_self(sx_hashfs_t *h);
rc_ty sx_hashfs_self_uuid(sx_hashfs_t *h, sx_uuid_t *uuid);
const char *sx_hashfs_self_unique(sx_hashfs_t *h);
const char *sx_hashfs_version(sx_hashfs_t *h);
const sx_uuid_t *sx_hashfs_uuid(sx_hashfs_t *h);

typedef struct _sx_hashfs_user_t {
    char name[SXLIMIT_MAX_USERNAME_LEN+1];
    sx_uid_t id;
    uint8_t uid[AUTH_UID_LEN];
    uint8_t key[AUTH_KEY_LEN];
    int role;
} sx_hashfs_user_t;

rc_ty sx_hashfs_create_user(sx_hashfs_t *h, const char *user, const uint8_t *uid, unsigned uid_size, const uint8_t *key, unsigned key_size, int role, const char *desc);
rc_ty sx_hashfs_user_newkey(sx_hashfs_t *h, const char *user, const uint8_t *key, unsigned key_size);
rc_ty sx_hashfs_delete_user(sx_hashfs_t *h, const char *username, const char *new_owner, int all_clones);
rc_ty sx_hashfs_get_uid(sx_hashfs_t *h, const char *user, int64_t *uid);
rc_ty sx_hashfs_get_uid_role(sx_hashfs_t *h, const char *user, int64_t *uid, int *role);
rc_ty sx_hashfs_get_user_by_uid(sx_hashfs_t *h, sx_uid_t uid, uint8_t *user, int inactivetoo);
rc_ty sx_hashfs_get_user_by_name(sx_hashfs_t *h, const char *name, uint8_t *user, int inactivetoo);
const char *sx_hashfs_authtoken(sx_hashfs_t *h);
char *sxi_hashfs_admintoken(sx_hashfs_t *h);
rc_ty sx_hashfs_uid_get_name(sx_hashfs_t *h, uint64_t uid, char *name, unsigned len);
rc_ty sx_hashfs_user_onoff(sx_hashfs_t *h, const char *user, int enable, int all_clones);
/* Generate unique user ID for new user */
rc_ty sx_hashfs_generate_uid(sx_hashfs_t *h, uint8_t *uid);

typedef int (*user_list_cb_t)(sx_uid_t user_id, const char *username, const uint8_t *user, const uint8_t *key, int is_admin, const char *decs, void *ctx);
rc_ty sx_hashfs_list_users(sx_hashfs_t *h, const uint8_t *list_clones, user_list_cb_t cb, int desc, void *ctx);

#define CLUSTER_USER (const uint8_t*)"\x08\xb5\x12\x4c\x44\x7f\x00\xb2\xcd\x38\x31\x3f\x44\xe3\x93\xfd\x44\x84\x47"
#define ADMIN_USER (const uint8_t*)"\xd0\x33\xe2\x2a\xe3\x48\xae\xb5\x66\x0f\xc2\x14\x0a\xec\x35\x85\x0c\x4d\xa9\x97"
rc_ty sx_hashfs_grant(sx_hashfs_t *h, uint64_t uid, const char *volume, int priv);
rc_ty sx_hashfs_revoke(sx_hashfs_t *h, uint64_t uid, const char *volume, int priv);

#define ROLE_USER 0
#define ROLE_ADMIN 1
#define ROLE_CLUSTER 2
/* Volume ops */
void sx_hashfs_volume_new_begin(sx_hashfs_t *h);
rc_ty sx_hashfs_volume_new_addmeta(sx_hashfs_t *h, const char *key, const void *value, unsigned int value_len);
rc_ty sx_hashfs_volume_new_finish(sx_hashfs_t *h, const char *volume, int64_t size, unsigned int replica, unsigned int revisions, sx_uid_t owner_uid);
/* Returns (and logs reason/error):
 *  - EFAULT
 *  - EINVAL
 */
rc_ty sx_hashfs_volume_enable(sx_hashfs_t *h, const char *volume);
rc_ty sx_hashfs_volume_disable(sx_hashfs_t *h, const char *volume);
rc_ty sx_hashfs_volume_delete(sx_hashfs_t *h, const char *volume, int force);
typedef struct _sx_hashfs_volume_t {
    int64_t id;
    int64_t size;
    int64_t cursize;
    unsigned int max_replica;
    unsigned int effective_replica;
    unsigned int revisions;
    char name[SXLIMIT_MAX_VOLNAME_LEN + 1];
    sx_uid_t owner;
    /* UNIX timestamp of last change time */
    int64_t changed;
} sx_hashfs_volume_t;

rc_ty sx_hashfs_list_clones_first(sx_hashfs_t *h, sx_uid_t id, const sx_hashfs_user_t **user, int inactivetoo);
rc_ty sx_hashfs_list_clones_next(sx_hashfs_t *h);

rc_ty sx_hashfs_volume_first(sx_hashfs_t *h, const sx_hashfs_volume_t **volume, const uint8_t *uid);
rc_ty sx_hashfs_volume_next(sx_hashfs_t *h);
rc_ty sx_hashfs_volume_by_name(sx_hashfs_t *h, const char *name, const sx_hashfs_volume_t **volume);
rc_ty sx_hashfs_volume_by_id(sx_hashfs_t *h, int64_t id, const sx_hashfs_volume_t **volume);
rc_ty sx_hashfs_volumemeta_begin(sx_hashfs_t *h, const sx_hashfs_volume_t *volume);
rc_ty sx_hashfs_volumemeta_next(sx_hashfs_t *h, const char **key, const void **value, unsigned int *value_len);
rc_ty sx_hashfs_all_volnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hashfs_volume_t *volume, int64_t size, sx_nodelist_t **nodes, unsigned int *block_size);
rc_ty sx_hashfs_effective_volnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hashfs_volume_t *volume, int64_t size, sx_nodelist_t **nodes, unsigned int *block_size);
int sx_hashfs_is_or_was_my_volume(sx_hashfs_t *h, const sx_hashfs_volume_t *vol);
typedef int (*acl_list_cb_t)(const char *username, int priv, int is_owner, void *ctx);
rc_ty sx_hashfs_list_acl(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, sx_uid_t uid, int uid_priv, acl_list_cb_t cb, void *ctx);
/* Set volume size to given value */
rc_ty sx_hashfs_reset_volume_cursize(sx_hashfs_t *h, int64_t volume_id, int64_t size);
/* Atomically add given value to volume size */
rc_ty sx_hashfs_update_volume_cursize(sx_hashfs_t *h, int64_t volume_id, int64_t size);

/* Retrieve timestamp used to compute intervals of volumes pushing */
struct timeval* sx_hashfs_volsizes_timestamp(sx_hashfs_t *h);
/* Update push time for particular node */
rc_ty sx_hashfs_update_node_push_time(sx_hashfs_t *h, const sx_node_t *n);
/* Check if given volume is not owned by given node and it is not owned by this node */
int sx_hashfs_is_volume_to_push(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const sx_node_t *node);
/* Return time of last push performed to given node */
int64_t sx_hashfs_get_node_push_time(sx_hashfs_t *h, const sx_node_t *n);
/* Return 1 if given node is a volnode for given volume */
int sx_hashfs_is_node_volume_owner(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_node_t *n, const sx_hashfs_volume_t *vol);
int sx_hashfs_is_node_faulty(sx_hashfs_t *h, const sx_uuid_t *node_uuid);
int sx_hashfs_is_node_ignored(sx_hashfs_t *h, const sx_uuid_t *node_uuid);
rc_ty sx_hashfs_set_unfaulty(sx_hashfs_t *h, const sx_uuid_t *nodeid, int64_t dist_rev);

/* Change volume ownership and/or size*/
rc_ty sx_hashfs_volume_mod(sx_hashfs_t *h, const char *volume, const char *newowner, int64_t newsize, int max_revs);

/* File list */
typedef struct _sx_hashfs_file_t {
    int64_t volume_id;
    int64_t file_size;
    unsigned int block_size;
    unsigned int nblocks;
    unsigned int created_at;
    char name[SXLIMIT_MAX_FILENAME_LEN+2];
    char revision[REV_LEN+1];
} sx_hashfs_file_t;
rc_ty sx_hashfs_list_first(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *pattern, const sx_hashfs_file_t **file, int recurse, const char *after);
rc_ty sx_hashfs_list_next(sx_hashfs_t *h);
rc_ty sx_hashfs_revision_first(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *name, const sx_hashfs_file_t **file, int reversed);
rc_ty sx_hashfs_revision_next(sx_hashfs_t *h, int reversed);
rc_ty sx_hashfs_list_etag(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *pattern, int8_t recurse, sx_hash_t *etag);

/* 0 = stop, 1 = continue */
typedef int (*sx_find_cb_t)(const sx_hashfs_volume_t *volume, const sx_hashfs_file_t *file, const sx_hash_t *contents, unsigned int nblocks, void *ctx);
rc_ty sx_hashfs_file_find(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char* lastpath, const char *lastrev, const char *maxrev, sx_find_cb_t cb, void *ctx);

/* File get */
rc_ty sx_hashfs_getfile_begin(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, sx_hashfs_file_t *filedata, sx_hash_t *etag);
uint64_t sx_hashfs_getfile_count(sx_hashfs_t *h);
rc_ty sx_hashfs_getfile_block(sx_hashfs_t *h, const sx_hash_t **hash, sx_nodelist_t **nodes);
void sx_hashfs_getfile_end(sx_hashfs_t *h);

rc_ty sx_hashfs_getfilemeta_begin(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, unsigned int *created_at, sx_hash_t *etag);
rc_ty sx_hashfs_getfilemeta_next(sx_hashfs_t *h, const char **key, const void **value, unsigned int *value_len);

/* Block xfer */
rc_ty sx_hashfs_block_get(sx_hashfs_t *h, unsigned int bs, const sx_hash_t *hash, const uint8_t **block);
rc_ty sx_hashfs_block_put(sx_hashfs_t *h, const uint8_t *data, unsigned int bs, unsigned int replica_count, int propagate);

/* hash batch ops for GC */
rc_ty sx_hashfs_hashop_perform(sx_hashfs_t *h, unsigned int block_size, unsigned replica_count, enum sxi_hashop_kind kind, const sx_hash_t *hash, const sx_hash_t *reserve_id, const sx_hash_t *revision_id, uint64_t op_expires_at, int *present);
rc_ty sx_hashfs_hashop_mod(sx_hashfs_t *h, const sx_hash_t *hash, const sx_hash_t *reserve_id, const sx_hash_t *revision_id, unsigned int blocksize, unsigned replica, int count, uint64_t op_expires_at);
rc_ty sx_hashfs_revision_op(sx_hashfs_t *h, unsigned blocksize, const sx_hash_t *revision_id, int op);
rc_ty sx_hashfs_gc_periodic(sx_hashfs_t *h, int *terminate, int grace_period);
rc_ty sx_hashfs_gc_run(sx_hashfs_t *h, int *terminate);
rc_ty sx_hashfs_gc_info(sx_hashfs_t *h, int *terminate);
rc_ty sx_hashfs_gc_expire_all_reservations(sx_hashfs_t *h);

/* Update volume sizes on remote non-volnodes */
rc_ty sx_hashfs_push_volume_sizes(sx_hashfs_t *h);

/* Delete all outdated revisions of files sotred in volume */
rc_ty sx_hashfs_delete_old_revs(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *name, unsigned int *deletes_scheduled);

/* File put */

const char *sx_hashfs_geterrmsg(sx_hashfs_t *h);
rc_ty sx_hashfs_check_file_size(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const char *filename, int64_t size);
rc_ty sx_hashfs_putfile_begin(sx_hashfs_t *h, sx_uid_t user_id, const char *volume, const char *file, const sx_hashfs_volume_t **volptr);
rc_ty sx_hashfs_putfile_extend_begin(sx_hashfs_t *h, sx_uid_t user_id, const uint8_t *user, const char *token);
rc_ty sx_hashfs_putfile_putblock(sx_hashfs_t *h, sx_hash_t *hash);
rc_ty sx_hashfs_putfile_putmeta(sx_hashfs_t *h, const char *key, const void *value, unsigned int value_len);
rc_ty sx_hashfs_putfile_gettoken(sx_hashfs_t *h, const uint8_t *user, int64_t size_or_seq, const char **token, hash_presence_cb_t hdck_cb, void *hdck_cb_ctx);
rc_ty sx_hashfs_putfile_getblock(sx_hashfs_t *h);
void sx_hashfs_putfile_end(sx_hashfs_t *h);
rc_ty sx_hashfs_createfile_begin(sx_hashfs_t *h);
rc_ty sx_hashfs_createfile_commit(sx_hashfs_t *h, const char *volume, const char *name, const char *revision, int64_t size);
void sx_hashfs_createfile_end(sx_hashfs_t *h);

rc_ty sx_hashfs_make_token(sx_hashfs_t *h, const uint8_t *user, const char *rndhex, unsigned int replica, int64_t expires_at, const char **token);
rc_ty sx_hashfs_token_get(sx_hashfs_t *h, const uint8_t *user, const char *token, unsigned int *replica_count, int64_t *expires_at);
rc_ty sx_hashfs_putfile_commitjob(sx_hashfs_t *h, const uint8_t *user, sx_uid_t user_id, const char *token, job_t *job_id);

typedef struct _sx_hashfs_tmpinfo_t {
    int64_t volume_id;
    int64_t file_size;
    int64_t tmpfile_id;
    const sx_nodelist_t *allnodes; /* The ordered list of nodes to which the nidx's refer to */
    sx_hash_t *all_blocks; /* All unsorted blocks - nblocks items */
    unsigned int *uniq_ids; /* Unique block index (from all_blocks) - nuniq items */
    unsigned int *nidxs; /* Unique block node index (parallel to all_blocks) - nblocks * replica_count items */
    int8_t *avlblty; /* Block availablity (-1, 0 = unavail, >0 = avail) flag index (parallel to all_blocks) - nblocks * replica_count items */
    unsigned int nall; /* Number of blocks */
    unsigned int nuniq; /* Number of unique blocks */
    unsigned int block_size; /* Block size */
    unsigned int replica_count; /* Replica count */
    unsigned int current_replica; /* Replica being presence checked */
    char name[SXLIMIT_MAX_FILENAME_LEN+1]; /* File name */
    char revision[128]; /* File revision */
    int somestatechanged;
} sx_hashfs_tmpinfo_t;
rc_ty sx_hashfs_tmp_getmeta(sx_hashfs_t *h, int64_t tmpfile_id, sxc_meta_t *metadata);
rc_ty sx_hashfs_tmp_getinfo(sx_hashfs_t *h, int64_t tmpfile_id, sx_hashfs_tmpinfo_t **tmpinfo, int recheck_presence);

rc_ty sx_hashfs_getinfo_by_revision(sx_hashfs_t *h, const char *revision, sx_hashfs_file_t *filerev);
rc_ty sx_hashfs_tmp_tofile(sx_hashfs_t *h, const sx_hashfs_tmpinfo_t *missing);
rc_ty sx_hashfs_tmp_delete(sx_hashfs_t *h, int64_t tmpfile_id);

/* File delete */
rc_ty sx_hashfs_file_delete(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *file, const char *revision);
rc_ty sx_hashfs_filedelete_job(sx_hashfs_t *h, sx_uid_t user_id, const sx_hashfs_volume_t *vol, const char *name, const char *revision, job_t *job_id);


/* Users */
typedef enum {
  PRIV_NONE = 0,
  PRIV_READ = 1,
  PRIV_WRITE = 2,
  PRIV_ACL = 4,
  PRIV_ADMIN = 8,
  PRIV_CLUSTER = 16} sx_priv_t;
rc_ty sx_hashfs_get_user_info(sx_hashfs_t *h, const uint8_t *user, sx_uid_t *uid, uint8_t *key, sx_priv_t *basepriv, char **desc);
rc_ty sx_hashfs_get_access(sx_hashfs_t *h, const uint8_t *user, const char *volume, sx_priv_t *access);

/* Jobs */
#define JOB_NO_EXPIRY (60 * 365 * 24 * 60 * 60)
rc_ty sx_hashfs_job_result(sx_hashfs_t *h, job_t job, sx_uid_t uid, job_status_t *status, const char **message);
rc_ty sx_hashfs_job_new_begin(sx_hashfs_t *h);
rc_ty sx_hashfs_job_new_end(sx_hashfs_t *h);
rc_ty sx_hashfs_job_new_abort(sx_hashfs_t *h);
rc_ty sx_hashfs_job_new(sx_hashfs_t *h, sx_uid_t user_id, job_t *job_id, jobtype_t type, unsigned int timeout_secs, const char *lock, const void *data, unsigned int datalen, const sx_nodelist_t *targets);
rc_ty sx_hashfs_job_new_notrigger(sx_hashfs_t *h, job_t parent, sx_uid_t user_id, job_t *job_id, jobtype_t type, unsigned int timeout_secs, const char *lock, const void *data, unsigned int datalen, const sx_nodelist_t *targets);
void sx_hashfs_job_trigger(sx_hashfs_t *h);
rc_ty sx_hashfs_countjobs(sx_hashfs_t *h, sx_uid_t user_id);
rc_ty sx_hashfs_job_lock(sx_hashfs_t *h, const char *owner);
rc_ty sx_hashfs_job_unlock(sx_hashfs_t *h, const char *owner);
unsigned int sx_hashfs_job_file_timeout(sx_hashfs_t *h, unsigned int ndests, uint64_t size);

/* Xfers */
rc_ty sx_hashfs_xfer_tonodes(sx_hashfs_t *h, sx_hash_t *block, unsigned int size, const sx_nodelist_t *targets);
rc_ty sx_hashfs_xfer_tonode(sx_hashfs_t *h, sx_hash_t *block, unsigned int size, const sx_node_t *target);
void sx_hashfs_xfer_trigger(sx_hashfs_t *h);

void sx_hashfs_gc_trigger(sx_hashfs_t *h);

typedef struct {
    block_meta_t *all;
    unsigned long n;
} blocks_t;

void sx_hashfs_blockmeta_free(block_meta_t **blockmeta);

typedef int (*cb_hash)(void *context, unsigned int bs, const sx_hash_t *hash);

/* a no-op, for compatibility with the dumb iteration API proposal */
rc_ty sx_hashfs_br_begin(sx_hashfs_t *h);

/* call this until you get ITER_NO_MORE or an error */
rc_ty sx_hashfs_br_next(sx_hashfs_t *h, block_meta_t **blockmetaptr);

/* must call either delete or done, or you'll eventually see the hash again. */
rc_ty sx_hashfs_br_delete(sx_hashfs_t *h, const block_meta_t *blockmeta);
rc_ty sx_hashfs_br_use(sx_hashfs_t *h, const block_meta_t *blockmeta);
rc_ty sx_hashfs_br_done(sx_hashfs_t *h, const block_meta_t *blockmeta);

rc_ty sx_hashfs_br_find(sx_hashfs_t *h, const sx_block_meta_index_t *previous, unsigned rebalance_ver, const sx_uuid_t *target, block_meta_t **blockmetaptr);

rc_ty sx_hashfs_blkrb_hold(sx_hashfs_t *h, const sx_hash_t *block, unsigned int blocksize, const sx_node_t *node);
rc_ty sx_hashfs_blkrb_can_gc(sx_hashfs_t *h, const sx_hash_t *block, unsigned int blocksize);
rc_ty sx_hashfs_blkrb_release(sx_hashfs_t *h, uint64_t pushq_id);
rc_ty sx_hashfs_blkrb_is_complete(sx_hashfs_t *h);

typedef struct _sx_reloc_t {
    sx_hashfs_volume_t volume;
    sx_hashfs_file_t file;
    sx_hash_t *blocks;
    sxc_meta_t *metadata;
    const sx_node_t *target;
    /* internal fields */
    int64_t reloc_id;
    unsigned int reloc_db;
} sx_reloc_t;
rc_ty sx_hashfs_relocs_populate(sx_hashfs_t *h);
void sx_hashfs_relocs_begin(sx_hashfs_t *h);
rc_ty sx_hashfs_relocs_next(sx_hashfs_t *h, const sx_reloc_t **reloc);
rc_ty sx_hashfs_relocs_delete(sx_hashfs_t *h, const sx_reloc_t *reloc);
void sx_hashfs_reloc_free(const sx_reloc_t *reloc);
rc_ty sx_hashfs_rb_cleanup(sx_hashfs_t *h);
rc_ty sx_hashfs_hdist_set_rebalanced(sx_hashfs_t *h);
typedef enum _sx_inprogress_t {
    INPRG_ERROR = -1,
    INPRG_IDLE = 0,
    INPRG_REBALANCE_RUNNING,
    INPRG_REBALANCE_COMPLETE,
    INPRG_REPLACE_RUNNING,
    INPRG_REPLACE_COMPLETE,
    INPRG_UPGRADE_RUNNING,
    INPRG_UPGRADE_COMPLETE,

    INPRG_LAST
} sx_inprogress_t;
rc_ty sx_hashfs_set_progress_info(sx_hashfs_t *h, sx_inprogress_t state, const char *description);
sx_inprogress_t sx_hashfs_get_progress_info(sx_hashfs_t *h, const char **description);

rc_ty sx_hashfs_replace_getstartblock(sx_hashfs_t *h, unsigned int *version, const sx_node_t **node, int *have_blkidx, uint8_t *blkidx);
rc_ty sx_hashfs_replace_setlastblock(sx_hashfs_t *h, const sx_uuid_t *node, const uint8_t *blkidx);
rc_ty sx_hashfs_replace_getstartfile(sx_hashfs_t *h, char *maxrev, char *startvol, char *startfile, char *startrev);
rc_ty sx_hashfs_replace_setlastfile(sx_hashfs_t *h, char *lastvol, char *lastfile, char *lastrev);
rc_ty sx_hashfs_init_replacement(sx_hashfs_t *h);

rc_ty sx_hashfs_node_status(sx_hashfs_t *h, sxi_node_status_t *status);

/* Distribution lock handling */
rc_ty sx_hashfs_distlock_acquire(sx_hashfs_t *h, const char *lockid);
rc_ty sx_hashfs_distlock_release(sx_hashfs_t *h);
rc_ty sx_hashfs_distlock_get(sx_hashfs_t *h, char *lockid, unsigned int lockid_len);
rc_ty sx_hashfs_job_new_2pc(sx_hashfs_t *h, const job_2pc_t *spec, void *yctx, sx_uid_t uid, job_t *job, int execute);

rc_ty sx_hashfs_cluster_set_mode(sx_hashfs_t *h, int mode);
rc_ty sx_hashfs_cluster_get_mode(sx_hashfs_t *h, int *mode);
rc_ty sx_hashfs_cluster_set_name(sx_hashfs_t *h, const char *name);
rc_ty sx_hashfs_cluster_get_name(sx_hashfs_t *h, const char **name);

int sx_hashfs_is_readonly(sx_hashfs_t *h);

typedef struct {
    sx_hash_t revision_id;
    int32_t blocksize;
    const char *lock;
    int op;
} sx_revision_op_t;
int sx_revision_op_of_blob(sx_blob_t *b, sx_revision_op_t *op);
int sx_unique_fileid(sxc_client_t *sx, const sx_hashfs_volume_t *volume, const char *name, const char *revision, sx_hash_t *fileid);
rc_ty sx_hashfs_upgrade_1_0_prepare(sx_hashfs_t *h);
rc_ty sx_hashfs_upgrade_1_0_local(sx_hashfs_t *h);

typedef int (*lrb_cb_t)(const sx_hashfs_volume_t *vol, const sx_uuid_t *target, const sx_hash_t *revision_id, const sx_hash_t *contents, int64_t nblocks, unsigned blocksize);
typedef int (*lrb_count_t)(int64_t count);
rc_ty sx_hashfs_list_revision_blocks(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const sx_uuid_t *target, sx_hash_t *min_revision_id, unsigned age_limit, unsigned metadb, lrb_cb_t cb, lrb_count_t cb_count);
typedef int (*heal_cb_t)(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const sx_hash_t *min_revision_id_in, int max_age, unsigned metadb);
rc_ty sx_hashfs_remote_heal(sx_hashfs_t *h, heal_cb_t cb);
rc_ty sx_hashfs_heal_update(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, const sx_hash_t *min_revision_id, unsigned metadb);

int sx_hashfs_has_upgrade_job(sx_hashfs_t *h);
const char *sx_hashfs_heal_status_local(sx_hashfs_t *h);
const char *sx_hashfs_heal_status_remote(sx_hashfs_t *h);
#endif
