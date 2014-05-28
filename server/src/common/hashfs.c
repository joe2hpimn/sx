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
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <fnmatch.h>

#include "sxdbi.h"
#include "hashfs.h"
#include "hdist.h"
#include "../libsx/src/misc.h"

#include "sx.h"
#include "qsort.h"
#include "utils.h"
#include "../libsx/src/vcrypto.h"

#define HASHDBS 16
#define METADBS 16
#define GCDBS 1
/* NOTE: HASHFS_VERSION must be kept below 15 bytes */
#define HASHFS_VERSION "WiPfs 2.0"
#define SIZES 3
const char sizedirs[SIZES] = "sml";
const char *sizelongnames[SIZES] = { "small", "medium", "large" };
const unsigned int bsz[SIZES] = {SX_BS_SMALL, SX_BS_MEDIUM, SX_BS_LARGE};

#define HDIST_SEED 0x1337
#define MURMUR_SEED 0xacab
#define TOKEN_REPLICA_LEN 8
#define TOKEN_EXPIRE_LEN 16
#define TOKEN_TEXT_LEN (UUID_STRING_SIZE + 1 + TOKEN_RAND_BYTES * 2 + 1 + TOKEN_REPLICA_LEN + 1 + TOKEN_EXPIRE_LEN + 1 + AUTH_KEY_LEN * 2)

/* FIXME: the following optimization is not currently used (filehash_xxx are no ops)
 * To be reviewed and reenabled or dropped for good */
/* #define FILEHASH_OPTIMIZATION */

#define WARNHASH(X) do {				\
    char _warnhash[sizeof(sx_hash_t)*2+1];		\
    bin2hex((X)->b, sizeof(*X), _warnhash, sizeof(_warnhash));	\
    WARN("(%s): HASH %s", __FUNCTION__, _warnhash); \
    } while(0)

#define DEBUGHASH(MSG, X) do {				\
    char _debughash[sizeof(sx_hash_t)*2+1];		\
    if (UNLIKELY(sxi_log_is_debug(&logger))) {          \
	bin2hex((X)->b, sizeof(*X), _debughash, sizeof(_debughash));	\
	DEBUG("%s: #%s#", MSG, _debughash);				\
    }\
    } while(0)

rc_ty sx_hashfs_check_blocksize(unsigned int bs) {
    unsigned int hs;
    for(hs = 0; hs < SIZES; hs++)
	if(bsz[hs] == bs)
	    break;
    return (hs == SIZES) ? FAIL_BADBLOCKSIZE : OK;
}

static int write_block(int fd, const void *data, uint64_t off, unsigned int data_len) {
    uint8_t *dt = (uint8_t *)data;
    while(data_len) {
	int l = pwrite(fd, dt, data_len, off);
	if(l<0) {
	    if(errno == EINTR)
		continue;
	    msg_set_errno_reason("Failed to write block");
	    return 1;
	}
	data_len -= l;
	dt += l;
	off += l;
    }
    return 0;
}

static int read_block(int fd, uint8_t *dt, uint64_t off, unsigned int buf_len) {
    while(buf_len) {
	int l = pread(fd, dt, buf_len, off);
	if(l<0) {
	    if(errno == EINTR)
		continue;
	    msg_set_errno_reason("Failed to read block");
	    return 1;
	}
	if(!l) {
	    msg_set_reason("Incomplete block read");
	    return 1;
	}
	buf_len -= l;
	dt += l;
	off += l;
    }
    return 0;
}

static int hash_buf(const void *salt, unsigned int salt_len, const void *buf, unsigned int buf_len, sx_hash_t *hash) {
    return sxi_sha1_calc(salt, salt_len, buf, buf_len, hash->b);
}

#define CREATE_DB(DBTYPE) \
do { \
    sqlite3 *handle = NULL;\
    /* Create the dbatabase */ \
    if(sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) { \
	CRIT("Failed to create %s database: %s", DBTYPE, sqlite3_errmsg(handle)); \
	goto create_hashfs_fail; \
    } \
    if (!(db = qnew(handle))) \
        goto create_hashfs_fail;\
    if(qprep(db, &q, "PRAGMA synchronous = OFF") || qstep_noret(q)) \
	goto create_hashfs_fail; \
    qnullify(q); \
    if(qprep(db, &q, "PRAGMA journal_mode = WAL") || qstep_ret(q)) \
	goto create_hashfs_fail; \
    qnullify(q); \
    /* Set create the hashfs table which is a generic k/v store for config items */ \
    if(qprep(db, &q, "CREATE TABLE hashfs (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)") || qstep_noret(q)) \
	goto create_hashfs_fail; \
    qnullify(q); \
    /* Fill in the basic settings */ \
    if(qprep(db, &q, "INSERT INTO hashfs (key, value) VALUES (:k, :v)")) \
	goto create_hashfs_fail; \
    if(qbind_text(q, ":k", "version") || qbind_text(q, ":v", HASHFS_VERSION) || qstep_noret(q)) \
	goto create_hashfs_fail; \
    sqlite3_reset(q); \
    if(qbind_text(q, ":k", "dbtype") || qbind_text(q, ":v", DBTYPE) || qstep_noret(q)) \
	goto create_hashfs_fail; \
    sqlite3_reset(q); \
    if(qbind_text(q, ":k", "cluster") || qbind_blob(q, ":v", cluster->binary, sizeof(cluster->binary)) || qstep_noret(q)) \
	goto create_hashfs_fail; \
    sqlite3_reset(q); \
    DEBUG("creating %s", path);\
} while(0)

/* TODO: share more code */
#define CREATE_DB2(DBTYPE) \
do { \
    sqlite3 *handle = NULL;\
    /* Create the dbatabase */ \
    if(sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) { \
	CRIT("Failed to create %s database: %s", DBTYPE, sqlite3_errmsg(handle)); \
	goto create_hashfs_fail; \
    } \
    if (!(db = qnew(handle))) \
        goto create_hashfs_fail; \
    if(qprep(db, &q, "PRAGMA synchronous=NORMAL") || qstep_noret(q)) \
	goto create_hashfs_fail; \
    qnullify(q); \
    if(qprep(db, &q, "PRAGMA journal_mode = WAL") || qstep_ret(q)) \
	goto create_hashfs_fail; \
    qnullify(q); \
    /* Set create the hashfs table which is a generic k/v store for config items */ \
    if(qprep(db, &q, "CREATE TABLE hashfs (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)") || qstep_noret(q)) \
	goto create_hashfs_fail; \
    qnullify(q); \
    /* Fill in the basic settings */ \
    if(qprep(db, &q, "INSERT INTO hashfs (key, value) VALUES (:k, :v)")) \
	goto create_hashfs_fail; \
    if(qbind_text(q, ":k", "version") || qbind_text(q, ":v", HASHFS_VERSION) || qstep_noret(q)) \
	goto create_hashfs_fail; \
    sqlite3_reset(q); \
    if(qbind_text(q, ":k", "dbtype") || qbind_text(q, ":v", DBTYPE) || qstep_noret(q)) \
	goto create_hashfs_fail; \
    sqlite3_reset(q); \
    if(qbind_text(q, ":k", "cluster") || qbind_blob(q, ":v", cluster->binary, sizeof(cluster->binary)) || qstep_noret(q)) \
	goto create_hashfs_fail; \
    sqlite3_reset(q); \
    DEBUG("creating %s", path);\
} while(0)


static int qlog_set = 0;
rc_ty sx_storage_create(const char *dir, sx_uuid_t *cluster, uint8_t *key, int key_size) {
    unsigned int dirlen, i, j;
    sxi_db_t *db = NULL;
    sqlite3_stmt *q = NULL;
    char *path, dbitem[64];
    int ret = FAIL_EINIT;
    sxc_uri_t *uri = NULL;

    if(!dir || !(dirlen = strlen(dir))) {
	CRIT("Bad path");
	return EINVAL;
    }

    if(ssl_version_check())
	return FAIL_EINIT;

    if(access(dir, R_OK | W_OK | X_OK)) {
	PCRIT("Cannot access storage directory %s", dir);
	return FAIL_EINIT;
    }

    if(!(path = wrap_malloc(dirlen + bsz[SIZES-1])))
	goto create_hashfs_fail;

    /* --- HASHFS db --- */
    sqlite3_config(SQLITE_CONFIG_LOG, qlog, NULL);
    qlog_set = 1;
    sprintf(path, "%s/hashfs.db", dir);
    CREATE_DB("hashfs");
    sqlite3_reset(q); /* q is now prepared for hashfs insertions */

    if(qbind_text(q, ":k", "current_dist_rev") || qbind_int64(q, ":v", 0) || qstep_noret(q))
	goto create_hashfs_fail;
    sqlite3_reset(q);
    if(qbind_text(q, ":k", "current_dist") || qbind_blob(q, ":v", "", 0) || qstep_noret(q))
	goto create_hashfs_fail;

    /* Set the path to the file dbs */
    for(i=0; i<METADBS; i++) {
	sprintf(dbitem, "metadb_%08x", i);
	sprintf(path, "f%08x.db", i);
	sqlite3_reset(q);
	if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
	    goto create_hashfs_fail;
    }

    /* Set the path to the block dbs */
    for(j = 0; j < SIZES; j++) {
	for(i=0; i<HASHDBS; i++) {
	    sprintf(dbitem, "hashdb_%c_%08x", sizedirs[j], i);
	    sprintf(path, "h%c%08x.db", sizedirs[j], i);
	    sqlite3_reset(q);
	    if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
		goto create_hashfs_fail;

	    sprintf(dbitem, "datafile_%c_%08x", sizedirs[j], i);
	    sprintf(path, "h%c%08x.bin", sizedirs[j], i);
	    sqlite3_reset(q);
	    if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
		goto create_hashfs_fail;
	}
    }

    /* Set the path to the temp db */
    strcpy(dbitem, "tempdb");
    strcpy(path, "temp.db");
    sqlite3_reset(q);
    if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
	goto create_hashfs_fail;

    /* Set the path to the event db */
    strcpy(dbitem, "eventdb");
    strcpy(path, "events.db");
    sqlite3_reset(q);
    if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
	goto create_hashfs_fail;

    /* main gc.db */
    sprintf(dbitem, "gcdb");
    sprintf(path, "%s/gc.db",dir);
    sqlite3_reset(q);
    if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
	goto create_hashfs_fail;

    /* Set the path to the xfer db */
    strcpy(dbitem, "xferdb");
    strcpy(path, "xfers.db");
    sqlite3_reset(q);
    if(qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);

    /* Create HASHFS tables */
    if(qprep(db, &q, "CREATE TABLE users (uid INTEGER PRIMARY KEY NOT NULL, user BLOB ("STRIFY(SXI_SHA1_BIN_LEN)") NOT NULL UNIQUE, name TEXT ("STRIFY(SXLIMIT_MAX_USERNAME_LEN)") NOT NULL UNIQUE, key BLOB ("STRIFY(AUTH_KEY_LEN)") NOT NULL UNIQUE, role INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 0)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
/*    if(qprep(db, &q, "CREATE INDEX users_byname ON users(name, enabled)") || qstep_noret(q))
       goto create_hashfs_fail;
    qnullify(q);*/

    if(qprep(db, &q, "INSERT INTO users(uid, user, name, key, role, enabled) VALUES(0, :userhash, :name, :key, :role, 1)") ||
       qbind_blob(q, ":userhash", CLUSTER_USER, AUTH_UID_LEN) ||
       qbind_text(q, ":name", "rootcluster") || qbind_blob(q,":key",key,key_size) ||
       qbind_int64(q, ":role", ROLE_CLUSTER) ||
       qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);

    if(qprep(db, &q, "CREATE TABLE volumes (vid INTEGER PRIMARY KEY NOT NULL, volume TEXT ("STRIFY(SXLIMIT_MAX_VOLNAME_LEN)") NOT NULL UNIQUE, replica INTEGER NOT NULL, maxsize INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, owner_id INTEGER NOT NULL REFERENCES users(uid))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);

    if(qprep(db, &q, "CREATE TABLE vmeta (volume_id INTEGER NOT NULL REFERENCES volumes(vid) ON DELETE CASCADE ON UPDATE CASCADE, key TEXT ("STRIFY(SXLIMIT_META_MAX_KEY_LEN)") NOT NULL, value BLOB ("STRIFY(SXLIMIT_META_MAX_VALUE_LEN)") NOT NULL, PRIMARY KEY(volume_id, key))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);

    if(qprep(db, &q, "CREATE TABLE privs (volume_id INTEGER NOT NULL REFERENCES volumes(vid) ON DELETE CASCADE ON UPDATE CASCADE, user_id INTEGER NOT NULL REFERENCES users(uid), priv INTEGER NOT NULL, PRIMARY KEY (volume_id, user_id))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);

    qclose(&db);

    /* --- META dbs --- */
    for(i=0; i<METADBS; i++) {
	sprintf(path, "%s/f%08x.db", dir, i);
	sprintf(dbitem, "metadb_%08x", i);
	CREATE_DB(dbitem);
	qnullify(q); /* q is now prepared for hashfs insertions */

	/* Create META tables */
	if(qprep(db, &q, "CREATE TABLE files (fid INTEGER NOT NULL PRIMARY KEY, volume_id INTEGER NOT NULL, name TEXT ("STRIFY(SXLIMIT_MAX_FILENAME_LEN)") NOT NULL, size INTEGER NOT NULL, rev TEXT (56) NOT NULL, content BLOB NOT NULL, UNIQUE(volume_id, name, rev))") || qstep_noret(q))
	    goto create_hashfs_fail;
	qnullify(q);
	if(qprep(db, &q, "CREATE TABLE fmeta (file_id INTEGER NOT NULL REFERENCES files(fid) ON DELETE CASCADE ON UPDATE CASCADE, key TEXT ("STRIFY(SXLIMIT_META_MAX_KEY_LEN)") NOT NULL, value BLOB ("STRIFY(SXLIMIT_META_MAX_VALUE_LEN)") NOT NULL, PRIMARY KEY(file_id, key))") || qstep_noret(q))
	    goto create_hashfs_fail;
	qnullify(q);

	qclose(&db);
    }

    /* --- HASH dbs --- */
    for(j = 0; j < SIZES; j++) {
	for(i=0; i<HASHDBS; i++) {
	    int fd;

	    sprintf(path, "%s/h%c%08x.db", dir, sizedirs[j], i);
	    sprintf(dbitem, "hashdb_%c_%08x", sizedirs[j], i);
	    CREATE_DB(dbitem);
	    sqlite3_reset(q); /* q is now prepared for hashfs insertions */
	    if(qbind_text(q, ":k", "block_size") || qbind_int(q, ":v", bsz[j]) || qstep_noret(q))
		goto create_hashfs_fail;
	    sqlite3_reset(q);
	    if(qbind_text(q, ":k", "next_blockno") || qbind_int(q, ":v", 1) || qstep_noret(q))
		goto create_hashfs_fail;
	    qnullify(q);

	    /* Create HASH tables */
	    if(qprep(db, &q, "CREATE TABLE blocks (hash BLOB("STRIFY(SXI_SHA1_BIN_LEN)") NOT NULL PRIMARY KEY, blockno INTEGER NOT NULL)") || qstep_noret(q))
		goto create_hashfs_fail;
	    qnullify(q);

	    /* Create freelist table */
	    if(qprep(db, &q, "CREATE TABLE avail (blocknumber INTEGER NOT NULL PRIMARY KEY ASC)") || qstep_noret(q))
		goto create_hashfs_fail;
	    qnullify(q);

	    qclose(&db);

	    /* Create DATA files */
	    sprintf(path, "%s/h%c%08x.bin", dir, sizedirs[j], i);
	    fd = creat(path, 0666);
	    if(fd < 0) {
		PCRIT("Cannot create data file %s", path);
		goto create_hashfs_fail;
	    }
	    memset(path, 0, bsz[j]);
	    sprintf(path, "%-16sdatafile_%c_%08x             %08x", HASHFS_VERSION, sizedirs[j], i, bsz[j]);
	    memcpy(path+64, cluster->binary, sizeof(cluster->binary));
	    if(write_block(fd, path, 0, bsz[j]))
		goto create_hashfs_fail;
	    close(fd);
	}
    }

    /* --- TEMP db --- */
    sprintf(path, "%s/temp.db", dir);
    CREATE_DB("tempdb");
    qnullify(q); /* q is now prepared for hashfs insertions */
    if(qprep(db, &q, "CREATE TABLE tmpfiles (tid INTEGER PRIMARY KEY, token TEXT (32) NULL UNIQUE, volume_id INTEGER NOT NULL, name TEXT ("STRIFY(SXLIMIT_MAX_FILENAME_LEN)") NOT NULL, size INTEGER NOT NULL DEFAULT 0, t TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f')), flushed INTEGER NOT NULL DEFAULT 0, content BLOB, uniqidx BLOB, ttl INTEGER NOT NULL DEFAULT 0, avail BLOB)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if (qprep(db, &q, "CREATE INDEX tmpfiles_ttl ON tmpfiles(ttl) WHERE ttl > 0") || qstep_noret(q))
        goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE tmpmeta (tid INTEGER NOT NULL REFERENCES tmpfiles(tid) ON DELETE CASCADE ON UPDATE CASCADE, key TEXT ("STRIFY(SXLIMIT_META_MAX_KEY_LEN)") NOT NULL, value BLOB ("STRIFY(SXLIMIT_META_MAX_VALUE_LEN)") NOT NULL, PRIMARY KEY (tid, key))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    qclose(&db);

    /* --- EVENT db --- */
    sprintf(path, "%s/events.db", dir);
    CREATE_DB("eventdb");
    qnullify(q); /* q is now prepared for hashfs insertions */
    if(qprep(db, &q, "INSERT INTO hashfs (key, value) VALUES ('next_version_check', datetime(strftime('%s', 'now') + (abs(random()) % 10800), 'unixepoch'))") || qstep_noret(q)) /* Schedule next version check within 3 hours */
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE jobs (job INTEGER NOT NULL PRIMARY KEY, type INTEGER NOT NULL, lock TEXT NULL, data BLOB NOT NULL, sched_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f')), expiry_time TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0, result INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT \"\", user INTEGER NULL, UNIQUE(lock))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE INDEX jobs_status ON jobs (complete, sched_time)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);

    if(qprep(db, &q, "CREATE TABLE actions (id INTEGER NOT NULL PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(job) ON DELETE CASCADE ON UPDATE CASCADE, phase INTEGER NOT NULL DEFAULT 0, target BLOB("STRIFY(UUID_BINARY_SIZE)") NOT NULL, addr TEXT NOT NULL, internaladdr TEXT NOT NULL, capacity INTEGER NOT NULL)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE INDEX actions_status ON actions (job_id, phase DESC)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    qclose(&db);

    /* --- XFER db --- */
    sprintf(path, "%s/xfers.db", dir);
    CREATE_DB("xferdb");
    qnullify(q); /* q is now prepared for hashfs insertions */
    if(qprep(db, &q, "CREATE TABLE topush (id INTEGER NOT NULL PRIMARY KEY, block BLOB("STRIFY(SXI_SHA1_BIN_LEN)") NOT NULL, size INTEGER NOT NULL, node BLOB("STRIFY(UUID_BINARY_SIZE)") NOT NULL, sched_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f')), expiry_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now', '"STRIFY(TOPUSH_EXPIRE)" seconds')), UNIQUE (block, size, node))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE INDEX topush_sched ON topush(sched_time ASC, expiry_time)") || qstep_noret(q))
        goto create_hashfs_fail;
    qnullify(q);
    qclose(&db);

    /* --- GC db ---- */
    sprintf(path, "%s/gc", dir);
    mkdir(path, 0700);
    sprintf(path, "%s/gc.db", dir);
    CREATE_DB("gcdb");
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE counters(hash BLOB(20) NOT NULL PRIMARY KEY, hs INTEGER NOT NULL, reserved INTEGER NOT NULL, used INTEGER NOT NULL, ver INTEGER NOT NULL)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE reserved(groupid BLOB(20) NOT NULL, hash BLOB(20) NOT NULL, hs INTEGER NOT NULL)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE activity(groupid BLOB(20) NOT NULL PRIMARY KEY, last_changed_at INTEGER NOT NULL, pending INTEGER NOT NULL, total INTEGER NOT NULL)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE tmpmoduse_maxidx(name TEXT PRIMARY KEY NOT NULL, maxidx INTEGER NOT NULL)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE tmpmoduse(groupid BLOB(20) NOT NULL, hash BLOB(20) NOT NULL, hs INTEGER NOT NULL, op INTEGER NOT NULL, applied_expires_at INTEGER, UNIQUE(hash, groupid, op))") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE INDEX tmpmoduse_applied ON tmpmoduse(applied_expires_at)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE INDEX activity_expiry ON activity(last_changed_at)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    /* TODO: can we merge these two indexes? */
    if(qprep(db, &q, "CREATE INDEX reserve_by_group ON reserved(groupid)") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "CREATE INDEX counters_0_ver ON counters(used, reserved, ver) WHERE used=0") || qstep_noret(q))
	goto create_hashfs_fail;
    qnullify(q);
    /* GC: two tasks: merge tables, track token activity, and
     * actually perform GC */
    sync();
    ret = OK;

create_hashfs_fail:
    if (ret != OK)
	WARN("failed to create hashfs");
    sqlite3_finalize(q);
    qclose(&db);
    free(path);
    sxc_free_uri(uri);
    if(ret)
	sxi_rmdirs(dir);
    return ret;
}

static int qopen(const char *path, sxi_db_t **dbp, const char *dbtype, sx_uuid_t *cluster) {
    sqlite3_stmt *q = NULL;
    const char *str;
    sqlite3 *handle = NULL;

    if(sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL)) {
	CRIT("Failed to open database %s: %s", path, sqlite3_errmsg(handle));
	goto qopen_fail;
    }
    if (!(*dbp = qnew(handle)))
        goto qopen_fail;
    if(sqlite3_busy_timeout(handle, SXDBI_BUSY_TIMEOUT * 1000)) {
	CRIT("Failed to set timeout on database %s: %s", path, sqlite3_errmsg(handle));
	goto qopen_fail;
    }
    if(qprep(*dbp, &q, "PRAGMA synchronous = NORMAL") || qstep_noret(q))
	goto qopen_fail;
    qnullify(q);

    if(qprep(*dbp, &q, "SELECT value FROM hashfs WHERE key = :k"))
	goto qopen_fail;

    if(qbind_text(q, ":k", "version") || qstep_ret(q))
	goto qopen_fail;
    str = (const char *)sqlite3_column_text(q, 0);
    if(!str || strcmp(str, HASHFS_VERSION)) {
	CRIT("Version mismatch on db %s: expected %s, found %s", path, HASHFS_VERSION, str ? str : "none");
	goto qopen_fail;
    }

    sqlite3_reset(q);
    if(qbind_text(q, ":k", "dbtype") || qstep_ret(q))
	goto qopen_fail;
    str = (const char *)sqlite3_column_text(q, 0);
    if(!str || (dbtype && strcmp(str, dbtype))) {
	CRIT("Type mismatch on db %s: expected %s, found %s", path, dbtype, str ? str : "none");
	goto qopen_fail;
    }

    if(cluster) {
	sqlite3_reset(q);
	if(qbind_text(q, ":k", "cluster") || qstep_ret(q))
	    goto qopen_fail;
	str = (const char *)sqlite3_column_blob(q, 0);
	if(!str || sqlite3_column_bytes(q, 0) != sizeof(cluster->binary) || memcmp(str, cluster->binary, sizeof(cluster->binary))) {
	    sx_uuid_t wrong;
	    uuid_from_binary(&wrong, str);
	    CRIT("Cluster UUID mismatch on db %s: expected %s, found %s", path, cluster->string, wrong.string);
	    goto qopen_fail;
	}
    }

    sqlite3_finalize(q);

    return 0;

qopen_fail:
    WARN("failed to open '%s'", path);
    sqlite3_finalize(q);
    qclose(dbp);
    return 1;
}

struct _sx_hashfs_t {
    uint8_t *blockbuf;

    sxi_db_t *db;
    sqlite3_stmt *q_getval;
    sqlite3_stmt *q_gethdrev;
    sqlite3_stmt *q_getuser;
    sqlite3_stmt *q_getuserbyid;
    sqlite3_stmt *q_getuserbyname;
    sqlite3_stmt *q_listusers;
    sqlite3_stmt *q_listadmins;
    sqlite3_stmt *q_listacl;
    sqlite3_stmt *q_createuser;
    sqlite3_stmt *q_onoffuser;
    sqlite3_stmt *q_grant;
    sqlite3_stmt *q_getuid;
    sqlite3_stmt *q_getuidname;
    sqlite3_stmt *q_revoke;
    sqlite3_stmt *q_volbyname;
    sqlite3_stmt *q_volbyid;
    sqlite3_stmt *q_metaget;
    sqlite3_stmt *q_nextvol;
    sqlite3_stmt *q_getaccess;
    sqlite3_stmt *q_addvol;
    sqlite3_stmt *q_addvolmeta;
    sqlite3_stmt *q_addvolprivs;
    sqlite3_stmt *q_onoffvol;
    sqlite3_stmt *q_getvolstate;
    sqlite3_stmt *q_delvol;

    sxi_db_t *tempdb;
    sqlite3_stmt *qt_new;
    sqlite3_stmt *qt_update;
    sqlite3_stmt *qt_updateuniq;
    sqlite3_stmt *qt_extend;
    sqlite3_stmt *qt_addmeta;
    sqlite3_stmt *qt_delmeta;
    sqlite3_stmt *qt_getmeta;
    sqlite3_stmt *qt_countmeta;
    sqlite3_stmt *qt_gettoken;
    sqlite3_stmt *qt_tokenstats;
    sqlite3_stmt *qt_tmpdata;
    sqlite3_stmt *qt_delete;
    sqlite3_stmt *qt_flush;
    sqlite3_stmt *qt_gc_tokens;

    sxi_db_t *metadb[METADBS];
    sqlite3_stmt *qm_ins[METADBS];
    sqlite3_stmt *qm_list[METADBS];
    sqlite3_stmt *qm_listrevs[METADBS];
    sqlite3_stmt *qm_get[METADBS];
    sqlite3_stmt *qm_getrev[METADBS];
    sqlite3_stmt *qm_tooold[METADBS];
    sqlite3_stmt *qm_metaget[METADBS];
    sqlite3_stmt *qm_metaset[METADBS];
    sqlite3_stmt *qm_metadel[METADBS];
    sqlite3_stmt *qm_delfile[METADBS];

    sxi_db_t *gcdb[GCDBS];
    sqlite3_stmt *qg_bump_reserved[GCDBS];
    sqlite3_stmt *qg_addop[GCDBS];
    unsigned gcdb_used;
    uint64_t gcdb_idx;
    int gcdb_lock;

    sxi_db_t *datadb[SIZES][HASHDBS];
    sqlite3_stmt *qb_get[SIZES][HASHDBS];
    sqlite3_stmt *qb_nextavail[SIZES][HASHDBS];
    sqlite3_stmt *qb_nextalloc[SIZES][HASHDBS];
    sqlite3_stmt *qb_add[SIZES][HASHDBS];
    sqlite3_stmt *qb_setfree[SIZES][HASHDBS];
    sqlite3_stmt *qb_gc1[SIZES][HASHDBS];
    sqlite3_stmt *qb_bumpavail[SIZES][HASHDBS];
    sqlite3_stmt *qb_bumpalloc[SIZES][HASHDBS];

    sxi_db_t *eventdb;
    sqlite3_stmt *qe_getjob;
    sqlite3_stmt *qe_addjob;
    sqlite3_stmt *qe_addact;
    sqlite3_stmt *qe_countjobs;

    sxi_db_t *xferdb;
    sqlite3_stmt *qx_add;

    char *ssl_ca_file;
    char *cluster_name;
    uint16_t http_port;

    sxi_hdist_t *hd;
    sx_nodelist_t *prev_dist, *next_dist, *nextprev_dist, *prevnext_dist;
    int64_t hd_rev;
    unsigned int have_hd, is_rebalancing;
    time_t last_dist_change;

    sx_hashfs_volume_t curvol;
    sx_uid_t curvoluid;

    sx_hashfs_file_t list_file;
    int list_recurse;
    int64_t list_volid;
    /* 2*SXLIMIT because each char can be a wildcard that might need to be
     * escaped for an exact match */
    char list_pattern[2*SXLIMIT_MAX_FILENAME_LEN+3];
    unsigned int list_pattern_slashes;

    int64_t get_id;
    const sx_hash_t *get_content;
    unsigned int get_nblocks;
    unsigned int get_replica;
    int get_ndb;
    int rev_ndb;


    int64_t put_id;
    int64_t put_extendsize;
    unsigned int put_extendfrom;
    unsigned int put_putblock;
    unsigned int put_getblock;
    unsigned int put_checkblock;
    unsigned int put_singlecheck;
    unsigned int put_replica;
    int64_t upload_minspeed;
    unsigned int put_hs;
    unsigned int put_success;
    sx_hash_t *put_blocks;
    sx_hash_t put_reserve_id;
    unsigned int *put_nidxs;
    unsigned int *put_hashnos;
    unsigned int put_nblocks;
    char put_token[TOKEN_TEXT_LEN + 1];
    struct {
	char key[SXLIMIT_META_MAX_KEY_LEN+1];
	uint8_t value[SXLIMIT_META_MAX_VALUE_LEN];
	int value_len;
    } meta[SXLIMIT_META_MAX_ITEMS];
    unsigned int nmeta;

    int datafd[SIZES][HASHDBS];
    sx_uuid_t cluster_uuid, node_uuid; /* MODHDIST: store sx_node_t instead - see sx_hashfs_self */
    char version[16];
    sx_hash_t tokenkey;

    sxc_client_t *sx;
    sxi_conns_t *sx_clust;
    sxi_hashop_t hc;
    char root_auth[AUTHTOK_ASCII_LEN+1];

    int job_trigger, xfer_trigger, gc_trigger;
    char job_message[JOB_FAIL_REASON_SIZE];

    char *dir;
    int gcver;
    int gc_wal_pages;
};

static void gcdb_close(sx_hashfs_t *h)
{
    unsigned i = 0;
    if (!h->gcdb[i])
	return;
    qnullify(h->qg_addop[i]);
    qnullify(h->qg_bump_reserved[i]);
    qclose(&h->gcdb[i]);
    close(h->gcdb_lock);
    h->gcdb_lock = 0;
}

static void close_all_dbs(sx_hashfs_t *h) {
    unsigned int i, j;

    gcdb_close(h);

    sqlite3_finalize(h->qx_add);
    qclose(&h->xferdb);

    sqlite3_finalize(h->qe_getjob);
    sqlite3_finalize(h->qe_addjob);
    sqlite3_finalize(h->qe_addact);
    sqlite3_finalize(h->qe_countjobs);
    qclose(&h->eventdb);

    for(j=0; j<SIZES; j++) {
	for(i=0; i<HASHDBS; i++) {
	    sqlite3_finalize(h->qb_get[j][i]);
	    sqlite3_finalize(h->qb_nextavail[j][i]);
	    sqlite3_finalize(h->qb_nextalloc[j][i]);
	    sqlite3_finalize(h->qb_add[j][i]);
	    sqlite3_finalize(h->qb_setfree[j][i]);
	    sqlite3_finalize(h->qb_gc1[j][i]);
	    sqlite3_finalize(h->qb_bumpavail[j][i]);
	    sqlite3_finalize(h->qb_bumpalloc[j][i]);
	    qclose(&h->datadb[j][i]);

	    if(h->datafd[j][i] >= 0)
		close(h->datafd[j][i]);
	}
    }
    for(i=0; i<METADBS; i++) {
	sqlite3_finalize(h->qm_ins[i]);
	sqlite3_finalize(h->qm_list[i]);
	sqlite3_finalize(h->qm_listrevs[i]);
	sqlite3_finalize(h->qm_get[i]);
	sqlite3_finalize(h->qm_getrev[i]);
	sqlite3_finalize(h->qm_tooold[i]);
	sqlite3_finalize(h->qm_metaget[i]);
	sqlite3_finalize(h->qm_metaset[i]);
	sqlite3_finalize(h->qm_metadel[i]);
	sqlite3_finalize(h->qm_delfile[i]);
	qclose(&h->metadb[i]);
    }

    sqlite3_finalize(h->q_addvol);
    sqlite3_finalize(h->q_addvolmeta);
    sqlite3_finalize(h->q_addvolprivs);
    sqlite3_finalize(h->q_onoffvol);
    sqlite3_finalize(h->q_getvolstate);
    sqlite3_finalize(h->q_delvol);
    sqlite3_finalize(h->q_onoffuser);
    sqlite3_finalize(h->q_gethdrev);
    sqlite3_finalize(h->q_getuser);
    sqlite3_finalize(h->q_getuserbyid);
    sqlite3_finalize(h->q_getuserbyname);
    sqlite3_finalize(h->q_listusers);
    sqlite3_finalize(h->q_listacl);
    sqlite3_finalize(h->q_listadmins);
    sqlite3_finalize(h->q_getaccess);
    sqlite3_finalize(h->q_createuser);
    sqlite3_finalize(h->q_grant);
    sqlite3_finalize(h->q_getuid);
    sqlite3_finalize(h->q_getuidname);
    sqlite3_finalize(h->q_revoke);
    sqlite3_finalize(h->q_nextvol);

    sqlite3_finalize(h->qt_new);
    sqlite3_finalize(h->qt_update);
    sqlite3_finalize(h->qt_updateuniq);
    sqlite3_finalize(h->qt_extend);
    sqlite3_finalize(h->qt_addmeta);
    sqlite3_finalize(h->qt_delmeta);
    sqlite3_finalize(h->qt_getmeta);
    sqlite3_finalize(h->qt_countmeta);
    sqlite3_finalize(h->qt_gettoken);
    sqlite3_finalize(h->qt_tmpdata);
    sqlite3_finalize(h->qt_tokenstats);
    sqlite3_finalize(h->qt_delete);
    sqlite3_finalize(h->qt_flush);
    sqlite3_finalize(h->qt_gc_tokens);

    sqlite3_finalize(h->q_volbyname);
    sqlite3_finalize(h->q_volbyid);
    sqlite3_finalize(h->q_metaget);
    sqlite3_finalize(h->q_getval);
    qclose(&h->tempdb);
    qclose(&h->db);
}

/* TODO: shouldn't use hidden variables */
#define OPEN_DB(DBNAME, DBHANDLE) \
do { \
    sqlite3_reset(h->q_getval); \
    if(qbind_text(h->q_getval, ":k", DBNAME) || qstep_ret(h->q_getval)) {\
	WARN("Couldn't find DB '%s'", DBNAME);				\
	goto open_hashfs_fail; \
    }\
    str = (const char *)sqlite3_column_text(h->q_getval, 0); \
    if(!str) \
	goto open_hashfs_fail; \
    if(*str != '/') { \
	unsigned int subpathlen = strlen(str) + 1; \
	if(subpathlen > pathlen) { \
	    pathlen = subpathlen; \
	    if(!(path = wrap_realloc_or_free(path, dirlen + pathlen))) \
		goto open_hashfs_fail; \
	} \
	memcpy(path + dirlen, str, subpathlen); \
	str = path; \
    } \
    if(qopen(str, DBHANDLE, DBNAME, &h->cluster_uuid)) \
	goto open_hashfs_fail; \
} while(0)


static int lock_file(const char *file, int do_unlink)
{
    struct flock lck;
    unsigned pathlen = strlen(file) + 16;
    char *path = wrap_malloc(pathlen);
    if (!path)
        return -1;
    snprintf(path, pathlen, "%s.inuse", file);
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        free(path);
        return -1;
    }
    memset(&lck, 0, sizeof(lck));
    lck.l_type = F_WRLCK;
    lck.l_whence = SEEK_SET;
    lck.l_start = 0;
    lck.l_len = 0;
    if (fcntl(fd, F_SETLK, &lck) == -1) {
        close(fd);
        fd = 0;
    }
    if (fd > 0 && do_unlink)
        unlink(path);
    free(path);
    /* when closed (or process dies) it automatically releases the lock */
    return fd;
}

static int counter = 0;

void sx_hashfs_checkpoint_passive(sx_hashfs_t *h)
{
    unsigned i, j;
    /* PASSIVE: doesn't block writers/readers
     * FULL/RESTART: blocks writers (not reader)
     * by default sqlite performs a PASSIVE checkpoint every 1000 pages,
     * and ignores errors
     * */
    qcheckpoint(h->db);
    qcheckpoint(h->tempdb);
    for (i=0;i<METADBS;i++)
        qcheckpoint(h->metadb[i]);
    qcheckpoint(h->gcdb[0]);
    for (i=0;i<SIZES;i++)
        for (j=0;j<SIZES;j++)
            qcheckpoint(h->datadb[i][j]);
    qcheckpoint(h->eventdb);
    qcheckpoint(h->xferdb);
}

void sx_hashfs_checkpoint_gc(sx_hashfs_t *h)
{
    qcheckpoint_idle(h->gcdb[0]);
}

void sx_hashfs_checkpoint_xferdb(sx_hashfs_t *h)
{
    qcheckpoint_idle(h->xferdb);
}

void sx_hashfs_checkpoint_eventdb(sx_hashfs_t *h)
{
    qcheckpoint_idle(h->eventdb);
    qcheckpoint_idle(h->tempdb);
}

rc_ty sx_hashfs_gc_open(sx_hashfs_t *h)
{
    rc_ty ret = FAIL_EINTERNAL;
    int i = 0;
    char dbitem[64];
    sqlite3_stmt *q = NULL;
    sx_uuid_t *cluster = &h->cluster_uuid;
    sxi_db_t *db = NULL;
    char *path = NULL;
    const char *str = NULL;
    unsigned int pathlen = 0, dirlen;
    struct timeval tv0, tv1;
    char rndhexbuf[TOKEN_RAND_BYTES*2+1];
    uint8_t rndbin[TOKEN_RAND_BYTES];

    gettimeofday(&tv0, NULL);
    if(sxi_rand_pseudo_bytes(rndbin, sizeof(rndbin)) == -1) {
        /* can also return 0 or 1 but that doesn't matter here */
        WARN("Cannot generate random bytes");
        msg_set_reason("Failed to generate random string");
        return FAIL_EINTERNAL;
    }
    bin2hex(rndbin, sizeof(rndbin), rndhexbuf, sizeof(rndhexbuf));

    sprintf(dbitem,"gcp_%d_%d_%s", getpid(), counter, rndhexbuf);

    gcdb_close(h);
    if(!h->dir || !(dirlen = strlen(h->dir))) {
	CRIT("Bad path");
	return EINVAL;
    }
    pathlen = dirlen + 1024;
    if(!(path = wrap_malloc(pathlen)))
	goto create_hashfs_fail;
    snprintf(path, pathlen, "%s/gc/%d_%d_%s.db", h->dir, getpid(), counter++, rndhexbuf);

    h->gcdb_lock = lock_file(path, 0);
    if (h->gcdb_lock == -1 || !h->gcdb_lock) {
        PWARN("Cannot mark DB '%s' as inuse", path);
        goto create_hashfs_fail;
    }
    CREATE_DB2(dbitem);
    qnullify(q);
    if (qbegin(h->db))
        goto create_hashfs_fail;
    if(qprep(h->db, &q, "INSERT INTO hashfs (key, value) VALUES (:k, :v)") ||
       qbind_text(q, ":k", dbitem) || qbind_text(q, ":v", path) || qstep_noret(q) ||
       qcommit(h->db)) {
        qrollback(h->db);
        WARN("Failed to create '%s'", dbitem);
        goto create_hashfs_fail;
    }
    qnullify(q);
    if(qprep(db, &q, "CREATE TABLE moduse(idx INTEGER PRIMARY KEY NOT NULL, groupid BLOB(20) NOT NULL, hash BLOB(20) NOT NULL, hs INTEGER NOT NULL, op INTEGER NOT NULL)") || qstep_noret(q))
        goto open_hashfs_fail;
    qnullify(q);
#if 0
    /* TODO: this needs to be real table */
    if (qprep(db, &q, "CREATE TABLE filehash_info (filehash BLOB("STRIFY(SXI_SHA1_BIN_LEN)") NOT NULL PRIMARY KEY, reserved INTEGER NOT NULL, used INTEGER NOT NULL)") || qstep_noret(q))
        goto create_hashfs_fail;
    qnullify(q);
#endif
    qclose(&db);
    OPEN_DB(dbitem, &h->gcdb[i]);
    sqlite3_reset(h->q_getval);
    if(qprep(h->gcdb[i], &h->qg_addop[i], "INSERT INTO moduse(idx, groupid, hash, hs, op) VALUES(:idx, :groupid, :hash, :hs, :op)"))
        goto open_hashfs_fail;
    qnullify(q);
    /* we shouldn't have temp files, but try to avoid if we can*/
    if(qprep(h->gcdb[i], &q, "PRAGMA temp_store=MEMORY") || qstep_noret(q))
        goto open_hashfs_fail;
    qnullify(q);
    ret = OK;
    gettimeofday(&tv1, NULL);
    if (h->gcdb_used)
        INFO("Per-process GC database opened in %.3f sec", timediff(&tv0, &tv1));

create_hashfs_fail:
open_hashfs_fail:
    free(path);
    qnullify(q);
    h->gcdb_used = 0;
    return ret;
}

static int load_config(sx_hashfs_t *h, sxc_client_t *sx) {
    const void *p;
    int r, ret = -1;

    DEBUG("Reloading cluster configuration");

    free(h->cluster_name);
    h->cluster_name = NULL;
    free(h->ssl_ca_file);
    h->ssl_ca_file = NULL;
    if(h->have_hd)
	sxi_hdist_free(h->hd);
    h->have_hd = 0;
    h->hd_rev = 0;
    sx_nodelist_delete(h->next_dist);
    h->next_dist = NULL;
    sx_nodelist_delete(h->prev_dist);
    h->prev_dist = NULL;
    sx_nodelist_delete(h->nextprev_dist);
    h->nextprev_dist = NULL;
    sx_nodelist_delete(h->prevnext_dist);
    h->prevnext_dist = NULL;
    h->is_rebalancing = 0;
    h->sx = sx;
    h->last_dist_change = time(NULL);

    sqlite3_reset(h->q_getval);
    if(qbind_text(h->q_getval, ":k", "cluster_name"))
	goto load_config_fail;
    switch(qstep(h->q_getval)) {
    case SQLITE_ROW:
	/* MODHDIST: this is an operational node */
	h->cluster_name = wrap_strdup((const char*)sqlite3_column_text(h->q_getval, 0));
	if (!h->cluster_name)
	    goto load_config_fail;

	h->http_port = 0;
	sqlite3_reset(h->q_getval);
	if(qbind_text(h->q_getval, ":k", "http_port")) {
	    CRIT("Failed to retrieve network settings from database");
	    goto load_config_fail;
	}
	r = qstep(h->q_getval);
	if(r == SQLITE_ROW)
	    h->http_port = sqlite3_column_int(h->q_getval, 0);
	else if(r != SQLITE_DONE) {
	    CRIT("Failed to retrieve network settings from database");
	    goto load_config_fail;
	}

	sqlite3_reset(h->q_getval);
	if(qbind_text(h->q_getval, ":k", "ssl_ca_file")) {
	    CRIT("Failed to retrieve security certificate from database");
	    goto load_config_fail;
	}

	r = qstep(h->q_getval);
	if(r == SQLITE_ROW) {
            const char *relpath = (const char*)sqlite3_column_text(h->q_getval, 0);
            unsigned cafilen;

	    cafilen = strlen(relpath);
	    if(cafilen) {
		cafilen += strlen(h->dir) + 2;
		h->ssl_ca_file = wrap_malloc(cafilen);
		if(!h->ssl_ca_file)
		    goto load_config_fail;
		if (*relpath == '/')
		    snprintf(h->ssl_ca_file, cafilen, "%s", relpath);
		else
		    snprintf(h->ssl_ca_file, cafilen, "%s/%s", h->dir, relpath);
	    }
	} else if(r != SQLITE_DONE) {
	    CRIT("Failed to retrieve node CA certificate file from database");
	    goto load_config_fail;
	}

	sqlite3_reset(h->q_getval);
	if(qbind_text(h->q_getval, ":k", "node") || qstep_ret(h->q_getval)) {
	    CRIT("Failed to retrieve node UUID from database");
	    goto load_config_fail;
	}
	p = sqlite3_column_blob(h->q_getval, 0);
	if(!p || sqlite3_column_bytes(h->q_getval, 0) != sizeof(h->node_uuid.binary)) {
	    CRIT("Bad node UUID retrieved from database");
	    goto load_config_fail;
	}
	uuid_from_binary(&h->node_uuid, p);

	sqlite3_reset(h->q_getval);
	if(qbind_text(h->q_getval, ":k", "current_dist_rev")) {
	    CRIT("Failed to retrieve cluster distribution from database");
	    goto load_config_fail;
	}
	r = qstep(h->q_getval);
	if(r == SQLITE_ROW) {
	    h->hd_rev = sqlite3_column_int64(h->q_getval, 0);

	    sqlite3_reset(h->q_getval);
	    if(qbind_text(h->q_getval, ":k", "current_dist") || qstep_ret(h->q_getval)) {
		CRIT("Failed to retrieve cluster distribution from database");
		goto load_config_fail;
	    }
	    if(!sqlite3_column_bytes(h->q_getval, 0)) {
		/* MODHDIST: this node has received its configuration but the hdist model wasn't
		 * enabled yet so we consider it effectively the same as a bare node */
		sqlite3_reset(h->q_getval);
		free(h->cluster_name);
		h->cluster_name = NULL;
		h->hd_rev = 0;
		break;
	    }
	} else if(r == SQLITE_DONE) {
	    if(qbind_text(h->q_getval, ":k", "dist_rev") || qstep_ret(h->q_getval)) {
		CRIT("Failed to retrieve cluster distribution from database");
		goto load_config_fail;
	    }
	    h->hd_rev = sqlite3_column_int64(h->q_getval, 0);

	    sqlite3_reset(h->q_getval);
	    if(qbind_text(h->q_getval, ":k", "dist") || qstep_ret(h->q_getval)) {
		CRIT("Failed to retrieve cluster distribution from database");
		goto load_config_fail;
	    }
	} else {
	    CRIT("Failed to retrieve cluster distribution from database");
	    goto load_config_fail;
	}
	p = sqlite3_column_blob(h->q_getval, 0);
	if(!p) {
	    CRIT("Bad cluster distribution retrieved from database");
	    goto load_config_fail;
	}
	if(!(h->hd = sxi_hdist_from_cfg(p, sqlite3_column_bytes(h->q_getval, 0)))) {
	    CRIT("Failed to load cluster distribution");
	    goto load_config_fail;
	}

	h->next_dist = sx_nodelist_dup(sxi_hdist_nodelist(h->hd, 0));
	if(sxi_hdist_buildcnt(h->hd) == 1) {
	    if(sx_nodelist_lookup(h->next_dist, &h->node_uuid)) {
		/* MODHDIST:
		 * we are out of the cluster
		 * turn on reject all mode (503 to every request) */
	    }
	    h->prev_dist = sx_nodelist_dup(h->next_dist);
	} else if(sxi_hdist_buildcnt(h->hd) == 2) {
	    h->prev_dist = sx_nodelist_dup(sxi_hdist_nodelist(h->hd, 1));
	    h->is_rebalancing = 1;
	} else {
	    CRIT("Failed to load cluster distribution: too many models");
	    goto load_config_fail;
	}

	h->nextprev_dist = sx_nodelist_dup(h->next_dist);
	h->prevnext_dist = sx_nodelist_dup(h->prev_dist);
	if(!h->next_dist || !h->prev_dist ||
	   sx_nodelist_addlist(h->nextprev_dist, h->prev_dist) ||
	   sx_nodelist_addlist(h->prevnext_dist, h->next_dist)) {
	    CRIT("Failed to allocate cluster distribution lists");
	    goto load_config_fail;
	}

	sqlite3_reset(h->q_getval);

	if(!h->sx_clust) {
	    h->sx_clust = sxi_conns_new(sx);
            sxi_conns_disable_proxy(h->sx_clust);
        }
	if(!h->sx_clust ||
	   sxi_conns_set_uuid(h->sx_clust, h->cluster_uuid.string) ||
	   sxi_conns_set_auth(h->sx_clust, h->root_auth) ||
	   sxi_conns_set_port(h->sx_clust, h->http_port) ||
	   sxi_conns_set_sslname(h->sx_clust, h->cluster_name)) {
	    CRIT("Failed to initialize cluster connectors");
	    goto load_config_fail;
	}
	sxi_conns_set_cafile(h->sx_clust, h->ssl_ca_file);

	h->have_hd = 1;
	break;

    case SQLITE_DONE:
	/* MODHDIST: this is a bare node which cannot operate until programmed */
	h->cluster_name = NULL;
	break;

    default:
	CRIT("Failed to retrieve cluster name from database");
	goto load_config_fail;
    }

    ret = 0;
 load_config_fail:
    sqlite3_reset(h->q_getval);
    return ret;
}



sx_hashfs_t *sx_hashfs_open(const char *dir, sxc_client_t *sx) {
    unsigned int dirlen, pathlen, i, j;
    sqlite3_stmt *q = NULL;
    char *path, dbitem[64];
    const char *str;
    sx_hashfs_t *h;

    if(!dir || !(dirlen = strlen(dir))) {
	CRIT("Bad path");
	return NULL;
    }
    if (ssl_version_check())
	return NULL;

    if(!(h = wrap_calloc(1, sizeof(*h))))
	return NULL;
    memset(h->datafd, -1, sizeof(h->datafd));
    h->sx = NULL;
    h->job_trigger = h->xfer_trigger = h->gc_trigger = -1;
    /* TODO: read from hashfs kv store */
    h->upload_minspeed = GC_UPLOAD_MINSPEED;

    dirlen++;
    pathlen = 1024;
    if(!(path = wrap_malloc(dirlen + pathlen)))
	goto open_hashfs_fail;
    h->dir = strdup(dir);
    if (!h->dir)
        goto open_hashfs_fail;

    if (!qlog_set) {
	sqlite3_config(SQLITE_CONFIG_LOG, qlog, NULL);
	qlog_set = 1;
    }
    /* reset sqlite3's PRNG, to avoid generating colliding tempfile names in
     * forked processes */
    sqlite3_test_control(SQLITE_TESTCTRL_PRNG_RESET);
    /* reset OpenSSL's PRNG otherwise it'll share state after a fork */
    sxi_rand_cleanup();

    sprintf(path, "%s/hashfs.db", dir);
    if(qopen(path, &h->db, "hashfs", NULL))
	goto open_hashfs_fail;
    if(qprep(h->db, &q, "PRAGMA foreign_keys = ON") || qstep_noret(q))
	goto open_hashfs_fail;
    qnullify(q);
    if(qprep(h->db, &h->q_getval, "SELECT value FROM hashfs WHERE key = :k"))
	goto open_hashfs_fail;
    if(qbind_text(h->q_getval, ":k", "cluster") || qstep_ret(h->q_getval))
	goto open_hashfs_fail;
    str = (const char *)sqlite3_column_blob(h->q_getval, 0);
    if(!str || sqlite3_column_bytes(h->q_getval, 0) != sizeof(h->cluster_uuid.binary)) {
	CRIT("Failed to retrieve cluster UUID from database");
	goto open_hashfs_fail;
    }
    uuid_from_binary(&h->cluster_uuid, str);

    sqlite3_reset(h->q_getval);
    if(qbind_text(h->q_getval, ":k", "version") || qstep_ret(h->q_getval))
	goto open_hashfs_fail;
    str = (const char *)sqlite3_column_text(h->q_getval, 0);
    if(!str || strlen(str) >= sizeof(h->version)) {
	CRIT("Failed to retrieve HashFS version from database");
	goto open_hashfs_fail;
    }
    strcpy(h->version, str);

    if(qprep(h->db, &q, "SELECT key FROM users WHERE uid = 0 AND role = "STRIFY(ROLE_CLUSTER)" AND enabled = 1") || qstep_ret(q)) {
	CRIT("Failed to retrieve cluster key from database");
	goto open_hashfs_fail;
    }
    if(!(str = sqlite3_column_blob(q, 0)) || sqlite3_column_bytes(q, 0) != AUTH_KEY_LEN) {
	CRIT("Bad cluster key retrieved from database");
	goto open_hashfs_fail;
    }
    if(encode_auth_bin(CLUSTER_USER, (const unsigned char *)str, AUTH_KEY_LEN, h->root_auth, sizeof(h->root_auth))) {
	CRIT("Failed to encode cluster key");
	goto open_hashfs_fail;
    }
    if(hash_buf("", 0, str, AUTH_KEY_LEN, &h->tokenkey)) {
	CRIT("Failed to generate token key");
	goto open_hashfs_fail;
    }
    qnullify(q);
    if(load_config(h, sx))
	goto open_hashfs_fail;

    if(qprep(h->db, &h->q_gethdrev, "SELECT MIN(value) FROM hashfs WHERE key IN ('current_dist_rev','dist_rev')"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getuser, "SELECT uid, key, role FROM users WHERE user = :user AND enabled=1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getuserbyid, "SELECT user FROM users WHERE uid = :uid AND enabled=1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getuserbyname, "SELECT user FROM users WHERE name = :name AND enabled=1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_listusers, "SELECT uid, name, user, key, role FROM users WHERE uid > :lastuid AND enabled=1 ORDER BY uid ASC LIMIT 1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_listadmins, "SELECT name, uid FROM users WHERE uid > :lastuid AND role = "STRIFY(ROLE_ADMIN)" AND enabled=1"))
	goto open_hashfs_fail;
    /* FIXME: this query is broken and should be rewritten - index usage not checked */
    /* e.g.:
     * $ sxacl list sx://admin@local/r2
     * admin: read write owner
     * acab: read write
     * admin: read write owner
     * adm: read write owner
     */
    if(qprep(h->db, &h->q_listacl, "SELECT name, priv, uid, owner_id FROM privs, volumes INNER JOIN users ON user_id=uid WHERE volume_id=:volid AND vid=:volid AND volumes.enabled = 1 AND users.enabled = 1 AND (priv <> 0 OR owner_id=uid) AND user_id > :lastuid ORDER BY user_id ASC LIMIT 1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getaccess, "SELECT privs.priv, volumes.owner_id FROM privs, volumes, users WHERE privs.volume_id = :volume AND privs.user_id = :user AND volumes.vid = :volume AND volumes.enabled = 1 AND users.uid = :user AND users.enabled = 1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_createuser, "INSERT INTO users(user, name, key, role) VALUES(:userhash,:name,:key,:role)"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_onoffuser, "UPDATE users SET enabled = :enable WHERE name = :username"))
	goto open_hashfs_fail;
    /* update if present otherwise insert:
     * note: the read and write has to be in same transaction otherwise
     * there'd be race conditions.
     * */
    if(qprep(h->db, &h->q_grant, "INSERT OR REPLACE INTO privs(volume_id, user_id, priv)\
	     VALUES(:volid, :uid,\
		    COALESCE((SELECT priv FROM privs WHERE volume_id=:volid AND user_id=:uid), 0)\
		    | :priv)"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getuid, "SELECT uid, role FROM users WHERE name = :name AND enabled=1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getuidname, "SELECT name FROM users WHERE uid = :uid AND enabled=1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_revoke, "REPLACE INTO privs(volume_id, user_id, priv)\
	     VALUES(:volid, :uid,\
		    COALESCE((SELECT priv FROM privs WHERE volume_id=:volid AND user_id=:uid), 0)\
		    & :privmask)"))
	goto open_hashfs_fail;
    /* To keep the next query simple we do not check if the user is enabled
     * This is preliminary enforced in auth_begin */
    if(qprep(h->db, &h->q_nextvol, "SELECT volumes.vid, volumes.volume, volumes.replica, volumes.maxsize, volumes.owner_id FROM volumes LEFT JOIN privs ON privs.volume_id = volumes.vid WHERE volumes.volume > :previous AND volumes.enabled = 1 AND (:user = 0 OR (privs.priv > 0 AND privs.user_id=:user)) ORDER BY volumes.volume ASC LIMIT 1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_volbyname, "SELECT vid, volume, replica, maxsize, owner_id FROM volumes WHERE volume = :name AND enabled = 1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_volbyid, "SELECT vid, volume, replica, maxsize, owner_id FROM volumes WHERE vid = :volid AND enabled = 1"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_metaget, "SELECT key, value FROM vmeta WHERE volume_id = :volume"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_addvol, "INSERT INTO volumes (volume, replica, maxsize, owner_id) VALUES (:volume, :replica, :size, :owner)"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_addvolmeta, "INSERT INTO vmeta (volume_id, key, value) VALUES (:volume, :key, :value)"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_addvolprivs, "INSERT INTO privs (volume_id, user_id, priv) VALUES (:volume, :user, :priv)"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_onoffvol, "UPDATE volumes SET enabled = :enable WHERE volume = :volume"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_getvolstate, "SELECT enabled FROM volumes WHERE volume = :volume"))
	goto open_hashfs_fail;
    if(qprep(h->db, &h->q_delvol, "DELETE FROM volumes WHERE volume = :volume AND enabled = 0"))
	goto open_hashfs_fail;

    OPEN_DB("tempdb", &h->tempdb);
    /* needed for ON DELETE CASCADE to work */
    if(qprep(h->tempdb, &q, "PRAGMA foreign_keys = ON") || qstep_noret(q))
	goto open_hashfs_fail;
    qnullify(q);

    if(qprep(h->tempdb, &h->qt_new, "INSERT INTO tmpfiles (volume_id, name, token) VALUES (:volume, :name, lower(hex(:random)))"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_update, "UPDATE tmpfiles SET size = :size, content = :all, uniqidx = :uniq, ttl = :expiry WHERE tid = :id AND flushed = 0"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_extend, "UPDATE tmpfiles SET content = cast((content || :all) as blob), uniqidx = cast((uniqidx || :uniq) as blob) WHERE tid = :id AND length(content) = :size AND flushed = 0"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_addmeta, "INSERT OR REPLACE INTO tmpmeta (tid, key, value) VALUES (:id, :key, :value)"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_delmeta, "DELETE FROM tmpmeta WHERE tid = :id AND key = :key"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_getmeta, "SELECT key, value FROM tmpmeta WHERE tid = :id"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_countmeta, "SELECT COUNT(*) FROM tmpmeta WHERE tid = :id"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_gettoken, "SELECT token, ttl FROM tmpfiles WHERE tid = :id AND flushed = 0"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_tokenstats, "SELECT tid, size, volume_id, length(content) FROM tmpfiles WHERE token = :token AND flushed = 0"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_tmpdata, "SELECT t || ':' || token AS revision, name, size, volume_id, content, uniqidx, flushed, avail, token FROM tmpfiles WHERE tid = :id"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_updateuniq, "UPDATE tmpfiles SET uniqidx = :uniq, avail = :avail WHERE tid = :id AND flushed = 1"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_flush, "UPDATE tmpfiles SET flushed = 1 WHERE tid = :id"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_delete, "DELETE FROM tmpfiles WHERE tid = :id"))
	goto open_hashfs_fail;
    if(qprep(h->tempdb, &h->qt_gc_tokens, "DELETE FROM tmpfiles WHERE ttl < :now AND ttl > 0"))
	goto open_hashfs_fail;

    if(!(h->blockbuf = wrap_malloc(bsz[SIZES-1])))
	goto open_hashfs_fail;

    for(j=0; j<SIZES; j++) {
	char hexsz[9];
	sprintf(hexsz, "%08x", bsz[j]);
	for(i=0; i<HASHDBS; i++) {
	    sprintf(dbitem, "hashdb_%c_%08x", sizedirs[j], i);
	    OPEN_DB(dbitem, &h->datadb[j][i]);

	    if(qprep(h->datadb[j][i], &h->qb_nextavail[j][i], "SELECT blocknumber FROM avail ORDER BY blocknumber ASC LIMIT 1"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_nextalloc[j][i], "SELECT value FROM hashfs WHERE key = 'next_blockno'"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_add[j][i], "INSERT INTO blocks (hash, blockno) VALUES (:hash, :next)"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_setfree[j][i], "INSERT OR IGNORE INTO avail VALUES(:blockno)"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_gc1[j][i], "DELETE FROM blocks WHERE hash = :hash"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_get[j][i], "SELECT blockno FROM blocks WHERE hash = :hash"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_bumpavail[j][i], "DELETE FROM avail WHERE blocknumber = :next"))
		goto open_hashfs_fail;
	    if(qprep(h->datadb[j][i], &h->qb_bumpalloc[j][i], "UPDATE hashfs SET value = value + 1 WHERE key = 'next_blockno'"))
		goto open_hashfs_fail;
	    sprintf(dbitem, "datafile_%c_%08x", sizedirs[j], i);
	    sqlite3_reset(h->q_getval);
	    if(qbind_text(h->q_getval, ":k", dbitem) || qstep_ret(h->q_getval))
		goto open_hashfs_fail;

	    str = (const char *)sqlite3_column_text(h->q_getval, 0);
	    if(!str || !*str)
		goto open_hashfs_fail;
	    if(*str != '/') {
		unsigned int subpathlen = strlen(str) + 1;
		if(subpathlen > pathlen) {
		    pathlen = subpathlen;
		    if(!(path = wrap_realloc_or_free(path, dirlen + pathlen)))
			goto open_hashfs_fail;
		}
		memcpy(path + dirlen, str, subpathlen);
		str = path;
	    }

	    h->datafd[j][i] = open(str, O_RDWR);
	    if(h->datafd[j][i] < 0) {
		perror("open");
		goto open_hashfs_fail;
	    }
	    if(read_block(h->datafd[j][i], h->blockbuf, 0, bsz[j]))
		goto open_hashfs_fail;
	    if(memcmp(h->blockbuf, HASHFS_VERSION, strlen(HASHFS_VERSION)) ||
	       memcmp(h->blockbuf + 16, dbitem, strlen(dbitem)) ||
	       memcmp(h->blockbuf + 48, hexsz, strlen(hexsz)) ||
	       memcmp(h->blockbuf + 64, h->cluster_uuid.binary, sizeof(h->cluster_uuid.binary))) {
		CRIT("Bad header in datafile %s", str);
		goto open_hashfs_fail;
	    }
	}
    }

    for(i=0; i<METADBS; i++) {
	sprintf(dbitem, "metadb_%08x", i);
	OPEN_DB(dbitem, &h->metadb[i]);
	if(qprep(h->metadb[i], &q, "PRAGMA foreign_keys = ON") || qstep_noret(q))
	    goto open_hashfs_fail;
	qnullify(q);
	if(qprep(h->metadb[i], &h->qm_ins[i], "INSERT INTO files (volume_id, name, size, content, rev) VALUES (:volume, :name, :size, :hashes, :revision)"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_list[i], "SELECT name, size, rev FROM files WHERE volume_id = :volume AND name > :previous GROUP BY name HAVING rev = MAX(rev) ORDER BY name ASC LIMIT 1"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_listrevs[i], "SELECT size, rev FROM files WHERE volume_id = :volume AND name = :name AND rev > :previous ORDER BY rev ASC LIMIT 1"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_get[i], "SELECT fid, size, content, rev FROM files WHERE volume_id = :volume AND name = :name GROUP BY name HAVING rev = MAX(rev) LIMIT 1"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_getrev[i], "SELECT fid, size, content, rev FROM files WHERE volume_id = :volume AND name = :name AND rev = :revision LIMIT 1"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_tooold[i], "SELECT fid, rev, COUNT(*) AS nrevs FROM files WHERE volume_id = :volume AND name = :name GROUP BY name HAVING rev = MIN(rev) LIMIT 1"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_metaget[i], "SELECT key, value FROM fmeta WHERE file_id = :file"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_metaset[i], "INSERT OR REPLACE INTO fmeta (file_id, key, value) VALUES (:file, :key, :value)"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_metadel[i], "DELETE FROM fmeta WHERE file_id = :file AND key = :key"))
	    goto open_hashfs_fail;
	if(qprep(h->metadb[i], &h->qm_delfile[i], "DELETE FROM files WHERE fid = :file"))
	    goto open_hashfs_fail;
    }

    OPEN_DB("eventdb", &h->eventdb);
    if(qprep(h->eventdb, &h->qe_getjob, "SELECT complete, result, reason FROM jobs WHERE job = :id AND :owner IN (user, 0)"))
	goto open_hashfs_fail;
    /* FIXME: job TTL should be dependent on the type */
    if(qprep(h->eventdb, &h->qe_addjob, "INSERT INTO jobs (type, lock, expiry_time, data, user) VALUES (:type, :lock, datetime(:expiry, 'unixepoch'), :data, :uid)"))
	goto open_hashfs_fail;
    if(qprep(h->eventdb, &h->qe_addact, "INSERT INTO actions (job_id, target, addr, internaladdr, capacity) VALUES (:job, :node, :addr, :int_addr, :capa)"))
	goto open_hashfs_fail;
    if(qprep(h->eventdb, &h->qe_countjobs, "SELECT COUNT(*) FROM jobs WHERE user = :uid AND complete = 0"))
	goto open_hashfs_fail;

    OPEN_DB("xferdb", &h->xferdb);
    if(qprep(h->xferdb, &h->qx_add, "INSERT INTO topush (block, size, node) VALUES (:b, :s, :n)"))
       goto open_hashfs_fail;

    qnullify(q);
    sqlite3_reset(h->q_getval);

    free(path);
    return h;

open_hashfs_fail:
    free(path);
    sqlite3_finalize(q);

    close_all_dbs(h);

    free(h->blockbuf);
    free(h);
    return NULL;
}

int sx_hashfs_distcheck(sx_hashfs_t *h) {
    int ret = 0;

    if(!h)
	return 0;

    sqlite3_reset(h->q_gethdrev);
    switch(qstep(h->q_gethdrev)) {
    case SQLITE_DONE:
	break;
    case SQLITE_ROW:
	if(sqlite3_column_int64(h->q_gethdrev, 0) > h->hd_rev)
	    ret = 1;
	break;
    default:
	WARN("Failed to check distribution version, assuming unchanged");
    }
    sqlite3_reset(h->q_gethdrev);

    if(ret && load_config(h, h->sx))
	ret = -1;

    return ret; /* return 0 = no change, 1 = hdist-change, -1 = error */
}

time_t sx_hashfs_disttime(sx_hashfs_t *h) {
    return h->last_dist_change;
}

const char *sx_hashfs_cluster_name(sx_hashfs_t *h) {
    return h ? h->cluster_name : NULL;
}

uint16_t sx_hashfs_http_port(sx_hashfs_t *h) {
    return h ? h->http_port : 0;
}

const char *sx_hashfs_ca_file(sx_hashfs_t *h) {
    return h ? h->ssl_ca_file : NULL;
}

int sx_hashfs_uses_secure_proto(sx_hashfs_t *h) {
    if(!h)
	return -1;
    return (h->ssl_ca_file != NULL);
}

void sx_hashfs_set_triggers(sx_hashfs_t *h, int job_trigger, int xfer_trigger, int gc_trigger) {
    if(!h)
	return;
    h->job_trigger = job_trigger;
    h->xfer_trigger = xfer_trigger;
    h->gc_trigger = gc_trigger;
}

void sx_hashfs_close(sx_hashfs_t *h) {
    if(!h)
	return;
    if(h->have_hd)
	sxi_hdist_free(h->hd);
    sx_nodelist_delete(h->prev_dist);
    sx_nodelist_delete(h->next_dist);
    sx_nodelist_delete(h->prevnext_dist);
    sx_nodelist_delete(h->nextprev_dist);

    close_all_dbs(h);

    free(h->blockbuf);
/*    if(h->sx)
	sx_shutdown(h->sx, 0);
    do not free sx here: it is not owned by hashfs.c!
    freeing it here would cause use-after-free if server_done() is called
    */
    if(h->sx_clust)
	sxi_conns_free(h->sx_clust);
    free(h->ssl_ca_file);
    free(h->cluster_name);
    free(h->dir);
    free(h);
}

int sx_storage_is_bare(sx_hashfs_t *h) {
    return (h != NULL) && (h->cluster_name == NULL);
}

rc_ty sx_storage_activate(sx_hashfs_t *h, const char *name, const sx_uuid_t *node_uuid, uint8_t *admin_uid, unsigned int uid_size, uint8_t *admin_key, int key_size, uint16_t port, const char *ssl_ca_file, const sx_nodelist_t *allnodes) {
    rc_ty r, ret = FAIL_EINTERNAL;
    sqlite3_stmt *q = NULL;
    const sx_node_t *self;
    unsigned int nodeidx;

    if(!h || !name || !node_uuid || !admin_key) {
	NULLARG();
	return EFAULT;
    }
    if(!sx_storage_is_bare(h)) {
	msg_set_reason("Storage was already activated");
	return EINVAL;
    }

    self = sx_nodelist_lookup_index(allnodes, node_uuid, &nodeidx);
    if(!self) {
	msg_set_reason("Failed to find node uuid in node list");
	return EINVAL;
    }

    if(qbegin(h->db))
	return FAIL_EINTERNAL;

    if(qprep(h->db, &q, "INSERT OR REPLACE INTO hashfs (key, value) VALUES (:k , :v)"))
	goto storage_activate_fail;

    r = sx_hashfs_create_user(h, "admin", admin_uid, uid_size, admin_key, key_size, ROLE_ADMIN);
    if(r != OK) {
	ret = r;
	goto storage_activate_fail;
    }
    r = sx_hashfs_user_onoff(h, "admin", 1);
    if(r != OK) {
	ret = r;
	goto storage_activate_fail;
    }

    if(ssl_ca_file) {
	if(qbind_text(q, ":k", "ssl_ca_file") || qbind_text(q, ":v", ssl_ca_file) || qstep_noret(q))
	    goto storage_activate_fail;
    }
    if(qbind_text(q, ":k", "cluster_name") || qbind_text(q, ":v", name) || qstep_noret(q))
	goto storage_activate_fail;
    if(qbind_text(q, ":k", "node") || qbind_blob(q, ":v", node_uuid->binary, sizeof(node_uuid->binary)) || qstep_noret(q))
	goto storage_activate_fail;
    if(qbind_text(q, ":k", "http_port") || qbind_int(q, ":v", port) || qstep_noret(q))
	goto storage_activate_fail;

    if(sx_hashfs_hdist_change_commit(h))
	goto storage_activate_fail;

    if(sx_hashfs_modhdist(h, allnodes))
	goto storage_activate_fail;

    if(qcommit(h->db))
	goto storage_activate_fail;

    ret = OK;
 storage_activate_fail:
    if(ret != OK)
	qrollback(h->db);

    sqlite3_finalize(q);
    return ret;
}

static unsigned int size_to_blocks(uint64_t size, unsigned int *size_type, unsigned int *block_size) {
    unsigned int ret, sizenum = 1, bs;
    if(size > 128*1024*1024)
	sizenum = 2;
    else if(size < 128*1024)
	sizenum = 0;
    bs = bsz[sizenum];
    ret = size / bs;
    if(size % bs)
	ret++;
    if(size_type)
	*size_type = sizenum;
    if(block_size)
	*block_size = bs;
    return ret;
}

static int cmphash(const void *a, const void *b) {
    return memcmp(a, b, sizeof(sx_hash_t));
}

static unsigned int gethashdb(const sx_hash_t *hash) {
    return MurmurHash64(hash, sizeof(*hash), MURMUR_SEED) & (HASHDBS-1);
}

static unsigned int getgcdb(const sx_hash_t *hash) {
    return MurmurHash64(hash, sizeof(*hash), MURMUR_SEED) & (GCDBS-1);
}

static int getmetadb(const char *filename) {
    sx_hash_t hash;
    if(hash_buf(NULL, 0, filename, strlen(filename), &hash))
	return -1;

    return MurmurHash64(&hash, sizeof(hash), MURMUR_SEED) & (METADBS-1);
}

/* Returns 0 if the volume name is valid,
 * sets reason otherwise */
rc_ty sx_hashfs_check_volume_name(const char *name) {
    unsigned int namelen;
    if (!name) {
	NULLARG();
	return EFAULT;
    }
    if(*name=='.') {
	msg_set_reason("Invalid volume name '%s': must not start with a '.'", name);
	return EINVAL;
    }
    namelen = strlen(name);
    if(namelen < SXLIMIT_MIN_VOLNAME_LEN || namelen > SXLIMIT_MAX_VOLNAME_LEN) {
	msg_set_reason("Invalid volume name '%s': must be between %d and %d bytes",
		       name, SXLIMIT_MIN_VOLNAME_LEN, SXLIMIT_MAX_VOLNAME_LEN);
	return EINVAL;
    }
    if(utf8_validate_len(name) < 0) {
	msg_set_reason("Invalid volume name '%s': must be valid UTF8", name);
	return EINVAL;
    }
    return 0;
}

static int check_file_name(const char *name) {
    unsigned int namelen;
    if(!name) {
	NULLARG();
	return -1;
    }
    namelen = strlen(name);
    if(namelen < SXLIMIT_MIN_FILENAME_LEN || namelen > SXLIMIT_MAX_FILENAME_LEN) {
	msg_set_reason("Invalid file name '%s': must be between %d and %d bytes",
		       name, SXLIMIT_MIN_FILENAME_LEN, SXLIMIT_MAX_FILENAME_LEN);
	return -1;
    }
    if(utf8_validate_len(name) < 0) {
	msg_set_reason("Invalid file name '%s': must be valid UTF8", name);
	return -1;
    }
    return namelen;
}

rc_ty sx_hashfs_check_meta(const char *key, const void *value, unsigned int value_len) {
    unsigned int key_len;

    if(!key || !value) {
	NULLARG();
	return EFAULT;
    }

    key_len = strlen(key);
    if(key_len < SXLIMIT_META_MIN_KEY_LEN) {
	msg_set_reason("Invalid metadata key length %d: must be between %d and %d",
		       key_len, SXLIMIT_META_MIN_KEY_LEN, SXLIMIT_META_MAX_KEY_LEN);
	return EINVAL;
    }
    if(key_len > SXLIMIT_META_MAX_KEY_LEN) {
	msg_set_reason("Invalid metadata key length %d: must be between %d and %d",
		       key_len, SXLIMIT_META_MIN_KEY_LEN, SXLIMIT_META_MAX_KEY_LEN);
	return EMSGSIZE;
    }
    if (SXLIMIT_META_MIN_VALUE_LEN > 0 && value_len < SXLIMIT_META_MIN_VALUE_LEN) {
	msg_set_reason("Invalid metadata value length %d: must be between %d and %d",
		       value_len, SXLIMIT_META_MIN_VALUE_LEN, SXLIMIT_META_MAX_VALUE_LEN);
	return EINVAL;
    }
    if (value_len > SXLIMIT_META_MAX_VALUE_LEN) {
	msg_set_reason("Invalid metadata value length %d: must be between %d and %d",
		       value_len, SXLIMIT_META_MIN_VALUE_LEN, SXLIMIT_META_MAX_VALUE_LEN);
	return EMSGSIZE;
    }

    if (utf8_validate_len(key) < 0) {
	msg_set_reason("Invalid metadata key '%s': must be valid UTF8", key);
	return EINVAL;
    }
    return 0;
}

int sx_hashfs_check_username(const char *name) {
    unsigned int namelen;
    if(!name)
	return -1;
    namelen = strlen(name);
    if(namelen < SXLIMIT_MIN_USERNAME_LEN || namelen > SXLIMIT_MAX_USERNAME_LEN)
	return -1;
    if(utf8_validate_len(name) < 0)
	return 1;
    return 0;
}


static int parse_revision(const char *revision, unsigned int *revtime) {
    const char *eod;
    time_t t;

    if(!revision)
	return -1;
    if(strlen(revision) != REV_LEN)
	return -1;
    if(revision[REV_TIME_LEN] != ':')
	return -1;

    eod = strptimegm(revision, "%Y-%m-%d %H:%M:%S", &t);
    if(eod != &revision[REV_TIME_LEN - 4])
	return -1;
    if(revtime)
	*revtime = (unsigned int)t;
    return 0;
}

static int check_revision(const char *revision) {
    return parse_revision(revision, NULL);
}

#define TOKEN_SIGNED_LEN UUID_STRING_SIZE + 1 + TOKEN_RAND_BYTES * 2 + 1 + TOKEN_REPLICA_LEN + 1 + TOKEN_EXPIRE_LEN + 1
rc_ty sx_hashfs_make_token(sx_hashfs_t *h, const uint8_t *user, const char *rndhex, unsigned int replica, int64_t expires_at, const char **token) {
    sxi_hmac_sha1_ctx *hmac_ctx;
    uint8_t md[SXI_SHA1_BIN_LEN], rndbin[TOKEN_RAND_BYTES];
    char rndhexbuf[TOKEN_RAND_BYTES * 2 + 1], replicahex[2 + TOKEN_REPLICA_LEN + 1], expirehex[TOKEN_EXPIRE_LEN + 1];
    sx_uuid_t node_uuid;
    unsigned int len;
    rc_ty ret;

    if(!h || !user) {
	NULLARG();
	return EINVAL;
    }

    if(rndhex) {
	if(strlen(rndhex) != TOKEN_RAND_BYTES * 2 || hex2bin(rndhex, TOKEN_RAND_BYTES * 2, rndbin, sizeof(rndbin))) {
	    msg_set_reason("Invalid random string");
	    return EINVAL;
	}
    } else {
	/* non-blocking pseudo-random bytes, i.e. we don't want to block or deplete
	 * entropy as we only need a unique sequence of bytes, not a secret one as
	 * it is sent in plaintext anyway, and signed with an HMAC */
	if(sxi_rand_pseudo_bytes(rndbin, sizeof(rndbin)) == -1) {
	    /* can also return 0 or 1 but that doesn't matter here */
	    WARN("Cannot generate random bytes");
	    msg_set_reason("Failed to generate random string");
	    return FAIL_EINTERNAL;
	}
	if (bin2hex(rndbin, sizeof(rndbin), rndhexbuf, sizeof(rndhexbuf)))
            WARN("bin2hex failed");
	rndhex = rndhexbuf;
    }

    ret = sx_hashfs_self_uuid(h, &node_uuid);
    if(ret) {
        WARN("self_uuid failed");
	return ret;
    }

    snprintf(replicahex, sizeof(replicahex), "%010x", replica);
    snprintf(expirehex, sizeof(expirehex), "%016llx", (long long)expires_at);
    snprintf(h->put_token, sizeof(h->put_token), "%s:%s:%s:%s:", node_uuid.string, rndhex, replicahex+2, expirehex);
    len = strlen(h->put_token);
    if(len != TOKEN_SIGNED_LEN) {
	msg_set_reason("Generated token with bad length");
	return EINVAL;
    }

    hmac_ctx = sxi_hmac_sha1_init();
    if(!sxi_hmac_sha1_init_ex(hmac_ctx, &h->tokenkey, sizeof(h->tokenkey)) ||
       !sxi_hmac_sha1_update(hmac_ctx, (unsigned char *)h->put_token, len) ||
       !sxi_hmac_sha1_final(hmac_ctx, md, &len) ||
       len != AUTH_KEY_LEN) {
	msg_set_reason("Failed to compute token hmac");
	CRIT("Cannot genearate token hmac");
	ret = FAIL_EINTERNAL;
    } else {
	bin2hex(md, AUTH_KEY_LEN, &h->put_token[TOKEN_SIGNED_LEN], AUTH_KEY_LEN * 2 + 1);
	h->put_token[sizeof(h->put_token)-1] = '\0';
	*token = h->put_token;
    }
    sxi_hmac_sha1_cleanup(&hmac_ctx);

    return ret;
}


struct token_data {
    sx_uuid_t uuid;
    char token[TOKEN_RAND_BYTES*2+1];
    unsigned int replica;
    int64_t expires_at;
};

static int parse_token(sxc_client_t *sx, const uint8_t *user, const char *token, const sx_hash_t *tokenkey, struct token_data *td) {
    char uuid_str[UUID_STRING_SIZE+1], hmac[AUTH_KEY_LEN*2+1];
    char *eptr;
    uint8_t md[SXI_SHA1_BIN_LEN];
    sxi_hmac_sha1_ctx *hmac_ctx;
    unsigned int ml;

    if(!user || !token || !td) {
	NULLARG();
	return 1;
    }
    if(strlen(token) != TOKEN_TEXT_LEN) {
	msg_set_reason("Invalid token length: expected %d, got %u", TOKEN_TEXT_LEN, (unsigned)strlen(token));
	return 1;
    }
    if(token[UUID_STRING_SIZE] != ':' ||
       token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2] != ':' ||
       token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2+1+TOKEN_REPLICA_LEN] != ':' ||
       token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2+1+TOKEN_REPLICA_LEN + 1 + TOKEN_EXPIRE_LEN] != ':') {
	msg_set_reason("Invalid token format");
	return 1;
    }

    hmac_ctx = sxi_hmac_sha1_init();
    if(!sxi_hmac_sha1_init_ex(hmac_ctx, tokenkey, sizeof(*tokenkey)) ||
       !sxi_hmac_sha1_update(hmac_ctx, (unsigned char *)token, TOKEN_SIGNED_LEN) ||
       !sxi_hmac_sha1_final(hmac_ctx, md, &ml) ||
       ml != AUTH_KEY_LEN) {
	sxi_hmac_sha1_cleanup(&hmac_ctx);
	CRIT("Cannot generate token hmac");
	return 1;
    }
    sxi_hmac_sha1_cleanup(&hmac_ctx);
    bin2hex(md, AUTH_KEY_LEN, hmac, sizeof(hmac));
    if(hmac_compare((const unsigned char *)&token[TOKEN_SIGNED_LEN], (const unsigned char *)hmac, AUTH_KEY_LEN*2)) {
	msg_set_reason("Token signature does not match");
	return 1;
    }

    memcpy(uuid_str, token, UUID_STRING_SIZE);
    uuid_str[UUID_STRING_SIZE] = '\0';
    if(uuid_from_string(&td->uuid, uuid_str)) {
	msg_set_reason("Invalid token format");
	return 1;
    }

    memcpy(td->token, &token[UUID_STRING_SIZE+1], sizeof(td->token));
    td->token[sizeof(td->token)-1] = '\0';

    td->replica = strtol(&token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2+1], &eptr, 16);
    if(eptr != &token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2+1+TOKEN_REPLICA_LEN]) {
	msg_set_reason("Invalid token format");
	return 1;
    }

    td->expires_at = strtol(&token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2+1 + TOKEN_REPLICA_LEN + 1], &eptr, 16);
    if(eptr != &token[UUID_STRING_SIZE+1+TOKEN_RAND_BYTES*2+1+TOKEN_REPLICA_LEN + 1 + TOKEN_EXPIRE_LEN]) {
	msg_set_reason("Invalid token format");
	return 1;
    }

    return 0;
}

rc_ty sx_hashfs_token_get(sx_hashfs_t *h, const uint8_t *user, const char *token, unsigned int *replica_count, int64_t *expires_at) {
    struct token_data tkdt;
    if(parse_token(h->sx, user, token, &h->tokenkey, &tkdt))
	return EINVAL;
    *replica_count = tkdt.replica;
    if (expires_at)
        *expires_at = tkdt.expires_at;
    return OK;
}

static long long get_count(sxi_db_t *db, const char *table)
{
    long long ret = 0;
    char query[128];
    sqlite3_stmt *q = NULL;
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM %s", table);
    if(!qprep(db, &q, query) && !qstep_ret(q))
	ret = sqlite3_column_int64(q, 0);
    sqlite3_finalize(q);
    return ret;
}

void sx_hashfs_stats(sx_hashfs_t *h)
{
    int i, j;
    INFO("User#: %lld", get_count(h->db, "users"));
    INFO("Volume#: %lld", get_count(h->db, "volumes"));
    INFO("Volume metadata#: %lld", get_count(h->db, "vmeta"));
    long long files = 0, fmeta = 0;
    for(i=0; i<METADBS; i++) {
	files += get_count(h->metadb[i], "files");
	fmeta += get_count(h->metadb[i], "fmeta");
    }
    INFO("File#: %lld", files);
    INFO("File metadata#: %lld", fmeta);
    INFO("Block counts:");
    for (j=0; j<SIZES; j++) {
	long long blocks = 0;
	for(i=0;i<HASHDBS;i++)
	    blocks += get_count(h->datadb[j][i], "blocks");
	INFO("\t%-8s (%8d byte) block#: %lld", sizelongnames[j], bsz[j], blocks);
    }
}

static void analyze_db(sxi_db_t *db)
{
    const char *name = sqlite3_db_filename(db->handle, "main");
    if (!name) name = "";
    INFO("%s:", name);
    sqlite3_stmt *q = NULL;
    if (!qprep(db, &q, "PRAGMA integrity_check;")) {
	while(qstep(q) == SQLITE_ROW)
	    INFO("\tintegrity_check: %s", sqlite3_column_text(q,0));
    }
    sqlite3_finalize(q);
}

void sx_hashfs_analyze(sx_hashfs_t *h)
{
    /* TODO: some reporting about jobs/events table */
    INFO("Analyzing databases...");
    analyze_db(h->db);
    unsigned i, j;
    for(i=0; i<METADBS; i++)
	analyze_db(h->metadb[i]);
    for (j=0; j<SIZES; j++) {
	for(i=0;i<HASHDBS;i++) {
	    analyze_db(h->datadb[j][i]);
	}
    }
}

int sx_hashfs_check(sx_hashfs_t *h, int debug) {
    unsigned int i, j;
    int64_t rows = 0; /* because arguing with gcc is pointless */
    int res = 0;

    for(i=0; i<METADBS; i++) {
	sqlite3_stmt *lock = NULL, *count = NULL, *list = NULL, *unlock = NULL;
	int fail = 1;

	if(qprep(h->metadb[i], &lock, "BEGIN EXCLUSIVE TRANSACTION") ||
	   qprep(h->metadb[i], &count, "SELECT COUNT(*) FROM files") ||
	   qprep(h->metadb[i], &list, "SELECT rowid, name, size, content FROM files ORDER BY name ASC") ||
	   qprep(h->metadb[i], &unlock, "ROLLBACK"))
	    goto hashfs_check_fileerr;
	if(qstep_noret(lock))
	    goto hashfs_check_fileerr;

	if(debug) {
	    if(qstep_ret(count))
		goto hashfs_check_fileerr;
	    rows = sqlite3_column_int64(count, 0);
	    INFO("Checking consistency of %lld files in metadata database %u / %u...", (long long int)rows, i+1, METADBS);
	}

	while(1) {
	    const char *name;
	    int64_t size, row;
	    unsigned int listlen;
	    int r = qstep(list);
	    if(r == SQLITE_DONE)
		break;
	    if(r != SQLITE_ROW)
		goto hashfs_check_fileerr;

	    row = sqlite3_column_int64(list, 0);
	    name = (const char *)sqlite3_column_text(list, 1);

	    if(!name || !strlen(name)) {
		WARN("Found invalid name on row %lld in metadata database %08x", (long long int)row, i);
		continue;
	    }

	    size = sqlite3_column_int64(list, 2);
	    sqlite3_column_blob(list, 3);
	    listlen = sqlite3_column_bytes(list, 3);
	    if(size < 0 || (listlen % SXI_SHA1_BIN_LEN) || size_to_blocks(size, NULL, NULL) != listlen / SXI_SHA1_BIN_LEN) {
		WARN("Invalid size for file %s (row %lld) in metadata database %08x", name, (long long int)row, i);
		continue;
	    }
	}

	fail = 0;

	hashfs_check_fileerr:
	if(unlock)
	    qstep(unlock);
	sqlite3_finalize(unlock);
	sqlite3_finalize(list);
	sqlite3_finalize(count);
	sqlite3_finalize(lock);

	if(fail) {
	    WARN("Verification of files in metadata database %08x aborted due to errors", i);
	    res = 1;
	}
    }

    for(j = 0; j < SIZES; j++) {
	for(i=0; i<HASHDBS; i++) {
	    sqlite3_stmt *lock = NULL, *count= NULL, *dups = NULL, *list = NULL, *unlock = NULL;
	    int fail = 1;

	    if(qprep(h->datadb[j][i], &lock, "BEGIN EXCLUSIVE TRANSACTION") ||
	       qprep(h->datadb[j][i], &count, "SELECT count(*) FROM blocks") ||
	       qprep(h->datadb[j][i], &list, "SELECT rowid, hash, blockno FROM blocks ORDER BY blockno ASC") ||
	       qprep(h->datadb[j][i], &dups, "SELECT b1.rowid, b1.hash, b2.rowid, b2.hash, b1.blockno FROM blocks AS b1 LEFT JOIN blocks AS b2 ON b1.rowid != b2.rowid WHERE b1.blockno = b2.blockno") ||
	       qprep(h->datadb[j][i], &unlock, "ROLLBACK"))
		goto hashfs_check_dataerr;
	    if(qstep_noret(lock))
		goto hashfs_check_dataerr;

	    if(debug) {
		if(qstep_ret(count))
		    goto hashfs_check_dataerr;
		rows = sqlite3_column_int64(count, 0);
		INFO("Checking consistency of %lld blocks in %s hash database %u / %u...", (long long int)rows, sizelongnames[j], i+1, HASHDBS);
	    }

	    while(1) {
		char h1[SXI_SHA1_BIN_LEN * 2 + 1], h2[SXI_SHA1_BIN_LEN * 2 + 1];
		const sx_hash_t *refhash;
		sx_hash_t comphash;
		int64_t off, row;
		int r = qstep(list);
		if(r == SQLITE_DONE)
		    break;
		if(r != SQLITE_ROW)
		    goto hashfs_check_dataerr;

		row = sqlite3_column_int64(list, 0);

		refhash = (const sx_hash_t *)sqlite3_column_blob(list, 1);
		if(!refhash || sqlite3_column_bytes(list, 1) != SXI_SHA1_BIN_LEN) {
		    WARN("Found invalid hash on row %lld in %s hash database %08x", (long long int)row, sizelongnames[j], i);
		    res = 1;
		    continue;
		}

		off = sqlite3_column_int(list, 2);
		if(off <= 0) {
		    bin2hex(refhash->b, sizeof(*refhash), h1, sizeof(h1));
		    WARN("Invalid offset found for hash %s (row %lld) in %s data file %08x", h1, (long long int)row, sizelongnames[j], i);
		    res = 1;
		    continue;
		}
		off *= bsz[j];

		if(read_block(h->datafd[j][i], h->blockbuf, off, bsz[j])) {
		    bin2hex(refhash->b, sizeof(*refhash), h1, sizeof(h1));
		    WARN("Failed to read hash %s (row %lld) from %s data file %08x at offset %lld", h1, (long long int)row, sizelongnames[j], i, (long long int)off);
		    res = 1;
		    continue;
		}

		if(hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), h->blockbuf, bsz[j], &comphash))
		    goto hashfs_check_dataerr;

		if(cmphash(refhash, &comphash)) {
		    bin2hex(refhash->b, sizeof(*refhash), h1, sizeof(h1));
		    bin2hex(comphash.b, sizeof(comphash), h2, sizeof(h2));
		    WARN("Mismatch %s (row %lld) vs %s on %s data file %08x at offset %lld", h1, (long long int)row, h2, sizelongnames[j], i, (long long int)off);
		    res = 1;
		}
	    }

	    if(debug)
		INFO("Checking duplicates within %lld blocks in %s hash database %u / %u...", (long long int)rows, sizelongnames[j], i+1, HASHDBS);

	    while(1) {
		char h1[SXI_SHA1_BIN_LEN * 2 + 1], h2[SXI_SHA1_BIN_LEN * 2 + 1];
		const sx_hash_t *hash1, *hash2;
		int64_t row1, row2;
		int r = qstep(dups);
		if(r == SQLITE_DONE)
		    break;
		if(r != SQLITE_ROW)
		    goto hashfs_check_dataerr;

		row1 = sqlite3_column_int64(dups, 0);
		row2 = sqlite3_column_int64(dups, 2);
		if(row1 > row2) /* Filtering out half of the set i.e. we report (A, B) but not (B, A) */
		    continue;   /* For some reasons doing this in sql is very slow */

		hash1 = (const sx_hash_t *)sqlite3_column_blob(dups, 1);
		hash2 = (const sx_hash_t *)sqlite3_column_blob(dups, 3);
		if(sqlite3_column_bytes(dups, 1) != sizeof(*hash1))
		    strcpy(h1, "<INVALID HASH>");
		else
		    bin2hex(hash1->b, sizeof(*hash1), h1, sizeof(h1));
		if(sqlite3_column_bytes(dups, 3) != sizeof(*hash2))
		    strcpy(h2, "<INVALID HASH>");
		else
		    bin2hex(hash2->b, sizeof(*hash2), h2, sizeof(h2));

		WARN("Hash %s (row %lld) and hash %s (row %lld) in %s hash database %08x share the same block number %lld", h1, (long long int)row1, h2, (long long int)row2, sizelongnames[j], i, sqlite3_column_int64(dups, 4));
		res = 1;
	    }

	    fail = 0;

	    hashfs_check_dataerr:
	    if(unlock)
		qstep(unlock);
	    sqlite3_finalize(unlock);
	    sqlite3_finalize(list);
	    sqlite3_finalize(dups);
	    sqlite3_finalize(count);
	    sqlite3_finalize(lock);

	    if(fail) {
		WARN("Verification of hashes in %s hash database %08x aborted due to errors", sizelongnames[j], i);
		res = 1;
	    }
	}
    }
    return res;

}

const char *sx_hashfs_version(sx_hashfs_t *h) {
    return h->version;
}

const sx_uuid_t *sx_hashfs_uuid(sx_hashfs_t *h) {
    return &h->cluster_uuid;
}

int sx_hashfs_is_rebalancing(sx_hashfs_t *h) {
    return h ? h->is_rebalancing : 0;
}

/* MODHDIST: this was forked off into sx_hashfs_hdist_change_add
 * it should be simplified to only handle local activation (sxadm cluster --new) */
rc_ty sx_hashfs_modhdist(sx_hashfs_t *h, const sx_nodelist_t *list) {
    sxi_hdist_t *newmod = NULL;
    unsigned int nnodes, i, blob_size;
    sqlite3_stmt *q;
    const void *blob;
    rc_ty ret = OK;

    if(!h || !list) {
	NULLARG();
	return EINVAL;
    }

    nnodes = sx_nodelist_count(list);
    if(nnodes < 1) {
	msg_set_reason("Called with empty distribution list");
	return EINVAL;
    }

    if(h->have_hd == 0) {
	newmod = sxi_hdist_new(HDIST_SEED, 2, NULL);
    } else if(!h->is_rebalancing) {
	if((ret = sxi_hdist_get_cfg(h->hd, &blob, &blob_size)) == OK &&
	   (newmod = sxi_hdist_from_cfg(blob, blob_size)) != NULL) {
	    ret = sxi_hdist_newbuild(newmod);
	    if(ret != OK)
		sxi_hdist_free(newmod);
	}
    } else
	ret = EEXIST;

    if(ret == OK && !newmod)
	ret = ENOMEM;

    if(ret != OK) {
	msg_set_reason("Failed to prepare the distribution update");
	sxi_hdist_free(newmod);
	return ret;
    }

    for(i=0; i<nnodes; i++) {
	const sx_node_t *n = sx_nodelist_get(list, i);
	ret = sxi_hdist_addnode(newmod, sx_node_uuid(n), sx_node_addr(n), sx_node_internal_addr(n), sx_node_capacity(n));
	if(ret == OK)
	    continue;
	msg_set_reason("Failed to add the distribution node");
	sxi_hdist_free(newmod);
	return FAIL_EINTERNAL;
    }

    ret = sxi_hdist_build(newmod);
    if(ret) {
	msg_set_reason("Failed to update the distribution model");
	sxi_hdist_free(newmod);
	return FAIL_EINTERNAL;
    }

    ret = sxi_hdist_get_cfg(newmod, &blob, &blob_size);
    if(ret) {
	msg_set_reason("Failed to update the distribution model");
	sxi_hdist_free(newmod);
	return FAIL_EINTERNAL;
    }

    if(qprep(h->db, &q, "INSERT OR REPLACE INTO hashfs (key, value) VALUES (:k , :v)") ||
       qbind_text(q, ":k", "dist") ||
       qbind_blob(q, ":v", blob, blob_size) ||
       qstep_noret(q)) {
	msg_set_reason("Failed to save the updated distribution model");
	ret = FAIL_EINTERNAL;
    } else {
	sqlite3_reset(q);
	if(qbind_text(q, ":k", "dist_rev") ||
	   qbind_int64(q, ":v", sxi_hdist_version(newmod)) ||
	   qstep_noret(q)) {
	    msg_set_reason("Failed to save the updated distribution model");
	    ret = FAIL_EINTERNAL;
	}
    }
    qnullify(q);
    if(ret)
	return ret;

    if(h->have_hd)
	sxi_hdist_free(h->hd);
    h->hd = newmod;
    h->have_hd = 1;
    return OK;
}


const sx_nodelist_t *sx_hashfs_nodelist(sx_hashfs_t *h, sx_hashfs_nl_t which) {
    if(!h)
	return NULL;
    switch(which) {
    case NL_PREV:
	return h->prev_dist;
    case NL_NEXT:
	return h->next_dist;
    case NL_PREVNEXT:
	return h->prevnext_dist;
    case NL_NEXTPREV:
	return h->nextprev_dist;
    default:
	return NULL;
    }
}

static int hash_nidx_tobuf(sx_hashfs_t *h, const sx_hash_t *hash, unsigned int replica_count, unsigned int *nidx) {
    const sx_nodelist_t *nodes;
    sx_nodelist_t *belongsto;
    unsigned int i, nnodes;

    if(!h || !hash) {
	NULLARG();
	return 1;
    }

    if(!h->have_hd) {
	BADSTATE("Called before initialization");
	return 1;
    }

    nodes = sx_hashfs_nodelist(h, NL_NEXT);
    nnodes = sx_nodelist_count(nodes);

    if(replica_count < 1 || replica_count > nnodes) {
	msg_set_reason("Bad replica count: %d must be between %d and %d", replica_count, 1, nnodes);
	return 1;
    }

    /* MODHDIST: using _next set - see rant under are_blocks_available() */
    belongsto = sxi_hdist_locate(h->hd, MurmurHash64(hash, sizeof(*hash), HDIST_SEED), replica_count, 0);
    if(!belongsto) {
	WARN("Cannot get nodes for volume");
	return 1;
    }

    for(i=0; i<replica_count; i++) {
	const sx_node_t *node = sx_nodelist_get(belongsto, i);
	const sx_uuid_t *uuid = sx_node_uuid(node);
	if(!sx_nodelist_lookup_index(nodes, uuid, &nidx[i])) {
	    CRIT("node id %s from hdist is unknown to us", uuid->string);
	    sx_nodelist_delete(belongsto);
	    return 1;
	}
    }

    sx_nodelist_delete(belongsto);
    return 0;
}

int sx_hashfs_is_or_was_my_volume(sx_hashfs_t *h, const sx_hashfs_volume_t *vol) {
    sx_nodelist_t *volnodes;
    sx_hash_t hash;
    int ret = 0;

    if(!h || !vol || !h->have_hd)
	return 0;

    if(hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), vol->name, strlen(vol->name), &hash)) {
	WARN("hashing volume name failed");
	return 0;
    }

    volnodes = sx_hashfs_hashnodes(h, NL_NEXTPREV, &hash, vol->replica_count);
    if(volnodes) {
	if(sx_nodelist_lookup(volnodes, &h->node_uuid))
	    ret = 1;
	sx_nodelist_delete(volnodes);
    }

    return ret;
}

static unsigned int slashes_in(const char *s) {
    unsigned int l = strlen(s), found = 0;
    const char *sl;
    while(l && (sl = memchr(s, '/', l))) {
	found++;
	sl++;
	l -= sl -s;
	s = sl;
    }
    return found;
}

static char *ith_slash(char *s, unsigned int i) {
    unsigned found = 0;
    while ((s = strchr(s, '/'))) {
        found++;
        if (found == i)
            return s;
        s++;
    }
    return NULL;
}

rc_ty sx_hashfs_revision_first(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *name, const sx_hashfs_file_t **file) {
    if(!volume || !file) {
	NULLARG();
	return EINVAL;
    }

    if(!sx_hashfs_is_or_was_my_volume(h, volume)) {
	msg_set_reason("Wrong node for volume '%s': ...", volume->name);
	return ENOENT;
    }

    if(check_file_name(name)<0) {
	msg_set_reason("Invalid file name");
	return EINVAL;
    }

    h->rev_ndb = getmetadb(name);
    if(h->rev_ndb < 0)
	return FAIL_EINTERNAL;

    sqlite3_reset(h->qm_listrevs[h->rev_ndb]);

    if(qbind_int64(h->qm_listrevs[h->rev_ndb], ":volume", volume->id) ||
       qbind_text(h->qm_listrevs[h->rev_ndb], ":name", name))
	return FAIL_EINTERNAL;

    strncpy(h->list_file.name, name, sizeof(h->list_file.name));
    h->list_file.name[sizeof(h->list_file.name)-1] = '\0';
    h->list_file.revision[0] = '\0';
    *file = &h->list_file;

    return sx_hashfs_revision_next(h);
}


rc_ty sx_hashfs_revision_next(sx_hashfs_t *h) {
    sqlite3_stmt *q = h->qm_listrevs[h->rev_ndb];
    const char *revision;
    int r;

    sqlite3_reset(q);
    if(qbind_text(q, ":previous", h->list_file.revision))
	return FAIL_EINTERNAL;

    r = qstep(q);
    if(r == SQLITE_DONE) {
	sqlite3_reset(q);
	return h->list_file.revision[0] ? ITER_NO_MORE : ENOENT;
    }
    if(r != SQLITE_ROW) {
	sqlite3_reset(q);
	return FAIL_EINTERNAL;
    }

    h->list_file.file_size = sqlite3_column_int64(q, 0);
    revision = (const char *)sqlite3_column_text(q, 1);
    if(parse_revision(revision, &h->list_file.created_at)) {
	WARN("Found bad revision %s", revision ? revision : "(NULL)");
	sqlite3_reset(q);
	return FAIL_EINTERNAL;
    }
    strncpy(h->list_file.revision, revision, sizeof(h->list_file.revision));
    h->list_file.revision[sizeof(h->list_file.revision)-1] = '\0';
    size_to_blocks(h->list_file.file_size, NULL, &h->list_file.block_size);

    sqlite3_reset(q);

    return OK;
}

static inline int has_wildcard(const char *str)
{
    return strcspn(str, "*?[") < strlen(str);
}

rc_ty sx_hashfs_list_first(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *pattern, const sx_hashfs_file_t **file, int recurse) {
    int l, r, plen;
    rc_ty rc;

    if(!pattern)
	pattern = "/";

    while(pattern[0] == '/')
	pattern++;

    if (!*pattern)
	pattern = "/";

    plen = check_file_name(pattern);
    if(!h || !volume || plen < 0 || !file) {
	NULLARG();
	return EINVAL;
    }

    if(!sx_hashfs_is_or_was_my_volume(h, volume)) {
	/* TODO: got, expected: */
	msg_set_reason("Wrong node for volume '%s': ...", volume->name);
	return ENOENT;
    }

    memcpy(h->list_pattern, pattern, plen + 1);
    for(l = 0, r = 1; r<plen; r++) {
	if(h->list_pattern[l] != '/' || h->list_pattern[r] != '/') {
	    l++;
	    if(l!=r)
		h->list_pattern[l] = h->list_pattern[r];
	}
    }
    plen = l+1;
    h->list_pattern[plen] = '\0';
    if (h->list_pattern[plen-1] == '/') {
        plen--;
        if (plen > 0)
            memcpy(&h->list_pattern[plen], "/*", 3);
        else
            memcpy(&h->list_pattern[plen], "*", 2);
    }
    h->list_pattern_slashes = slashes_in(h->list_pattern);
    h->list_file.name[0] = '\0';
    h->list_file.itername[0] = '\0';
    h->list_file.lastname[0] = '\0';
    h->list_recurse = recurse;
    h->list_volid = volume->id;
    *file = &h->list_file;

    rc = sx_hashfs_list_next(h);
    if (rc == ITER_NO_MORE && has_wildcard(h->list_pattern)) {
        char old_pattern[sizeof(h->list_pattern)];
        strncpy(old_pattern, h->list_pattern, sizeof(old_pattern)-1);
        old_pattern[sizeof(old_pattern)-1] = '\0';
        /* matching with wildcards failed, try exact match now:
         * build a pattern with all wildcards escaped, except
         * the one used for dir listing.*/
        for (l=0, r=0; r<plen;) {
            if (strchr("*?[", old_pattern[r])) {
                h->list_pattern[l++] = '\\';
            }
            h->list_pattern[l++] = old_pattern[r++];
        }
        /* copy plen => strlen unchanged, needed for dir listing */
        memcpy(&h->list_pattern[l], &old_pattern[r], strlen(old_pattern) - r + 1);
        DEBUG("doing exact match: %s", h->list_pattern);
        h->list_file.name[0] = '\0';
        h->list_file.itername[0] = '\0';
        h->list_file.lastname[0] = '\0';
        rc = sx_hashfs_list_next(h);
    }
    return rc;
}

rc_ty sx_hashfs_list_next(sx_hashfs_t *h) {
    int found, list_ndb, match_failed;
    if(!h || !h->list_pattern || !*h->list_pattern)
	return EINVAL;

    do {
	found = 0;
	for(list_ndb=0; list_ndb < METADBS; list_ndb++) {
	    sqlite3_reset(h->qm_list[list_ndb]);
	    if(qbind_int64(h->qm_list[list_ndb], ":volume", h->list_volid) ||
	       qbind_text(h->qm_list[list_ndb], ":previous", h->list_file.itername))
		return FAIL_EINTERNAL;

	    int r = qstep(h->qm_list[list_ndb]);

	    if(r == SQLITE_DONE)
		continue;

	    if(r != SQLITE_ROW)
		return FAIL_EINTERNAL;

	    const char *n = (char *)sqlite3_column_text(h->qm_list[list_ndb], 0);
	    if(!n) {
		WARN("Cannot list NULL filename on meta database %u", list_ndb);
		return FAIL_EINTERNAL;
	    }

	    if(!found || strcmp(n, h->list_file.name+1) < 0) {
		found = 1;
		h->list_file.name[0] = '/';
		strncpy(h->list_file.name+1, n, sizeof(h->list_file.name)-1);
		h->list_file.name[sizeof(h->list_file.name)-1] = '\0';

		h->list_file.file_size = sqlite3_column_int64(h->qm_list[list_ndb], 1);
		h->list_file.nblocks = size_to_blocks(h->list_file.file_size, NULL, &h->list_file.block_size);

		const char *revision = (const char *)sqlite3_column_text(h->qm_list[list_ndb], 2);
		if(!revision || parse_revision(revision, &h->list_file.created_at)) {
		    /* Failsafe, not reached */
		    h->list_file.created_at = 0;
		    h->list_file.revision[0] = '\0';
		} else {
		    strncpy(h->list_file.revision, revision, sizeof(h->list_file.revision));
		    h->list_file.revision[sizeof(h->list_file.revision)-1] = '\0';
		}
	    }
	    sqlite3_reset(h->qm_list[list_ndb]);
	}

	if(!found)
	    return ITER_NO_MORE;

	strncpy(h->list_file.itername, h->list_file.name+1, sizeof(h->list_file.itername));
	h->list_file.itername[sizeof(h->list_file.itername)-1] = '\0';

	char *q = ith_slash(h->list_file.name+1, h->list_pattern_slashes + 1);
	if (q)
	    *q = '\0';/* match just dir part */

        match_failed = fnmatch(h->list_pattern, h->list_file.name+1, FNM_PATHNAME);
        DEBUG("pattern: %s, path: %s -> %d",
              h->list_pattern, h->list_file.name+1, match_failed);

	if (q)
	    *q = '/';/* full path again */
	if (!h->list_recurse && q) {
	    q[1] = '\0';
            h->list_file.file_size = h->list_file.nblocks = 0;
        }
        /* only continue if pattern matched, and it is a new file / directory */
    } while (match_failed || !strcmp(h->list_file.lastname, h->list_file.name));

    strncpy(h->list_file.lastname, h->list_file.name, sizeof(h->list_file.lastname));
    h->list_file.lastname[sizeof(h->list_file.lastname)-1] = '\0';
    return OK;
}

sx_nodelist_t *sx_hashfs_hashnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hash_t *hash, unsigned int replica_count) {
    sx_nodelist_t *prev = NULL, *next = NULL;
    unsigned int nnodes;
    int64_t mh;

    if(!h || !hash) {
	NULLARG();
	return NULL;
    }

    if(replica_count < 1) {
	msg_set_reason("Bad replica count: %d", replica_count);
	return NULL;
    }

    if(!h->have_hd) {
	BADSTATE("Called before initialization");
	return NULL;
    }

    mh = MurmurHash64(hash, sizeof(*hash), HDIST_SEED);

    if(h->is_rebalancing && (which == NL_PREV || which == NL_PREVNEXT || which == NL_NEXTPREV)) {
	nnodes = sx_nodelist_count(h->prev_dist);
	if(replica_count <= nnodes) {
	    prev = sxi_hdist_locate(h->hd, mh, replica_count, 1);
	    if(!prev) {
		msg_set_reason("Failed to locate hash");
		return NULL;
	    }
	} else if(which == NL_PREV)
	    msg_set_reason("Bad replica count: %d should be below %d", replica_count, nnodes);

	/* MODHDIST: over replica request is only fatal if we don't have a NEXT part */
	if(which == NL_PREV)
	    return prev;
    }

    nnodes = sx_nodelist_count(h->next_dist);
    if(replica_count > nnodes) {
	/* MODHDIST: over replica request is always fatal (replica can't have decreased) */
	msg_set_reason("Bad replica count: %d should be below %d", replica_count, nnodes);
	sx_nodelist_delete(prev);
	return NULL;
    }
    next = sxi_hdist_locate(h->hd, mh, replica_count, 0);
    if(!next) {
	msg_set_reason("Failed to locate hash");
	return NULL;
    }

    if(prev) {
	sx_nodelist_t *ret, *del;
	rc_ty r;
	if(which == NL_NEXTPREV) {
	    ret = next;
	    del = prev;
	} else {
	    ret = prev;
	    del = next;
	}
	r = sx_nodelist_addlist(ret, del);
	sx_nodelist_delete(del);
	if(r) {
	    sx_nodelist_delete(ret);
	    ret = NULL;
	}
	return ret;
    }

    return next;
}

sx_nodelist_t *sx_hashfs_putfile_hashnodes(sx_hashfs_t *h, const sx_hash_t *hash) {
    return sx_hashfs_hashnodes(h, NL_NEXT, hash, h->put_replica);
}

rc_ty sx_hashfs_volnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hashfs_volume_t *volume, int64_t size, sx_nodelist_t **nodes, unsigned int *block_size) {
    sx_hash_t hash;

    if(!h || !volume || !nodes) {
	NULLARG();
	return EFAULT;
    }
    if (size < SXLIMIT_MIN_FILE_SIZE || size > SXLIMIT_MAX_FILE_SIZE) {
	msg_set_reason("Invalid size %lld: must be between %lld and %lld",
		       (long long)size, (long long)SXLIMIT_MIN_FILE_SIZE,
		       (long long)SXLIMIT_MAX_FILE_SIZE);
	return EINVAL;
    }

    if(hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), volume->name, strlen(volume->name), &hash))
	return FAIL_EINTERNAL;

    if(!(*nodes = sx_hashfs_hashnodes(h, which, &hash, volume->replica_count)))
	return FAIL_EINTERNAL;

    size_to_blocks(size, NULL, block_size);
    return OK;
}


/* MODHDIST: there might now be 0, 1 or 2 selves. which do we return? */
const sx_node_t *sx_hashfs_self(sx_hashfs_t *h) {
    if(!h || sx_storage_is_bare(h))
	return NULL;
    return sx_nodelist_lookup(h->next_dist, &h->node_uuid);
}

rc_ty sx_hashfs_self_uuid(sx_hashfs_t *h, sx_uuid_t *uuid) {
    if(!h || !uuid) {
	NULLARG();
	return EFAULT;
    }
    if(sx_storage_is_bare(h))
	return FAIL_EINIT;

    memcpy(uuid, &h->node_uuid, sizeof(*uuid));
    return OK;
}

const char *sx_hashfs_self_unique(sx_hashfs_t *h) {
    char *r = (char *)h->blockbuf;
    uint64_t a, b;

    if(sx_storage_is_bare(h))
	a = 0;
    else
	a = MurmurHash64(h->node_uuid.binary, sizeof(h->node_uuid.binary), HDIST_SEED);

    b = MurmurHash64(h->cluster_uuid.binary, sizeof(h->cluster_uuid.binary), HDIST_SEED);
    sprintf(r, "%016llx%016llx", (long long)a, (long long)b);

    return r;
}

const char *sx_hashfs_authtoken(sx_hashfs_t *h) {
    return (h && strlen(h->root_auth) == AUTHTOK_ASCII_LEN) ? h->root_auth : NULL;
}

char *sxi_hashfs_admintoken(sx_hashfs_t *h) {
    uint8_t key[AUTH_KEY_LEN];
    char auth[AUTHTOK_ASCII_LEN + 1];

    if(!h) {
	NULLARG();
	return NULL;
    }

    if(sx_hashfs_get_user_info(h, ADMIN_USER, NULL, key, NULL))
	return NULL;

    if(encode_auth_bin(ADMIN_USER, (const unsigned char *) key, AUTH_KEY_LEN, auth, sizeof(auth))) {
	CRIT("Failed to encode cluster key");
	fprintf(stderr, "encode_auth_bin failed\n");
	return NULL;
    }

    return strdup(auth);
}

rc_ty sx_hashfs_derive_key(sx_hashfs_t *h, unsigned char *key, int len, const char *info)
{
    if (derive_key(h->cluster_uuid.binary, sizeof(h->cluster_uuid.binary),
		   (const unsigned char*)h->root_auth, strlen(h->root_auth), info,
		   key, len))
	return FAIL_EINTERNAL;
    return OK;
}

rc_ty sx_hashfs_create_user(sx_hashfs_t *h, const char *user, const uint8_t *uid, unsigned uid_size, const uint8_t *key, unsigned key_size, int role)
{
    rc_ty rc = FAIL_EINTERNAL;
    if (!h || !user || !key) {
	NULLARG();
	return EFAULT;
    }

    if(sx_hashfs_check_username(user)) {
	msg_set_reason("Invalid user");
	return EINVAL;
    }

    if(key_size != AUTH_KEY_LEN) {
	msg_set_reason("Invalid key");
	return EINVAL;
    }

    if(uid && uid_size != AUTH_UID_LEN) {
	msg_set_reason("Invalid uid");
	return EINVAL;
    }

    if(role != ROLE_ADMIN && role != ROLE_USER) {
	msg_set_reason("Invalid role");
	return EINVAL;
    }

    sqlite3_stmt *q = h->q_createuser;
    sqlite3_reset(q);
    do {
	sx_hash_t uh;
	if(!uid) {
	    if (hash_buf(NULL, 0, user, strlen(user), &uh))
		break;
	    uid = uh.b;
	}
	if(qbind_blob(q, ":userhash", uid, AUTH_UID_LEN))
	    break;
	if (qbind_text(q, ":name", user))
	    break;
	if (qbind_blob(q, ":key", key, key_size))
	    break;
	if (qbind_int64(q, ":role", role))
	    break;
	int ret = qstep(q);
	if (ret == SQLITE_CONSTRAINT) {
	    rc = EEXIST;
	    break;
	}
	if (ret != SQLITE_DONE)
	    break;
	rc = OK;
    } while(0);
    sqlite3_reset(q);
    return rc;
}

int encode_auth(const char *user, const unsigned char *key, unsigned key_size, char *auth, unsigned auth_size)
{
    if (!user || !key || !auth) {
	NULLARG();
	return -1;
    }
    if (key_size != AUTH_KEY_LEN) {
	msg_set_reason("Key of wrong size: %d != %d", key_size, AUTH_KEY_LEN);
	return -1;
    }
    if (auth_size < AUTHTOK_ASCII_LEN + 1) {
	msg_set_reason("Auth of wrong size: %d != %d",
		       auth_size, AUTHTOK_ASCII_LEN+1);
	return -1;
    }
    sx_hash_t h;
    if (hash_buf(NULL, 0, user, strlen(user), &h)) {
	WARN("hashing username failed");
	return -1;
    }
    if (!h.b || !key || !auth) {
	WARN("impossible NULL args");
	return -1;
    }
    return encode_auth_bin(h.b, key, key_size, auth, auth_size);
}

int encode_auth_bin(const uint8_t *userhash, const unsigned char *key, unsigned key_size, char *auth, unsigned auth_size)
{
    uint8_t buf[AUTHTOK_BIN_LEN];
    if (!userhash) {
	WARN("NULL userhash");
	return -1;
    }
    if (!key) {
	WARN("NULL key");
	return -1;
    }
    if (!auth) {
	WARN("NULL auth");
	return -1;
    }

    if (key_size != AUTH_KEY_LEN) {
	msg_set_reason("bad key size: %d != %d",
		       key_size, AUTH_KEY_LEN);
	return -1;
    }
    if (auth_size < AUTHTOK_ASCII_LEN + 1) {
	msg_set_reason("bad auth token size: %d != %d",
		       auth_size, AUTHTOK_ASCII_LEN+1);
	return -1;
    }

    memset(buf, 0, sizeof(buf));
    memcpy(buf, userhash, AUTH_UID_LEN);
    memcpy(buf + AUTH_UID_LEN, key, AUTH_KEY_LEN);
    char *a = sxi_b64_enc_core(buf, sizeof(buf));
    strncpy(auth, a, auth_size);
    auth[auth_size - 1] = 0;
    free(a);
    return 0;
}

rc_ty sx_hashfs_list_users(sx_hashfs_t *h, user_list_cb_t cb, void *ctx) {
    rc_ty rc = FAIL_EINTERNAL;
    int ret;
    uint64_t lastuid = 0;

    if (!h || !cb) {
	NULLARG();
	return EFAULT;
    }

    sqlite3_stmt *q = h->q_listusers;
    while(1) {
        sqlite3_reset(q);
        if(qbind_int64(q, ":lastuid", lastuid))
            break;
        ret = qstep(q);
	if(ret == SQLITE_DONE)
	    rc = OK;
	if(ret != SQLITE_ROW)
            break;
	sx_uid_t uid = sqlite3_column_int64(q, 0);
	const char *name = (const char *)sqlite3_column_text(q, 1);
	const uint8_t *user = sqlite3_column_blob(q, 2);
	const uint8_t *key = sqlite3_column_blob(q, 3);
	int is_admin = sqlite3_column_int64(q, 4) == ROLE_ADMIN;
        lastuid = uid;

	if(sqlite3_column_bytes(q, 2) != SXI_SHA1_BIN_LEN || sqlite3_column_bytes(q, 3) != AUTH_KEY_LEN) {
	    WARN("User %s (%lld) is invalid", name, (long long)uid);
	    continue;
	}

	if(cb(uid, name, user, key, is_admin, ctx)) {
	    rc = EINTR;
	    break;
	}
    }
    sqlite3_reset(q);
    return rc;
}

rc_ty sx_hashfs_list_acl(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, sx_uid_t uid, int uid_priv, acl_list_cb_t cb, void *ctx)
{
    char user[SXLIMIT_MAX_USERNAME_LEN+1];
    int64_t lastuid = 0;
    sx_priv_t priv = PRIV_NONE;
    rc_ty rc = FAIL_EINTERNAL;
    if (!h || !cb || !ctx)
	return EINVAL;

    if(!sx_hashfs_is_or_was_my_volume(h, vol))
	return ENOENT;

    /* list privileges for self */
    priv = uid_priv;
    if (uid > 0 ) {
        if ((rc = sx_hashfs_uid_get_name(h, uid, user, sizeof(user))))
            return rc;

        rc = FAIL_EINTERNAL;
        if (cb(user, priv, ctx))
            return rc;
    }

    if (!(priv & (PRIV_ADMIN | PRIV_OWNER))) {
        DEBUG("Not an owner/admin: printed only self privileges");
        return OK;
    }
    /* admin and owner can see full ACL list */

    sqlite3_stmt *q = h->q_listacl;
    do {
        int ret = SQLITE_ROW;
	if (qbind_int64(q, ":volid", vol->id))
            break;
        while (1) {
            sqlite3_reset(q);
            if (qbind_int64(q, ":lastuid", lastuid))
                break;
            ret = qstep(q);
            if (ret != SQLITE_ROW)
               break;
            int64_t list_uid = sqlite3_column_int64(q, 2);
            lastuid = list_uid;
            if (list_uid == uid)
                continue;/* we've already printed permissions for self */
	    int perm = sqlite3_column_int64(q, 1);
	    if (list_uid == sqlite3_column_int64(q, 3))
		perm |= PRIV_OWNER;
	    if (cb((const char*)sqlite3_column_text(q, 0), perm, ctx))
		break;
	}
	if (ret != SQLITE_DONE)
	    break;
        q = h->q_listadmins;
        lastuid = 0;
        ret = SQLITE_ROW;
        while (1) {
            sqlite3_reset(q);
            if (qbind_int64(q, ":lastuid", lastuid))
                break;
            ret = qstep(q);
            if (ret != SQLITE_ROW)
                break;
            int64_t list_uid = sqlite3_column_int64(q, 1);
            lastuid = list_uid;
            if (list_uid == uid || list_uid == vol->owner)
                continue;/* we've already printed permissions for self and owner */
            if (cb((const char*)sqlite3_column_text(q, 0), PRIV_ADMIN | PRIV_OWNER | PRIV_READ | PRIV_WRITE, ctx))
                break;
        }
	if (ret != SQLITE_DONE)
	    break;
        sqlite3_reset(q);
	rc = OK;
    } while(0);
    sqlite3_reset(q);
    return rc;
}

rc_ty sx_hashfs_get_uid_role(sx_hashfs_t *h, const char *user, int64_t *uid, int *role)
{
    rc_ty rc = FAIL_EINTERNAL;
    if (!h || !user)
	return EINVAL;
    sqlite3_stmt *q = h->q_getuid;
    sqlite3_reset(q);
    do {
	if (qbind_text(q, ":name", user))
	    break;
	int ret = qstep(q);
	if (ret == SQLITE_DONE) {
	    rc = ENOENT;
	    break;
	}
	if (ret != SQLITE_ROW)
	    break;
	if(uid)
	    *uid = sqlite3_column_int64(q, 0);
        if(role)
            *role = sqlite3_column_int(q, 1);
	rc = OK;
    } while(0);
    sqlite3_reset(q);
    return rc;
}

rc_ty sx_hashfs_get_uid(sx_hashfs_t *h, const char *user, int64_t *uid)
{
    return sx_hashfs_get_uid_role(h, user, uid, NULL);
}

rc_ty sx_hashfs_uid_get_name(sx_hashfs_t *h, uint64_t uid, char *name, unsigned len)
{
    rc_ty rc = FAIL_EINTERNAL;
    if (!h || !name || !len)
	return EINVAL;
    sqlite3_stmt *q = h->q_getuidname;
    sqlite3_reset(q);
    do {
	if (qbind_int64(q, ":uid", uid))
	    break;
	int ret = qstep(q);
	if (ret == SQLITE_DONE) {
	    rc = ENOENT;
	    break;
	}
	if (ret != SQLITE_ROW)
	    break;
	strncpy(name, (const char*)sqlite3_column_text(q, 0), len);
	name[len-1] = 0;
	rc = OK;
    } while(0);
    sqlite3_reset(q);
    return rc;
}

void sx_hashfs_volume_new_begin(sx_hashfs_t *h) {
    h->nmeta = 0;
}

rc_ty sx_hashfs_volume_new_addmeta(sx_hashfs_t *h, const char *key, const void *value, unsigned int value_len) {
    if(!h)
	return FAIL_EINTERNAL;

    rc_ty rc;
    if((rc = sx_hashfs_check_meta(key, value, value_len)))
	return rc;

    if(h->nmeta >= SXLIMIT_META_MAX_ITEMS)
	return EOVERFLOW;

    memcpy(h->meta[h->nmeta].key, key, strlen(key)+1);
    memcpy(h->meta[h->nmeta].value, value, value_len);
    h->meta[h->nmeta].value_len = value_len;
    h->nmeta++;
    return OK;
}

rc_ty sx_hashfs_volume_new_finish(sx_hashfs_t *h, const char *volume, int64_t size, unsigned int replica, sx_uid_t uid) {
    unsigned int reqlen = 0;
    rc_ty ret = FAIL_EINTERNAL;
    int64_t volid;
    int r;

    if(!h) {
	NULLARG();
	return EFAULT;
    }
    if ((ret = sx_hashfs_check_volume_name(volume)))
	return ret;

    if(h->have_hd) {
	unsigned int nnodes = sx_nodelist_count(sx_hashfs_nodelist(h, NL_NEXT));
	if(replica < 1 || replica > nnodes) {
	    msg_set_reason("Invalid replica count %d: must be between %d and %d",
			   replica, 1, nnodes);
	    return EINVAL;
	}
    }
    if(size < SXLIMIT_MIN_VOLUME_SIZE || size > SXLIMIT_MAX_VOLUME_SIZE) {
	msg_set_reason("Invalid volume size %lld: must be between %lld and %lld",
		       (long long)size,
		       (long long)SXLIMIT_MIN_VOLUME_SIZE,
		       (long long)SXLIMIT_MAX_VOLUME_SIZE);
	return EINVAL;
    }

    sqlite3_reset(h->q_addvol);
    sqlite3_reset(h->q_addvolmeta);
    sqlite3_reset(h->q_addvolprivs);

    if(qbegin(h->db))
	return FAIL_EINTERNAL;

    if(qbind_text(h->q_addvol, ":volume", volume) ||
       qbind_int(h->q_addvol, ":replica", replica) ||
       qbind_int64(h->q_addvol, ":size", size) ||
       qbind_int64(h->q_addvol, ":owner", uid))
	goto volume_new_err;

    r = qstep(h->q_addvol);
    if(r == SQLITE_CONSTRAINT) {
	const sx_hashfs_volume_t *vol;
	if(sx_hashfs_volume_by_name(h, volume, &vol) == OK)
	    ret = FAIL_VOLUME_EEXIST;
	else
	    ret = FAIL_LOCKED;
    }

    if(r != SQLITE_DONE)
	goto volume_new_err;

    volid = sqlite3_last_insert_rowid(sqlite3_db_handle(h->q_addvol));

    if(h->nmeta) {
	unsigned int nmeta = h->nmeta;
	if(qbind_int64(h->q_addvolmeta, ":volume", volid))
	    goto volume_new_err;

	while(nmeta--) {
	    reqlen += strlen(h->meta[nmeta].key) + 3 + h->meta[nmeta].value_len * 2 + 3; /* "key":"hex(value)", */
	    sqlite3_reset(h->q_addvolmeta);
	    if(qbind_text(h->q_addvolmeta, ":key", h->meta[nmeta].key) ||
	       qbind_blob(h->q_addvolmeta, ":value", h->meta[nmeta].value, h->meta[nmeta].value_len) ||
	       qstep_noret(h->q_addvolmeta))
		goto volume_new_err;
	}
    }

    if(qbind_int64(h->q_addvolprivs, ":volume", volid) ||
       qbind_int64(h->q_addvolprivs, ":user", uid) ||
       qbind_int(h->q_addvolprivs, ":priv", PRIV_READ | PRIV_WRITE) ||
       qstep_noret(h->q_addvolprivs))
	goto volume_new_err;

    if(qcommit(h->db))
	goto volume_new_err;

    ret = OK;

    volume_new_err:
    sqlite3_reset(h->q_addvol);
    sqlite3_reset(h->q_addvolmeta);
    sqlite3_reset(h->q_addvolprivs);

    if(ret != OK)
	qrollback(h->db);

    h->nmeta = 0;

    return ret;
}

rc_ty sx_hashfs_volume_enable(sx_hashfs_t *h, const char *volume) {
    int ret = OK;

    if(qbind_text(h->q_onoffvol, ":volume", volume) ||
       qbind_int(h->q_onoffvol, ":enable", 1) ||
       qstep_noret(h->q_onoffvol))
	ret = FAIL_EINTERNAL;

    return ret;
}

rc_ty sx_hashfs_volume_disable(sx_hashfs_t *h, const char *volume) {
    const sx_hashfs_volume_t *vol;
    const sx_hashfs_file_t *file;
    unsigned int mdb = 0;
    rc_ty ret;

    if(!h) {
	NULLARG();
	return EFAULT;
    }
    if((ret = sx_hashfs_check_volume_name(volume)))
	return ret;

    sqlite3_reset(h->q_onoffvol);
    if(qbegin(h->db)) {
	ret = FAIL_EINTERNAL;
	goto volume_disable_err;
    }
    for(mdb=0; mdb<METADBS; mdb++) {
	if(qbegin(h->metadb[mdb])) {
	    ret = FAIL_EINTERNAL;
	    goto volume_disable_err;
	}
    }
    ret = sx_hashfs_volume_by_name(h, volume, &vol);
    /* FIXME: should _disable() fail if already disabled? if not _by_name cannot be used */
    if(ret != OK)
	goto volume_disable_err;

    ret = sx_hashfs_list_first(h, vol, NULL, &file, 1);
    if(ret == OK) {
	msg_set_reason("Cannot disable non empty volume");
	ret = ENOTEMPTY;
    }
    if(ret != ITER_NO_MORE)
	goto volume_disable_err;
    ret = OK;

    if(qbind_text(h->q_onoffvol, ":volume", volume) ||
       qbind_int(h->q_onoffvol, ":enable", 0) ||
       qstep_noret(h->q_onoffvol)) {
	ret = FAIL_EINTERNAL;
	goto volume_disable_err;
    }

    if(qcommit(h->db))
	ret = FAIL_EINTERNAL;

 volume_disable_err:
    if(ret != OK)
	qrollback(h->db);

    while(mdb--)
	qrollback(h->metadb[mdb]);

    sqlite3_reset(h->q_onoffvol);

    return ret;
}

rc_ty sx_hashfs_volume_delete(sx_hashfs_t *h, const char *volume) {
    rc_ty ret;
    int r;

    if(!h) {
	NULLARG();
	return EFAULT;
    }
    if((ret = sx_hashfs_check_volume_name(volume)))
	return ret;

    sqlite3_reset(h->q_getvolstate);
    sqlite3_reset(h->q_delvol);

    if(qbegin(h->db) ||
       qbind_text(h->q_getvolstate, ":volume", volume)) {
	ret = FAIL_EINTERNAL;
	goto volume_delete_err;
    }

    r = qstep(h->q_getvolstate);
    if(r == SQLITE_DONE) {
	ret = ENOENT;
	goto volume_delete_err;
    }
    if(r != SQLITE_ROW) {
	ret = FAIL_EINTERNAL;
	goto volume_delete_err;
    }
    r = sqlite3_column_int(h->q_getvolstate, 0);
    if(r) {
	ret = EPERM;
	msg_set_reason("Cannot delete an enabled volume");
	goto volume_delete_err;
    }
    if(qbind_text(h->q_delvol, ":volume", volume) ||
       qstep_noret(h->q_delvol) ||
       qcommit(h->db))
	ret = FAIL_EINTERNAL;
    else
	ret = OK;

 volume_delete_err:
    if(ret != OK)
	qrollback(h->db);

    sqlite3_reset(h->q_getvolstate);
    sqlite3_reset(h->q_delvol);

    return ret;
}

rc_ty sx_hashfs_user_onoff(sx_hashfs_t *h, const char *user, int enable) {
    int ret = OK;

    if(qbind_text(h->q_onoffuser, ":username", user) ||
       qbind_int(h->q_onoffuser, ":enable", enable) ||
       qstep_noret(h->q_onoffuser))
	ret = FAIL_EINTERNAL;

    return ret;
}


rc_ty sx_hashfs_volume_first(sx_hashfs_t *h, const sx_hashfs_volume_t **volume, int64_t uid) {
    if(!h || !volume) {
	WARN("Called with invalid arguments");
	return EINVAL;
    }

    h->curvol.name[0] = '\0';
    h->curvoluid = uid;
    *volume = &h->curvol;
    return sx_hashfs_volume_next(h);
}

rc_ty sx_hashfs_volume_next(sx_hashfs_t *h) {
    const char *name;
    rc_ty res = FAIL_EINTERNAL;
    int r;

    if(!h) {
	WARN("Called with invalid arguments");
	return EINVAL;
    }

    sqlite3_reset(h->q_nextvol);
    if(qbind_text(h->q_nextvol, ":previous", h->curvol.name))
	goto volume_list_err;
    if(qbind_int64(h->q_nextvol, ":user", h->curvoluid))
	goto volume_list_err;

    r = qstep(h->q_nextvol);
    if(r == SQLITE_DONE)
	res = ITER_NO_MORE;
    if(r != SQLITE_ROW)
	goto volume_list_err;

    name = (const char *)sqlite3_column_text(h->q_nextvol, 1);
    if(!name)
	goto volume_list_err;

    strncpy(h->curvol.name, name, sizeof(h->curvol.name) - 1);
    h->curvol.name[sizeof(h->curvol.name) - 1] = '\0';
    h->curvol.id = sqlite3_column_int64(h->q_nextvol, 0);
    h->curvol.replica_count = sqlite3_column_int(h->q_nextvol, 2);
    h->curvol.size = sqlite3_column_int64(h->q_nextvol, 3);
    h->curvol.owner = sqlite3_column_int64(h->q_nextvol, 4);
    res = OK;

    volume_list_err:
    sqlite3_reset(h->q_nextvol);
    return res;
}


static rc_ty volume_get_common(sx_hashfs_t *h, const char *name, int64_t volid, const sx_hashfs_volume_t **volume) {
    sqlite3_stmt *q;
    rc_ty res = FAIL_EINTERNAL;
    int r;

    if(!h || !volume) {
	WARN("Called with invalid arguments");
	return EINVAL;
    }

    if(name) {
	q = h->q_volbyname;
	sqlite3_reset(q);
	if(qbind_text(q, ":name", name))
	    goto volume_err;
    } else {
	q = h->q_volbyid;
	sqlite3_reset(q);
	if(qbind_int64(q, ":volid", volid))
	    goto volume_err;
    }

    r = qstep(q);
    if(r == SQLITE_DONE)
	res = ENOENT;
    if(r != SQLITE_ROW)
	goto volume_err;

    name = (const char *)sqlite3_column_text(q, 1);
    if(!name)
	goto volume_err;

    strncpy(h->curvol.name, name, sizeof(h->curvol.name) - 1);
    h->curvol.name[sizeof(h->curvol.name) - 1] = '\0';
    h->curvol.id = sqlite3_column_int64(q, 0);
    h->curvol.replica_count = sqlite3_column_int(q, 2);
    h->curvol.size = sqlite3_column_int64(q, 3);
    h->curvol.owner = sqlite3_column_int64(q, 4);
    *volume = &h->curvol;
    res = OK;

    volume_err:
    sqlite3_reset(q);
    return res;
}

rc_ty sx_hashfs_grant(sx_hashfs_t *h, uint64_t uid, const char *volume, int priv)
{
    if (!h || !volume)
	return EINVAL;

    rc_ty rc = FAIL_EINTERNAL;
    sqlite3_stmt *q = h->q_grant;
    sqlite3_reset(q);
    const sx_hashfs_volume_t *vol = NULL;
    do {
	rc = volume_get_common(h, volume, -1, &vol);
	if (rc) {
	    WARN("Cannot retrieve volume id for '%s': %s", volume, rc2str(rc));
	    break;
	}
	if (qbind_int64(q,":uid", uid))
	    break;
	if (qbind_int64(q,":volid", vol->id))
	    break;
	if (qbind_int64(q,":priv", priv))
	    break;
	if (qstep_noret(q))
	    break;
	INFO("%s: granted priv %d to %ld on %s", h->dir, priv, (long)uid, volume);
    } while(0);
    sqlite3_reset(q);
    return rc;
}

rc_ty sx_hashfs_revoke(sx_hashfs_t *h, uint64_t uid, const char *volume, int privmask)
{
    if (!h || !volume)
	return EINVAL;
    rc_ty rc = FAIL_EINTERNAL;
    sqlite3_stmt *q = h->q_revoke;
    sqlite3_reset(q);
    const sx_hashfs_volume_t *vol = NULL;
    do {
	rc = volume_get_common(h, volume, -1, &vol);
	if (rc) {
	    WARN("Cannot retrieve volume id for '%s': %s", volume, rc2str(rc));
	    break;
	}
	if (qbind_int64(q,":uid", uid))
	    break;
	if (qbind_int64(q,":volid", vol->id))
	    break;
	if (qbind_int64(q,":privmask", privmask))
	    break;
	if (qstep_noret(q))
	    break;
	INFO("%s: revoked privmask %d to %ld on %s", h->dir, privmask, (long)uid, volume);
    } while(0);
    sqlite3_reset(q);
    return rc;
}

rc_ty sx_hashfs_volume_by_name(sx_hashfs_t *h, const char *name, const sx_hashfs_volume_t **volume) {
    if(sx_hashfs_check_volume_name(name)) {
	WARN("Called with invalid arguments");
	return EINVAL;
    }

    return volume_get_common(h, name, 0, volume);
}

rc_ty sx_hashfs_volume_by_id(sx_hashfs_t *h, int64_t volid, const sx_hashfs_volume_t **volume) {
    return volume_get_common(h, NULL, volid, volume);
}

static void sx_hashfs_getfile_reset(sx_hashfs_t *h)
{
    if(h->get_ndb < METADBS) {
	sqlite3_reset(h->qm_get[h->get_ndb]);
	sqlite3_reset(h->qm_getrev[h->get_ndb]);
    }
}

rc_ty sx_hashfs_getfile_begin(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, int64_t *file_size, unsigned int *block_size, unsigned int *created_at, sx_hash_t *etag) {
    const sx_hashfs_volume_t *vol;
    unsigned int content_len, bsize;
    sqlite3_stmt *q;
    int64_t size;
    rc_ty res;
    int r;

    /* reset previous getfile queries */
    sx_hashfs_getfile_end(h);
    res = sx_hashfs_volume_by_name(h, volume, &vol);
    if(res)
	return res;

    if(check_file_name(filename)<0) {
	msg_set_reason("Invalid file name");
	return EINVAL;
    }

    h->get_ndb = getmetadb(filename);
    if(h->get_ndb < 0)
	return FAIL_EINTERNAL;
    /* reset current getfile queries */
    sx_hashfs_getfile_reset(h);

    if(revision) {
	if(check_revision(revision)) {
	    msg_set_reason("Invalid file name");
	    return EINVAL;
	}
	q = h->qm_getrev[h->get_ndb];
	if(qbind_text(q, ":revision", revision))
	    return FAIL_EINTERNAL;
    } else
	q = h->qm_get[h->get_ndb];

    if(qbind_int64(q, ":volume", vol->id) || qbind_text(q, ":name", filename))
	return FAIL_EINTERNAL;

    r = qstep(q);
    if(r == SQLITE_DONE) {
	DEBUG("No such file: %s/%s", volume, filename);
	sx_hashfs_getfile_end(h);
	return ENOENT;
    }
    if(r != SQLITE_ROW) {
	sx_hashfs_getfile_end(h);
	return FAIL_EINTERNAL;
    }

    h->get_id = sqlite3_column_int64(q, 0);
    size = sqlite3_column_int64(q, 1);
    h->get_nblocks = size_to_blocks(size, NULL, &bsize);
    h->get_content = sqlite3_column_blob(q, 2);
    content_len = sqlite3_column_bytes(q, 2);

    if(created_at || etag) {
	const char *rev = (const char *)sqlite3_column_text(q, 3);
	if(!rev ||
	   (created_at && parse_revision(rev, created_at)) ||
	   (etag && hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), rev, strlen(rev), etag))) {
	    sx_hashfs_getfile_end(h);
	    return FAIL_EINTERNAL;
	}
    }

    if(content_len != sizeof(sx_hash_t) * h->get_nblocks) {
	WARN("Inconsistent entry for %s:%s", volume, filename);
	sx_hashfs_getfile_end(h);
	return FAIL_EINTERNAL;
    }

    h->get_replica = vol->replica_count;

    if(file_size)
	*file_size = size;
    if(block_size)
	*block_size = bsize;
    return OK;
}

rc_ty sx_hashfs_getfile_block(sx_hashfs_t *h, const sx_hash_t **hash, sx_nodelist_t **nodes) {
    if(!h || !hash || !nodes || (h->get_nblocks && !h->get_content))
	return EINVAL;

    if(!h->get_nblocks)
	return ITER_NO_MORE;

    *nodes = sx_hashfs_hashnodes(h, NL_NEXTPREV, h->get_content, h->get_replica);
    if(!*nodes) {
	sx_hashfs_getfile_end(h);
	return FAIL_EINTERNAL;
    }

    *hash = h->get_content;
    h->get_content++;
    h->get_nblocks--;
    return OK;
}

void sx_hashfs_getfile_end(sx_hashfs_t *h) {
    sx_hashfs_getfile_reset(h);
    h->get_content = NULL;
    h->get_nblocks = 0;
    h->get_ndb = METADBS;
}

rc_ty sx_hashfs_block_get(sx_hashfs_t *h, unsigned int bs, const sx_hash_t *hash, const uint8_t **block) {
    unsigned int ndb = gethashdb(hash), hs;
    uint64_t dboff;
    int r;

    for(hs = 0; hs < SIZES; hs++)
	if(bsz[hs] == bs)
	    break;
    if(hs == SIZES) {
	WARN("bad blocksize: %d", bs);
	return FAIL_BADBLOCKSIZE;
    }

    sqlite3_reset(h->qb_get[hs][ndb]);
    if(qbind_blob(h->qb_get[hs][ndb], ":hash", hash, sizeof(*hash)))
	return FAIL_EINTERNAL;

    r = qstep(h->qb_get[hs][ndb]);
    if(r == SQLITE_DONE) {
	char thash[41];
	DEBUG("Hash not in database");
	sqlite3_reset(h->qb_get[hs][ndb]);
	bin2hex(hash->b, 20, thash, 41);
/*        WARN("{%s}: hash %s missing",
	     sx_node_internal_addr(sx_nodelist_get(h->nodes, h->thisnode)), thash);*/
	return ENOENT;
    }
    if(r != SQLITE_ROW) {
	sqlite3_reset(h->qb_get[hs][ndb]);
	return FAIL_EINTERNAL;
    }
    if(!block) {
	sqlite3_reset(h->qb_get[hs][ndb]);
	return OK;
    }
    dboff = sqlite3_column_int64(h->qb_get[hs][ndb], 0);
    sqlite3_reset(h->qb_get[hs][ndb]);
    dboff *= bs;

    if(read_block(h->datafd[hs][ndb], h->blockbuf, dboff, bs))
	return FAIL_EINTERNAL;

    *block = h->blockbuf;
    return OK;
}

rc_ty sx_hashfs_hashop_begin(sx_hashfs_t *h, unsigned bs)
{
    unsigned hs;
    /* FIXME: code duplicated with block_put */
    for(hs = 0; hs < SIZES; hs++)
	if(bsz[hs] == bs)
	    break;
    if(hs == SIZES)
	return FAIL_BADBLOCKSIZE;
    h->put_hs = hs;
    h->gcdb_used = 1;
    if (qbegin(h->gcdb[0]))
	return FAIL_EINTERNAL;
    /* would be nice to begin a transaction here, but the DB we use depends on
     * the hash...*/
    return OK;
}

static rc_ty sx_hashfs_hashop_ishash(sx_hashfs_t *h, const sx_hash_t *hash)
{
    rc_ty ret;
    unsigned hs;
    unsigned ndb;
    hs = h->put_hs;
    ndb = gethashdb(hash);
    sqlite3_reset(h->qb_get[hs][ndb]);
    if(qbind_blob(h->qb_get[hs][ndb], ":hash", hash, sizeof(*hash)))
        return FAIL_EINTERNAL;
    switch (qstep(h->qb_get[hs][ndb])) {
        case SQLITE_ROW:
            ret = OK;
            break;
        case SQLITE_DONE:
            ret = ENOENT;
            break;
        default:
            ret = FAIL_EINTERNAL;
            break;
    }
    sqlite3_reset(h->qb_get[hs][ndb]);
    return ret;
}

static rc_ty sx_hashfs_hashop_moduse(sx_hashfs_t *h, const char *id, const sx_hash_t *hash, int op)
{
    unsigned gdb;
    sx_hash_t groupid;
    /* FIXME: maybe enable this
    if(!is_hash_local(h, hash, replica_count))
	return ENOENT;*/

    if (!id) {
        msg_set_reason("missing id");
        return EINVAL;
    }
    gdb = getgcdb(hash);

    sqlite3_reset(h->qg_addop[gdb]);
    /* groupid = either the fileid, or a token.
     * When there is no activity on the groupid, the reservations on all hashes
     * from that groupid are dropped */
    if (hex2bin(id, strlen(id), groupid.b, sizeof(groupid.b))) {
        WARN("Cannot decode hash id: %s", id);
        return FAIL_EINTERNAL;
    }
    DEBUG("moduse %d, groupid: %s", op, id);
    DEBUGHASH("groupid", &groupid);
    if (qbind_blob(h->qg_addop[gdb], ":groupid", &groupid, sizeof(groupid)) ||
        qbind_blob(h->qg_addop[gdb], ":hash", hash, sizeof(*hash)) ||
        qbind_int(h->qg_addop[gdb], ":hs", h->put_hs) ||
        qbind_int(h->qg_addop[gdb], ":op", op) ||
        qbind_int64(h->qg_addop[gdb], ":idx", h->gcdb_idx++) ||
        qstep_noret(h->qg_addop[gdb])) {
        return FAIL_EINTERNAL;
    }
    sqlite3_reset(h->qg_addop[gdb]);
    return OK;
}

rc_ty sx_hashfs_hashop_finish(sx_hashfs_t *h, rc_ty rc)
{
    if (rc == ENOENT)
        rc = OK;
    if (rc == OK && qcommit(h->gcdb[0]))
        rc = FAIL_EINTERNAL;
    if (rc != OK)
        qrollback(h->gcdb[0]);
    /* would have to commit/rollback if we can batch updates */
    return rc;
}

rc_ty sx_hashfs_hashop_perform(sx_hashfs_t *h, enum sxi_hashop_kind kind, const sx_hash_t *hash, const char *id)
{
    rc_ty rc;
    if (UNLIKELY(sxi_log_is_debug(&logger))) {
        char debughash[sizeof(sx_hash_t)*2+1];		\
        bin2hex(hash->b, sizeof(*hash), debughash, sizeof(debughash));	\
        DEBUG("processing %s, #%s# (id: %s)",
              kind == HASHOP_CHECK ? "check" :
              kind == HASHOP_RESERVE ? "reserve" :
              kind == HASHOP_INUSE ? "inuse" :
              kind == HASHOP_DELETE ? "decuse" : "??",
              debughash, id ? id : "");
    }
    switch (kind) {
        case HASHOP_CHECK:
            rc = sx_hashfs_hashop_ishash(h, hash);
            break;
        case HASHOP_RESERVE:
            /* we must always reserve, even if ENOENT */
            rc = sx_hashfs_hashop_moduse(h, id, hash, 0);
            if (rc == OK)
                rc = sx_hashfs_hashop_ishash(h, hash);
            break;
        case HASHOP_INUSE:
            /* we must only moduse if not ENOENT */
            rc = sx_hashfs_hashop_ishash(h, hash);
            if (rc)
                break;
            rc = sx_hashfs_hashop_moduse(h, id, hash, 1);
            break;
        case HASHOP_DELETE:
            /* we must only moduse if not ENOENT */
            rc = sx_hashfs_hashop_ishash(h, hash);
            if (rc)
                break;
            rc = sx_hashfs_hashop_moduse(h, id, hash, -1);
            break;
        default:
            msg_set_reason("Invalid hashop");
            return EINVAL;
    }
    DEBUG("result: %s", rc2str(rc));
    return rc;
}

rc_ty sx_hashfs_block_put(sx_hashfs_t *h, const uint8_t *data, unsigned int bs, unsigned int replica_count, int propagate) {
    sx_nodelist_t *belongsto;
    unsigned int ndb, hs;
    sx_hash_t hash;
    rc_ty ret = FAIL_EINTERNAL;
    int r;

    if(!h->have_hd) {
	WARN("Called before initialization");
	return FAIL_EINIT;
    }

    for(hs = 0; hs < SIZES; hs++)
	if(bsz[hs] == bs)
	    break;
    if(hs == SIZES)
	return FAIL_BADBLOCKSIZE;

    if(hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), data, bs, &hash)) {
	WARN("hashing failed");
	return FAIL_EINTERNAL;
    }

    DEBUGHASH("Block uploaded by user", &hash);

    /* MODHDIST: lookup is strictly on bidx 0 */
    belongsto = sxi_hdist_locate(h->hd, MurmurHash64(&hash, sizeof(hash), HDIST_SEED), replica_count, 0);
    r = sx_nodelist_lookup(belongsto, &h->node_uuid) == NULL;
    sx_nodelist_delete(belongsto);
    if(r) {
	DEBUGHASH("Block doesn't belong to this node", &hash);
	return ENOENT;
    }

    ndb = gethashdb(&hash);

    sqlite3_reset(h->qb_get[hs][ndb]);
    if(qbind_blob(h->qb_get[hs][ndb], ":hash", &hash, sizeof(hash))) {
	WARN("binding hash failed");
	return FAIL_EINTERNAL;
    }

    r = qstep(h->qb_get[hs][ndb]);
    sqlite3_reset(h->qb_get[hs][ndb]);
    if(r == SQLITE_DONE) {
	int64_t dsto, next;

	if(qbegin(h->datadb[hs][ndb])) {
	    WARN("begin failed");
	    return FAIL_EINTERNAL;
	}

	sqlite3_reset(h->qb_nextavail[hs][ndb]);
	sqlite3_reset(h->qb_nextalloc[hs][ndb]);
	sqlite3_reset(h->qb_bumpavail[hs][ndb]);
	sqlite3_reset(h->qb_bumpalloc[hs][ndb]);
	sqlite3_reset(h->qb_add[hs][ndb]);

	r = qstep(h->qb_nextavail[hs][ndb]);
	if(r == SQLITE_ROW) {
	    next = sqlite3_column_int64(h->qb_nextavail[hs][ndb], 0);
	    sqlite3_reset(h->qb_nextavail[hs][ndb]);

	    if(qbind_int64(h->qb_bumpavail[hs][ndb], ":next", next) || qstep_noret(h->qb_bumpavail[hs][ndb])) {
		qrollback(h->datadb[hs][ndb]);
		WARN("bumpavail failed");
		return FAIL_EINTERNAL;
	    }
	} else if(r == SQLITE_DONE) {
	    r = qstep(h->qb_nextalloc[hs][ndb]);
	    if(r == SQLITE_ROW) {
		next = sqlite3_column_int64(h->qb_nextalloc[hs][ndb], 0);
		sqlite3_reset(h->qb_nextalloc[hs][ndb]);

		if(qstep_noret(h->qb_bumpalloc[hs][ndb])) {
		    qrollback(h->datadb[hs][ndb]);
		    WARN("bumpalloc failed");
		    return FAIL_EINTERNAL;
		}
	    }
	}

	if(r != SQLITE_ROW || qcommit(h->datadb[hs][ndb])) {
	    qrollback(h->datadb[hs][ndb]);
	    WARN("nextavail failed");
	    return FAIL_EINTERNAL;
	}

	dsto = next * bs;
	DEBUG("Block stored @%d/%d/%ld", hs, ndb, dsto);

	if(write_block(h->datafd[hs][ndb], data, dsto, bs)) {
	    WARN("write failed");
	    return FAIL_EINTERNAL;
	}

	/* insert it now */
	if(qbind_blob(h->qb_add[hs][ndb], ":hash", &hash, sizeof(hash)) ||
	   qbind_int64(h->qb_add[hs][ndb], ":next", next)) {
	    WARN("add failed");
	    return FAIL_EINTERNAL;
	}
	r = qstep(h->qb_add[hs][ndb]);
	if (r != SQLITE_DONE) {
	    if (r == SQLITE_CONSTRAINT) {
		DEBUG("Race in block_store, falling back");
		ret = EAGAIN;/* race condition: block already present */
	    }
	} else
	    ret = OK;
    } else if(r == SQLITE_ROW)
        ret = EAGAIN;
    if(ret != OK && ret != EAGAIN)
	return FAIL_EINTERNAL;

    if(propagate && replica_count > 1) {
	sx_nodelist_t *targets = sx_hashfs_hashnodes(h, NL_NEXT, &hash, replica_count);
	rc_ty ret = sx_hashfs_xfer_tonodes(h, &hash, bs, targets);
	sx_nodelist_delete(targets);
	return ret;
    }
    return OK;
}

static void putfile_reinit(sx_hashfs_t *h) {
    if(!h)
	return;

    h->put_id = 0;
    h->put_putblock = 0;
    h->put_getblock = 0;
    h->put_checkblock = 0;
    h->put_replica = 0;
    h->put_hs = 0;
    h->put_success = 0;
    h->put_token[0] = '\0';
    h->put_blocks = NULL;
    h->put_nidxs = NULL;
    h->put_nblocks = 0;
    h->put_extendsize = -1LL;
    h->put_extendfrom = 0;
    h->nmeta = 0;
}

const char *sx_hashfs_geterrmsg(sx_hashfs_t *h)
{
    return sxc_geterrmsg(h->sx);
}

rc_ty sx_hashfs_createfile_begin(sx_hashfs_t *h) {
    if(!h) {
	NULLARG();
	return EFAULT;
    }

    putfile_reinit(h);

    h->put_id = -1; /* Fake id so that the blocks are actually accepted */
    return OK;
}

rc_ty sx_hashfs_putfile_begin(sx_hashfs_t *h, sx_uid_t user_id, const char *volume, const char *file) {
    uint8_t rnd[TOKEN_RAND_BYTES];
    const sx_hashfs_volume_t *vol;
    int flen;
    rc_ty r;

    putfile_reinit(h);

    flen = check_file_name(file);
    if(!h || flen < 0 || file[flen - 1] == '/')
	return EINVAL;

    if((r = sx_hashfs_volume_by_name(h, volume, &vol)))
	return r;

    if(!sx_hashfs_is_or_was_my_volume(h, vol))
	return ENOENT;

    sqlite3_reset(h->qt_new);
    /* non-blocking pseudo-random bytes, i.e. we don't want to block or deplete
     * entropy as we only need a unique sequence of bytes, not a secret one as
     * it is sent in plaintext anyway, and signed with an HMAC */
    if (sxi_rand_pseudo_bytes(rnd, sizeof(rnd)) == -1) {
	/* can also return 0 or 1 but that doesn't matter here */
	WARN("Cannot generate random bytes");
	return FAIL_EINTERNAL;
    }
    if(qbind_int64(h->qt_new, ":volume", vol->id) || qbind_text(h->qt_new, ":name", file) ||
       qbind_blob(h->qt_new, ":random", rnd, sizeof(rnd)) || qstep_noret(h->qt_new)) {
	sqlite3_reset(h->qt_new);
	return FAIL_EINTERNAL;
    }
    sqlite3_reset(h->qt_new);

    h->put_id = sqlite3_last_insert_rowid(sqlite3_db_handle(h->qt_new));
    h->put_replica = vol->replica_count;
    return sx_hashfs_countjobs(h, user_id);
}

rc_ty sx_hashfs_putfile_extend_begin(sx_hashfs_t *h, sx_uid_t user_id, const uint8_t *user, const char *token) {
    const sx_hashfs_volume_t *vol;
    const sx_uuid_t *self_uuid;
    struct token_data tkdt;
    const sx_node_t *self;
    rc_ty ret = FAIL_EINTERNAL;
    int r;

    if(!h)
	return EINVAL;

    putfile_reinit(h);

    if(parse_token(h->sx, user, token, &h->tokenkey, &tkdt))
	return EINVAL;

    if(!(self = sx_hashfs_self(h)) || !(self_uuid = sx_node_uuid(self)))
	return FAIL_EINTERNAL;
    if(memcmp(self_uuid->binary, tkdt.uuid.binary, sizeof(tkdt.uuid.binary)))
	return EINVAL;

    sqlite3_reset(h->qt_tokenstats);
    if(qbind_text(h->qt_tokenstats, ":token", tkdt.token))
	goto putfile_extend_err;

    r = qstep(h->qt_tokenstats);
    if(r == SQLITE_DONE)
	ret = ENOENT;
    if(r != SQLITE_ROW)
	goto putfile_extend_err;

    if((ret = sx_hashfs_volume_by_id(h, sqlite3_column_int64(h->qt_tokenstats, 2), &vol)))
	goto putfile_extend_err;

    h->put_id = sqlite3_column_int64(h->qt_tokenstats, 0);
    h->put_replica = vol->replica_count;
    h->put_extendsize = sqlite3_column_int64(h->qt_tokenstats, 1);
    h->put_extendfrom = sqlite3_column_int(h->qt_tokenstats, 3) / sizeof(sx_hash_t);
    ret = sx_hashfs_countjobs(h, user_id);

    putfile_extend_err:
    sqlite3_reset(h->qt_tokenstats);
    return ret;
}

rc_ty sx_hashfs_putfile_putblock(sx_hashfs_t *h, sx_hash_t *hash) {
    if(!h || !hash || !h->put_id)
	return EINVAL;

    if(h->put_putblock >= h->put_nblocks) {
	h->put_nblocks += 128;
	h->put_blocks = wrap_realloc_or_free(h->put_blocks, sizeof(*hash) * h->put_nblocks);
	if(!h->put_blocks)
	    return FAIL_EINTERNAL;
    }
    memcpy(&h->put_blocks[h->put_putblock], hash, sizeof(*hash));
    h->put_putblock++;
    return OK;
}

rc_ty sx_hashfs_putfile_putmeta(sx_hashfs_t *h, const char *key, void *value, unsigned int value_len) {
    rc_ty rc;

    if(!h)
	return FAIL_EINTERNAL;

    if(h->nmeta >= SXLIMIT_META_MAX_ITEMS)
	return EOVERFLOW;

    if(!value) {
	/* Delete key: check key (and bogus value) */
	char checkme[SXLIMIT_META_MIN_VALUE_LEN + 1];
	memset(checkme, 0, sizeof(checkme));
	rc = sx_hashfs_check_meta(key, checkme, SXLIMIT_META_MIN_VALUE_LEN);
	if(rc)
	    return rc;
	h->meta[h->nmeta].value_len = -1;
    } else {
	/* Add/replace key: check key and value */
	rc = sx_hashfs_check_meta(key, value, value_len);
	if(rc)
	    return rc;
	memcpy(h->meta[h->nmeta].value, value, value_len);
	h->meta[h->nmeta].value_len = value_len;
    }	

    memcpy(h->meta[h->nmeta].key, key, strlen(key)+1);

    h->nmeta++;
    return OK;
}

struct sort_by_node_t {
    sx_hash_t *hashes;
    unsigned int *nidxs;
    unsigned int sort_replica;
    unsigned int replica_count;
};

static int sort_by_node_func(const void *thunk, const void *a, const void *b) {
     unsigned int hashno_a = *(unsigned int *)a;
     unsigned int hashno_b = *(unsigned int *)b;
     const struct sort_by_node_t *support = (const struct sort_by_node_t *)thunk;

     int nidxa = support->nidxs[support->replica_count * hashno_a + support->sort_replica - 1];
     int nidxb = support->nidxs[support->replica_count * hashno_b + support->sort_replica - 1];

     /* Sort by node first */
     if(nidxa < nidxb)
	 return -1;
     if(nidxa > nidxb)
	 return 1;

     /* Then either sort by hash, if so requested */
     if(support->hashes)
	 return memcmp(&support->hashes[hashno_a], &support->hashes[hashno_b], sizeof(support->hashes[0]));

     /* Or alternatively sort by position */
     if(hashno_a < hashno_b)
	 return -1;
     if(hashno_a > hashno_b)
	 return 1;
     return 0;
}

static void sort_by_node_then_hash(sx_hash_t *hashes, unsigned int *hashnos, unsigned int *nidxs, unsigned int items, unsigned int replica, unsigned int replica_count) {
    struct sort_by_node_t sortsupport = {hashes, nidxs, replica, replica_count};
    sx_qsort(hashnos, items, sizeof(*hashnos), &sortsupport, sort_by_node_func);
}

static void sort_by_node_then_position(unsigned int *hashnos, unsigned int *nidxs, unsigned int items, unsigned int replica, unsigned int replica_count) {
    struct sort_by_node_t sortsupport = {NULL, nidxs, replica, replica_count};
    sx_qsort(hashnos, items, sizeof(*hashnos), &sortsupport, sort_by_node_func);
}

static int sort_by_hash_func(const void *thunk, const void *a, const void *b) {
    unsigned int ia = *(const unsigned int *)a;
    unsigned int ib = *(const unsigned int *)b;
    const sx_hash_t *hashes = (const sx_hash_t *)thunk;
    return cmphash(&hashes[ia], &hashes[ib]);
}

static void build_uniq_hash_index(const sx_hash_t *hashes, unsigned *idxs, unsigned *n)
{
    unsigned i, l, r;
    /* Build an index and an array of first nodes */
    for (i=0; i<*n; i++)
        idxs[i] = i;
    /* Sort by hash */
    sx_qsort(idxs, *n, sizeof(*idxs), hashes, sort_by_hash_func);
    /* Remove duplicates */
    for(l = 0, r = 1; r<*n; r++) {
        if(cmphash(&hashes[idxs[l]], &hashes[idxs[r]])) {
            l++;
            if(l!=r)
                idxs[l] = idxs[r];
        }
    }
    *n = l+1;
}

#ifdef FILEHASH_OPTIMIZATION
static rc_ty filehash_reserve(sx_hashfs_t *h, const sx_hash_t *filehash)
{
    rc_ty ret = FAIL_EINTERNAL, ret_ok = OK;
    unsigned gdb = getgcdb(filehash);
    sqlite3_reset(h->qg_filehash_add[gdb]);
    sqlite3_reset(h->qg_filehash_bump_reserved[gdb]);
    if (qbegin(h->gcdb[gdb]))
        return FAIL_EINTERNAL;
    do {
        int r;
        if (qbind_blob(h->qg_filehash_add[gdb], ":filehash", filehash, sizeof(*filehash)) ||
            qbind_blob(h->qg_filehash_bump_reserved[gdb], ":filehash", filehash, sizeof(*filehash)))
            break;
        r = qstep(h->qg_filehash_add[gdb]);
        if (r == SQLITE_CONSTRAINT) {
            /* just bump expiration timestamp */
            if (qstep_noret(h->qg_filehash_bump_reserved[gdb]))
                break;
            ret_ok = ITER_NO_MORE;/* do not bump the individual hashes */
            /* TODO: only if used > 0? */
        } else if (r != SQLITE_DONE) {
            SQLERR(h->qg_filehash_add[gdb], "filehash_add failed");
            break;
        }
        if (qcommit(h->gcdb[gdb]))
            break;
        ret = ret_ok;
    } while(0);
    if (ret != ret_ok) {
        qrollback(h->gcdb[gdb]);
    }
    sqlite3_reset(h->qg_filehash_add[gdb]);
    sqlite3_reset(h->qg_filehash_bump_reserved[gdb]);
    return ret;
}

static int filehash_is_used(sx_hashfs_t *h, const sx_hash_t *filehash)
{
    unsigned gdb = getgcdb(filehash);
    unsigned used;
    sqlite3_reset(h->qg_filehash_get[gdb]);
    if (qbind_blob(h->qg_filehash_get[gdb], ":filehash", filehash, sizeof(*filehash)) ||
        qstep_ret(h->qg_filehash_get[gdb]))
        return 0;

    used = sqlite3_column_int(h->qg_filehash_get[gdb], 0);
    sqlite3_reset(h->qg_filehash_get[gdb]);
    return used > 0;
}

static rc_ty filehash_mod_used(sx_hashfs_t *h, const sx_hash_t *filehash, int operation)
{
    rc_ty ret = FAIL_EINTERNAL, ret_ok = OK;
    unsigned gdb = getgcdb(filehash);
    sqlite3_reset(h->qg_filehash_mod_used[gdb]);
    sqlite3_reset(h->qg_filehash_get[gdb]);
    sqlite3_reset(h->qg_filehash_delete[gdb]);
    if (qbegin(h->gcdb[gdb]))
        return FAIL_EINTERNAL;
    do {
        unsigned used;
        if (qbind_blob(h->qg_filehash_mod_used[gdb], ":filehash", filehash, sizeof(*filehash)) ||
            qbind_blob(h->qg_filehash_get[gdb], ":filehash", filehash, sizeof(*filehash)) ||
            qbind_blob(h->qg_filehash_delete[gdb], ":filehash", filehash, sizeof(*filehash)) ||
            qbind_int(h->qg_filehash_mod_used[gdb], ":operation", operation) ||
            qstep_noret(h->qg_filehash_mod_used[gdb]) ||
            qstep_ret(h->qg_filehash_get[gdb]))
            break;
        used = sqlite3_column_int(h->qg_filehash_get[gdb], 0);
        if ((used == 1 && operation == 1) || /* used: 0 -> 1: we need to update hash counters */
            (used == 0 && operation == -1)) /* used : 1 -> 0: we need to update hash counters */
            ret_ok = OK;
        else
            ret_ok = ITER_NO_MORE;/* used is > 0, no need to modify it yet */
        if (used == 0)
            qstep_noret(h->qg_filehash_delete[gdb]);

        if (qcommit(h->gcdb[gdb]))
            break;
        ret = ret_ok;
    } while(0);
    if (ret != ret_ok)
        qrollback(h->gcdb[gdb]);
    sqlite3_reset(h->qg_filehash_mod_used[gdb]);
    sqlite3_reset(h->qg_filehash_get[gdb]);
    sqlite3_reset(h->qg_filehash_delete[gdb]);
    return ret;
}
#endif /* FILEHASH_OPTIMIZATION */

static int unique_tmpid(sx_hashfs_t *h, const char *token, sx_hash_t *hash)
{
    sx_uuid_t self;

    if (sx_hashfs_self_uuid(h, &self))
        return 1;
    return hash_buf(self.binary, sizeof(self.binary), token, strlen(token), hash);
}

rc_ty sx_hashfs_putfile_gettoken(sx_hashfs_t *h, const uint8_t *user, int64_t size_or_seq, const char **token, hash_presence_cb_t hdck_cb, void *hdck_cb_ctx) {
    const char *ptr;
    sqlite3_stmt *q;
    unsigned int i;
    uint64_t total_blocks;
    rc_ty ret = FAIL_EINTERNAL;
    unsigned int blocksize;
#ifdef FILEHASH_OPTIMIZATION
    sx_hash_t filehash;
#endif
    int64_t expires_at;

    if(!h || !h->put_id)
	return EINVAL;

    if(h->put_extendsize < 0) {
	/* creating */
	if(size_or_seq < SXLIMIT_MIN_FILE_SIZE || size_or_seq > SXLIMIT_MAX_FILE_SIZE) {
	    msg_set_reason("Cannot obtain upload token: file size must be between %llu and %llu bytes", SXLIMIT_MIN_FILE_SIZE, SXLIMIT_MAX_FILE_SIZE);
	    return EINVAL;
	}
	q = h->qt_update;
	total_blocks = size_to_blocks(size_or_seq, &h->put_hs, &blocksize);
	/* calculate expiry time of token proportional to the amount of data
	 * uploaded with _this_ token, i.e. we issue a new token for an extend.
	 * */
	sqlite3_reset(q);
	expires_at = time(NULL) + GC_GRACE_PERIOD + blocksize * total_blocks / h->upload_minspeed
            + GC_MIN_LATENCY * size_or_seq / UPLOAD_CHUNK_SIZE / 1000;
	if(qbind_int64(q, ":expiry", expires_at))
	    return FAIL_EINTERNAL;
    } else {
	/* extending */
	if(size_or_seq != h->put_extendfrom) {
	    msg_set_reason("Cannot obtain upload token: out of sequence");
	    return EINVAL;
	}
	q = h->qt_extend;
	total_blocks = size_to_blocks(h->put_extendsize, &h->put_hs, &blocksize);
	size_or_seq *= sizeof(sx_hash_t);
	sqlite3_reset(q);
    }

    if(h->put_putblock + h->put_extendfrom > total_blocks) {
	msg_set_reason("Cannot obtain upload token: cannot extend beyond the file size");
	return EINVAL;
    }

    if(qbind_int64(q, ":id", h->put_id) ||
       qbind_int64(q, ":size", size_or_seq))
	goto gettoken_err;

    if(h->put_putblock) {
	if(qbind_blob(q, ":all", h->put_blocks, sizeof(h->put_blocks[0]) * h->put_putblock))
	    goto gettoken_err;
#ifdef FILEHASH_OPTIMIZATION
        if (hash_buf("", 0, h->put_blocks, sizeof(h->put_blocks[0]) * h->put_putblock, &filehash)) {
            WARN("Failed to calculate file hash");
            goto gettoken_err;
        }
#endif
	h->put_nidxs = wrap_malloc(h->put_putblock * sizeof(h->put_nidxs[0]) * 2);
	if(!h->put_nidxs) {
	    OOM();
	    goto gettoken_err;
	}
	h->put_hashnos = &h->put_nidxs[h->put_putblock];
        build_uniq_hash_index(h->put_blocks, h->put_hashnos, &h->put_putblock);

	/* Lookup first node */
	for(i=0; i<h->put_putblock; i++) {
	    /* MODHDIST: pick only from _next, bidx = 0 */
	    if(hash_nidx_tobuf(h, &h->put_blocks[h->put_hashnos[i]], 1, &h->put_nidxs[h->put_hashnos[i]]))
		goto gettoken_err;
	}
	if(h->put_putblock > 1) {
	    /* Group by node, then by original position
	     * so that we second the readahead instead of fighting it */
	    sort_by_node_then_position(h->put_hashnos, h->put_nidxs, h->put_putblock, 1, 1);
	}
	if(h->put_extendfrom) {
	    for(i=0; i<h->put_putblock; i++)
		h->put_hashnos[i] += h->put_extendfrom;
	}
	if(qbind_blob(q, ":uniq", h->put_hashnos, sizeof(h->put_hashnos[0]) * h->put_putblock))
	    goto gettoken_err;
	if(h->put_extendfrom) {
	    for(i=0; i<h->put_putblock; i++)
		h->put_hashnos[i] -= h->put_extendfrom;
	}
    } else {
	if(qbind_blob(q, ":all", "", 0) || qbind_blob(q, ":uniq", "", 0))
	    goto gettoken_err;
#ifdef FILEHASH_OPTIMIZATION
        if (hash_buf("", 0, "", 0, &filehash)) {
            WARN("Failed to calculate file hash");
            goto gettoken_err;
        }
#endif
    }

    if(qstep_noret(q))
	goto gettoken_err;
    sqlite3_reset(q);

    if(h->nmeta) {
	int items;
	for(i=0; i<h->nmeta; i++) {
	    sqlite3_stmt *q;
	    if(h->meta[i].value_len < 0)
		q = h->qt_delmeta;
	    else
		q = h->qt_addmeta;

	    sqlite3_reset(q);
	    if(qbind_int64(q, ":id", h->put_id) ||
	       qbind_text(q, ":key", h->meta[i].key) ||
	       (h->meta[i].value_len >=0 && qbind_blob(q, ":value", h->meta[i].value, h->meta[i].value_len)) ||
	       qstep_noret(q))
		goto gettoken_err;
	    sqlite3_reset(q);
	}
	sqlite3_reset(h->qt_countmeta);
	if(qbind_int64(h->qt_countmeta, ":id", h->put_id) ||
	   qstep_ret(h->qt_countmeta)) {
	    sqlite3_reset(h->qt_countmeta);
	    goto gettoken_err;
	}

	items = sqlite3_column_int(h->qt_countmeta, 0);
	sqlite3_reset(h->qt_countmeta);
	if(items > SXLIMIT_META_MAX_ITEMS) {
	    ret = EOVERFLOW;
	    goto gettoken_err;
	}
    }

    sqlite3_reset(h->qt_gettoken);
    if(qbind_int64(h->qt_gettoken, ":id", h->put_id) || qstep_ret(h->qt_gettoken))
	goto gettoken_err;

    ptr = (const char *)sqlite3_column_text(h->qt_gettoken, 0);
    expires_at = sqlite3_column_int64(h->qt_gettoken, 1);
    if(sx_hashfs_make_token(h, user, ptr, h->put_replica, expires_at, token))
	goto gettoken_err;


    if (unique_tmpid(h, ptr, &h->put_reserve_id))
        goto gettoken_err;
    sxi_hashop_begin(&h->hc, h->sx_clust, hdck_cb, HASHOP_RESERVE, &h->put_reserve_id, hdck_cb_ctx);
#ifdef FILEHASH_OPTIMIZATION
    if (filehash_reserve(h, &filehash) == ITER_NO_MORE) {
        h->put_checkblock = h->put_putblock;/* no need to reserve each hash, we bumped the filehash's counter */
        DEBUG("skipping hash reserves");
    }
#endif

    sqlite3_reset(h->qt_gettoken);
    return OK;

    gettoken_err:
    sqlite3_reset(h->qt_addmeta);
    sqlite3_reset(h->qt_delmeta);
    sqlite3_reset(q);
    sqlite3_reset(h->qt_gettoken);
    return ret;
}

/* WARNING: MUST BE CALLED WITHIN A TANSACTION ON META !!! */
#define FIXME_MAX_NREVS 5
static rc_ty create_file(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *name, const char *revision, sx_hash_t *blocks, unsigned int nblocks, int64_t size, int64_t *file_id) {
    unsigned int nblocks2;
    int r, mdb;

    if(!h || !volume || !name || !revision || (!blocks && nblocks)) {
	NULLARG();
	return EFAULT;
    }

    if(check_file_name(name)<0) {
	msg_set_reason("Invalid file name");
	return EINVAL;
    }

    if(check_revision(revision)) {
	msg_set_reason("Invalid revision");
	return EINVAL;
    }

    nblocks2 = size_to_blocks(size, NULL, NULL);
    if(nblocks != nblocks2) {
	WARN("Inconsistent size: %u blocks given, %u expected", nblocks, nblocks2);
	return EFAULT;
    }

    mdb = getmetadb(name);
    if(mdb < 0) {
	msg_set_reason("Failed to locate file database");
	return FAIL_EINTERNAL;
    }

    /* Count current file revisions */
    sqlite3_reset(h->qm_tooold[mdb]);
    if(qbind_int64(h->qm_tooold[mdb], ":volume", volume->id) ||
       qbind_text(h->qm_tooold[mdb], ":name", name))
	return FAIL_EINTERNAL;

    r = qstep(h->qm_tooold[mdb]);
    if(r == SQLITE_ROW) {
	/* There are some revs */
	const char *tooold_rev = (const char *)sqlite3_column_text(h->qm_tooold[mdb], 1);
	int nrevs = sqlite3_column_int(h->qm_tooold[mdb], 2);
	int can_replace = tooold_rev && strcmp(revision, tooold_rev) >= 0;
        rc_ty rc = EINVAL;

        do {
            if(nrevs >= FIXME_MAX_NREVS) {
                /* There are too many revs */
                if(!can_replace) {
                    /* All existing revs are more recent than this one */
                    msg_set_reason("Newer copies of this file already exist");
                    break;
                }
                /* Remove the oldest */
                if (sx_hashfs_file_delete(h, volume, name, tooold_rev)) {
                    /* Removal failed */
                    msg_set_reason("Failed to delete older file revision: %s", tooold_rev);
                    break;
                }
            }
            rc = OK;
        } while(0);
        sqlite3_reset(h->qm_tooold[mdb]);
        if (rc)
            return rc;
        /* Yay we have a slot now */
    } else {
	sqlite3_reset(h->qm_tooold[mdb]);
	if(r != SQLITE_DONE) /* Something didn't quite work */
	    return FAIL_EINTERNAL;

	/* There are no existing revs */
    }

    sqlite3_reset(h->qm_ins[mdb]);
    if(qbind_int64(h->qm_ins[mdb], ":volume", volume->id) ||
       qbind_text(h->qm_ins[mdb], ":name", name) ||
       qbind_text(h->qm_ins[mdb], ":revision", revision) ||
       qbind_int64(h->qm_ins[mdb], ":size", size) ||
       qbind_blob(h->qm_ins[mdb], ":hashes", nblocks ? (const void *)blocks : "", nblocks * sizeof(blocks[0])) ||
       qstep_noret(h->qm_ins[mdb])) {
	WARN("Failed to create file '%s' on volume '%s'", name, volume->name);
	sqlite3_reset(h->qm_ins[mdb]);
	return FAIL_EINTERNAL;
    }

    if(file_id)
	*file_id = sqlite3_last_insert_rowid(sqlite3_db_handle(h->qm_ins[mdb]));
    sqlite3_reset(h->qm_ins[mdb]);
    return OK;
}

rc_ty sx_hashfs_createfile_commit(sx_hashfs_t *h, const char *volume, const char *name, const char *revision, int64_t size) {
    const sx_hashfs_volume_t *vol;
    unsigned int i, nblocks;
    int64_t file_id;
    int mdb, flen;
#ifdef FILEHASH_OPTIMIZATION
    sx_hash_t filehash;
#endif
    rc_ty ret = FAIL_EINTERNAL, ret2;

    if(!h || !name || !revision || h->put_id != -1) {
	NULLARG();
	return EFAULT;
    }

    if(check_file_name(name)<0) {
	msg_set_reason("Invalid file name");
	return EINVAL;
    }

    if(check_revision(revision)) {
	msg_set_reason("Invalid revision");
	return EINVAL;
    }

    flen = check_file_name(name);
    if(flen < 0 || name[flen - 1] == '/') {
	msg_set_reason("Bad file name");
	return EINVAL;
    }

    nblocks = size_to_blocks(size, NULL, NULL);
    if(h->put_putblock != nblocks) {
	msg_set_reason("Blocks do not match the file size");
	return EINVAL;
    }

    if((ret2 = sx_hashfs_volume_by_name(h, volume, &vol)))
	return ret2;

    if(!sx_hashfs_is_or_was_my_volume(h, vol)) {
	msg_set_reason("This volume does not belong here");
	return ENOENT;
    }

    mdb = getmetadb(name);
    if(mdb < 0) {
	msg_set_reason("Failed to locate file database");
	return FAIL_EINTERNAL;
    }

    if(qbegin(h->metadb[mdb]))
	return FAIL_EINTERNAL;

#ifdef FILEHASH_OPTIMIZATION
    /* direct file creation during replication: adjust filehash counters
     * accordingly */
    if (hash_buf("", 0, h->put_blocks, nblocks * sizeof(h->put_blocks[0]), &filehash)) {
        WARN("Failed to calculate file hash");
        return FAIL_EINTERNAL;
    }
    filehash_reserve(h, &filehash);
#endif
    ret2 = create_file(h, vol, name, revision, h->put_blocks, nblocks, size, &file_id);
    if(ret2) {
	ret = ret2;
	goto cretatefile_rollback;
    }
#ifdef FILEHASH_OPTIMIZATION
    filehash_mod_used(h, &filehash, 1);
#endif

    for(i=0; i<h->nmeta; i++) {
	sqlite3_reset(h->qm_metaset[mdb]);
	if(qbind_int64(h->qm_metaset[mdb], ":file", file_id) ||
	   qbind_text(h->qm_metaset[mdb], ":key", h->meta[i].key) ||
	   qbind_blob(h->qm_metaset[mdb], ":value", h->meta[i].value, h->meta[i].value_len) ||
	   qstep_noret(h->qm_metaset[mdb]))
	    break;
    }
    sqlite3_reset(h->qm_metaset[mdb]);
    if(i != h->nmeta)
	goto cretatefile_rollback;

    if(qcommit(h->metadb[mdb]))
	goto cretatefile_rollback;

    ret = OK;

 cretatefile_rollback:
    if(ret != OK)
	qrollback(h->metadb[mdb]);

    sx_hashfs_createfile_end(h);

    return ret;
}

static rc_ty are_blocks_available(sx_hashfs_t *h, sx_hash_t *hashes,
				  sxi_hashop_t *hdck,
				  unsigned int *hashnos, unsigned int *nidxs,
				  unsigned int *current, unsigned int count,
				  unsigned int hash_size, unsigned int check_replica,
				  unsigned int replica_count) {
    /* h: main hashfs
     * hashes: complete array of hashes, unsorted
     * hashnos: array of hash indexes sorted by node id
     * nidxs: array of node indexes
     * current: current hash to be checked
     * count: number of hashes in the list (also the numer of items in hashnos the number of items per replica in nidxs)
     * hash_size: the size (small, medium, big) of the hashes in hashes
     * check_replica: which set to check (1 <= check_replica <= replica_count)
     * replica_count: the number of replica sets
     */

    /* MODHDIST:
     * this is a major PITA. With the current api (and callbacks) we can only check presence
     * on a single set, which, for functional reasons outta be the _next set.
     * In practice this means that the clients (i.e. cluster users) effectively help the
     * migration process with their bandwith. This also means that the clients (i.e. the users) might
     * experience unexpected spikes in resource usage for reasons which are outside their control.
     * A better approach would be to check presence on _prev, then _next and merge the results.
     * This is however not possible without a major api rework :(
     */
    const sx_nodelist_t *nodes = sx_hashfs_nodelist(h, NL_NEXT);
    unsigned int check_item = *current;
    unsigned int thisnode, nextnode, prevnode = nidxs[replica_count * hashnos[check_item] + check_replica - 1];

    if(!count)
	return OK;

    if(check_item >= count) {
	WARN("bad check_item: %d >= %d", check_item, count);
	return FAIL_EINTERNAL;
    }

    /* hash is local */
    if(sx_nodelist_lookup_index(nodes, &h->node_uuid, &thisnode) && prevnode == thisnode) {
	sx_hash_t *hash = &hashes[hashnos[check_item]];
	unsigned int ndb = gethashdb(hash);
	int r;
        rc_ty rc;

	sqlite3_reset(h->qb_get[hash_size][ndb]);
	if(qbind_blob(h->qb_get[hash_size][ndb], ":hash", hash, sizeof(*hash))) {
	    WARN("qbind_blob failed");
	    sqlite3_reset(h->qb_get[hash_size][ndb]);
	    return FAIL_EINTERNAL;
	}
	r = qstep(h->qb_get[hash_size][ndb]);
	sqlite3_reset(h->qb_get[hash_size][ndb]);

	*current = check_item+1;
        if (sxi_hashop_batch_flush(hdck))
            WARN("Failed to query hash: %s", sxc_geterrmsg(h->sx));
	hdck->queries++;
	hdck->finished++;
	if (r == SQLITE_ROW)
	    hdck->ok++;
	else
	    hdck->enoent++;
        rc = sx_hashfs_hashop_begin(h, bsz[hash_size]);
        if (rc) {
            WARN("hashop_begin failed: %s", rc2str(rc));
            return rc;
        }
        rc = sx_hashfs_hashop_perform(h, hdck->kind, hash, hdck->id);
        rc = sx_hashfs_hashop_finish(h, rc);
        if (rc && rc != ENOENT) {
            WARN("hashop_perform/finish failed: %s", rc2str(rc));
            return rc;
        }
	if (hdck->cb) {
	    int code = r == SQLITE_ROW ? 200 : 404;
	    char thash[SXI_SHA1_TEXT_LEN + 1];
	    if (bin2hex(hash->b, SXI_SHA1_BIN_LEN, thash, sizeof(thash))) {
		WARN("bin2hex failed for hash");
		return FAIL_EINTERNAL;
	    }
	    if (hdck->cb(thash, check_item, code, hdck->context) == -1) {
		WARN("callback returned failure");
		return FAIL_EINTERNAL;
	    }
	}
	return OK;
    }

    const sx_node_t *node = sx_nodelist_get(nodes, prevnode);
    if(!node) {
	WARN("failed to get nodelist");
	return FAIL_EINTERNAL;
    }
    const char *host = sx_node_internal_addr(node);
    do {
        if (sxi_hashop_batch_add(hdck, host, check_item, hashes[hashnos[check_item]].b, bsz[hash_size])) {
            WARN("Failed to query hash on %s: %s", host, sxc_geterrmsg(h->sx));
        }
	check_item++;
	if(check_item >= count)
	    break; /* end of set for this replica */
	nextnode = nidxs[replica_count * hashnos[check_item] + check_replica - 1];
    } while (nextnode == prevnode); /* end of current node */

    *current = check_item;
    return OK;
}

rc_ty reserve_replicas(sx_hashfs_t *h)
{
    /*
     * assign more understandable names to pointers and counters
     */
    rc_ty ret = OK;
    sx_hash_t *all_hashes = h->put_blocks;
    sxi_hashop_t *hashop = &h->hc;
    unsigned int *uniq_hash_indexes = h->put_hashnos;
    unsigned uniq_count = h->put_putblock;
    if (!uniq_count)
        return OK;
    unsigned int *node_indexes = wrap_malloc((1+h->put_replica) * h->put_nblocks * sizeof(*node_indexes));
    unsigned hash_size = h->put_hs;
    if (!node_indexes)
        return ENOMEM;

    unsigned i;
    for(i=0; i<uniq_count; i++) {
	/* MODHDIST: pick from _next, bidx=0 */
	if(hash_nidx_tobuf(h, &all_hashes[uniq_hash_indexes[i]],
                           h->put_replica, &node_indexes[uniq_hash_indexes[i]*h->put_replica])) {
	    WARN("hash_nidx_tobuf failed");
            ret = FAIL_EINTERNAL;
	}
    }
    for(i=2; ret == OK && i<=h->put_replica; i++) {
        unsigned int cur_item = 0;
        sort_by_node_then_hash(all_hashes, uniq_hash_indexes, node_indexes, uniq_count, i, h->put_replica);
        memset(hashop, 0, sizeof(*hashop));
        sxi_hashop_begin(hashop, h->sx_clust, NULL,
                         HASHOP_RESERVE, &h->put_reserve_id, NULL);
        while((ret = are_blocks_available(h, all_hashes, hashop,
                                          uniq_hash_indexes, node_indexes,
                                          &cur_item, uniq_count, hash_size,
                                          i, h->put_replica)) == OK) {
            if(cur_item >= uniq_count)
                break;
        }
        if (ret)
            WARN("are_blocks_available failed: %s", rc2str(ret));
        if (!ret && sxi_hashop_end(hashop) == -1) {
            WARN("sxi_hashop_end failed: %s", sxc_geterrmsg(h->sx));
            ret = FAIL_EINTERNAL;
        }
    }
    free(node_indexes);
    return ret;
}

rc_ty sx_hashfs_putfile_getblock(sx_hashfs_t *h) {
    rc_ty ret;
    if(!h || !h->put_token[0])
	return EINVAL;

    if(h->put_checkblock >= h->put_putblock) {
	if(sxi_hashop_end(&h->hc) == -1) {
	    WARN("hashop_end failed: %s", sxc_geterrmsg(h->sx));
            return FAIL_EINTERNAL;
        } else
	    DEBUG("{%s}: finished:%d, queries:%d, ok:%d, enoent:%d, cbfail:%d",
		  h->node_uuid.string,
		  h->hc.finished, h->hc.queries, h->hc.ok, h->hc.enoent, h->hc.cb_fail);
        ret = reserve_replicas(h);
        if (ret) {
            WARN("failed to reserve replicas: %s", rc2str(ret));
            return ret;
        }
	h->put_success = 1;
	return ITER_NO_MORE;
    }
    ret = are_blocks_available(h, h->put_blocks, &h->hc, h->put_hashnos, h->put_nidxs, &h->put_checkblock, h->put_putblock, h->put_hs, 1, 1);
    return ret;
}

void sx_hashfs_createfile_end(sx_hashfs_t *h) {
    if(!h)
	return;

    free(h->put_blocks);
    putfile_reinit(h);
}

void sx_hashfs_putfile_end(sx_hashfs_t *h) {
    if(!h)
	return;
    /* ensure no callbacks are running anymore, or they'd access
     * a wrong ctx data */
    sxi_hashop_end(&h->hc);
    memset(&h->hc, 0, sizeof(h->hc));

    free(h->put_blocks);
    free(h->put_nidxs);

    if(!h->put_success && h->put_id) {
	sqlite3_reset(h->qt_delete);
	if(!qbind_int64(h->qt_delete, ":id", h->put_id))
	    qstep_noret(h->qt_delete);
	sqlite3_reset(h->qt_delete);
    }

    putfile_reinit(h);
}

rc_ty sx_hashfs_putfile_commitjob(sx_hashfs_t *h, const uint8_t *user, sx_uid_t user_id, const char *token, job_t *job_id) {
    unsigned int expected_blocks, actual_blocks, job_timeout, ndests;
    int64_t tmpfile_id, expected_size, volid;
    rc_ty ret = FAIL_EINTERNAL, ret2;
    sx_nodelist_t *volnodes = NULL;
    const sx_hashfs_volume_t *vol;
    const sx_uuid_t *self_uuid;
    const sx_node_t *self;
    struct token_data tkdt;
    int r, has_begun = 0;

    if(!h || !user || !job_id) {
	NULLARG();
	return EFAULT;
    }
    if(parse_token(h->sx, user, token, &h->tokenkey, &tkdt)) {
	WARN("bad token: %s", token);
	return EINVAL;
    }

    if(!(self = sx_hashfs_self(h)) || !(self_uuid = sx_node_uuid(self)))
	return FAIL_EINTERNAL;
    if(memcmp(self_uuid->binary, tkdt.uuid.binary, sizeof(tkdt.uuid.binary))) {
	WARN("bad token uuid");
	return EINVAL;
    }

    if(qbegin(h->tempdb))
	goto putfile_commitjob_err;
    has_begun = 1;

    sqlite3_reset(h->qt_tokenstats);
    if(qbind_text(h->qt_tokenstats, ":token", tkdt.token))
	goto putfile_commitjob_err;
    r = qstep(h->qt_tokenstats);
    if(r == SQLITE_DONE) {
        msg_set_reason("Token is unknown or already flushed");
	ret = ENOENT;
    }
    if(r != SQLITE_ROW)
	goto putfile_commitjob_err;

    tmpfile_id = sqlite3_column_int64(h->qt_tokenstats, 0);
    expected_size = sqlite3_column_int64(h->qt_tokenstats, 1);
    volid = sqlite3_column_int64(h->qt_tokenstats, 2);
    ret2 = sx_hashfs_volume_by_id(h, volid, &vol);
    if(ret2) {
	WARN("Cannot locate volume %lld for tmp file %lld", (long long)volid, (long long)tmpfile_id);
	ret = ret2;
	goto putfile_commitjob_err;
    }
    ret2 = sx_hashfs_volnodes(h, NL_NEXTPREV, vol, 0, &volnodes, NULL);
    if(ret2) {
	WARN("Cannot determine volume nodes for '%s'", vol->name);
	ret = ret2;
	goto putfile_commitjob_err;
    }
    actual_blocks = sqlite3_column_int64(h->qt_tokenstats, 3);
    if(actual_blocks % sizeof(sx_hash_t)) {
	msg_set_reason("Corrupted token data");
	goto putfile_commitjob_err;
    }
    actual_blocks /= sizeof(sx_hash_t);
    expected_blocks = size_to_blocks(expected_size, NULL, NULL);
    if(actual_blocks != expected_blocks) {
	/* File was not extended enough to match its size */
	msg_set_reason("Token not extended to its final size");
	ret = EINVAL;
	goto putfile_commitjob_err;
    }

    sqlite3_reset(h->qt_flush);
    if(qbind_int64(h->qt_flush, ":id", tmpfile_id) ||
       qstep_noret(h->qt_flush)) {
	/* The job itself will fail in case a token is still present */
	goto putfile_commitjob_err;
    }

    expected_size = expected_size / 1024 / 1024;
    ndests = sx_nodelist_count(volnodes);
    if(ndests > 1) {
	for(job_timeout = 50; expected_size; expected_size >>= 3)
	    job_timeout <<= 1;
	if(ndests > 2)
	    job_timeout = job_timeout * ndests / (ndests - 1);
    } else
	job_timeout = 20;
    job_timeout += expected_blocks / DOWNLOAD_MAX_BLOCKS * 4;
    if(job_timeout > JOB_FILE_MAX_TIME)
	job_timeout = JOB_FILE_MAX_TIME;
    ret2 = sx_hashfs_job_new_notrigger(h, user_id, job_id, JOBTYPE_FLUSH_FILE, job_timeout, token, &tmpfile_id, sizeof(tmpfile_id), volnodes);
    if(ret2) {
        INFO("job_new returned: %s", rc2str(ret2));
	ret = ret2;
	goto putfile_commitjob_err;
    }

    if(qcommit(h->tempdb))
	goto putfile_commitjob_err;

    ret = OK;
    sx_hashfs_job_trigger(h);

 putfile_commitjob_err:
    if(ret != OK && has_begun)
	qrollback(h->tempdb);

    sqlite3_reset(h->qt_tokenstats);

    sx_nodelist_delete(volnodes);

    return ret;
}

static int tmp_getmissing_cb(const char *hexhash, unsigned int index, int code, void *context) {
    sx_hashfs_missing_t *mis = (sx_hashfs_missing_t *)context;
    sx_hash_t binhash;
    unsigned int blockno;

    if(!hexhash || !mis)
	return -1;
    DEBUG("remote hash #%.*s#: %d", SXI_SHA1_TEXT_LEN, hexhash, code);
    if(code != 200)
	return 0;

    if(index >= mis->nuniq) {
	WARN("Index out of bounds");
	return -1;
    }

    hex2bin(hexhash, SXI_SHA1_TEXT_LEN, binhash.b, sizeof(binhash));
    blockno = mis->uniq_ids[index];
    if(memcmp(&mis->all_blocks[blockno], &binhash, sizeof(binhash))) {
	char idxhash[SXI_SHA1_TEXT_LEN + 1];
	bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), idxhash, sizeof(idxhash));
	WARN("Hash mismatch: called for %.*s but index %d points to %s", SXI_SHA1_TEXT_LEN, hexhash, index, idxhash);
	return -1;
    }

    if(mis->avlblty[blockno * mis->replica_count + mis->current_replica - 1] != 1) {
	mis->avlblty[blockno * mis->replica_count + mis->current_replica - 1] = 1;
	mis->somestatechanged = 1;
        DEBUG("(cb): Block %.*s set %u is NOW available on node %c",
              SXI_SHA1_TEXT_LEN, hexhash, mis->current_replica - 1, 'a' +
              mis->nidxs[blockno * mis->replica_count + mis->current_replica - 1]);
    }
    return 0;
}

static int unique_fileid(sxc_client_t *sx, const sx_hashfs_volume_t *volume, const char *name, const char *revision, sx_hash_t *fileid)
{
    int ret = 0;
    sxi_md_ctx *hash_ctx = sxi_md_init();
    if (!hash_ctx)
        return 1;
    if (!sxi_sha1_init(hash_ctx))
        return 1;

    if (!sxi_sha1_update(hash_ctx, volume->name, strlen(volume->name) + 1) ||
        !sxi_sha1_update(hash_ctx, name, strlen(name) + 1) ||
        !sxi_sha1_update(hash_ctx, revision, strlen(revision)) ||
        !sxi_sha1_final(hash_ctx, fileid->b, NULL)) {
        ret = 1;
    }

    sxi_md_cleanup(&hash_ctx);
    return ret;
}

rc_ty sx_hashfs_tmp_getmissing(sx_hashfs_t *h, int64_t tmpfile_id, sx_hashfs_missing_t **missing, int commit) {
    unsigned int contentsz, nblocks, bs, nuniqs, i, hash_size, navl;
    const unsigned int *uniqs;
    const sx_hashfs_volume_t *volume;
    rc_ty ret = FAIL_EINTERNAL, ret2;
    const sx_hash_t *content;
    sx_hashfs_missing_t *tbd = NULL;
    const char *name, *revision;
    const uint8_t *avl;
    int64_t file_size;
#ifdef FILEHASH_OPTIMIZATION
    sx_hash_t filehash;
#endif
    int r;
    char token[TOKEN_RAND_BYTES*2 + 1];

    if(!h || !missing) {
	NULLARG();
	return EFAULT;
    }
    DEBUG("tmp_getmissing for file %ld", tmpfile_id);

    /* Get tmp data */
    sqlite3_reset(h->qt_tmpdata);
    if(qbind_int64(h->qt_tmpdata, ":id", tmpfile_id))
	goto getmissing_err;

    r = qstep(h->qt_tmpdata);
    if(r == SQLITE_DONE) {
	msg_set_reason("Token not found");
	ret = ENOENT;
    }
    if(r != SQLITE_ROW) {
	WARN("Error looking up token");
	goto getmissing_err;
    }

    if(sqlite3_column_int(h->qt_tmpdata, 6) == 0) {
	/* Not yet flushed, need to retry later */
	msg_set_reason("Token not ready yet");
	ret = EAGAIN;
	goto getmissing_err;
    }

    /* Quickly validate tmp data */
    revision = (const char *)sqlite3_column_text(h->qt_tmpdata, 0);
    if(!revision || strlen(revision) >= sizeof(tbd->revision)) {
	WARN("Tmpfile with %s revision", revision ? "bad" : "NULL");
	msg_set_reason("Internal corruption detected (bad revision)");
	ret = EFAULT;
	goto getmissing_err;
    }

    if((ret2 = sx_hashfs_volume_by_id(h, sqlite3_column_int64(h->qt_tmpdata, 3), &volume))) {
	ret = ret2;
	if(ret2 == ENOENT)
	    msg_set_reason("Volume no longer exists");
	goto getmissing_err;
    }

    name = (const char *)sqlite3_column_text(h->qt_tmpdata, 1);
    if(check_file_name(name) < 0) {
	WARN("Tmpfile with bad name");
	msg_set_reason("Internal corruption detected (bad name)");
	ret = EFAULT;
	goto getmissing_err;
    }

    file_size = sqlite3_column_int64(h->qt_tmpdata, 2);
    nblocks = size_to_blocks(file_size, &hash_size, &bs);

    content = sqlite3_column_blob(h->qt_tmpdata, 4);
    contentsz = sqlite3_column_bytes(h->qt_tmpdata, 4);
    if(contentsz % sizeof(sx_hash_t) || contentsz / sizeof(*content) != nblocks) {
	WARN("Tmpfile with bad content length");
	msg_set_reason("Internal corruption detected (bad content)");
	ret = EFAULT;
	goto getmissing_err;
    }
#ifdef FILEHASH_OPTIMIZATION
    if (hash_buf("", 0, content, contentsz, &filehash)) {
        WARN("Cannot calculate file hash");
        goto getmissing_err;
    }
#endif

    uniqs = sqlite3_column_blob(h->qt_tmpdata, 5);
    contentsz = sqlite3_column_bytes(h->qt_tmpdata, 5);
    nuniqs = contentsz / sizeof(*uniqs);
    if(contentsz % sizeof(*uniqs) || nuniqs > nblocks)  {
	WARN("Tmpfile with bad unique length");
	msg_set_reason("Internal corruption detected (bad unique content)");
	ret = EFAULT;
	goto getmissing_err;
    }

#ifdef FILEHASH_OPTIMIZATION
    if (commit) {
        if (filehash_mod_used(h, &filehash, 1) == ITER_NO_MORE) {
            nuniqs = 0; /* do not bump/check any hash counters */
            DEBUG("skipping moduse (commit)");
        }
    } else {
        if (filehash_is_used(h, &filehash)) {
            nuniqs = 0;
            DEBUG("skipping moduse (request)");
        }
    }
#endif

    avl = sqlite3_column_blob(h->qt_tmpdata, 7);
    if(avl) {
	navl = sqlite3_column_bytes(h->qt_tmpdata, 7);
	if(navl != nblocks * volume->replica_count) {
	    WARN("Tmpfile with bad availability length");
	    msg_set_reason("Internal corruption detected (bad availability content)");
	    ret = EFAULT;
	    goto getmissing_err;
	}
    } else
	navl = nblocks * volume->replica_count;

    tbd = wrap_malloc(sizeof(*tbd) + /* The struct itself */
		      nblocks * sizeof(sx_hash_t) + /* all_blocks */
		      nuniqs * sizeof(tbd->uniq_ids[0]) + /* uniq_ids */
		      nblocks * sizeof(tbd->nidxs[0]) * volume->replica_count + /* nidxs */
		      navl); /* avlblty */
    if(!tbd) {
	OOM();
	ret = ENOMEM;
	goto getmissing_err;
    }

    tbd->allnodes = sx_hashfs_nodelist(h, NL_NEXT);

    tbd->volume_id = volume->id;
    tbd->all_blocks = (sx_hash_t *)(tbd+1);
    tbd->uniq_ids = (unsigned int *)&tbd->all_blocks[nblocks];
    tbd->nidxs = &tbd->uniq_ids[nuniqs];
    tbd->avlblty = (uint8_t *)&tbd->nidxs[nblocks * volume->replica_count];
    memcpy(tbd->all_blocks, content, nblocks * sizeof(sx_hash_t));
    memcpy(tbd->uniq_ids, uniqs, nuniqs * sizeof(tbd->uniq_ids[0]));
    memset(tbd->nidxs, -1, nblocks * sizeof(tbd->nidxs[0]) * volume->replica_count);
    for(i=0; i<nuniqs; i++) {
	/* MODHDIST: pick from _next, bidx=0 */
	if(hash_nidx_tobuf(h, &tbd->all_blocks[tbd->uniq_ids[i]], volume->replica_count, &tbd->nidxs[tbd->uniq_ids[i]*volume->replica_count])) {
	    WARN("hash_nidx_tobuf failed");
	    goto getmissing_err;
	}
    }
    if(!avl)
	memset(tbd->avlblty, 0, navl);
    else
	memcpy(tbd->avlblty, avl, navl);
    tbd->nall = nblocks;
    tbd->nuniq = nuniqs;
    tbd->replica_count = volume->replica_count;
    tbd->block_size = bs;
    strcpy(tbd->revision, revision);
    strcpy(tbd->name, name);
    strcpy(tbd->revision, revision);
    tbd->file_size = file_size;
    tbd->tmpfile_id = tmpfile_id;
    tbd->somestatechanged = 0;

    strncpy(token, (const char*)sqlite3_column_text(h->qt_tmpdata, 8), sizeof(token)-1);
    token[sizeof(token)-1] = '\0';
    sqlite3_reset(h->qt_tmpdata); /* Do not deadlock if we need to update this very entry */

    if(nuniqs) {
	unsigned int r, l;

	/* For each replica set populate tbd->avlblty via hash_presence callback */
	for(i=1; i<=tbd->replica_count; i++) {
            sx_hash_t tmpid;
	    unsigned int cur_item = 0;
	    sort_by_node_then_hash(tbd->all_blocks, tbd->uniq_ids, tbd->nidxs, tbd->nuniq, i, tbd->replica_count);
            /* tmpid must match the ID used for reserving hashes in gettoken */
            if (unique_tmpid(h, token, &tmpid))
                goto getmissing_err;
            sxi_hashop_begin(&h->hc, h->sx_clust, tmp_getmissing_cb,
                             HASHOP_INUSE, &tmpid, tbd);
	    tbd->current_replica = i;
	    while((ret2 = are_blocks_available(h,
					       tbd->all_blocks,
					       &h->hc,
					       tbd->uniq_ids,
					       tbd->nidxs,
					       &cur_item,
					       tbd->nuniq,
					       hash_size,
					       i,
					       tbd->replica_count)) == OK) {
		if(cur_item >= nuniqs)
		    break;
	    }
	    if(ret2 != OK) {
		ret = ret2;
		goto getmissing_err;
	    }
	    if(sxi_hashop_end(&h->hc) == -1) {
                ret = EAGAIN;
		goto getmissing_err;
            }
	}

	/* Drop all hashes which are already fully replicated */
	for(r=0, l=0; r < tbd->nuniq; r++) {
	    for(i=0; i<tbd->replica_count; i++) {
		if(tbd->avlblty[tbd->uniq_ids[r] * tbd->replica_count + i] != 1)
		    break;
	    }
	    if(i == tbd->replica_count) {
		tbd->somestatechanged = 1; /* Should be implied but explicitly setting this won't harm */
		nuniqs--;
		continue;
	    }
	    if(l != r)
		tbd->uniq_ids[l] = tbd->uniq_ids[r];
	    l++;
	}

	if(tbd->somestatechanged) {
	    /* If we've harvested some hash bring the counter down */
	    tbd->nuniq = nuniqs;

	    /* and update the db so they won't be hashop'd again on the next run */
	    sqlite3_reset(h->qt_updateuniq);
	    if(!qbind_int64(h->qt_updateuniq, ":id", tmpfile_id) &&
	       !qbind_blob(h->qt_updateuniq, ":uniq", tbd->uniq_ids, sizeof(*tbd->uniq_ids) * tbd->nuniq) &&
	       !qbind_blob(h->qt_updateuniq, ":avail", tbd->avlblty, navl))
		qstep_noret(h->qt_updateuniq);
	    sqlite3_reset(h->qt_updateuniq);
	}
    }

    *missing = tbd;
    ret = OK;

 getmissing_err:
    if(ret != OK)
	free(tbd);

    sqlite3_reset(h->qt_tmpdata);

    return ret;
}

rc_ty sx_hashfs_tmp_tofile(sx_hashfs_t *h, const sx_hashfs_missing_t *missing) {
    rc_ty ret = FAIL_EINTERNAL, ret2;
    const sx_hashfs_volume_t *volume;
    int64_t file_id;
    int r, mdb;

    if(!h || !missing) {
	NULLARG();
	return EFAULT;
    }

    mdb = getmetadb(missing->name);
    if(mdb < 0) {
	msg_set_reason("Failed to locate file database");
	return FAIL_EINTERNAL;
    }

    ret2 = sx_hashfs_volume_by_id(h, missing->volume_id, &volume);
    if(ret2) {
	WARN("Cannot locate volume %lld", (long long)missing->volume_id);
	return ret2;
    }

    sqlite3_reset(h->qt_getmeta);

    if(qbegin(h->metadb[mdb]))
	return FAIL_EINTERNAL;

    ret2 = create_file(h, volume, missing->name, missing->revision, missing->all_blocks, missing->nall, missing->file_size, &file_id);
    if(ret2) {
	ret = ret2;
	goto tmp2file_rollback;
    }

    if(qbind_int64(h->qt_getmeta, ":id", missing->tmpfile_id))
	goto tmp2file_rollback;
    while((r = qstep(h->qt_getmeta)) == SQLITE_ROW) {
	const char *key = (const char *)sqlite3_column_text(h->qt_getmeta, 0);
	const void *value = sqlite3_column_blob(h->qt_getmeta, 1);
	int value_len = sqlite3_column_bytes(h->qt_getmeta, 1);

	sqlite3_reset(h->qm_metaset[mdb]);
	if(qbind_int64(h->qm_metaset[mdb], ":file", file_id) ||
	   qbind_text(h->qm_metaset[mdb], ":key", key) ||
	   qbind_blob(h->qm_metaset[mdb], ":value", value, value_len) ||
	   qstep_noret(h->qm_metaset[mdb])) {
	    sqlite3_reset(h->qm_metaset[mdb]);
	    goto tmp2file_rollback;
	}
    }
    sqlite3_reset(h->qm_metaset[mdb]);
    sqlite3_reset(h->qt_getmeta);
    if(r != SQLITE_DONE)
	goto tmp2file_rollback;

    if(qcommit(h->metadb[mdb]))
	goto tmp2file_rollback;

    sqlite3_reset(h->qt_delete);
    if(!qbind_int64(h->qt_delete, ":id", missing->tmpfile_id))
	qstep_noret(h->qt_delete);
    sqlite3_reset(h->qt_delete);

    ret = OK;

 tmp2file_rollback:
    if(ret != OK)
	qrollback(h->metadb[mdb]);

    sqlite3_reset(h->qm_metaset[mdb]);
    sqlite3_reset(h->qt_getmeta);

    return ret;
}


rc_ty sx_hashfs_tmp_getmeta(sx_hashfs_t *h, const char *name, int64_t tmpfile_id, sxc_meta_t *metadata) {
    rc_ty ret = FAIL_EINTERNAL;
    int r, mdb;

    if(!h || !metadata) {
	NULLARG();
	return EFAULT;
    }

    mdb = getmetadb(name);
    if(mdb < 0) {
	msg_set_reason("Failed to locate file database");
	return FAIL_EINTERNAL;
    }

    sqlite3_reset(h->qt_getmeta);
    if(qbind_int64(h->qt_getmeta, ":id", tmpfile_id))
	return FAIL_EINTERNAL;
    while((r = qstep(h->qt_getmeta)) == SQLITE_ROW) {
	const char *key = (const char *)sqlite3_column_text(h->qt_getmeta, 0);
	const void *value = sqlite3_column_blob(h->qt_getmeta, 1);
	int value_len = sqlite3_column_bytes(h->qt_getmeta, 1);

	if(sxc_meta_setval(metadata, key, value, value_len)) {
	    msg_set_reason("Not enough memory to collect file metadata");
	    ret = ENOMEM;
	    goto tmpgetmeta_err;
	}
    }
    if(r != SQLITE_DONE) {
	msg_set_reason("Database error collecting file metadata");
	goto tmpgetmeta_err;
    }

    ret = OK;

 tmpgetmeta_err:
    sqlite3_reset(h->qm_metaset[mdb]);

    return ret;
}

static rc_ty get_file_id(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, int64_t *file_id, int *database_number, unsigned int *created_at, sx_hash_t *etag) {
    const sx_hashfs_volume_t *vol;
    sqlite3_stmt *q;
    int r, ndb;
    rc_ty res;

    if(!h || !volume || !filename || !file_id) {
	NULLARG();
	return EFAULT;
    }

    if(check_file_name(filename)<0) {
	msg_set_reason("Invalid file name");
	return EINVAL;
    }

    res = sx_hashfs_volume_by_name(h, volume, &vol);
    if(res)
	return res;

    ndb = getmetadb(filename);
    if(ndb < 0)
	return FAIL_EINTERNAL;

    if(revision) {
	if(check_revision(revision)) {
	    msg_set_reason("Invalid revision");
	    return EINVAL;
	}
	q = h->qm_getrev[ndb];
	if(qbind_text(q, ":revision", revision))
	    return FAIL_EINTERNAL;
    } else
	q = h->qm_get[ndb];

    if(qbind_int64(q, ":volume", vol->id) || qbind_text(q, ":name", filename))
	return FAIL_EINTERNAL;

    r = qstep(q);
    if(r == SQLITE_ROW) {
	*file_id = sqlite3_column_int64(q, 0);
	*database_number = ndb;
	res = OK;
	if(created_at || etag) {
	    const char *rev = (const char *)sqlite3_column_text(q, 3);
	    if(!rev ||
	       (created_at && parse_revision(rev, created_at)) ||
	       (etag && hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), rev, strlen(rev), etag)))
		res = FAIL_EINTERNAL;
	}
    } else if(r == SQLITE_DONE)
	res = ENOENT;
    else
	res = FAIL_EINTERNAL;

    sqlite3_reset(q);
    return res;
}

rc_ty sx_hashfs_file_delete(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *file, const char *revision) {
    unsigned int bs, i, idx = 0, *idxs = NULL, uniq;
    sx_hash_t hash;
    int ndb, current_replica;
    sx_nodelist_t *belongsto;
    int64_t file_id, mh;
    rc_ty ret;
    char fileidhex[SXI_SHA1_TEXT_LEN+1];

    if(!h || !volume || !file) {
	NULLARG();
	return EFAULT;
    }

    if(!h->have_hd) {
	WARN("Called before initialization");
	return FAIL_EINIT;
    }

    /* MODHDIST: only decrementing hash refcounts from the newer distibution atm
     * This does not work for files deleted when not yet sync'd.
     * Review the delete/unbump strategy based on the final rebalance process */
    if(hash_buf(h->cluster_uuid.string, strlen(h->cluster_uuid.string), volume->name, strlen(volume->name), &hash)) {
        WARN("Cannot calculate volume hash");
        return FAIL_EINTERNAL;
    }
    mh = MurmurHash64(&hash, sizeof(hash), HDIST_SEED);
    belongsto = sxi_hdist_locate(h->hd, mh, volume->replica_count, 0);
    if(!belongsto) {
        WARN("Cannot get nodes for volume");
        return FAIL_EINTERNAL;
    }
    if(!sx_nodelist_lookup_index(belongsto, &h->node_uuid, (unsigned int *)&current_replica))
	current_replica = -1;
    sx_nodelist_delete(belongsto);
    if(current_replica < 0) {
	int is_mine = 1;
	if(h->is_rebalancing) {
	    belongsto = sxi_hdist_locate(h->hd, mh, volume->replica_count, 1);
	    if(!belongsto) {
		WARN("Cannot get nodes for volume");
		return FAIL_EINTERNAL;
	    }
	    is_mine = sx_nodelist_lookup(belongsto, &h->node_uuid) != NULL;
	    sx_nodelist_delete(belongsto);
	}
	if(!is_mine) {
	    msg_set_reason("Wrong node for volume '%s': ...", volume->name);
	    return ENOENT;
	}
    }

    if(check_file_name(file)<0) {
	msg_set_reason("Invalid file name");
	return EINVAL;
    }

    if(check_revision(revision)) {
	msg_set_reason("Invalid revision");
	return EINVAL;
    }

    ret = get_file_id(h, volume->name, file, revision, &file_id, &ndb, NULL, NULL);
    if (ret)
        return ret;

    if(current_replica >= 0) {
	if (unique_fileid(h->sx, volume, file, revision, &hash) ||
	    bin2hex(hash.b, sizeof(hash.b), fileidhex, sizeof(fileidhex)))
	    return FAIL_EINTERNAL;
	sxi_hashop_begin(&h->hc, h->sx_clust, NULL, HASHOP_DELETE, &hash, NULL);
	ret = sx_hashfs_getfile_begin(h, volume->name, file, revision, NULL, &bs, NULL, NULL);
	if (ret != OK)
	    return ret;

#ifdef FILEHASH_OPTIMIZATION
	if (hash_buf("", 0, h->get_content, h->get_nblocks * sizeof(sx_hash_t), &hash)) {
	    WARN("Cannot calculate file hash");
	    return FAIL_EINTERNAL;
	}
	if (filehash_mod_used(h, &hash, 1) == ITER_NO_MORE)
	    h->get_nblocks = 0; /* do not modify/check any hash counters */
#endif

	if (h->get_nblocks) do {
		idxs = wrap_malloc(h->get_nblocks * sizeof(*idxs));
		if (!idxs) {
		    ret = ENOMEM;
		    break;
		}

		const sx_node_t *self = sx_hashfs_self(h);

		uniq = h->get_nblocks;
		build_uniq_hash_index(h->get_content, idxs, &uniq);
		if (uniq > 0) {
		    sx_nodelist_t **nodes = wrap_calloc(uniq, sizeof(*nodes));
		    if (!nodes) {
			ret = ENOMEM;
			break;
		    }

		    for (i=0; i<uniq; i++) {
			const sx_hash_t *hash = &h->get_content[idxs[i]];
			/* MODHDIST: if we move all the blocks first, then it is safe to only delete from _NEXT */
			nodes[i] = sx_hashfs_hashnodes(h, NL_NEXT, hash, h->get_replica);
			const sx_node_t *node = sx_nodelist_get(nodes[i], current_replica);
			DEBUGHASH("decuse on", hash);
			if (!sx_node_cmp(node, self)) {
			    ret = sx_hashfs_hashop_begin(h, bs);
			    if (ret == OK) {
				ret = sx_hashfs_hashop_perform(h, HASHOP_DELETE, hash, fileidhex);
				if (ret != OK)
				    WARN("hashop_perform failed: %s", rc2str(ret));
				ret = sx_hashfs_hashop_finish(h, ret);
			    } else
				WARN("hashop_begin failed: %s", rc2str(ret));
			} else {
			    ret = sxi_hashop_batch_add(&h->hc, sx_node_internal_addr(node), idx++, hash->b, bs);
			    if (ret)
				WARN("hashop_batch_add failed: %s", rc2str(ret));
			}
			if (ret)
			    WARN("Failed to query hash...: %s", rc2str(ret));
		    }
		    sx_hashfs_getfile_end(h);
		    DEBUG("waiting for hashop_end");
		    if (sxi_hashop_end(&h->hc) == -1) {
			WARN("hashop_end failed: %s", sxc_geterrmsg(h->sx));
			ret = sxc_geterrnum(h->sx);
		    }
		    for (i=0; i<uniq;i++)
			sx_nodelist_delete(nodes[i]);
		    free(nodes);
		    nodes = NULL;
		    free(idxs);
		    idxs = NULL;
		}
	    } while(0);
	sx_hashfs_getfile_end(h);
	free(idxs);
	if (ret != OK && ret != ITER_NO_MORE)
	    return ret;
    }

    sqlite3_reset(h->qm_delfile[ndb]);
    if(qbind_int64(h->qm_delfile[ndb], ":file", file_id) ||
       qstep_noret(h->qm_delfile[ndb]))
	ret = FAIL_EINTERNAL;
    else
	ret = OK;
    sqlite3_reset(h->qm_delfile[ndb]);
    return ret;
}

rc_ty sx_hashfs_getfilemeta_begin(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, unsigned int *created_at, sx_hash_t *etag) {
    rc_ty res, ret = FAIL_EINTERNAL;
    int metaget_ndb, r;
    int64_t file_id;

    if(!h)
	return EINVAL;

    res = get_file_id(h, volume, filename, revision, &file_id, &metaget_ndb, created_at, etag);
    if(res)
	return res;

    sqlite3_reset(h->qm_metaget[metaget_ndb]);
    if(qbind_int64(h->qm_metaget[metaget_ndb], ":file", file_id))
	return FAIL_EINTERNAL;

    h->nmeta = 0;
    while((r = qstep(h->qm_metaget[metaget_ndb])) == SQLITE_ROW) {
	const char *key = (const char *)sqlite3_column_text(h->qm_metaget[metaget_ndb], 0);
	const void *value = sqlite3_column_text(h->qm_metaget[metaget_ndb], 1);
	int value_len = sqlite3_column_bytes(h->qm_metaget[metaget_ndb], 1), key_len;
	if(!key)
	    goto getfilemeta_begin_err;
	key_len = strlen(key);
	if(key_len >= sizeof(h->meta[0].key))
	    goto getfilemeta_begin_err;
	if(!value || value_len > sizeof(h->meta[0].value))
	    goto getfilemeta_begin_err;
	memcpy(h->meta[h->nmeta].key, key, key_len+1);
	memcpy(h->meta[h->nmeta].value, value, value_len);
	h->meta[h->nmeta].value_len = value_len;
	h->nmeta++;
	if(h->nmeta >= SXLIMIT_META_MAX_ITEMS)
	    break;
    }

    if(r != SQLITE_DONE)
	goto getfilemeta_begin_err;

    ret = OK;

 getfilemeta_begin_err:
    sqlite3_reset(h->qm_metaget[metaget_ndb]);

    return ret;
}

rc_ty sx_hashfs_getfilemeta_next(sx_hashfs_t *h, const char **key, const void **value, unsigned int *value_len) {
    if(!h || !key || (value && !value_len)) {
	NULLARG();
	return EFAULT;
    }

    if(!h->nmeta || h->nmeta > SXLIMIT_META_MAX_ITEMS)
	return ITER_NO_MORE;

    h->nmeta--;
    *key = h->meta[h->nmeta].key;
    if(value) {
	*value = h->meta[h->nmeta].value;
	*value_len = h->meta[h->nmeta].value_len;
    }

    return OK;
}

rc_ty sx_hashfs_volumemeta_begin(sx_hashfs_t *h, const sx_hashfs_volume_t *volume) {
    rc_ty ret = FAIL_EINTERNAL;
    int r;

    if(!h || !volume) {
	NULLARG();
	return EFAULT;
    }

    sqlite3_reset(h->q_metaget);
    if(qbind_int64(h->q_metaget, ":volume", volume->id)) {
	sqlite3_reset(h->q_metaget);
	return FAIL_EINTERNAL;
    }

    h->nmeta = 0;
    while((r = qstep(h->q_metaget)) == SQLITE_ROW) {
	const char *key = (const char *)sqlite3_column_text(h->q_metaget, 0);
	const void *value = sqlite3_column_text(h->q_metaget, 1);
	int value_len = sqlite3_column_bytes(h->q_metaget, 1), key_len;
	if(!key || !value) {
	    OOM();
	    goto getvolumemeta_begin_err;
	}
	key_len = strlen(key);
	if(key_len >= sizeof(h->meta[0].key)) {
	    msg_set_reason("Key '%s' is too long: must be <%ld", key, sizeof(h->meta[0].key));
	    goto getvolumemeta_begin_err;
	}
	if(value_len > sizeof(h->meta[0].value)) {
	    /* Do not log the value, might contain sensitive data */
	    msg_set_reason("Value is too long: %d >= %ld", value_len, sizeof(h->meta[0].key));
	    goto getvolumemeta_begin_err;
	}
	memcpy(h->meta[h->nmeta].key, key, key_len+1);
	memcpy(h->meta[h->nmeta].value, value, value_len);
	h->meta[h->nmeta].value_len = value_len;
	h->nmeta++;
	if(h->nmeta >= SXLIMIT_META_MAX_ITEMS)
	    break;
    }

    if(r != SQLITE_DONE)
	goto getvolumemeta_begin_err;

    ret = OK;

 getvolumemeta_begin_err:
    sqlite3_reset(h->q_metaget);

    return ret;
}

rc_ty sx_hashfs_volumemeta_next(sx_hashfs_t *h, const char **key, const void **value, unsigned int *value_len) {
    return sx_hashfs_getfilemeta_next(h, key, value, value_len);
}

rc_ty sx_hashfs_get_user_info(sx_hashfs_t *h, const uint8_t *user, sx_uid_t *uid, uint8_t *key, sx_priv_t *basepriv) {
    const uint8_t *kcol;
    rc_ty ret = FAIL_EINTERNAL;
    sx_priv_t userpriv;
    int r;

    if(!h || !user)
	return EINVAL;

    sqlite3_reset(h->q_getuser);
    if(qbind_blob(h->q_getuser, ":user", user, AUTH_UID_LEN))
	goto get_user_info_err;

    r = qstep(h->q_getuser);
    if(r == SQLITE_DONE) {
	ret = ENOENT;
	goto get_user_info_err;
    }
    if(r != SQLITE_ROW)
	goto get_user_info_err;

    switch(sqlite3_column_int(h->q_getuser, 2)) {
    case ROLE_CLUSTER:
	userpriv = PRIV_CLUSTER;
	break;
    case ROLE_ADMIN:
	userpriv = PRIV_ADMIN;
	break;
    case ROLE_USER:
	userpriv = PRIV_NONE;
	break;
    default:
	WARN("Found invalid role");
	goto get_user_info_err;
    }
    if(basepriv)
	*basepriv = userpriv;

    kcol = (const uint8_t *)sqlite3_column_blob(h->q_getuser, 1);
    if(!kcol || sqlite3_column_bytes(h->q_getuser, 1) != AUTH_KEY_LEN) {
	WARN("Found bad key");
	goto get_user_info_err;
    }
    if(key)
	memcpy(key, kcol, AUTH_KEY_LEN);
    if(uid)
	*uid = sqlite3_column_int64(h->q_getuser, 0);
    ret = OK;

get_user_info_err:
    sqlite3_reset(h->q_getuser);
    return ret;
}


static rc_ty get_user_common(sx_hashfs_t *h, sx_uid_t uid, const char *name, uint8_t *user) {
    rc_ty ret = FAIL_EINTERNAL;
    sqlite3_stmt *q;
    int r;

    if(!h || !uid) {
	NULLARG();
	return EFAULT;
    }

    if(!name) {
	q = h->q_getuserbyid;
	sqlite3_reset(q);
	if(qbind_int64(q, ":uid", uid)) 
	    goto get_user_common_fail;
    } else {
	q = h->q_getuserbyname;
	sqlite3_reset(q);
	if(qbind_text(q, ":name", name)) 
	    goto get_user_common_fail;
    }

    r = qstep(q);
    if(r == SQLITE_ROW) {
	const void *sqlusr = sqlite3_column_blob(q, 0);
	if(sqlusr && sqlite3_column_bytes(q, 0) == AUTH_UID_LEN) {
	    if(user)
		memcpy(user, sqlusr, AUTH_UID_LEN);
	    ret = OK;
	}
    } else if(r == SQLITE_DONE)
	ret = ENOENT;

 get_user_common_fail:
    sqlite3_reset(q);
    return ret;
}


rc_ty sx_hashfs_get_user_by_uid(sx_hashfs_t *h, sx_uid_t uid, uint8_t *user) {
    return get_user_common(h, uid, NULL, user);
}

rc_ty sx_hashfs_get_user_by_name(sx_hashfs_t *h, const char *name, uint8_t *user) {
    return get_user_common(h, -1, name, user);
}
	      

rc_ty sx_hashfs_get_access(sx_hashfs_t *h, sx_uid_t uid, const char *volume, sx_priv_t *access) {
    const sx_hashfs_volume_t *vol;
    rc_ty ret;
    int r;

    if(!h || !volume || !access)
	return EINVAL;

    ret = sx_hashfs_volume_by_name(h, volume, &vol);
    if(ret)
	return ret;

    sqlite3_reset(h->q_getaccess);
    if(qbind_int64(h->q_getaccess, ":volume", vol->id) ||
       qbind_int64(h->q_getaccess, ":user", uid))
	return FAIL_EINTERNAL;

    r = qstep(h->q_getaccess);
    if(r == SQLITE_DONE) {
	*access = PRIV_NONE;
	return OK;
    }
    if(r != SQLITE_ROW)
	return FAIL_EINTERNAL;

    r = sqlite3_column_int(h->q_getaccess, 0);
    if(!(r & ~(PRIV_READ | PRIV_WRITE))) {
	ret = OK;
	*access = r;
    } else
	WARN("Found invalid priv for user %lld on volume %lld: %d", (long long int)uid, (long long int)vol->id, r);
    if (sqlite3_column_int(h->q_getaccess, 1) == uid)
	*access |= PRIV_OWNER;

    sqlite3_reset(h->q_getaccess);
    return ret;
}

sxi_db_t *sx_hashfs_eventdb(sx_hashfs_t *h) {
    return h->eventdb;
}

sxi_db_t *sx_hashfs_xferdb(sx_hashfs_t *h) {
    return h->xferdb;
}

sxc_client_t *sx_hashfs_client(sx_hashfs_t *h) {
    return h->sx;
}

sxi_conns_t *sx_hashfs_conns(sx_hashfs_t *h) {
    return h->sx_clust;
}


rc_ty sx_hashfs_job_result(sx_hashfs_t *h, job_t job, sx_uid_t uid, job_status_t *status, const char **message) {
    int r;

    if(!h || !status || !message) {
	NULLARG();
	return EFAULT;
    }

    sqlite3_reset(h->qe_getjob);

    if(qbind_int64(h->qe_getjob, ":id", job) ||
       qbind_int64(h->qe_getjob, ":owner", uid))
	return FAIL_EINTERNAL;

    r = qstep(h->qe_getjob);
    if(r == SQLITE_DONE)
	return ENOENT;

    if(r != SQLITE_ROW)
	return FAIL_EINTERNAL;

    if(!sqlite3_column_int(h->qe_getjob, 0)) {
	/* Pending job */
	*status = JOB_PENDING;
	*message = "Job status pending";
    } else {
	/* Completed */
	int result = sqlite3_column_int(h->qe_getjob, 1);
	if(result) {
	    /* Failed */
	    const char *reason = (const char *)sqlite3_column_text(h->qe_getjob, 2);
	    *status = JOB_ERROR;
	    if(!reason || !*reason)
		*message = "Unknown job failure";
	    else {
		strncpy(h->job_message, reason, sizeof(h->job_message));
		h->job_message[sizeof(h->job_message)-1] = '\0';
		*message = h->job_message;
	    }
	} else {
	    /* Succeded */
	    *status = JOB_OK;
	    *message = "Job completed succesfully";
	}
    }

    sqlite3_reset(h->qe_getjob);
    return OK;
}


static const char *locknames[] = {
    "VOL", /* JOBTYPE_CREATE_VOLUME */
    "USER", /* JOBTYPE_CREATE_USER */
    "ACL",
    "TOKEN", /* JOBTYPE_FLUSH_FILE */
    "DELFILE", /* JOBTYPE_DELETE_FILE */
    "*" /* JOBTYPE_DIST - MODHDIST: this must become a global lock */
};


#define MAX_PENDING_JOBS 128
rc_ty sx_hashfs_countjobs(sx_hashfs_t *h, sx_uid_t user_id) {
    rc_ty ret = FAIL_EINTERNAL;

    sqlite3_reset(h->qe_countjobs);
    if(qbind_int64(h->qe_countjobs, ":uid", user_id) ||
       qstep_ret(h->qe_countjobs)) 
	goto countjobs_out;
    if(sqlite3_column_int64(h->qe_countjobs, 0) > MAX_PENDING_JOBS) {
	ret = FAIL_ETOOMANY;
        DEBUG("too many jobs");
	goto countjobs_out;
    }
    ret = OK;

 countjobs_out:
    sqlite3_reset(h->qe_countjobs);
    return ret;
}

rc_ty sx_hashfs_job_new_notrigger(sx_hashfs_t *h, sx_uid_t user_id, job_t *job_id, jobtype_t type, unsigned int timeout_secs, const char *lock, const void *data, unsigned int datalen, const sx_nodelist_t *targets) {
    job_t id = JOB_FAILURE;
    char *lockstr = NULL;
    unsigned int i, ntargets;
    int r;
    rc_ty ret = FAIL_EINTERNAL, ret2;

    /* FIXME: add support for delayed jobs */
    if(!h || !job_id || (datalen && !data) || !targets) {
	msg_set_reason("Internal error: NULL argument given");
        return ret;
    }

    ntargets = sx_nodelist_count(targets);
    if(!ntargets) {
	msg_set_reason("Internal error: request with no targets");
	goto addjob_out;
    }

    if(!data)
	data = "";

    if (type < 0 || type >= sizeof(locknames) / sizeof(locknames[0])) {
	msg_set_reason("Internal error: bad action type");
	goto addjob_out;
    }
    if(lock) {
	if(!(lockstr = malloc(2 + strlen(locknames[type]) + strlen(lock) + 1))) {
	    msg_set_reason("Not enough memory to create job");
	    goto addjob_out;
	}
	sprintf(lockstr, "$%s$%s", locknames[type], lock);
    }

    ret2 = sx_hashfs_countjobs(h, user_id);
    if(ret2 != OK) {
	ret = ret2;
	goto addjob_out;
    }
    if(qbegin(h->eventdb)) {
	msg_set_reason("Internal error: failed to start database transaction");
	goto addjob_out;
    }

    /* Cap the minimum timeout to 2.5 * SXDBI_BUSY_TIMEOUT
       which lets a very simple job complete even if 50% of
       its queries are slow - by default this is 50 seconds */
    if (timeout_secs < (SXDBI_BUSY_TIMEOUT * 2 + SXDBI_BUSY_TIMEOUT / 2))
        timeout_secs = (SXDBI_BUSY_TIMEOUT * 2 + SXDBI_BUSY_TIMEOUT / 2);

    if(qbind_int(h->qe_addjob, ":type", type) ||
       qbind_int(h->qe_addjob, ":expiry", time(NULL) + timeout_secs) ||
       qbind_blob(h->qe_addjob, ":data", data, datalen)) {
	msg_set_reason("Internal error: failed to add job to database");
	goto addjob_rollback;
    }
    if(user_id == 0) {
	if(qbind_null(h->qe_addjob, ":uid"))
	    goto addjob_rollback;
    } else {
	if(qbind_int64(h->qe_addjob, ":uid", user_id))
	    goto addjob_rollback;
    }

    if(lockstr)
	r = qbind_text(h->qe_addjob, ":lock", lockstr);
    else
	r = qbind_null(h->qe_addjob, ":lock");
    if(r) {
	msg_set_reason("Internal error: failed to add job to database");
	goto addjob_rollback;
    }

    r = qstep(h->qe_addjob);
    if(r == SQLITE_CONSTRAINT) {
	msg_set_reason("Resource is temporarily locked");
	ret = FAIL_LOCKED;
	goto addjob_rollback;
    }
    if(r != SQLITE_DONE) {
	msg_set_reason("Internal error: failed to add job to database");
	goto addjob_rollback;
    }

    id = sqlite3_last_insert_rowid(sqlite3_db_handle(h->qe_addjob));

    if(qbind_int64(h->qe_addact, ":job", id)) {
	msg_set_reason("Internal error: failed to add job action to database");
	goto addjob_rollback;
    }
    for(i=0; i<ntargets; i++) {
	const sx_node_t *node = sx_nodelist_get(targets, i);
	const sx_uuid_t *uuid = sx_node_uuid(node);
	if(qbind_blob(h->qe_addact, ":node", uuid->binary, sizeof(uuid->binary)) ||
	   qbind_text(h->qe_addact, ":addr", sx_node_addr(node)) ||
	   qbind_text(h->qe_addact, ":int_addr", sx_node_internal_addr(node)) ||
	   qbind_int64(h->qe_addact, ":capa", sx_node_capacity(node)) ||
	   qstep_noret(h->qe_addact)) {
	    msg_set_reason("Internal error: failed to add job action to database");
	    goto addjob_rollback;
	}
    }

    if(!qcommit(h->eventdb)) {
	ret = OK;
	goto addjob_out;
    }
    msg_set_reason("Internal error: failed to commit new job to database");

 addjob_rollback:
    qrollback(h->eventdb);
    id = JOB_FAILURE;

 addjob_out:
    free(lockstr);
    sqlite3_reset(h->qe_addjob);
    sqlite3_reset(h->qe_addact);

    *job_id = id;
    return ret;
}

rc_ty sx_hashfs_job_new(sx_hashfs_t *h, sx_uid_t user_id, job_t *job_id, jobtype_t type, unsigned int timeout_secs, const char *lock, const void *data, unsigned int datalen, const sx_nodelist_t *targets) {
    rc_ty ret = sx_hashfs_job_new_notrigger(h, user_id, job_id, type, timeout_secs, lock, data, datalen, targets);

    if(ret == OK)
	sx_hashfs_job_trigger(h);

    return ret;
}


void sx_hashfs_job_trigger(sx_hashfs_t *h) {
    if(h && h->job_trigger >= 0) {
	int w = write(h->job_trigger, ".", 1);
	w = w;
    }
}

void sx_hashfs_xfer_trigger(sx_hashfs_t *h) {
    if(h && h->xfer_trigger >= 0) {
	int w = write(h->xfer_trigger, ".", 1);
	w = w;
    }
}

void sx_hashfs_gc_trigger(sx_hashfs_t *h) {
    if(h && h->gc_trigger >= 0) {
        INFO("triggered GC");
	int w = write(h->gc_trigger, ".", 1);
	w = w;
    }
}

rc_ty sx_hashfs_xfer_tonodes(sx_hashfs_t *h, sx_hash_t *block, unsigned int size, const sx_nodelist_t *targets) {
    const sx_node_t *self = sx_hashfs_self(h);
    unsigned int i, nnodes;
    rc_ty ret;

    if(!targets) {
	NULLARG();
	return EFAULT;
    }

    if(!self) {
	WARN("Called before initialization");
	return FAIL_EINIT;
    }
    if (sx_hashfs_block_get(h, size, block, NULL) != OK) {
        char hash[sizeof(sx_hash_t)*2+1];
        bin2hex(block->b, sizeof(block->b), hash, sizeof(hash));
        DEBUG("Asked to push a hash we don't have: #%s#", hash);
    }

    nnodes = sx_nodelist_count(targets);
    sqlite3_reset(h->qx_add);

    if(qbind_blob(h->qx_add, ":b", block, sizeof(*block))) {
	ret = FAIL_EINTERNAL;
	goto xfer_err;
    }

    for(i=0; i<nnodes; i++) {
	const sx_node_t *target = sx_nodelist_get(targets, i);
	const sx_uuid_t *target_uuid;
	int r;

	if(!sx_node_cmp(target, self))
	    continue;

	target_uuid = sx_node_uuid(target);
	if(qbind_int(h->qx_add, ":s", size) ||
	   qbind_blob(h->qx_add, ":n", target_uuid->binary, sizeof(target_uuid->binary))) {
	    break;
	}
	r = qstep(h->qx_add);
	if(r != SQLITE_DONE && r != SQLITE_CONSTRAINT)
	    break;

	sqlite3_reset(h->qx_add);
    }

    ret = (i == nnodes) ? OK : FAIL_EINTERNAL;
    DEBUG("xfer_to_nodes job added: %s", ret == OK ? "OK" : "Error");

 xfer_err:
    sqlite3_reset(h->qx_add);

    if(ret != OK)
	msg_set_reason("Internal error: failed to add block transfer request to database");

    return ret;
}

static sxi_db_t *open_gcdb(sx_hashfs_t *h)
{
    sxi_db_t *db = NULL;
    sqlite3_stmt *q = NULL;
    const char *str;
    char *path = "";
    unsigned int pathlen=0, dirlen=0;
    OPEN_DB("gcdb", &db);
    if(qprep(db, &q, "PRAGMA locking_mode=EXCLUSIVE") || qstep_ret(q))
        goto open_hashfs_fail;
    qnullify(q);
    if(qprep(db, &q, "PRAGMA temp_store=MEMORY") || qstep_noret(q))
        goto open_hashfs_fail;
    qnullify(q);
    return db;

open_hashfs_fail:
    qnullify(q);
    qclose(&db);
    return NULL;
}

#define GC_ROW_LIMIT 10000

static rc_ty sx_hashfs_gc_merge(sx_hashfs_t *h, sxi_db_t *db, int *terminate)
{
    sqlite3_stmt *q = NULL, *q_iter = NULL, *q_queue_del = NULL, *q_del_gc = NULL, *q_truncate_tmp = NULL;
    sqlite3_stmt *q_insert = NULL, *q_get_maxidx = NULL, *q_update_maxidx = NULL;
    rc_ty ret = FAIL_EINTERNAL;
    do {
        int r;
        if (qprep(h->db, &q, "CREATE TEMP TABLE IF NOT EXISTS tmp_hashfs_delete(key TEXT NOT NULL)") || qstep_noret(q))
            break;
        qnullify(q);
        if(qprep(h->db, &q_truncate_tmp, "DELETE FROM tmp_hashfs_delete") ||
           qprep(h->db, &q_iter, "SELECT key, value FROM hashfs WHERE key >= 'gcp' AND KEY < 'gcq' ") ||
           qprep(h->db, &q_queue_del, "INSERT INTO tmp_hashfs_delete(key) VALUES(:key)") ||
           qprep(h->db, &q_del_gc, "DELETE FROM hashfs WHERE key IN (SELECT key FROM tmp_hashfs_delete)") ||
           qprep(db, &q_insert, "INSERT OR IGNORE INTO tmpmoduse(groupid, hash, hs, op, applied_expires_at) VALUES(:groupid, :hash, :hs, :op, NULL)") ||
           qprep(db, &q_get_maxidx, "SELECT maxidx FROM tmpmoduse_maxidx WHERE name=:key") ||
           qprep(db, &q_update_maxidx, "INSERT OR REPLACE INTO tmpmoduse_maxidx(name, maxidx) VALUES(:key,:maxidx)")
          )
            break;
        sqlite3_reset(q_iter);
        while((r = qstep(q_iter)) == SQLITE_ROW && !*terminate) {
            sxi_db_t *dbsource = NULL;
            const char *key = (const char *)sqlite3_column_text(q_iter, 0);
            const char *path = (const char*)sqlite3_column_text(q_iter, 1);
            int64_t previdx = -1;
            int has_rows = 1;

            sqlite3_reset(q_get_maxidx);
            if(qbind_text(q_get_maxidx, ":key", key) ||
               qbind_text(q_update_maxidx, ":key", key))
                break;
            int r2 = qstep(q_get_maxidx);
            if (r2 == SQLITE_ROW)
                previdx = sqlite3_column_int64(q_get_maxidx, 0);
            sqlite3_reset(q_get_maxidx);

            INFO("Trying to open '%s'", path);
            if (access(path, R_OK|W_OK)) {
                sqlite3_reset(q_queue_del);
                if (!qbind_text(q_queue_del, ":key", key))
                    qstep_noret(q_queue_del);
                continue;
            }
            if (qopen(path, &dbsource, NULL, &h->cluster_uuid))
                continue;
            ret = FAIL_EINTERNAL;
            if(qprep(dbsource, &q, "SELECT groupid, hash, hs, op, idx FROM moduse WHERE idx > :previdx ORDER BY idx ASC LIMIT "STRIFY(GC_ROW_LIMIT)) ||
               qbind_int64(q, ":previdx", previdx))
                has_rows = 0;
            while(has_rows) {
                int64_t maxidx = previdx;
                has_rows = 0;
                if (qbegin(db))
                    break;
                INFO("Processing '%s'", path);
                while((r2 = qstep(q)) == SQLITE_ROW && !*terminate) {
                    has_rows = 1;
                    sqlite3_reset(q_insert);
                    if (qbind_blob(q_insert, ":groupid", sqlite3_column_blob(q, 0), sqlite3_column_bytes(q, 0)) ||
                        qbind_blob(q_insert, ":hash", sqlite3_column_blob(q, 1), sqlite3_column_bytes(q, 1)) ||
                        qbind_int(q_insert, ":hs", sqlite3_column_int(q, 2)) ||
                        qbind_int(q_insert, ":op", sqlite3_column_int(q, 3)) ||
                        qstep_noret(q_insert))
                        break;
                    maxidx = sqlite3_column_int(q, 4);
                }
                if (r2 != SQLITE_DONE)
                    break;
                INFO("Added %d entries", sqlite3_changes(db->handle));
                qnullify(q);
                sqlite3_reset(q_update_maxidx);
                if (qbind_int64(q_update_maxidx, ":maxidx", maxidx) ||
                    qstep_noret(q_update_maxidx))
                    break;
                sqlite3_reset(q_update_maxidx);
                if (qcommit(db))
                    break;
                ret = OK;
            };
            qnullify(q);
            if (ret != OK)
                qrollback(db);
            qclose(&dbsource);
            if (ret != OK)
                continue;
            int lockfd = lock_file(path, 1);
            if (lockfd <= 0)
                continue;/* it is still in use */
            close(lockfd);
            /* it is not longer inuse, we can delete */
            /* cannot DELETE here, because the SELECT on hashfs is still active,
             * have to queue up the deletes in a temp table, and apply it all
             * when the iteration is finished */
            sqlite3_reset(q_queue_del);
            if(qbind_text(q_queue_del, ":key", key) || qstep_noret(q_queue_del))
                break;
            if (unlink(path))
                PWARN("Cannot unlink '%s'", path);
        }
        if (r != SQLITE_DONE)
            break;
        ret = OK;
    } while(0);
    qnullify(q);
    qnullify(q_iter);
    qnullify(q_queue_del);
    qnullify(q_insert);
    qnullify(q_get_maxidx);
    qnullify(q_update_maxidx);
    if (qbegin(h->db)) {
        ret = FAIL_EINTERNAL;
    } else if (qstep_noret(q_del_gc) ||
        qcommit(h->db)) {
        qrollback(h->db);
        ret = FAIL_EINTERNAL;
    }
    qnullify(q_del_gc);
    if(q_truncate_tmp && qstep_noret(q_truncate_tmp))
        ret = FAIL_EINTERNAL;
    qnullify(q_truncate_tmp);
    return ret;
}

static rc_ty sx_hashfs_gc_apply(sx_hashfs_t *h, sxi_db_t *db, int *terminate)
{
    DEBUG("in gc_apply");
    int has_begun, has_rows = 1;
    rc_ty ret = FAIL_EINTERNAL;
    sqlite3_stmt *q = NULL, *q_delreservation = NULL, *q_add_counters = NULL,
                 *q_update_counters = NULL, *q_reserve = NULL,
                 *q_apply_delres = NULL, *q_get = NULL, *q_apply = NULL,
                 *q_del_tmp = NULL;
    if(qprep(db, &q, "SELECT groupid, hash, hs, op FROM tmpmoduse WHERE applied_expires_at IS NULL LIMIT " STRIFY(GC_ROW_LIMIT)) ||
       qprep(db, &q_delreservation, "INSERT OR IGNORE INTO tmpdelreserves(groupid) VALUES(:groupid)") ||
       qprep(db, &q_add_counters, "INSERT OR IGNORE INTO counters(hash, hs, reserved, used, ver) VALUES(:hash, :hs, :reserved, :used, :ver)") ||
       qprep(db, &q_update_counters, "UPDATE counters SET used = used + :operation, reserved = reserved + :reserved, ver = :ver WHERE hash = :hash") ||
       qprep(db, &q_reserve, "INSERT INTO reserved(groupid, hash, hs) VALUES(:groupid, :hash, :hs)") ||
       qprep(db, &q_apply_delres, "DELETE FROM reserved WHERE groupid IN (SELECT groupid FROM tmpdelreserves)") ||
       /* TODO: when deleting from reserverations update the counters again!
        * */
       qprep(db, &q_get, "SELECT reserved, used FROM counters WHERE hash = :hash") ||
       qprep(db, &q_apply, "UPDATE tmpmoduse SET applied_expires_at=:expiry WHERE applied_expires_at IS NULL AND groupid=:groupid AND hash=:hash AND op=:op") ||
       qprep(db, &q_del_tmp, "DELETE FROM tmpmoduse WHERE applied_expires_at <= :now")
      )
        has_rows = 0;
    while (has_rows) {
        int r;
        uint64_t now = time(NULL);
        uint64_t expiry = now + JOB_FILE_MAX_TIME;
        has_begun = has_rows = 0;
        ret = FAIL_EINTERNAL;
        if (qbegin(db))
            break;
        has_begun = 1;
        if (qbind_int64(q_apply,":expiry",expiry))
            break;
        while ((r = qstep(q)) == SQLITE_ROW && !*terminate) {
            has_rows = 1;
            const sx_hash_t *group = sqlite3_column_blob(q, 0);
            const sx_hash_t *hash = sqlite3_column_blob(q, 1);
            unsigned hs = sqlite3_column_int(q, 2);
            int op = sqlite3_column_int(q, 3);
            if (!group || !hash || sqlite3_column_bytes(q, 0) != sizeof(*group) ||
                sqlite3_column_bytes(q, 1) != sizeof(*hash)) {
                WARN("bad select results (q)");
                break;
            }
            int reserved_op = op > 0 ? -1 : op == 0 ? 1 : 0;
            if(qbind_blob(q_update_counters, ":hash", hash, sizeof(*hash)) ||
               qbind_int(q_update_counters, ":operation", op) ||
               qbind_int(q_update_counters, ":reserved", reserved_op) ||
               qbind_int(q_update_counters, ":ver", h->gcver) ||
               qstep_noret(q_update_counters))
                break;
            if (qbind_blob(q_add_counters, ":hash", hash, sizeof(*hash)) ||
                qbind_int(q_add_counters, ":reserved", reserved_op) ||
                qbind_int(q_add_counters, ":used", op) ||
                qbind_int(q_add_counters, ":hs", hs) ||
                qbind_int(q_add_counters, ":ver", h->gcver) ||
                qstep_noret(q_add_counters))
                break;
            if (op) {
                DEBUG("op: %d", op);
                DEBUGHASH("Operation on hash", hash);
                DEBUGHASH("Groupid is", group);
                /* a delete, or an inuse: remove all reservations for this id */
                if (qbind_blob(q_delreservation, ":groupid", group, sizeof(*group)) || qstep_noret(q_delreservation))
                    break;
            } else {
                /* a reserve */
                if (qbind_blob(q_reserve, ":groupid", group, sizeof(*group)) ||
                    qbind_blob(q_reserve, ":hash", hash, sizeof(*hash)) ||
                    qbind_int(q_reserve, ":hs", hs) ||
                    qstep_noret(q_reserve)
                   )
                    break;
                DEBUGHASH("Reserved hash", hash);
                DEBUGHASH("Groupid is", group);
            }
            if (UNLIKELY(sxi_log_is_debug(&logger))) {
                sqlite3_reset(q_get);
                if(!qbind_blob(q_get, ":hash", hash, sizeof(*hash)) &&
                   !qstep_ret(q_get)) {
                    DEBUGHASH("Hash updated", hash);
                    DEBUG("reserved: %d, used: %d", sqlite3_column_int(q_get, 0), sqlite3_column_int(q_get, 1));
                }
            }
            sqlite3_reset(q_apply);
            if (qbind_blob(q_apply, ":groupid", group, sizeof(*group)) ||
                qbind_blob(q_apply, ":hash", hash, sizeof(*hash)) ||
                qbind_int(q_apply, ":op", op) ||
                qstep_noret(q_apply))
                break;
        }
        if (r != SQLITE_DONE)
            break;
        if (qstep_noret(q_apply_delres))
            break;
        if (qbind_int64(q_del_tmp,":now", now) || qstep_noret(q_del_tmp))
            break;
        if (qcommit(db))
            break;
        ret = OK;
    }
    qnullify(q);
    qnullify(q_delreservation);
    qnullify(q_add_counters);
    qnullify(q_update_counters);
    qnullify(q_reserve);
    qnullify(q_apply_delres);
    qnullify(q_get);
    qnullify(q_apply);
    qnullify(q_del_tmp);
    if (has_begun && ret)
        qrollback(db);
    if (ret)
        WARN("gc_apply failed");
    return ret;
}

static rc_ty sx_hashfs_gc_track(sx_hashfs_t *h, sxi_db_t *db, int *terminate)
{
    DEBUG("in gc_track");
    int has_rows = 1;
    int has_begun;
    rc_ty ret = FAIL_EINTERNAL;
    sqlite3_stmt *q_res_groups = NULL,
                 *q_res_hashes = NULL, *q_get_activity = NULL,
                 *q_set_activity = NULL, *q_expired_reservations = NULL,
                 *q_update_counters = NULL,
                 *q_del1 = NULL, *q_del2 = NULL;
    if (qprep(db, &q_res_groups, "SELECT DISTINCT(groupid) FROM reserved LIMIT " STRIFY(GC_ROW_LIMIT)) ||
        qprep(db, &q_res_hashes, "SELECT hash, hs FROM reserved WHERE groupid = :groupid") ||
        qprep(db, &q_get_activity, "SELECT last_changed_at, pending, total FROM activity WHERE groupid = :groupid") ||
        qprep(db, &q_set_activity, "INSERT OR REPLACE INTO activity(groupid, last_changed_at, pending, total) VALUES(:groupid, :last_changed_at, :pending, :total)") ||
        qprep(db, &q_expired_reservations, "SELECT hash FROM reserved AS a INNER JOIN activity AS b ON a.groupid = b.groupid WHERE b.last_changed_at < :expires LIMIT "STRIFY(GC_ROW_LIMIT)) ||
        qprep(db, &q_update_counters, "UPDATE counters SET reserved = MAX(0, reserved  - 1) WHERE hash = :hash") ||
        qprep(db, &q_del1, "DELETE FROM reserved WHERE groupid IN (SELECT groupid FROM activity WHERE last_changed_at < :expires)") ||
        qprep(db, &q_del2, "DELETE FROM activity WHERE last_changed_at < :expires")
       )
        has_rows = 0;
    while (has_rows) {
        int r;
        int64_t expires = time(NULL) - JOB_FILE_MAX_TIME;/* last_changed_at + JOB_FILE_MAX_TIME <= now */
        has_begun = has_rows = 0;
        ret = FAIL_EINTERNAL;
        if (qbegin(db))
            break;
        has_begun = 1;
        /* track token activity */
        while ((r = qstep(q_res_groups)) == SQLITE_ROW && !*terminate) {
            int r2;
            has_rows = 1;
            unsigned pending = 0, total = 0, prev_pending = 0, prev_total = 0, last_changed_at = 0;
            const sx_hash_t *group = sqlite3_column_blob(q_res_groups, 0);
            if (!group || sqlite3_column_bytes(q_res_groups, 0) != sizeof(*group) ||
                qbind_blob(q_res_hashes, ":groupid", group, sizeof(*group)))
                break;
            while ((r2 = qstep(q_res_hashes)) == SQLITE_ROW) {
                int r3;
                const sx_hash_t *hash = sqlite3_column_blob(q_res_hashes, 0);
                unsigned hs = sqlite3_column_int(q_res_hashes, 1);
                unsigned ndb;
                if (!hash || sqlite3_column_bytes(q_res_hashes, 0) != sizeof(*hash) ||
                    hs >= HASHDBS)
                    break;
                ndb = gethashdb(hash);
                sqlite3_reset(h->qb_get[hs][ndb]);
                r3 = qstep(h->qb_get[hs][ndb]);
                sqlite3_reset(h->qb_get[hs][ndb]);
                if (r3 == SQLITE_DONE)
                    pending++;
                else if (r3 != SQLITE_ROW)
                    break;
                total++;
            }
            if (r2 != SQLITE_DONE)
                break;
            DEBUGHASH("groupid", group);
            sqlite3_reset(q_get_activity);
            if(qbind_blob(q_get_activity, ":groupid", group, sizeof(*group)))
                break;
            r2 = qstep(q_get_activity);
            if (r2 == SQLITE_ROW) {
                last_changed_at = sqlite3_column_int(q_get_activity, 0);
                prev_pending = sqlite3_column_int(q_get_activity, 1);
                prev_total = sqlite3_column_int(q_get_activity, 2);
            }
            sqlite3_reset(q_get_activity);
            if (r2 == SQLITE_DONE || (prev_pending != pending || prev_total != total)) {
                last_changed_at = time(NULL);
                DEBUG("r2_done: %d, prev_pending: %d, prev_total: %d", r2 == SQLITE_DONE,
                      prev_pending, prev_total);
                DEBUG("pending: %d, total: %d, last_changed_at: %d", pending, total, last_changed_at);
                if (qbind_blob(q_set_activity, ":groupid", group, sizeof(*group)) ||
                    qbind_int(q_set_activity, ":last_changed_at", last_changed_at) ||
                    qbind_int(q_set_activity, ":pending", pending) ||
                    qbind_int(q_set_activity, ":total", total) ||
                    qstep_noret(q_set_activity))
                    break;
            }
        }
        if (r != SQLITE_DONE)
            break;
        if (qbind_int64(q_expired_reservations, ":expires", expires) ||
            qbind_int64(q_del1, ":expires", expires) ||
            qbind_int64(q_del2, ":expires", expires))
            break;
        while ((r = qstep(q_expired_reservations)) == SQLITE_ROW && !*terminate) {
            has_rows = 1;
            const sx_hash_t *hash = sqlite3_column_blob(q_expired_reservations, 0);
            if (!hash || sqlite3_column_bytes(q_expired_reservations, 0) != sizeof(*hash)) {
                WARN("bad select results (expired)");
                break;
            }
            DEBUGHASH("Reservation expired for", hash);
            sqlite3_reset(q_update_counters);
            if (qbind_blob(q_update_counters, ":hash", hash, sizeof(*hash)) ||
                qstep_noret(q_update_counters))
                break;
        }
        if (r != SQLITE_DONE)
            break;
        if (qcommit(db))
            break;
        ret = OK;
    };
    if (qstep_noret(q_del1) || qstep_noret(q_del2))
        ret = FAIL_EINTERNAL;
    qnullify(q_res_groups);
    qnullify(q_res_hashes);
    qnullify(q_get_activity);
    qnullify(q_set_activity);
    qnullify(q_expired_reservations);
    qnullify(q_del1);
    qnullify(q_del2);
    qnullify(q_update_counters);
    if (has_begun && ret)
        qrollback(db);
    if (ret)
        WARN("gc_track failed");
    DEBUG("gc_track returning %d", ret);
    return ret;
}

static rc_ty print_count(sxi_db_t *db, const char *table)
{
    char query[128];
    sqlite3_stmt *q = NULL;
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM %s", table);
    if (qprep(db, &q, query) || qstep_ret(q)) {
        WARN("print_count failed");
        return FAIL_EINTERNAL;
    }
    INFO("Table %s has %d entries", table, sqlite3_column_int(q, 0));
    qnullify(q);
    return OK;
}

static rc_ty sx_hashfs_gc_info(sx_hashfs_t *h, sxi_db_t *db)
{
    DEBUG("in gc_info");
    if (print_count(db, "reserved") ||
        print_count(db, "activity") ||
        print_count(db, "tmpmoduse")
       )
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sx_hashfs_gc_periodic(sx_hashfs_t *h, int *terminate)
{
    struct timeval tv0, tv1, tv2;
    rc_ty ret = FAIL_EINTERNAL;
    sqlite3_stmt *q = NULL;
    sxi_db_t *db = open_gcdb(h);
    if (!db)
        return FAIL_EINTERNAL;
    /* don't have a per-process gcdb open in the gc itself, it'll just fail with
     * BUSY */
    gcdb_close(h);
    if (!h->gcver) {
        int rc;
        if (qprep(db, &q, "SELECT max(ver) FROM counters")) {
            WARN("failed to prepare gcver query");
            return FAIL_EINTERNAL;
        }
        rc = qstep(q);
        if (rc == SQLITE_ROW)
            h->gcver = sqlite3_column_int(q, 0);
        qnullify(q);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            WARN("failed to query gcver");
            return FAIL_EINTERNAL;
        }
    }
    do {
        if(qprep(db, &q, "CREATE TEMP TABLE IF NOT EXISTS tmpdelreserves(groupid BLOB(20) NOT NULL PRIMARY KEY)") || qstep_noret(q))
            break;
        qnullify(q);
        gettimeofday(&tv0, NULL);
        do {
            if (sx_hashfs_gc_merge(h, db, terminate)) {
                WARN("gc_merge failed");
                break;
            }
            if (*terminate) {
                INFO("terminate");
                break;
            }
            h->gcver++;
            gettimeofday(&tv1, NULL);
            INFO("Merged GC tables into temp table %.3f sec", timediff(&tv0, &tv1));
            if (sx_hashfs_gc_apply(h, db, terminate) ||
                sx_hashfs_gc_track(h, db, terminate) ||
                *terminate ||
                sx_hashfs_gc_info(h, db)) {
                WARN("failed to apply/track/info");
                h->gcver--;
                break;
            }
            gettimeofday(&tv2, NULL);
            INFO("Updated GC counters and token activity in %.3f sec", timediff(&tv1, &tv2));
            ret = OK;
        } while(0);
        if (qprep(db, &q, "DROP TABLE tmpdelreserves") || qstep_noret(q)) {
            WARN("failed to drop temp table");
            ret = FAIL_EINTERNAL;
            break;
        }
        qnullify(q);
    } while(0);
    qnullify(q);
    qclose(&db);
    if (ret)
        WARN("periodic failed");
    return ret;
}

rc_ty sx_hashfs_gc_run(sx_hashfs_t *h, int *terminate)
{
    rc_ty ret = FAIL_EINTERNAL;
    sqlite3_stmt *q = NULL, *q_used0 = NULL,
                 *q_apply_del = NULL;
    sxi_db_t *db = open_gcdb(h);
    unsigned n = 0;
    if (!db)
        return FAIL_EINTERNAL;
    int has_begun = 0;
    do {
        int r;
        /* GC only hashes that didn't have the counters changed in last periodic
         * iteration to avoid race conditions */
        if (qprep(db, &q_used0, "SELECT hash, hs FROM counters WHERE used=0 AND reserved=0 AND ver < :ver") ||
            qprep(db, &q_apply_del, "DELETE FROM counters WHERE used=0 AND reserved=0 AND ver < :ver") ||
            qbind_int(q_used0, ":ver", h->gcver) ||
            qbind_int(q_apply_del, ":ver", h->gcver))
            break;
        if(qbegin(db))
            break;
        has_begun = 1;
        while((r = qstep(q_used0)) == SQLITE_ROW && !*terminate) {
            const sx_hash_t *hash = sqlite3_column_blob(q_used0, 0);
            unsigned hs = sqlite3_column_int(q_used0, 1);
            unsigned ndb;
            uint64_t blockno = ~0;
            if (!hash || hs > HASHDBS || sqlite3_column_bytes(q_used0, 0) != sizeof(*hash)) {
                WARN("bad select results (used0)");
                break;
            }
            DEBUGHASH("Checking hash", hash);
            /* not reserved, and used=0: we can GC */
            ndb = gethashdb(hash);
            sqlite3_reset(h->qb_get[hs][ndb]);
            if (qbind_blob(h->qb_get[hs][ndb], ":hash", hash, sizeof(*hash)))
                break;
            r = qstep(h->qb_get[hs][ndb]);
            if (r == SQLITE_ROW)
                blockno = sqlite3_column_int64(h->qb_get[hs][ndb], 0);
            sqlite3_reset(h->qb_get[hs][ndb]);
            if (r == SQLITE_ROW) {
                if (qbegin(h->datadb[hs][ndb]))
                    break;
                sqlite3_reset(h->qb_setfree[hs][ndb]);
                sqlite3_reset(h->qb_gc1[hs][ndb]);
                if(qbind_int64(h->qb_setfree[hs][ndb], ":blockno", blockno) ||
                   qstep_noret(h->qb_setfree[hs][ndb]) ||
                   qbind_blob(h->qb_gc1[hs][ndb], ":hash", hash, sizeof(*hash)) ||
                   qstep_noret(h->qb_gc1[hs][ndb]) ||
                   qcommit(h->datadb[hs][ndb])) {
                    qrollback(h->datadb[hs][ndb]);
                    break;
                }
                DEBUGHASH("GCed hash", hash);
                n++;
            }
        }
        if (r != SQLITE_DONE)
            break;
        if(qstep_noret(q_apply_del))
            break;
        if (qcommit(db))
            break;
        INFO("GC freed %d hashes", n);
        ret = OK;
    } while(0);
    if (has_begun && ret)
        qrollback(db);
    qnullify(q);
    qnullify(q_used0);
    qnullify(q_apply_del);
    qclose(&db);
    if (!ret) {
        sqlite3_reset(h->qt_gc_tokens);
        if (qbind_int64(h->qt_gc_tokens, ":now",time(NULL)) ||
            qstep_noret(h->qt_gc_tokens))
            return FAIL_EINTERNAL;
        INFO("Deleted %d tokens", sqlite3_changes(h->tempdb->handle));
    }
    return ret;
}

static rc_ty get_min_reqs(sx_hashfs_t *h, unsigned int *min_nodes, int64_t *min_capa) {
    sqlite3_stmt *q = NULL;

    if(qprep(h->db, &q, "SELECT COALESCE(MAX(replica), 1), COALESCE(SUM(maxsize*replica), 0) FROM volumes") ||
       qstep_ret(q)) {
	qnullify(q);
	return FAIL_EINTERNAL;
    }

    if(min_nodes)
	*min_nodes = sqlite3_column_int(q, 0);
    if(min_capa)
	*min_capa = sqlite3_column_int64(q, 1);

    qnullify(q);
    return OK;
}

rc_ty sx_hashfs_hdist_change_req(sx_hashfs_t *h, const sx_nodelist_t *newdist, job_t *job_id) {
    sxi_hdist_t *newmod;
    unsigned int nnodes, minnodes, i, cfg_len;
    int64_t newclustersize = 0, minclustersize;
    sx_nodelist_t *targets;
    const void *cfg;
    rc_ty r;

    if(!h || !newdist || !job_id) {
	NULLARG();
	return EFAULT;
    }

    if(!h->have_hd) {
	WARN("Called before initialization");
	return FAIL_EINIT;
    }

    if(h->is_rebalancing) {
	msg_set_reason("The cluster is still being rebalanced");
	return EINVAL;
    }

    /* REBALANCED HACK BEGIN */
    do {
	const sx_hashfs_volume_t *vol;
	if(sx_hashfs_volume_first(h, &vol, 0) != ITER_NO_MORE) {
	    msg_set_reason("The cluster cannot be modified because it contains data. *** NOTE: SUCH LIMITATION IS ONLY PRESENT IN THIS BETA AND WILL BE REMOVED IN THE FINAL RELEASE. WE ARE SORRY FOR THE INCOVENIENCE ***");
	    return EINVAL;
	}
    } while(0);
    /* REBALANCED HACK ENDS */

    r = get_min_reqs(h, &minnodes, &minclustersize);
    if(r) {
	msg_set_reason("Failed to compute cluster requirements");
	return r;
    }

    nnodes = sx_nodelist_count(newdist);
    if(nnodes < minnodes) {
	msg_set_reason("Invalid distribution: this cluster requires at least %u nodes to operate.", minnodes);
	return EINVAL;
    }

    if((r = sxi_hdist_get_cfg(h->hd, &cfg, &cfg_len)) != OK) {
	msg_set_reason("Failed to duplicate current distribution (get)");
	return r;
    }

    if(!(newmod = sxi_hdist_from_cfg(cfg, cfg_len))) {
	msg_set_reason("Failed to duplicate current distribution (from_cfg)");
	return EINVAL;
    }

    if((r = sxi_hdist_newbuild(newmod))) {
	sxi_hdist_free(newmod);
	msg_set_reason("Failed to update current distribution");
	return r;
    }

    for(i=0; i<nnodes; i++) {
	const sx_node_t *n = sx_nodelist_get(newdist, i);
	unsigned int j;
	for(j=i+1; j<nnodes; j++) {
	    const sx_node_t *other = sx_nodelist_get(newdist, j);
	    if(!sx_node_cmp(n, other)) {
		sxi_hdist_free(newmod);
		msg_set_reason("Node %s cannot appear more than once", sx_node_uuid_str(n));
		return EINVAL;
	    }
	}
	newclustersize += sx_node_capacity(n);
	r = sxi_hdist_addnode(newmod, sx_node_uuid(n), sx_node_addr(n), sx_node_internal_addr(n), sx_node_capacity(n));
	if(r) {
	    sxi_hdist_free(newmod);
	    msg_set_reason("Failed to update current distribution");
	    return FAIL_EINTERNAL;
	}
    }

    if(newclustersize < minclustersize) {
	sxi_hdist_free(newmod);
	msg_set_reason("Invalid distribution: this cluster requires a total capacity of at least %lld bytes to operate.", (long long)minclustersize);
	return EINVAL;
    }

    if((r = sxi_hdist_build(newmod)) != OK) {
	sxi_hdist_free(newmod);
	msg_set_reason("Failed to build updated distribution");
	return r;
    }

    if((r = sxi_hdist_get_cfg(newmod, &cfg, &cfg_len)) != OK) {
	sxi_hdist_free(newmod);
	msg_set_reason("Failed to retrieve updated distribution");
	return r;
    }

    targets = sx_nodelist_new();
    if(!targets) {
	sxi_hdist_free(newmod);
	msg_set_reason("Failed to setup job targets");
	return ENOMEM;
    }

    if((r = sx_nodelist_addlist(targets, sxi_hdist_nodelist(newmod, 1))) ||
       (r = sx_nodelist_addlist(targets, sxi_hdist_nodelist(newmod, 0)))) {
	sx_nodelist_delete(targets);
	sxi_hdist_free(newmod);
	msg_set_reason("Failed to setup job targets");
	return r;
    }

    r = sx_hashfs_job_new(h, 0, job_id, JOBTYPE_DISTRIBUTION, sx_nodelist_count(targets) * 20, "MODHDIST: this should lock everything!", cfg, cfg_len, targets);
    sx_nodelist_delete(targets);
    sxi_hdist_free(newmod);

    return r;
}

rc_ty sx_hashfs_hdist_change_add(sx_hashfs_t *h, const void *cfg, unsigned int cfg_len) {
    int64_t newclustersize = 0, minclustersize;
    unsigned int nnodes, minnodes, i;
    sxi_hdist_t *newmod;
    const sx_nodelist_t *nodes;
    sqlite3_stmt *q = NULL;
    rc_ty ret;

    if(!h || !cfg) {
	NULLARG();
	return EINVAL;
    }

    if(h->is_rebalancing) {
	msg_set_reason("The cluster is still being rebalanced");
	return EEXIST;
    }	

    newmod = sxi_hdist_from_cfg(cfg, cfg_len);
    if(!newmod) {
	msg_set_reason("Failed to load the new distribution");
	return EINVAL;
    }

    if(sxi_hdist_buildcnt(newmod) != 2 ||
       (h->have_hd && (!sxi_hdist_same_origin(newmod, h->hd) || sxi_hdist_version(newmod) != sxi_hdist_version(h->hd) + 1))) {
	sxi_hdist_free(newmod);
	msg_set_reason("The new model is not a direct descendent of the current model");
	return EINVAL;
    }

    /* REBALANCED HACK BEGIN */
    if(sxi_hdist_rebalanced(newmod)) {
	msg_set_reason("Failed to flat the distribution");
	sxi_hdist_free(newmod);
	return EINVAL;
    }
    if(sxi_hdist_get_cfg(newmod, &cfg, &cfg_len)) {
	msg_set_reason("Failed to read flat config");
	sxi_hdist_free(newmod);
	return EINVAL;
    }
    /* REBALANCED HACK END */

    if(qbegin(h->db)) {
	sxi_hdist_free(newmod);
	return FAIL_EINTERNAL;
    }

    ret = get_min_reqs(h, &minnodes, &minclustersize);
    if(ret) {
	msg_set_reason("Failed to compute cluster requirements");
	goto change_add_fail;
    }

    nodes = sxi_hdist_nodelist(newmod, 0);
    if(!nodes || !(nnodes = sx_nodelist_count(nodes))) {
	msg_set_reason("Failed to retrieve the list of the updated nodes");
	ret = FAIL_EINTERNAL;
	goto change_add_fail;
    }

    if(nnodes < minnodes) {
	msg_set_reason("Invalid distribution: this cluster requires at least %u nodes to operate.", minnodes);
	ret = EINVAL;
	goto change_add_fail;
    }

    for(i = 0; i<nnodes; i++) {
	const sx_node_t *n = sx_nodelist_get(nodes, i);
	unsigned int j;
	for(j=i+1; j<nnodes; j++) {
	    const sx_node_t *other = sx_nodelist_get(nodes, j);
	    if(!sx_node_cmp(n, other)) {
		msg_set_reason("Node %s cannot appear more than once", sx_node_uuid_str(n));
		ret = EINVAL;
		goto change_add_fail;
	    }
	}
	newclustersize += sx_node_capacity(n);
    }

    if(newclustersize < minclustersize) {
	msg_set_reason("Invalid distribution: this cluster requires a total capacity of at least %lld bytes to operate.", (long long)minclustersize);
	ret = EINVAL;
	goto change_add_fail;
    }

    if(qprep(h->db, &q, "INSERT OR REPLACE INTO hashfs (key, value) VALUES (:k , :v)")) {
	msg_set_reason("Failed to save the updated distribution model");
	ret = FAIL_EINTERNAL;
	goto change_add_fail;
    }

    if(h->have_hd) {
	const void *cur_cfg;
	unsigned int cur_cfg_len;

	ret = sxi_hdist_get_cfg(h->hd, &cur_cfg, &cur_cfg_len);
	if(ret) {
	    msg_set_reason("Failed to retrieve the current distribution model");
	    goto change_add_fail;
	}
	if(qbind_text(q, ":k", "current_dist") ||
	   qbind_blob(q, ":v", cur_cfg, cur_cfg_len) ||
	   qstep_noret(q)) {
	    msg_set_reason("Failed to save current distribution model");
	    ret = FAIL_EINTERNAL;
	    goto change_add_fail;
	}

	sqlite3_reset(q);
	if(qbind_text(q, ":k", "current_dist_rev") ||
	   qbind_int64(q, ":v", sxi_hdist_version(h->hd)) ||
	   qstep_noret(q)) {
	    msg_set_reason("Failed to save current distribution model");
	    ret = FAIL_EINTERNAL;
	    goto change_add_fail;
	}
	sqlite3_reset(q);
    }
	
    if(qbind_text(q, ":k", "dist") ||
       qbind_blob(q, ":v", cfg, cfg_len) ||
       qstep_noret(q)) {
	msg_set_reason("Failed to save target distribution model");
	ret = FAIL_EINTERNAL;
	goto change_add_fail;
    }

    sqlite3_reset(q);
    if(qbind_text(q, ":k", "dist_rev") ||
       qbind_int64(q, ":v", sxi_hdist_version(newmod)) ||
       qstep_noret(q)) {
	msg_set_reason("Failed to save target distribution model");
	ret = FAIL_EINTERNAL;
	goto change_add_fail;
    }

    if(qcommit(h->db)) {
	msg_set_reason("Failed to save distribution model");
	ret = FAIL_EINTERNAL;
    } else {
	ret = OK;
	DEBUG("Distribution change added from %lld to %lld", (long long)h->hd_rev, (long long)sxi_hdist_version(newmod));
    }
 change_add_fail:
    qnullify(q);
    if(ret != OK)
	qrollback(h->db);
    sxi_hdist_free(newmod);

    return ret;
}

rc_ty sx_hashfs_hdist_change_commit(sx_hashfs_t *h) {
    sqlite3_stmt *q;
    rc_ty s = OK;

    if(qprep(h->db, &q, "DELETE FROM hashfs WHERE key IN ('current_dist', 'current_dist_rev')") ||
       qstep_noret(q))
	s = FAIL_EINTERNAL;
    else
	DEBUG("Distribution change committed");

    qnullify(q);
    return s;
}

rc_ty sx_hashfs_challenge_gen(sx_hashfs_t *h, sx_hash_challenge_t *c, int random_challenge) {
    unsigned char md[SXI_SHA1_BIN_LEN];
    unsigned int mdlen;
    sxi_hmac_sha1_ctx *hmac_ctx;
    rc_ty ret;

    if(random_challenge) {
	if(sxi_rand_pseudo_bytes(c->challenge, sizeof(c->challenge)) == -1) {
	    WARN("Cannot generate random bytes");
	    msg_set_reason("Failed to generate random nounce");
	    return FAIL_EINTERNAL;
	}
    }

    hmac_ctx = sxi_hmac_sha1_init();
    if (!hmac_ctx)
        return 1;
    if(!sxi_hmac_sha1_init_ex(hmac_ctx, &h->tokenkey, sizeof(h->tokenkey)) ||
       !sxi_hmac_sha1_update(hmac_ctx, c->challenge, sizeof(c->challenge)) ||
       !sxi_hmac_sha1_update(hmac_ctx, h->cluster_uuid.binary, sizeof(h->cluster_uuid.binary)) ||
       !sxi_hmac_sha1_final(hmac_ctx, md, &mdlen) ||
       mdlen != sizeof(c->response)) {
	msg_set_reason("Failed to compute nounce hmac");
	CRIT("Cannot genearate nounce hmac");
	ret = FAIL_EINTERNAL;
    } else {
	memcpy(c->response, md, sizeof(c->response));
	ret = OK;
    }
    sxi_hmac_sha1_cleanup(&hmac_ctx);

    return ret;
}

/* MODHDIST: this has got a lot in common with sx_storage_activate
 * except it's the entry for the cluster instead od sxadm */
rc_ty sx_hashfs_setnodedata(sx_hashfs_t *h, const char *name, const sx_uuid_t *node_uuid, uint16_t port, int use_ssl, const char *ssl_ca_crt) {
    rc_ty ret = FAIL_EINTERNAL;
    char *ssl_ca_file = NULL;
    sqlite3_stmt *q = NULL;
    int rollback = 0;

    if(!h || !name || !node_uuid || !*name) {
	NULLARG();
	return EFAULT;
    }
    if(!sx_storage_is_bare(h)) {
	msg_set_reason("Storage was already activated");
	return EINVAL;
    }

    if(use_ssl && ssl_ca_crt) {
	unsigned int cafilen = strlen(h->dir) + sizeof("/sxcert.012345678.pem");
	unsigned int cadatalen = strlen(ssl_ca_crt);
	if(cadatalen) {
	    ssl_ca_file = wrap_malloc(cafilen);
	    if(!ssl_ca_file) {
		OOM();
		return ENOMEM;
	    }
	    snprintf(ssl_ca_file, cafilen, "%s/sxcert.pem", h->dir);
	    while(1) {
		int fd = open(ssl_ca_file, O_CREAT|O_EXCL|O_WRONLY, 0640);
		if(fd < 0) {
		    if(errno == EEXIST) {
			snprintf(ssl_ca_file, cafilen, "%s/sxcert.%08x.pem", h->dir, rand());
			continue;
		    }
		    msg_set_reason("Cannot create CA certificate file");
		    goto setnodedata_fail;
		}
		while(cadatalen) {
		    ssize_t done = write(fd, ssl_ca_crt, cadatalen);
		    if(done < 0) {
			close(fd);
			msg_set_reason("Cannot write CA certificate file");
			goto setnodedata_fail;
		    }
		    cadatalen -= done;
		    ssl_ca_crt += done;
		}
		close(fd);
		break;
	    }
	}
    }

    if(qbegin(h->db))
	goto setnodedata_fail;
    rollback = 1;

    if(qprep(h->db, &q, "INSERT OR REPLACE INTO hashfs (key, value) VALUES (:k , :v)"))
	goto setnodedata_fail;

    if(qbind_text(q, ":k", "ssl_ca_file") || qbind_text(q, ":v", ssl_ca_file ? ssl_ca_file : "") || qstep_noret(q))
	goto setnodedata_fail;
    if(qbind_text(q, ":k", "cluster_name") || qbind_text(q, ":v", name) || qstep_noret(q))
	goto setnodedata_fail;
    if(qbind_text(q, ":k", "http_port") || qbind_int(q, ":v", port) || qstep_noret(q))
	goto setnodedata_fail;
    if(qbind_text(q, ":k", "node") || qbind_blob(q, ":v", node_uuid->binary, sizeof(node_uuid->binary)) || qstep_noret(q))
	goto setnodedata_fail;
    qnullify(q);

    if(qprep(h->db, &q, "DELETE FROM users WHERE uid <> 0") || qstep_noret(q))
	goto setnodedata_fail;

    if(qcommit(h->db))
	goto setnodedata_fail;

    ret = OK;
    rollback = 0;
 setnodedata_fail:
    if(rollback)
	qrollback(h->db);

    sqlite3_finalize(q);
    free(ssl_ca_file);
    return ret;
}


static int64_t dbfilesize(sxi_db_t *db) {
    const char *dbfile;
    struct stat st;
    if(!db || !db->handle)
	return 0;

    dbfile = sqlite3_db_filename(db->handle, "main");
    if(!dbfile)
	return 0;

    if(stat(dbfile, &st))
	return 0;

    return st.st_size;
}

void sx_storage_usage(sx_hashfs_t *h, int64_t *allocated, int64_t *committed) {
    unsigned int i, j;
    int64_t al, ci;

    /* The allocated size is the amount of space taken on disk.
     * - for the DB files this it the size of the .db files
     * - for the DATA files this is the size of the .bin files
     *
     * The committed size is the amount of space actually used.
     * - for the DB files it's the same as for allocated (*)
     * - for the DATA files this is the number of blocks * the block size
     * (*) we could use PRAGMA (page_size * page_count) here but, considering that
     * the outcome could be puzzling to the casual user and that, in the end, the
     * difference would be pretty tiny compared to the overall space usage, it's
     * better to just account for the file size here too
     */

    al = dbfilesize(h->db);
    al += dbfilesize(h->tempdb);
    al += dbfilesize(h->tempdb);
    al += dbfilesize(h->eventdb);
    al += dbfilesize(h->xferdb);

    for(i=0; i<METADBS; i++)
	al += dbfilesize(h->metadb[i]);

    for(i=0; i<GCDBS; i++)
	al += dbfilesize(h->gcdb[i]);

    ci = al;

    for(j=0; j<SIZES; j++) {
	for(i=0; i<HASHDBS; i++) {
	    int64_t rows = get_count(h->datadb[j][i], "blocks");
	    int64_t dbsize = dbfilesize(h->datadb[j][i]);
	    struct stat st;

	    al += dbsize;
	    ci += dbsize + rows * bsz[j];
	    if(!fstat(h->datafd[j][i], &st))
		al += st.st_size;
	}
    }
    if(allocated)
	*allocated = al;
    if(committed)
	*committed = ci;
}

const sx_uuid_t *sx_hashfs_distinfo(sx_hashfs_t *h, unsigned int *version, uint64_t *checksum) {
    const sx_uuid_t *ret;
    if(!h || !h->have_hd)
	return NULL;

    ret = sxi_hdist_uuid(h->hd);
    if(!ret)
	return NULL;

    if(checksum)
	*checksum = sxi_hdist_checksum(h->hd);
    if(version)
	*version = sxi_hdist_version(h->hd);

    return ret;
}

