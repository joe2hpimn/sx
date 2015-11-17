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

#include "intervalset.h"
#include "log.h"
#include "../libsxclient/src/vcrypto.h"
#include <string.h>

#define ID_SELF 0

rc_ty sxi_iset_create(sxi_db_t *db)
{
    rc_ty ret = FAIL_EINTERNAL;
    sqlite3_stmt *q = NULL;
    do {
        if (qprep(db, &q, "CREATE TABLE node_uuids(node_id INTEGER PRIMARY KEY, node_uuid TEXT NOT NULL, UNIQUE(node_uuid))") ||
            qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q, "CREATE TABLE op_counter(value INTEGER NOT NULL)") ||
            qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q, "INSERT INTO op_counter(value) VALUES(0)") ||
            qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q, "CREATE TABLE intervals(node_id INTEGER NOT NULL REFERENCES node_uuids(node_id), start INTEGER NOT NULL, stop INTEGER NOT NULL, CHECK (start <= stop))") ||
            qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q, "CREATE INDEX intervals_idx_start ON intervals(node_id, start, stop)") ||
            qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q, "CREATE INDEX intervals_idx_stop ON intervals(node_id, stop, start)") ||
            qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q, "CREATE VIEW intervals_pack AS SELECT * FROM intervals") ||
            qstep_noret(q))
            break;
        qnullify(q);
        /* you need an SQLite built with -DSQLITE_DEBUG or -DSQLITE_ENABLE_EXPLAIN_COMMENTS
           and run 'explain' not 'explain query plan' on the insert into intervals_pack to see the explain for the trigger's queries */
        if (qprep(db, &q,
                  "CREATE TRIGGER pack_left INSTEAD OF INSERT ON intervals_pack BEGIN\n"
                  /* find interval to join with on left side */
                  "UPDATE intervals SET stop=MAX(stop, NEW.stop) WHERE node_id=NEW.node_id AND start <= NEW.start AND NEW.start-1 <= stop AND stop <= NEW.stop;\n"
                  /*  if we didn't find an interval to join with then insert it, but only if the interval is not already contained in another interval*/
                  "INSERT INTO intervals(node_id, start, stop) SELECT NEW.node_id, NEW.start, NEW.stop WHERE changes()=0;\n"
                  /* TODO: avoid inserting overlapping intervals AND NOT EXISTS (SELECT rowid FROM intervals WHERE node_id=NEW.node_id AND start <= NEW.start AND NEW.stop <= stop);*/
                  "END"
                  ) || qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q,
                  "CREATE TRIGGER delete_overlap1 AFTER INSERT ON intervals BEGIN\n"
                  /* delete intervals entirely contained within the newly inserted interval, but not the newly inserted interval itself */
                  /* stop <= NEW.stop && start <= stop => start <= NEW.stop */
                  "DELETE FROM intervals WHERE node_id=NEW.node_id AND NEW.start <= start AND stop <= NEW.stop AND start <= NEW.stop AND rowid != NEW.rowid;\n"
                  "END"
                  ) || qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q,
                  "CREATE TRIGGER delete_overlap2 AFTER UPDATE ON intervals BEGIN\n"
                  /* delete intervals entirely contained within the newly inserted interval, but not the newly inserted interval itself */
                  /* stop <= NEW.stop && start <= stop => start <= NEW.stop */
                  "DELETE FROM intervals WHERE node_id=NEW.node_id AND NEW.start <= start AND stop <= NEW.stop AND start <= NEW.stop AND rowid != NEW.rowid;\n"
                  "END"
                  ) || qstep_noret(q))
            break;
        qnullify(q);
        if (qprep(db, &q,
                  "CREATE TRIGGER pack_right AFTER UPDATE OF stop ON intervals BEGIN\n"
                  /* join with interval on right (delete_overlap2 will take care of removing the other interval) */
                  "UPDATE intervals SET start=NEW.start WHERE node_id=NEW.node_id AND start <= NEW.stop+1 AND NEW.stop <= stop AND NEW.start <= start;\n"
                  "END"
                  ) || qstep_noret(q))
            break;
        qnullify(q);
        ret = OK;
    } while(0);
    qnullify(q);
    return ret;
}

void sxi_iset_finalize(sxi_iset_t *iset)
{
    if (!iset)
        return;
    sqlite3_finalize(iset->qins);
    sqlite3_finalize(iset->qmerge);
    sqlite3_finalize(iset->qmem);
    sqlite3_finalize(iset->qdelall);
    sqlite3_finalize(iset->qlookup_uuid);
    sqlite3_finalize(iset->qinsert_uuid);
    sqlite3_finalize(iset->qget_counter);
    sqlite3_finalize(iset->qupd_counter);
    sqlite3_finalize(iset->qlookup_id);
    sqlite3_finalize(iset->qsel_all);
    sqlite3_finalize(iset->qiter);
    memset(iset, 0, sizeof(*iset));
}

rc_ty sxi_iset_prepare(sxi_iset_t *iset, sxi_db_t *db)
{
    sqlite3_stmt *q = NULL;
    memset(iset, 0, sizeof(*iset));
    iset->db = db;
    if (qprep(db, &iset->qins, "INSERT INTO intervals_pack(node_id, start, stop) VALUES(:node_id, :start, :stop)") ||
        qprep(db, &iset->qmerge, "INSERT INTO intervals_pack(node_id, start, stop) SELECT :lhs_node_id, start, stop FROM intervals WHERE node_id=:rhs_node_id") ||
        /* SQLite doesn't know intervals are not overlapping so the subquery and limit is needed to avoid searching half the DB when there is no match */
        qprep(db, &iset->qmem, "SELECT 1 FROM (SELECT start, stop FROM intervals WHERE node_id=:node_id AND :val <= stop ORDER BY stop LIMIT 1) WHERE start <= :val AND :val <= stop") ||
        qprep(db, &iset->qdelall, "DELETE FROM intervals WHERE node_id=:node_id") ||
        qprep(db, &iset->qlookup_uuid, "SELECT node_id FROM node_uuids WHERE node_uuid=:node_uuid") ||
        qprep(db, &iset->qinsert_uuid, "INSERT INTO node_uuids(node_uuid) VALUES(:node_uuid)") ||
        qprep(db, &iset->qget_counter, "SELECT value FROM op_counter LIMIT 1") ||
        qprep(db, &iset->qupd_counter, "UPDATE op_counter SET value=MAX(value, :value)+1") ||
        qprep(db, &iset->qlookup_id, "SELECT node_uuid FROM node_uuids WHERE node_id=:node_id") ||
        qprep(db, &iset->qsel_all, "SELECT node_id, start, stop FROM intervals ORDER BY node_id, start") ||
        qprep(db, &iset->qiter, "SELECT start, stop FROM intervals NATURAL INNER JOIN node_uuids WHERE node_uuid=:node_uuid ORDER BY start") ||
        qprep(db, &q, "PRAGMA foreign_keys = ON") ||
        qstep_noret(q))
        {
            qnullify(q);
            sxi_iset_finalize(iset);
            return FAIL_EINTERNAL;
        }
    qnullify(q);
    return OK;
}

rc_ty sxi_iset_add(sxi_iset_t *iset, int64_t node_id, int64_t start, int64_t stop)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }

    if (qbind_int64(iset->qins, ":node_id", node_id) ||
        qbind_int64(iset->qins, ":start", start) ||
        qbind_int64(iset->qins, ":stop", stop) ||
        qstep_noret(iset->qins))
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sxi_iset_is_mem(sxi_iset_t *iset, int64_t node_id, int64_t val)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }

    sqlite3_reset(iset->qmem);
    if (qbind_int64(iset->qmem, ":node_id", node_id) ||
        qbind_int64(iset->qmem, ":val", val))
        return FAIL_EINTERNAL;
    int ret = qstep(iset->qmem);
    sqlite3_reset(iset->qmem);
    return ret == SQLITE_ROW ? OK : ret == SQLITE_DONE ? ENOENT : FAIL_EINTERNAL;
}

rc_ty sxi_iset_merge(sxi_iset_t *iset, int64_t lhs_node_id, int64_t rhs_node_id)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }

    if (qbind_int64(iset->qmerge, ":lhs_node_id", lhs_node_id) ||
        qbind_int64(iset->qmerge, ":rhs_node_id", rhs_node_id) ||
        qstep_noret(iset->qmerge))
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sxi_iset_delall(sxi_iset_t *iset, int64_t node_id)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }
    if (qbind_int64(iset->qdelall, ":node_id", node_id) ||
        qstep_noret(iset->qdelall))
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sxi_iset_node_id(sxi_iset_t *iset, const sx_uuid_t* uuid, int64_t *node_id)
{
    if (!iset || !uuid) {
        NULLARG();
        return EFAULT;
    }
    if (!iset->qlookup_uuid) {
        WARN("iset not initialized");
        return FAIL_EINTERNAL;
    }
    sqlite3_reset(iset->qlookup_uuid);
    if (qbind_text(iset->qlookup_uuid, ":node_uuid", uuid->string) ||
        qstep_ret(iset->qlookup_uuid))
        return FAIL_EINTERNAL;
    *node_id = sqlite3_column_int64(iset->qlookup_uuid, 0);
    sqlite3_reset(iset->qlookup_uuid);
    return OK;
}

rc_ty sxi_iset_node_add(sxi_iset_t *iset, const sx_uuid_t* uuid)
{
    if (!iset || !uuid) {
        NULLARG();
        return EFAULT;
    }
    if (qbind_text(iset->qinsert_uuid, ":node_uuid", uuid->string) ||
        qstep_noret(iset->qinsert_uuid))
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sxi_iset_node_uuid(sxi_iset_t *iset, int64_t node_id, sx_uuid_t *node_uuid)
{
    rc_ty ret;
    if (!iset || !node_uuid) {
        NULLARG();
        return EFAULT;
    }
    sqlite3_reset(iset->qlookup_id);
    if (qbind_int64(iset->qlookup_id, ":node_id", node_id) ||
        qstep_ret(iset->qlookup_id))
        return FAIL_EINTERNAL;
    if (uuid_from_string(node_uuid, (const char*)sqlite3_column_text(iset->qlookup_id, 0)))
        ret = FAIL_EINTERNAL;
    else
        ret = OK;
    sqlite3_reset(iset->qlookup_id);
    return ret;
}

int64_t sxi_iset_self_id(sxi_iset_t *iset)
{
    if (!iset) {
        NULLARG();
        return -1;
    }
    return iset->self_id;
}

rc_ty sxi_iset_set_self_id(sxi_iset_t *iset, const sx_uuid_t *uuid)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }
    return sxi_iset_node_id(iset, uuid, &iset->self_id);
}

rc_ty sxi_iset_get_counter(sxi_iset_t *iset, int64_t *node_counter)
{
    if (!iset || !node_counter) {
        NULLARG();
        return EFAULT;
    }
    if (iset->self_id < 0)
        return EINVAL;
    sqlite3_reset(iset->qget_counter);
    if (qstep_ret(iset->qget_counter))
        return FAIL_EINTERNAL;
   *node_counter = sqlite3_column_int64(iset->qget_counter, 0);
    sqlite3_reset(iset->qget_counter);
    return OK;
}

rc_ty sxi_iset_update_counter(sxi_iset_t *iset, int64_t node_counter)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }
    if (qbind_int64(iset->qupd_counter, ":value", node_counter) ||
        qstep_noret(iset->qupd_counter))
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sxi_iset_etag(sxi_iset_t *iset, sx_hash_t *etag)
{
    if (!iset || !etag) {
        NULLARG();
        return EFAULT;
    }
    sqlite3_reset(iset->qsel_all);
    int ret;
    sxi_md_ctx *hash_ctx = sxi_md_init();
    if (!hash_ctx)
        return FAIL_EINTERNAL;
    if (!sxi_sha1_init(hash_ctx)) {
        sxi_md_cleanup(&hash_ctx);
        return FAIL_EINTERNAL;
    }
    while ((ret = qstep(iset->qsel_all)) == OK) {
        int64_t node_id, start, stop;
        node_id = sqlite3_column_int64(iset->qsel_all, 0);
        start = sqlite3_column_int64(iset->qsel_all, 1);
        stop = sqlite3_column_int64(iset->qsel_all, 2);
        if (!sxi_sha1_update(hash_ctx, &node_id, sizeof(node_id)) ||
            !sxi_sha1_update(hash_ctx, &start, sizeof(start)) ||
            !sxi_sha1_update(hash_ctx, &stop, sizeof(stop)))
            break;
    }
    if (ret == ITER_NO_MORE) {
        if (!sxi_sha1_final(hash_ctx, etag->b, NULL))
            ret = FAIL_EINTERNAL;
        else
            ret = OK;
    }
    sxi_md_cleanup(&hash_ctx);
    sqlite3_reset(iset->qsel_all);
    return ret;
}

rc_ty sxi_iset_iter_begin(sxi_iset_t *iset, const sx_uuid_t *node)
{
    if (!iset || !node) {
        NULLARG();
        return EFAULT;
    }
    sqlite3_reset(iset->qiter);
    if (qbind_text(iset->qiter, ":node_uuid", node->string))
        return FAIL_EINTERNAL;
    return OK;
}

rc_ty sxi_iset_iter_next(sxi_iset_t *iset, int64_t *start, int64_t *stop)
{
    if (!iset || !start || !stop) {
        NULLARG();
        return EFAULT;
    }
    switch (qstep(iset->qiter)) {
    case SQLITE_ROW:
        *start = sqlite3_column_int64(iset->qsel_all, 0);
        *stop = sqlite3_column_int64(iset->qsel_all, 1);
        return OK;
    case SQLITE_DONE:
        return ITER_NO_MORE;
    default:
        return FAIL_EINTERNAL;
    }
}

rc_ty sxi_iset_iter_done(sxi_iset_t *iset)
{
    if (!iset) {
        NULLARG();
        return EFAULT;
    }
    sqlite3_reset(iset->qsel_all);
    return OK;
}
