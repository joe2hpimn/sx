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
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "sxdbi.h"
#include "utils.h"
#include "log.h"

static void qclose_db(sqlite3 **dbp)
{
    sqlite3 *db;
    int r;
    if (!dbp) {
        DEBUG("Null DBp");
        return;
    }
    db = *dbp;
    if (!db)
        return;
    r = sqlite3_close(db);
    if (r) {
        if (r == SQLITE_BUSY) {
            sqlite3_stmt* q = NULL;
            while ((q = sqlite3_next_stmt(db, q)))
                WARN("SQLite statement not finalized: '%s'", sqlite3_sql(q));
        }
        WARN("Cannot close database %s: %s", sqlite3_db_filename(db, NULL), sqlite3_errstr(r));
    }
    *dbp = NULL;
}

static int qwal_hook(void *ctx, sqlite3 *handle, const char *name, int pages)
{
    sxi_db_t *db = ctx;
    if (db)
        db->wal_pages = pages;
    if (pages >= db_max_passive_wal_pages)
        qcheckpoint(db);
    return SQLITE_OK;
}

sxi_db_t *qnew(sqlite3 *handle)
{
    sxi_db_t *db;
    if (!handle)
        return NULL;
    db = wrap_calloc(1, sizeof(*db));
    if (!db) {
        qclose_db(&handle);
        return NULL;
    }
    db->handle = handle;
    sqlite3_wal_hook(handle, qwal_hook, db);
    return db;
}

static void qcheckpoint_run(sxi_db_t *db, int kind)
{
    struct timeval tv0, tv1;
    int log, ckpt, rc;
    if (!db)
        return;
    gettimeofday(&tv0, NULL);
    rc = sqlite3_wal_checkpoint_v2(db->handle, NULL, kind, &log, &ckpt);
    gettimeofday(&tv1, NULL);
    if (rc != SQLITE_OK && rc != SQLITE_BUSY && rc != SQLITE_LOCKED) {
        WARN("Failed to checkpoint db '%s': %s", sqlite3_db_filename(db->handle, "main"), sqlite3_errmsg(db->handle));
    } else if (ckpt > 0) {
        DEBUG("WAL %s: %d frames, %d checkpointed: %s in %.1fs", sqlite3_db_filename(db->handle, "main"), log, ckpt, sqlite3_errmsg(db->handle),
             timediff(&tv0, &tv1));
    }
    db->wal_pages = 0;
}

void qcheckpoint(sxi_db_t *db)
{
    if (!db)
        return;
    if (db->wal_pages >= db_max_restart_wal_pages)
        qcheckpoint_run(db, SQLITE_CHECKPOINT_RESTART);
    else if (db->wal_pages >= db_max_passive_wal_pages)
        qcheckpoint_run(db, SQLITE_CHECKPOINT_PASSIVE);
}

void qcheckpoint_restart(sxi_db_t *db)
{
    if (db && db->wal_pages >= db_min_passive_wal_pages)
        qcheckpoint_run(db, SQLITE_CHECKPOINT_RESTART);
}

void qcheckpoint_idle(sxi_db_t *db)
{
    if (db) {
        int changes = sqlite3_total_changes(db->handle);
        if (changes != db->last_total_changes) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            if (timediff(&db->tv_last, &tv) >= db_idle_restart) {
                qcheckpoint_run(db, SQLITE_CHECKPOINT_RESTART);
                memcpy(&db->tv_last, &tv, sizeof(tv));
                db->last_total_changes = changes;
            }
        }
    }
}

void qclose(sxi_db_t **db)
{
    if (!db) {
        WARN("Null DBp");
        return;
    }
    qclose_db(&(*db)->handle);
    free(*db);
    *db = NULL;
}

static int qexplain(sqlite3_stmt *pStmt) {
    /* see https://www.sqlite.org/eqp.html */
    const char *zSql;               /* Input SQL */
    char *zExplain;                 /* SQL with EXPLAIN QUERY PLAN prepended */
    sqlite3_stmt *pExplain;         /* Compiled EXPLAIN QUERY PLAN command */
    int rc;                         /* Return code from sqlite3_prepare_v2() */
    sqlite3 *db;
    const char *name;
    struct sxi_fmt fmt;

    zSql = sqlite3_sql(pStmt);
    if (!zSql) return SQLITE_ERROR;

    zExplain = sqlite3_mprintf("EXPLAIN QUERY PLAN %s", zSql);
    if (!zExplain) return SQLITE_NOMEM;
    db = sqlite3_db_handle(pStmt);

    rc = sqlite3_prepare_v2(db, zExplain, -1, &pExplain, 0);
    name = sqlite3_db_filename(db, "main");
    name = strrchr(name, '/');

    sxi_fmt_start(&fmt);

    sxi_fmt_msg(&fmt, "%s %s", name ? name : "N/A", zExplain);
    sqlite3_free(zExplain);
    if (rc != SQLITE_OK) return rc;

    while (SQLITE_ROW == sqlite3_step(pExplain)) {
        int iSelectid = sqlite3_column_int(pExplain, 0);
        int iOrder = sqlite3_column_int(pExplain, 1);
        int iFrom = sqlite3_column_int(pExplain, 2);
        const char *zDetail = (const char *)sqlite3_column_text(pExplain, 3);

        if (zDetail)
            sxi_fmt_msg(&fmt, "\n\t%d|%d|%d|%s", iSelectid, iOrder, iFrom, zDetail);
    }
    DEBUG("%s", fmt.buf);

    return sqlite3_finalize(pExplain);
}

static int qprep_db(sqlite3 *db, sqlite3_stmt **q, const char *query) {
    int i, ret = SQLITE_OK;
    *q = NULL;
    for(i=0; i<30; i++) {
	ret = sqlite3_prepare_v2(db, query, -1, q, NULL);
	if(ret == SQLITE_BUSY) {
	    DEBUG("Waiting (%d/%d) to prepare query \"%s\"", i+1, 30, query);
	    sqlite3_sleep(100);
	    continue;
	}
        break;
    }
    if(ret) {
        CRIT("Cannot prepare query \"%s\": %s", query, sqlite3_errmsg(db));
        return -1;
    }
    if (UNLIKELY(sxi_log_is_debug(&logger)))
        qexplain(*q);
    return 0;
}

int qprep(sxi_db_t *db, sqlite3_stmt **q, const char *query) {
    return qprep_db(db->handle, q, query);
}


static int qstep_retry(sqlite3_stmt *q)
{
    static const unsigned int us_delays[] = {
        1*1000, 2*1000, 5*1000, 10*1000, 15*1000, 20*1000, 25*1000, 25*1000,  25*1000,  50*1000,  50*1000, 100*1000
    };
    unsigned ms_timeout = 0, curdelay = 0;
    struct timeval t1, t2;
    int ret;

    gettimeofday(&t1, NULL);
    while((ret = sqlite3_step(q)) == SQLITE_BUSY) {
        unsigned int us_delay = us_delays[curdelay], ms_dt;

        sqlite3_reset(q);

        if(curdelay < (sizeof(us_delays) / sizeof(us_delays[0])) - 1)
            curdelay++;

        gettimeofday(&t2, NULL);
        if (!ms_timeout) {
            sqlite3_stmt *q2 = NULL;
            if(!qprep_db(sqlite3_db_handle(q), &q2, "PRAGMA busy_timeout") && !qstep_ret(q2))
                ms_timeout = sqlite3_column_int(q2, 0);
            else
                ms_timeout = 25 * 1000;
            sqlite3_finalize(q2);
        }

        ms_dt = timediff(&t1, &t2) * 1000;
        if(ms_dt >= ms_timeout) {
            WARN("SQLite was busy on '%s' for more than %d ms", sqlite3_sql(q), ms_dt);
            msg_set_busy();
            ret = SQLITE_BUSY;
            break;
        }
        if((ms_timeout - ms_dt) * 1000 < us_delay)
            us_delay = (ms_timeout - ms_dt) * 1000;
        usleep(us_delay);
    }
    return ret;
}

int qstep(sqlite3_stmt *q) {
    struct timeval t1, t2;
    int ret;

    gettimeofday(&t1, NULL);
    ret = sqlite3_step(q);
    if(ret != SQLITE_DONE && ret != SQLITE_ROW) {
	if(ret != SQLITE_CONSTRAINT)
	    SQLERR(q, sqlite3_errmsg(sqlite3_db_handle(q)));
	if(ret == SQLITE_BUSY)
	    msg_set_busy();
    } else {
	double dt;
	gettimeofday(&t2, NULL);
	dt = timediff(&t1, &t2);
	if(dt > 5)
	    INFO("Slow query \"%s\" completed in %.2f sec", sqlite3_sql(q), dt);
    }
    if(ret != SQLITE_ROW)
	sqlite3_reset(q);
    return ret;
}

int qstep_expect(sqlite3_stmt *q, int expect) {
    int ret = qstep(q);
    if(ret == expect)
	return 0;
    if(ret == SQLITE_DONE)
        SQLERR(q, "Query unexpectedly returned no results");
    else if(ret == SQLITE_ROW) {
        SQLERR(q, "Query unexpectedly returned results");
	sqlite3_reset(q);
    } else {
        SQLERR(q, "Query returned unexpected results");
        sqlite3_reset(q);
    }
    return -1;
}
#define qstep_ret(q) qstep_expect((q), SQLITE_ROW)
#define qstep_noret(q) qstep_expect((q), SQLITE_DONE)

static int qparam(sqlite3_stmt *q, const char *param) {
    int pos = sqlite3_bind_parameter_index(q, param);
    if(!pos) {
	CRIT("Cannot bind invalid parameter \"%s\" to query \"%s\"", param, sqlite3_sql(q));
        msg_add_detail(NULL,"SQLite bind error", "Cannot bind invalid parameter \"%s\"", param);
    }
    return pos;
}

int qbind_int(sqlite3_stmt *q, const char *param, int val) {
    int pos = qparam(q, param);
    if(!pos)
	return -1;
    if(sqlite3_bind_int(q, pos, val)) {
        SQLPARAMERR(q, param);
	return -1;
    }
    return 0;
}

int qbind_int64(sqlite3_stmt *q, const char *param, int64_t val) {
    int pos = qparam(q, param);
    if(!pos)
	return -1;
    if(sqlite3_bind_int64(q, pos, val)) {
        SQLPARAMERR(q, param);
	return -1;
    }
    return 0;
}

int qbind_text(sqlite3_stmt *q, const char *param, const char *val) {
    int pos = qparam(q, param);
    if(!pos)
	return -1;
    if(sqlite3_bind_text(q, pos, val, -1, SQLITE_TRANSIENT)) {
        SQLPARAMERR(q, param);/* do not log val, it might contain sensitive data such as auth keys */
	return -1;
    }
    return 0;
}

int qbind_blob(sqlite3_stmt *q, const char *param, const void *val, int len) {
    int pos = qparam(q, param);
    if(!pos)
	return -1;
    if(sqlite3_bind_blob(q, pos, val, len, SQLITE_TRANSIENT)) {
        SQLPARAMERR(q, param);/* do not log val, it might contain sensitive data such as auth keys */
	return -1;
    }
    return 0;
}

int qbind_null(sqlite3_stmt *q, const char *param) {
    int pos = qparam(q, param);
    if(!pos)
	return -1;
    if(sqlite3_bind_null(q, pos)) {
        SQLPARAMERR(q, param);/* do not log val, it might contain sensitive data such as auth keys */
	return -1;
    }
    return 0;
}

void qlog(void *parg, int errcode, const char *msg)
{
    int prio;
    switch (errcode & 0xff) { /* The upper byte keeps the extended result */
        case SQLITE_OK:/* fall-through */
        case SQLITE_ROW:
        case SQLITE_DONE:
        case SQLITE_CONSTRAINT:
            return;/* not an error */
        case SQLITE_BUSY:
            prio = SX_LOG_INFO;
            break;
        case SQLITE_NOTICE:
            prio = SX_LOG_NOTICE;
            break;
        case SQLITE_IOERR:/* fall-through */
        case SQLITE_CANTOPEN:
        case SQLITE_NOTADB:
            prio = SX_LOG_CRIT;
            break;
        case SQLITE_CORRUPT:/* fall-through */
        case SQLITE_FULL:
            prio = SX_LOG_ALERT;/* errors requiring immediate attention */
            break;
        default:
            prio = SX_LOG_WARNING;/* possibly transient errors, or errors the admin can't fix */
            break;
    }
    sxi_log_msg(&logger, "qlog", prio, "SQLite error %x: %s", errcode, msg);
}

int qbegin(sxi_db_t *db) {
    int ret;
    sqlite3_stmt *q = NULL;

    if(qprep(db, &q, "BEGIN IMMEDIATE TRANSACTION"))
	return -1;

    /* BEGIN IMMEDIATE will not invoke the busy handler, must simulate it here */
    ret = qstep_retry(q);
    sqlite3_finalize(q);
    if(ret != SQLITE_DONE) {
        WARN("SQLITE begin failed: %s", sqlite3_errstr(ret));
	return -1;
    }
    return 0;
}

int qcommit(sxi_db_t *db) {
    sqlite3_stmt *q;
    int ret;

    if(qprep(db, &q, "COMMIT"))
	return -1;

    ret = qstep_noret(q);
    sqlite3_finalize(q);
    return ret;
}

void qrollback(sxi_db_t *db) {
    sqlite3_stmt *q = NULL;

    if(qprep(db, &q, "ROLLBACK") ||  qstep_noret(q))
	CRIT("ROLLBACK failed");
    sqlite3_finalize(q);
}
