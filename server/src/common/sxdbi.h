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

#ifndef __SXDBI_H
#define __SXDBI_H

#include "default.h"
#include "sqlite3.h"
#include <sys/time.h>
typedef struct {
    sqlite3 *handle;
    int wal_pages;
    int last_total_changes;
    struct timeval tv_last;
    struct timeval tv_begin;
    int has_begin_time;
} sxi_db_t;

sxi_db_t* qnew(sqlite3 *handle);
void qcheckpoint(sxi_db_t *db);
void qcheckpoint_idle(sxi_db_t *db);
int qprep(sxi_db_t *db, sqlite3_stmt **q, const char *query);
int qstep(sqlite3_stmt *q);
int qstep_expect(sqlite3_stmt *q, int expect);
#define qstep_ret(q) qstep_expect((q), SQLITE_ROW)
#define qstep_noret(q) qstep_expect((q), SQLITE_DONE)
int qbind_int(sqlite3_stmt *q, const char *param, int val);
int qbind_int64(sqlite3_stmt *q, const char *param, int64_t val);
int qbind_text(sqlite3_stmt *q, const char *param, const char *val);
int qbind_blob(sqlite3_stmt *q, const char *param, const void *val, int len);
int qbind_null(sqlite3_stmt *q, const char *param);
int qlasterr_busy(sxi_db_t *db);
double qelapsed(sxi_db_t *db);
void qlog(void *parg, int errcode, const char *msg);
int qbegin(sxi_db_t *db);
void qyield(sxi_db_t *db);
int qcommit_real(sxi_db_t *db, const char *file, int line);
void qrollback_real(sxi_db_t *db, const char *file, int line);
#define qcommit(db) qcommit_real(db, __FILE__, __LINE__)
#define qrollback(db) qrollback_real(db, __FILE__, __LINE__)
void qclose(sxi_db_t **db);
void pmatch(sqlite3_context *ctx, int argc, sqlite3_value **argv);
void qreadahead(sxi_db_t *db);
int qincore(sxi_db_t *db, int64_t *incore_pages, int64_t *total_pages);
int qvacuum(sxi_db_t *db);

#define qnullify(Q) do { sqlite3_finalize(Q); Q = NULL; } while(0)

#endif
