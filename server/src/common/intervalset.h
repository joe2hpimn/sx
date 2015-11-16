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
#ifndef INTERVALSET_H
#define INTERVALSET_H

#include "default.h"
#include "sxdbi.h"
#include "errors.h"
#include "utils.h"
#include "../libsxclient/src/sxproto.h"

typedef struct {
    sxi_db_t *db;
    sqlite3_stmt *qins;
    sqlite3_stmt *qmerge;
    sqlite3_stmt *qmem;
    sqlite3_stmt *qdelall;
    sqlite3_stmt *qlookup_uuid;
    sqlite3_stmt *qinsert_uuid;
    sqlite3_stmt *qget_counter;
    sqlite3_stmt *qupd_counter;
    sqlite3_stmt *qlookup_id;
    sqlite3_stmt *qsel_all;
    int64_t self_id;
} sxi_iset_t;

rc_ty sxi_iset_create(sxi_db_t *db);
rc_ty sxi_iset_prepare(sxi_iset_t *iset, sxi_db_t *db);
void sxi_iset_finalize(sxi_iset_t *iset);

rc_ty sxi_iset_set_self_id(sxi_iset_t *iset, const sx_uuid_t *uuid);
int64_t sxi_iset_self_id(sxi_iset_t *iset);

rc_ty sxi_iset_get_counter(sxi_iset_t *iset, int64_t *node_counter);
rc_ty sxi_iset_update_counter(sxi_iset_t *iset, int64_t node_counter);

rc_ty sxi_iset_node_id(sxi_iset_t *iset, const sx_uuid_t* uuid, int64_t *node_id);
rc_ty sxi_iset_node_uuid(sxi_iset_t *iset, int64_t node_id, sx_uuid_t *node_uuid);

rc_ty sxi_iset_add(sxi_iset_t *iset, int64_t node_id, int64_t start, int64_t stop);
rc_ty sxi_iset_is_mem(sxi_iset_t *iset, int64_t node_id, int64_t val);
rc_ty sxi_iset_merge(sxi_iset_t *iset, int64_t lhs_node_id, int64_t rhs_node_id);
rc_ty sxi_iset_delall(sxi_iset_t *iset, int64_t node_id);

rc_ty sxi_iset_iter_begin(sxi_iset_t *iset);
rc_ty sxi_iset_iter_next(sxi_iset_t *iset, int64_t *node_id, int64_t *start, int64_t *stop);
rc_ty sxi_iset_iter_done(sxi_iset_t *iset);

rc_ty sxi_iset_etag(sxi_iset_t *iset, sx_hash_t *etag);

#endif
