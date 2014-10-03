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

#ifndef __HDIST_H
#define __HDIST_H

#define SXI_HDIST_MAX_NODE_POINTS 20000
#define SXI_HDIST_MAX_TOTAL_POINTS 500000

#include <stdint.h>
#include "isaac.h"
#include "errors.h"
#include "nodes.h"
#include "utils.h"

typedef struct _sxi_hdist_t sxi_hdist_t;

sxi_hdist_t *sxi_hdist_new(unsigned int seed, unsigned int max_builds, sx_uuid_t *uuid);

sxi_hdist_t *sxi_hdist_from_cfg(const void *cfg, unsigned int cfg_len);

rc_ty sxi_hdist_get_cfg(const sxi_hdist_t *model, const void **cfg, unsigned int *cfg_len);

rc_ty sxi_hdist_addnode(sxi_hdist_t *model, const sx_uuid_t *uuid, const char *addr, const char *internal_addr, int64_t capacity, const sx_uuid_t *prev_uuid);

rc_ty sxi_hdist_newbuild(sxi_hdist_t *model);

rc_ty sxi_hdist_build(sxi_hdist_t *model);

rc_ty sxi_hdist_rebalanced(sxi_hdist_t *model);

sx_nodelist_t *sxi_hdist_locate(const sxi_hdist_t *model, uint64_t hash, unsigned int replica_count, int bidx);

const sx_nodelist_t *sxi_hdist_nodelist(const sxi_hdist_t *model, int bidx);

unsigned int sxi_hdist_buildcnt(const sxi_hdist_t *model);

unsigned int sxi_hdist_version(const sxi_hdist_t *model);

uint64_t sxi_hdist_checksum(const sxi_hdist_t *model);

const sx_uuid_t *sxi_hdist_uuid(const sxi_hdist_t *model);

int sxi_hdist_same_origin(const sxi_hdist_t *model1, const sxi_hdist_t *model2);

void sxi_hdist_free(sxi_hdist_t *model);

#endif
