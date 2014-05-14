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
    HASHOP_DELETE
};

sxi_query_t *sxi_useradd_proto(sxc_client_t *sx, const char *username, const uint8_t *key, int admin);
sxi_query_t *sxi_volumeadd_proto(sxc_client_t *sx, const char *volname, const char *owner, int64_t size, unsigned int replica, sxc_meta_t *metadata);
sxi_query_t *sxi_flushfile_proto(sxc_client_t *sx, const char *token);
sxi_query_t *sxi_fileadd_proto_begin(sxc_client_t *sx, const char *volname, const char *path, const char *revision, int64_t pos, int64_t blocksize, int64_t size);
sxi_query_t *sxi_fileadd_proto_addhash(sxc_client_t *sx, sxi_query_t *query, const char *hexhash);
sxi_query_t *sxi_fileadd_proto_end(sxc_client_t *sx, sxi_query_t *query, sxc_meta_t *metadata);
sxi_query_t *sxi_filedel_proto(sxc_client_t *sx, const char *volname, const char *path, const char *revision);
sxi_query_t *sxi_hashop_proto(sxc_client_t *sx, unsigned blocksize, const char *hashes, unsigned hashes_len, enum sxi_hashop_kind kind, const char *id);
sxi_query_t *sxi_nodeinit_proto(sxc_client_t *sx, const char *cluster_name, const char *node_uuid, uint16_t http_port, int ssl_flag, const char *ssl_file);
sxi_query_t *sxi_distribution_proto(sxc_client_t *sx, const void *cfg, unsigned int cfg_len);

typedef const char* (*acl_cb_t)(void *ctx);
sxi_query_t *sxi_volumeacl_proto(sxc_client_t *sx, const char *volname,
                                 acl_cb_t grant_read, acl_cb_t grant_write,
                                 acl_cb_t revoke_read, acl_cb_t revoke_write,
                                 void *ctx);

void sxi_query_free(sxi_query_t *query);

#endif
