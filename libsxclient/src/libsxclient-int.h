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

#ifndef __LIBSXCLIENT_INT_H
#define __LIBSXCLIENT_INT_H

#include "sx.h"
#include "sxlog.h"
#include <stdint.h>

void sxi_debug(sxc_client_t *sx, const char *fn, const char *fmt, ...) FMT_PRINTF(3,4) COLD;
void sxi_info(sxc_client_t *sx, const char *fmt, ...) FMT_PRINTF(2,3);
void sxi_notice(sxc_client_t *sx, const char *fmt, ...) FMT_PRINTF(2,3);
void sxi_seterr(sxc_client_t *sx, enum sxc_error_t err, const char *fmt, ...) FMT_PRINTF(3,4);
void sxi_setsyserr(sxc_client_t *sx, enum sxc_error_t err, const char *fmt, ...) FMT_PRINTF(3,4);

void sxi_clear_operation(sxc_client_t *sx);
void sxi_set_operation(sxc_client_t *sx, const char *op, const char *cluster, const char *vol, const char *path);
const char *sxi_get_operation(sxc_client_t *sx);
void sxi_operation_info(const sxc_client_t *sx, const char **op, const char **host, const char **vol, const char **path);

int sxi_is_debug_enabled(sxc_client_t *sx);

const char *sxi_get_tempdir(sxc_client_t *sx);

#define SXDEBUG(...) sxi_debug(sx, __func__, __VA_ARGS__)
#define CFGDEBUG(...) do{ sxc_client_t *_sx; if(cluster && (_sx = sxi_cluster_get_client(cluster))) sxi_debug(_sx, __func__, __VA_ARGS__); } while(0)
#define CBDEBUG(...) do{ sxc_client_t *_sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata)); sxi_debug(_sx, __func__, __VA_ARGS__); } while(0)
#define CBDATADEBUG(...) do{ sxc_client_t *_sx = sxi_conns_get_client(sxi_cbdata_get_conns(cbdata)); sxi_debug(_sx, __func__, __VA_ARGS__); } while(0)

struct filter_cfg {
    char *volname;
    void *cfg;
    unsigned int cfg_len;
    struct filter_cfg *next;
};

struct filter_handle {
    void *dlh;	/* dlhandle */
    void *ctx; /* filter's own data/ctx */
    int active;
    sxc_filter_t *f;
    uint8_t uuid_bin[16];
    struct filter_cfg *cfg;
    sxc_client_t *sx;
};

struct filter_ctx {
    int filter_cnt; /* -1 if lt_dlinit() fails */
    struct filter_handle *filters;
};

struct tempfile_track {
    int slots;
    char **names;
};

struct filter_ctx *sxi_get_fctx(sxc_client_t *sx);
struct tempfile_track *sxi_get_temptrack(sxc_client_t *sx);
const char *sxi_get_useragent(void);
int sxi_get_input(sxc_client_t *sx, sxc_input_t type, const char *prompt, const char *def, char *in, unsigned int insize);
float sxi_get_node_preference(sxc_client_t *sx);

#endif
