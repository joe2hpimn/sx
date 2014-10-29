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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "sx.h"
#include "zlib.h"

#define ERROR(...)	sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__)

struct zcomp_ctx {
    z_stream strm;
    int init, end, level;
};

static int zcomp_init(const sxf_handle_t *handle, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static int zcomp_configure(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len)
{
	const char *pt = cfgstr;

    if(!pt)
        return 0;

    if(strncmp(pt, "level:", 6)) {
	ERROR("Invalid configuration data");
	return 1;
    }
    pt += 6;
    if(atoi(pt) < 1 || atoi(pt) > 9) {
	ERROR("Invalid compression level");
	return 1;
    }
    *cfgdata = strdup(cfgstr);
    if(!*cfgdata) {
	ERROR("OOM");
	return 1;
    }
    *cfgdata_len = strlen(cfgstr);
    return 0;
}

static int zcomp_shutdown(const sxf_handle_t *handle, void *ctx)
{
	struct zcomp_ctx *zctx = ctx;

    if(zctx) {
	if(zctx->init == 1)
	    deflateEnd(&zctx->strm);
	else if(zctx->init == 2)
	    inflateEnd(&zctx->strm);
	free(zctx);
    }
    return 0;
}

static int zcomp_data_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode)
{
	struct zcomp_ctx *zctx;
	int level = Z_DEFAULT_COMPRESSION;

    if(cfgdata) {
	if(cfgdata_len != 7 || strncmp(cfgdata, "level:", 6)) {
	    ERROR("Invalid configuration data");
	    return -1;
	}
	level = ((const char *) cfgdata)[6] - 48;
	if(level < 1 || level > 9) {
	    ERROR("Invalid compression level (%d)", level);
	    return -1;
	}
    }

    zctx = malloc(sizeof(struct zcomp_ctx));
    if(!zctx)
	return -1;

    zctx->strm.zalloc = Z_NULL;
    zctx->strm.zfree = Z_NULL;
    zctx->strm.opaque = Z_NULL;
    zctx->init = 0;
    zctx->end = 0;
    zctx->level = level;
    zctx->end = 0;

    *ctx = zctx;
    return 0;
}

static ssize_t zcomp_data_compress(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_action_t *action)
{
	struct zcomp_ctx *zctx = ctx;
	int ret;

    if(!zctx->init) {
	ret = deflateInit(&zctx->strm, zctx->level);
	if(ret != Z_OK)
	    return -1;
	zctx->init = 1;
    }

    if(*action != SXF_ACTION_REPEAT) {
	zctx->strm.avail_in = insize;
	zctx->strm.next_in = in;
    }
    if(*action == SXF_ACTION_DATA_END)
	zctx->end = 1;

    zctx->strm.avail_out = outsize;
    zctx->strm.next_out = out;
    ret = deflate(&zctx->strm, zctx->end == 1 ? Z_FINISH : Z_NO_FLUSH);
    if(ret == Z_STREAM_ERROR)
	return -1;

    if(!zctx->strm.avail_out)
	*action = SXF_ACTION_REPEAT;
    else
	*action = SXF_ACTION_NORMAL;

    return outsize - zctx->strm.avail_out;
}

static ssize_t zcomp_data_decompress(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_action_t *action)
{
	struct zcomp_ctx *zctx = ctx;
	int ret;

    if(!zctx->init) {
	zctx->strm.avail_in = 0;
	zctx->strm.next_in = Z_NULL;
	ret = inflateInit(&zctx->strm);
	if(ret != Z_OK)
	    return -1;
	zctx->init = 2;
    }

    if(*action != SXF_ACTION_REPEAT) {
	zctx->strm.avail_in = insize;
	zctx->strm.next_in = in;
    }

    zctx->strm.avail_out = outsize;
    zctx->strm.next_out = out;
    ret = inflate(&zctx->strm, Z_SYNC_FLUSH);
    switch(ret) {
	case Z_STREAM_ERROR:
        case Z_NEED_DICT:
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
	    ERROR("ERROR: inflate error (%d)", ret);
	    return -1;
    }

    if(zctx->strm.avail_in && !zctx->strm.avail_out)
	*action = SXF_ACTION_REPEAT;
    else
	*action = SXF_ACTION_NORMAL;

    return outsize - zctx->strm.avail_out;
}

static ssize_t zcomp_data_process(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action)
{
    if(mode == SXF_MODE_UPLOAD)
	return zcomp_data_compress(handle, ctx, in, insize, out, outsize, action);
    else
	return zcomp_data_decompress(handle, ctx, in, insize, out, outsize, action);
}

static int zcomp_data_finish(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode)
{
	struct zcomp_ctx *zctx = *ctx;

    if(zctx->init == 1)
	deflateEnd(&zctx->strm);
    else if(zctx->init == 2)
	inflateEnd(&zctx->strm);

    free(zctx);
    *ctx = NULL;
    return 0;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "zcomp",
/* const char *shortdesc */	    "Compress files using zlib",
/* const char *summary */	    "The filter automatically compresses and decompresses all data using zlib library.",
/* const char *options */	    "level:N (N = 1..9)",
/* const char *uuid */		    "d5dbdf0a-fb17-4d1b-a9ce-4060317af5b5",
/* sxf_type_t type */		    SXF_TYPE_COMPRESS,
/* int version[2] */		    {1, 0},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */	    zcomp_init,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */    zcomp_shutdown,
/* int (*configure)(const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len) */
				    zcomp_configure,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    zcomp_data_prepare,
/* ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action) */
				    zcomp_data_process,
/* int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode) */
				    zcomp_data_finish,
/* int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_metalist_t **metalist, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    NULL,
/* void (*file_notify)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path) */
				    NULL,
/* int (*file_update)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive) */
				    NULL,
/* internal */
/* const char *tname; */	    NULL
};

