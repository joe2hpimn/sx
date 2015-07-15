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

#include "sx.h"

#define DEFAULT_TRASH "/.Trash/"

#define ERROR(...)      sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__)
#define WARNING(...)    sxc_filter_msg(handle, SX_LOG_WARNING, __VA_ARGS__)

struct undelete_ctx {
    int warn;
};

static int undelete_init(const sxf_handle_t *handle, void **ctx)
{
    struct undelete_ctx *uctx;

    uctx = malloc(sizeof(struct undelete_ctx));
    if(!uctx)
	return 1;
    uctx->warn = 0;
    *ctx = uctx;
    return 0;
}

static int undelete_shutdown(const sxf_handle_t *handle, void *ctx)
{
    free(ctx);
    return 0;
}

static int undelete_configure(const sxf_handle_t *handle, const char *cfg, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_meta)
{
    const char *path = cfg;
    char *parsed;

    if(!cfg)
        return 0;

    parsed = calloc(strlen(cfg) + 2, sizeof(char));
    if(!parsed) {
	ERROR("OOM");
	return 1;
    }
    if(*cfg != '/') {
	const char *pt = strchr(cfg, ':');
	if(!pt) {
	    ERROR("Invalid configuration data, must be in format '[volume:]/dir'");
	    free(parsed);
	    return 1;
	}
	strncpy(parsed, cfg, pt - cfg + 1);
	path = ++pt;
    }
    if(*path != '/') {
	ERROR("Invalid configuration data, must be in format '[volume:]/dir'");
	free(parsed);
	return 1;
    }
    while(strlen(path) > 1 && path[1] == '/')
	path++;
    if(strlen(path) <= 1) {
	ERROR("Invalid configuration data, must be in format '[volume:]/dir'");
	free(parsed);
	return 1;
    }
    strcat(parsed, path);
    if(path[strlen(path) - 1] != '/')
	strcat(parsed, "/");

    *cfgdata = parsed;
    *cfgdata_len = strlen(parsed);
    return 0;
}

int copy_to_trash(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive)
{
    struct undelete_ctx *uctx = ctx;
    sxc_file_t *copy;
    char *cfg = NULL, *newpath;
    const char *vol = sxc_file_get_volume(source), *trash = DEFAULT_TRASH, *path = sxc_file_get_path(source), *tp;
    int ret = 1;

    if(mode != SXF_MODE_DELETE || !path || !strlen(path))
	return 0;

    if(cfgdata_len) {
	char *pt;
	cfg = malloc(cfgdata_len + 1);
	if(!cfg) {
	    ERROR("OOM");
	    return 1;
	}
	memcpy(cfg, cfgdata, cfgdata_len);
	cfg[cfgdata_len] = 0;
	if((pt = strchr(cfg, ':'))) {
	    *pt = 0;
	    vol = cfg;
	    trash = ++pt;
	} else
	    trash = cfg;
    }

    tp = (*path == '/') ? trash : &trash[1];
    if(!strncmp(path, tp, strlen(tp)) && !strcmp(vol, sxc_file_get_volume(source))) {
	if(recursive) {
	    if(!uctx->warn) {
		WARNING("Files from '%s' will not be removed in recursive mode", trash);
		uctx->warn = 1;
	    }
	    free(cfg);
	    return 100;
	}
	free(cfg);
	return 0;
    }

    newpath = malloc(strlen(trash) + strlen(path) + 1);
    if(!newpath) {
	free(cfg);
	ERROR("OOM");
	return 1;
    }
    sprintf(newpath, "%s%s", trash, path);
    copy = sxc_file_remote(sxc_file_get_cluster(source), vol, newpath, NULL);
    if(copy) {
	ret = sxc_copy(source, copy, 0, 0, 0, NULL, 1);
	if(ret)
	    ERROR("Cannot make a backup copy, file will not be deleted");
	sxc_file_free(copy);
    }
    free(cfg);
    free(newpath);

    return ret;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "undelete",
/* const char *shortdesc */	    "Backup removed files",
/* const char *summary */	    "Move files to a trash directory (default /.Trash/) when they're deleted. Deleting files from trash will remove them permanently.",
/* const char *options */	    "[volume:]/path/to/trash",
/* const char *uuid */		    "7e7b7a8f-e294-458a-a2ab-ed8944ffce5c",
/* sxf_type_t type */		    SXF_TYPE_GENERIC,
/* int version[2] */		    {1, 2},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */
				    undelete_init,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */
				    undelete_shutdown,
/* int (*configure)(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_meta) */
				    undelete_configure,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    NULL,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_meta, sxf_mode_t mode) */
				    NULL,
/* int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode) */
				    NULL,
/* int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_metalist_t **metalist, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    NULL,
/* void (*file_notify)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path) */
				    NULL,
/* int (*file_update)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive) */
				    copy_to_trash,
/* internal */
/* const char *tname; */	    NULL
};

