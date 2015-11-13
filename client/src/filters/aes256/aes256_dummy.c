/*
 *  Copyright (C) 2012-2015 Skylable Ltd. <info-copyright@skylable.com>
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

#include "libsxclient/src/misc.h"
#include "libsxclient/src/fileops.h"
#include "server/src/common/sxlimits.h"
#include "sx.h"

#define ERROR(...)	sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__)

static int aes256_dummy_init(const sxf_handle_t *handle, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static int aes256_dummy_configure(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_volume_meta)
{
    ERROR("This filter cannot be configured, please use 'aes256' instead.");
    return -1;
}

static int aes256_dummy_data_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode)
{
    if(mode == SXF_MODE_UPLOAD)
	ERROR("The old version of this filter is no longer supported. Please create a new volume with the latest version of the aes256 filter from SX 2.x");
    else
	ERROR("The old version of this filter is no longer supported. Please use SX 1.2 to download all files from the volume, then create a new volume with the latest version of the aes256 filter from SX 2.x");

    return -1;
}

static ssize_t aes256_dummy_data_process(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action)
{
    return -1;
}

static int aes256_dummy_shutdown(const sxf_handle_t *handle, void *ctx)
{
    return 0;
}

static int aes256_dummy_data_finish(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode)
{
    return -1;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "aes256_old",
/* const char *shortdesc */	    "dummy filter for old aes256 versions",
/* const char *summary */	    "This filter does nothing, use 'aes256' instead.",
/* const char *options */	    "",
/* const char *uuid */		    "35a5404d-1513-4009-904c-6ee5b0cd8634",
/* sxf_type_t type */		    SXF_TYPE_CRYPT,
/* int version[2] */		    {0, 0},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */	    aes256_dummy_init,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */    aes256_dummy_shutdown,
/* int (*configure)(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_volume_meta) */
				    aes256_dummy_configure,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_volume_meta, sxf_mode_t mode) */
				    aes256_dummy_data_prepare,
/* ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action) */
				    aes256_dummy_data_process,
/* int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode) */
				    aes256_dummy_data_finish,
/* int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_metalist_t **metalist, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    NULL,
/* void (*file_notify)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path) */
				    NULL,
/* int (*file_update)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive) */
				    NULL,
/* int (*filemeta_process)(const sxf_handle_t *handle, void **ctx, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_file_t *file, sxf_filemeta_type_t filemeta_type, const char *filename, char **new_filename, sxc_meta_t *file_meta, sxc_meta_t *custom_volume_meta) */
				    NULL,
/* internal */
/* const char *tname; */	    NULL
};
