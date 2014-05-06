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
#include <sys/types.h>

#include "sx.h"

#define DEBUG(...)	sxc_filter_msg(handle, SX_LOG_DEBUG, __VA_ARGS__)

static int null_init(const sxf_handle_t *handle, void **ctx)
{
    DEBUG("in null_init()");
    return 0;
}

static int null_shutdown(const sxf_handle_t *handle, void *ctx)
{
    DEBUG("in null_shutdown()");
    return 0;
}

static int null_data_prepare(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode)
{
    DEBUG("in null_data_prepare()");
    return 0;
}

static ssize_t null_data_process(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action)
{
    size_t l = insize > outsize ? outsize : insize;
    DEBUG("in null_data_process()");
    memcpy(out, in, l);
    return l;
}

int null_data_finish(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode)
{
    DEBUG("in null_data_end()");
    return 0;
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "null",
/* const char *fullname */	    "Null Filter",
/* const char *summary */	    "It does nothing.",
/* const char *options */	    NULL,
/* const char *uuid */		    "22d5cda2-9ed2-4229-a50a-04a249b1ad3d",
/* sxf_type_t type */		    SXF_TYPE_GENERIC,
/* int version[2] */		    {1, 1},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */	    null_init,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */   null_shutdown,
/* int (*configure)(const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len) */
				    NULL,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    null_data_prepare,
/* ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action) */
				    null_data_process,
/* int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode) */
				    null_data_finish,
/* int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_metalist_t **metalist, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    NULL,
/* internal */
/* const char *tname; */	    NULL
};

