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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>

#include "sx.h"

#ifdef WORDS_BIGENDIAN
uint32_t swapu32(uint32_t v)
{
    v = ((v << 8) & 0xff00ff00) | ((v >> 8) & 0xff00ff); 
    return (v << 16) | (v >> 16);
}
uint64_t swapu64(uint64_t v)
{
    v = ((v << 8) & 0xff00ff00ff00ff00ULL) | ((v >> 8) & 0x00ff00ff00ff00ffULL);
    v = ((v << 16) & 0xffff0000ffff0000ULL) | ((v >> 16) & 0x0000ffff0000ffffULL);
    return (v << 32) | (v >> 32);
}
#else
#define swapu32(x) (x)
#define swapu64(x) (x)
#endif

#define ERROR(...)	{ sxc_filter_msg(handle, SX_LOG_ERR, __VA_ARGS__); }
#define WARN(...)	{ sxc_filter_msg(handle, SX_LOG_WARNING, __VA_ARGS__); }

static int attribs_process_up(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_meta_t *meta, const void *cfgdata, unsigned int cfgdata_len)
{
	struct stat sb;
	uint32_t val32;
	uint64_t val64;
	unsigned int i, nmeta = sxc_meta_count(meta);

    /* Do not override existing attributes */
    for(i=0; i<nmeta; i++) {
	const char *key;
	if(sxc_meta_getkeyval(meta, i, &key, NULL, NULL))
	    return 1;
	if(!strncmp(key, "attribs", sizeof("attribs")-1))
	    return 0;
    }

    if(sxc_meta_setval(meta, "attribsName", filename, strlen(filename)))
	return 1;

    if(stat(filename, &sb) == -1) {
	ERROR("Failed to stat file %s", filename);
	return 1;
    }

    val32 = swapu32(sb.st_mode);
    if(sxc_meta_setval(meta, "attribsMode", &val32, sizeof(val32)))
	return 1;

    val32 = swapu32(sb.st_uid);
    if(sxc_meta_setval(meta, "attribsUID", &val32, sizeof(val32)))
	return 1;

    val32 = swapu32(sb.st_gid);
    if(sxc_meta_setval(meta, "attribsGID", &val32, sizeof(val32)))
	return 1;

    val64 = swapu64(sb.st_mtime);
    if(sxc_meta_setval(meta, "attribsAtime", &val64, sizeof(val64)))
	return 1;

    val64 = swapu64(sb.st_mtime);
    if(sxc_meta_setval(meta, "attribsMtime", &val64, sizeof(val64)))
	return 1;

    val64 = swapu64(sb.st_size);
    if(sxc_meta_setval(meta, "attribsSize", &val64, sizeof(val64)))
	return 1;

    return 0;
}

static int attribs_process_down(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_meta_t *meta, const void *cfgdata, unsigned int cfgdata_len)
{
	const void *val, *val2;
	unsigned int len, len2;
	struct utimbuf utb;

    sxc_meta_getval(meta, "attribsMode", &val, &len);
    if(len != sizeof(uint32_t))
	return 1;
    if(chmod(filename, (mode_t)swapu32(*(uint32_t *) val)))
	WARN("Failed to chmod file %s", filename);

    /* root only */
    sxc_meta_getval(meta, "attribsUID", &val, &len);
    sxc_meta_getval(meta, "attribsGID", &val2, &len2);
    if(len != sizeof(uint32_t) || len2 != sizeof(uint32_t))
	return 1;
    chown(filename, (uid_t)swapu32(*(uint32_t *) val), (gid_t)swapu32(*(uint32_t *) val2));

    sxc_meta_getval(meta, "attribsAtime", &val, &len);
    sxc_meta_getval(meta, "attribsMtime", &val2, &len2);
    if(len != sizeof(uint64_t) || len2 != sizeof(uint64_t))
	return 1;
    utb.actime = swapu64(*(uint64_t *) val);
    utb.modtime = swapu64(*(uint64_t *) val2);
    if(utime(filename, &utb))
	WARN("Failed to set times for file %s", filename);

    return 0;
}

static int attribs_process(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_meta_t *filemeta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode)
{
    if(mode == SXF_MODE_UPLOAD)
	return attribs_process_up(handle, ctx, filename, filemeta, cfgdata, cfgdata_len);
    else
	return attribs_process_down(handle, ctx, filename, filemeta, cfgdata, cfgdata_len);
}

sxc_filter_t sxc_filter={
/* int abi_version */		    SXF_ABI_VERSION,
/* const char *shortname */	    "attribs",
/* const char *shortdesc */	    "Preserve file attributes",
/* const char *summary */	    "Preserve attributes while storing files in SX.",
/* const char *options */	    NULL,
/* const char *uuid */		    "43122b8c-56d1-4671-8500-aa6831eb983c",
/* sxf_type_t type */		    SXF_TYPE_GENERIC,
/* int version[2] */		    {1, 2},
/* int (*init)(const sxf_handle_t *handle, void **ctx) */	    NULL,
/* int (*shutdown)(const sxf_handle_t *handle, void *ctx) */    NULL,
/* int (*configure)(const sxf_handle_t *handle, const char *cfgstr, const char *cfgdir, void **cfgdata, unsigned int *cfgdata_len, sxc_meta_t *custom_meta) */
				    NULL,
/* int (*data_prepare)(const sxf_handle_t *handle, void **ctx, const char *filename, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxc_meta_t *custom_meta, sxf_mode_t mode) */
				    NULL,
/* ssize_t (*data_process)(const sxf_handle_t *handle, void *ctx, const void *in, size_t insize, void *out, size_t outsize, sxf_mode_t mode, sxf_action_t *action) */
				    NULL,
/* int (*data_finish)(const sxf_handle_t *handle, void **ctx, sxf_mode_t mode) */
				    NULL,
/* int (*file_process)(const sxf_handle_t *handle, void *ctx, const char *filename, sxc_meta_t *meta, const char *cfgdir, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode) */
				    attribs_process,
/* void (*file_notify)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path) */
				    NULL,
/* int (*file_update)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, sxc_file_t *source, sxc_file_t *dest, int recursive) */
				    NULL,
/* internal */
/* const char *tname; */	    NULL
};

