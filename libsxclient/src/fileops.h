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

#ifndef __FILEOPS_H
#define __FILEOPS_H

#include "default.h"
#include <sys/types.h>

#include "sx.h"

struct file_upload_ctx;
struct host_upload_ctx;
struct file_download_ctx;
struct generic_ctx;

/* Rate at wchich progress function should call external progress handler */
#define XFER_PROGRESS_INTERVAL          0.5
#define XFER_TIME_WINDOW_WIDTH          (256.0 * XFER_PROGRESS_INTERVAL)
#define XFER_PROGRESS_ETA_DELAY         2.0 /* after 2 seconds we will compute speed and eta */

/* Timeouts for block transfers */
#define BLOCK_XFER_HARD_TIMEOUT         3600 /* 1 hour */
#define BLOCK_XFER_SOFT_TIMEOUT         1200  /* 20 minutes */

/* Set information about current transfer download value */
int sxi_file_download_set_xfer_stat(struct file_download_ctx* ctx, int64_t downloaded, int64_t to_download);
/* Get numner of bytes to be downloaded */
int64_t sxi_file_download_get_xfer_to_send(const struct file_download_ctx *ctx);
/* Get number of bytes already downloaded */
int64_t sxi_file_download_get_xfer_sent(const struct file_download_ctx *ctx);

/* Set information about current transfer upload value */
int sxi_host_upload_set_xfer_stat(struct host_upload_ctx* ctx, int64_t uploaded, int64_t to_upload);
/* Get number of bytes to be downloaded */
int64_t sxi_host_upload_get_xfer_to_send(const struct host_upload_ctx *ctx);
/* Get number of bytes already downloaded */
int64_t sxi_host_upload_get_xfer_sent(const struct host_upload_ctx *ctx);

/* Update transfer information */
int sxi_set_xfer_stat(sxc_xfer_stat_t *xfer_stat, int64_t dl, int64_t ul, double timediff);

/* Update timing information for progress stats */
int sxi_update_time_window(sxc_xfer_progress_t *xfer, int64_t bytes, int64_t skipped);

/* sxfs related helpers */
typedef struct _sxi_sxfs_data_t {
    unsigned int blocksize, nhashes;
    int64_t filesize;
    char *sourcepath, **ha;
    void *bh;
} sxi_sxfs_data_t;

sxi_sxfs_data_t *sxi_sxfs_download_init(sxc_file_t *source);
int sxi_sxfs_download_run(sxi_sxfs_data_t *sxfs, sxc_cluster_t *cluster, sxc_file_t *dest, off_t offset, long int size);
void sxi_sxfs_download_finish(sxi_sxfs_data_t *sxfs);

int sxi_file_set_ctime(sxc_file_t *file, time_t creatd_at);

int sxi_filemeta_process(sxc_client_t *sx, struct filter_handle *fh, const char *cfgdir, sxc_file_t *file, sxc_meta_t *custom_volume_meta);

int sxi_file_process(sxc_client_t *sx, struct filter_handle *fh, const char *cfgdir, sxc_file_t *file, sxf_mode_t mode);

sxc_file_t *sxi_file_remote(sxc_cluster_t *cluster, const char *volume, const char *path, const char *remote_path, const char *revision, sxc_meta_t *filemeta, int meta_fetched);
sxc_file_t *sxi_file_dup(sxc_file_t *file);
char *sxi_get_filter_dir(sxc_client_t *sx, const char *confdir, const char *uuid, const char *volume);
sxc_file_t *sxi_file_local(sxc_client_t *sx, const char *path, sxc_meta_t *meta);


/* File properties setters */
int sxi_file_set_mode(sxc_file_t *file, mode_t mode);
int sxi_file_set_ctime(sxc_file_t *file, time_t c_time);
int sxi_file_set_atime(sxc_file_t *file, time_t a_time);
int sxi_file_set_mtime(sxc_file_t *file, time_t m_time);
int sxi_file_set_created_at(sxc_file_t *file, time_t created_at);
int sxi_file_set_uid(sxc_file_t *file, uid_t uid);
int sxi_file_set_gid(sxc_file_t *file, uid_t gid);
int sxi_file_set_remote_path(sxc_file_t *file, const char *newpath);
int sxi_file_set_size(sxc_file_t *file, uint64_t size);
int sxi_file_set_remote_size(sxc_file_t *file, uint64_t remote_size);
int sxi_file_set_meta(sxc_file_t *file, sxc_meta_t *meta);
int sxi_file_meta_add (sxc_file_t *file, const char *key, const void* value, unsigned int value_len);

#endif
