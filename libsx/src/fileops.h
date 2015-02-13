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
/* Get numner of bytes to be downloaded */
int64_t sxi_host_upload_get_xfer_to_send(const struct host_upload_ctx *ctx);
/* Get number of bytes already downloaded */
int64_t sxi_host_upload_get_xfer_sent(const struct host_upload_ctx *ctx);

/* Update transfer information */
int sxi_set_xfer_stat(sxc_xfer_stat_t *xfer_stat, int64_t dl, int64_t ul, double timediff);

/* Update timing information for progress stats */
int sxi_update_time_window(sxc_xfer_progress_t *xfer, int64_t bytes, int64_t skipped);

#endif
