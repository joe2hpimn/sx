/*
 *  Copyright (C) 2012-2015 Skylable Ltd. <info-copyright@skylable.com>
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

#include "default.h" /* must include before system headers, cause it changes size of off_t! */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>
#include <curl/curl.h>
#include <fnmatch.h>
#include <utime.h>

#include "sx.h"
#include "misc.h"
#include "hostlist.h"
#include "clustcfg.h"
#include "filter.h"
#include "volops.h"
#include "sxproto.h"
#include "jobpoll.h"
#include "libsxclient-int.h"
#include "curlevents.h"
#include "vcrypto.h"
#include "jparse.h"

struct _sxc_file_t {
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    char *volume;
    char *path;
    char *rev;
    char *origpath;
    char *remote_path;
    uint64_t size;
    uint64_t remote_size;
    time_t created_at;
    sxi_ht *seen;
    int cat_fd;
    /* Set to 1 when filemeta has been fetched from the server */
    int meta_fetched;

    /* Needed for file processing filters */
    sxc_meta_t *meta;

    time_t a_time;
    time_t c_time;
    time_t m_time;

    uid_t uid;
    uid_t gid;

    mode_t mode;
};

sxc_xfer_stat_t* sxi_xfer_new(sxc_client_t *sx, sxc_xfer_callback xfer_callback, void *ctx) {
    sxc_xfer_stat_t *xfer_stat;

    if(!xfer_callback)
        return NULL;

    xfer_stat = calloc(1, sizeof(sxc_xfer_stat_t));
    if(!xfer_stat) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        return NULL;
    }

    xfer_stat->status = SXC_XFER_STATUS_STARTED;
    xfer_stat->ctx = ctx;
    gettimeofday(&xfer_stat->start_time, NULL);
    gettimeofday(&xfer_stat->interval_timer, NULL);
    xfer_stat->xfer_callback = xfer_callback;
    return xfer_stat;
}

static void xfer_update_speed(sxc_xfer_progress_t *xfer) {
    unsigned int i;
    int64_t total_sent = 0; /* Total number of bytes sent in time window */
    int64_t total_skipped = 0; /* Total number of bytes skipped in time window */
    double total_time = xfer->total_time < XFER_TIME_WINDOW_WIDTH ? xfer->total_time : XFER_TIME_WINDOW_WIDTH;

    for(i = 0; i < 256; i++) {
        total_sent += xfer->timing[i].sent;
        total_skipped += xfer->timing[i].skipped;
    }

    if(xfer->total_time > XFER_PROGRESS_ETA_DELAY) {
        xfer->speed = (total_sent + total_skipped) / total_time;
        xfer->eta = xfer->speed > 0 && xfer->to_send - xfer->sent > 0 ? (xfer->to_send - xfer->sent) / xfer->speed : 0;
    }
    xfer->real_speed = total_sent / total_time;
}

/* Update timing information for progress stats */
int sxi_update_time_window(sxc_xfer_progress_t *xfer, int64_t bytes, int64_t skipped) {
    unsigned int s, i;

    if(!xfer)
        return 1;

    s = (long long)(xfer->total_time / XFER_PROGRESS_INTERVAL) & 255;

    if(xfer->last_time_idx != s) {
        for(i = 1; i < 256 && ((xfer->last_time_idx + i) & 255) != s; i++) {
            xfer->timing[(xfer->last_time_idx + i) & 255].sent = 0;
            xfer->timing[(xfer->last_time_idx + i) & 255].skipped = 0;
        }
        xfer->timing[s].sent = 0;
        xfer->timing[s].skipped = 0;
    }

    xfer->timing[s].sent += bytes;
    xfer->timing[s].skipped += skipped;

    xfer_update_speed(xfer);

    /* Remember last update index */
    xfer->last_time_idx = s;

    return 0;
}

static void reset_time_window(sxc_xfer_progress_t *xfer) {
    unsigned int i;

    xfer->last_time_idx = 0;
    for(i = 0; i < 256; i++) {
        xfer->timing[i].sent = 0;
        xfer->timing[i].skipped = 0;
    }

    xfer->speed = 0;
    xfer->real_speed = 0;
    xfer->eta = 0;
}

int sxi_set_xfer_stat(sxc_xfer_stat_t *xfer_stat, int64_t dl, int64_t ul, double timediff) {
    struct timeval now;
    if(!xfer_stat || !xfer_stat->xfer_callback)
        return SXE_EARG; /* Called with wrong arguments */

    /* Increase current file counter */
    xfer_stat->current_xfer.sent += dl + ul;

    /* Increase total counters */
    if(xfer_stat->current_xfer.direction & SXC_XFER_DIRECTION_DOWNLOAD)
        xfer_stat->total_dl += dl;
    if(xfer_stat->current_xfer.direction & SXC_XFER_DIRECTION_UPLOAD)
        xfer_stat->total_ul += ul;

    gettimeofday(&now, NULL);
    xfer_stat->current_xfer.total_time = sxi_timediff(&now, &xfer_stat->current_xfer.start_time);

    if(sxi_update_time_window(&xfer_stat->current_xfer, dl + ul, 0)) /* update timing information */
        return SXE_EARG; /* sxi_update_time_window returns error only if given arguments are not correct */

    if(timediff >= XFER_PROGRESS_INTERVAL) {
        memcpy(&xfer_stat->interval_timer, &now, sizeof(struct timeval));

        /* Update total transfer time */
        xfer_stat->total_time += timediff;

        /* Invoke callback */
        return xfer_stat->xfer_callback(xfer_stat);
    }

    return SXE_NOERROR;
}

static int sxi_xfer_set_file(sxc_xfer_stat_t *xfer_stat, const char *file_name, int64_t file_size, unsigned int blocksize, sxc_xfer_direction_t xfer_direction) {
    if(!xfer_stat)
        return 1;

    if(xfer_direction & SXC_XFER_DIRECTION_DOWNLOAD) {
        xfer_stat->total_to_dl += file_size;
        xfer_stat->total_data_dl += file_size;
    }
    if(xfer_direction & SXC_XFER_DIRECTION_UPLOAD) {
        xfer_stat->total_to_ul += file_size;
        xfer_stat->total_data_ul += file_size;
    }

    xfer_stat->current_xfer.file_name = file_name;
    xfer_stat->current_xfer.file_size = file_size;
    xfer_stat->current_xfer.blocksize = blocksize;
    xfer_stat->current_xfer.direction = xfer_direction;
    xfer_stat->current_xfer.to_send = file_size;

    /* If data is to be transferred both ways we have to double size of data to send */
    if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_BOTH)
        xfer_stat->current_xfer.to_send *= 2;

    xfer_stat->current_xfer.sent = 0;
    xfer_stat->current_xfer.total_time = 0;
    gettimeofday(&xfer_stat->current_xfer.start_time, NULL);
    reset_time_window(&xfer_stat->current_xfer);

    xfer_stat->status = SXC_XFER_STATUS_PART_STARTED;
    return 0;
}

/*
 * Skip part of transfer data
 * Return error code
 */
static int skip_xfer(sxc_cluster_t *cluster, int64_t bytes) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxc_xfer_stat_t *xfer_stat = sxi_cluster_get_xfer_stat(cluster);
    struct timeval now;

    if(!xfer_stat || !xfer_stat->xfer_callback) 
        return SXE_EARG;

    xfer_stat->current_xfer.to_send -= bytes;

    /* If we are skipping transfers that are needed to be downloaded and uploaded, we have to double its value */
    if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_BOTH)
        xfer_stat->current_xfer.to_send -= bytes;

    if(xfer_stat->current_xfer.direction & SXC_XFER_DIRECTION_DOWNLOAD)
        xfer_stat->total_to_dl -= bytes;
    if(xfer_stat->current_xfer.direction & SXC_XFER_DIRECTION_UPLOAD)
        xfer_stat->total_to_ul -= bytes;

    gettimeofday(&now, NULL);
    xfer_stat->current_xfer.total_time = sxi_timediff(&now, &xfer_stat->current_xfer.start_time);

    if(sxi_update_time_window(&xfer_stat->current_xfer, 0, bytes))
        return SXE_EARG; /* sxi_update_time_window returns an error if wrong arguments were given */

    if(sxc_geterrnum(sx) != SXE_ABORT && sxi_timediff(&now, &xfer_stat->interval_timer) >= XFER_PROGRESS_INTERVAL) {
        memcpy(&xfer_stat->interval_timer, &now, sizeof(struct timeval));

        /* Invoke callback to allow client side to present skipped blocks */
        return xfer_stat->xfer_callback(xfer_stat);
    } else
        return sxc_geterrnum(sx);
}

/* Download table is at most 5MB and allows for up to 128GB of uniq content */
#define BLOCKS_PER_TABLE 131072
#define INITIAL_HASH_ITEMS MIN(BLOCKS_PER_TABLE, 256)
#define cluster_err(...) sxi_seterr(sxi_cluster_get_client(cluster), __VA_ARGS__)
#define cluster_syserr(...) sxi_setsyserr(sxi_cluster_get_client(cluster), __VA_ARGS__)

struct _sxc_exclude_t {
    unsigned int n; /* Number of patterns */
    char **pattern; /* Array of patterns */
    int mode; /* Set SXC_EXCLUDE for excludes and SXC_INCLUDE for includes */
};

/* Fill sxc_exclude_t structure */
sxc_exclude_t *sxc_exclude_init(sxc_client_t *sx, const char **patterns, unsigned int npatterns, int mode) {
    sxc_exclude_t *ret = NULL, *e;
    unsigned int i;

    if(!patterns) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return NULL;
    }

    e = malloc(sizeof(*e));
    if(!e) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        return NULL;
    }
    e->n = npatterns;
    e->mode = mode;

    e->pattern = calloc(1, sizeof(char*) * npatterns);
    if(!e->pattern) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
        goto sxc_exclude_init_err;
    }

    for(i = 0; i < npatterns; i++) {
        if(!patterns[i]) {
            sxi_seterr(sx, SXE_EARG, "Invalid argument: NULL pattern");
            goto sxc_exclude_init_err;
        }

        if(!(e->pattern[i] = strdup(patterns[i]))) {
            sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
            goto sxc_exclude_init_err;
        }
    }

    ret = e;
sxc_exclude_init_err:
    if(!ret)
        sxc_exclude_delete(e);
    return ret;
}

void sxc_exclude_delete(sxc_exclude_t *e) {
    unsigned int i;

    if(!e)
        return;

    for(i = 0; i < e->n; i++)
        free(e->pattern[i]);
    free(e->pattern);
    free(e);
}

/* Return 1 if file should be excluded, 0 if not, -1 if error occured.
 * When NULL is passed as exclude argument 0 is returned. */
static int is_excluded(sxc_client_t *sx, const char *path, const sxc_exclude_t *exclude) {
    unsigned int i;

    if(!path) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }

    if(!exclude) /* If no patterns given, skip checking */
        return 0;
 
    /* Iterate over given patterns */
    for(i = 0; i < exclude->n; i++) {
        if(!fnmatch(exclude->pattern[i], path, 0))
            return exclude->mode == SXC_EXCLUDE ? 1 : 0;
    }

    return exclude->mode == SXC_EXCLUDE ? 0 : 1;
}

static int is_remote(sxc_file_t *f) {
    return f->cluster != NULL;
}

sxc_file_t *sxi_file_remote(sxc_cluster_t *cluster, const char *volume, const char *path, const char *remote_path, const char *revision, sxc_meta_t *filemeta, int meta_fetched) {
    sxc_file_t *ret;

    if(!cluster || !sxi_is_valid_cluster(cluster))
	return NULL;

    if(!volume || (!path && !remote_path)) {
	CFGDEBUG("called with NULL param");
	cluster_err(SXE_EARG, "Cannot create remote file object: Invalid argument");
	return NULL;
    }

    if(!(ret = calloc(1, sizeof(*ret)))) {
	CFGDEBUG("OOM allocating results");
	cluster_err(SXE_EMEM, "Cannot create remote file object: Out of memory");
	return NULL;
    }

    ret->sx = sxi_cluster_get_client(cluster);
    ret->cluster = cluster;
    ret->volume = strdup(volume);
    ret->rev = revision ? strdup(revision) : NULL;
    ret->path = path ? strdup(path) : NULL;
    ret->remote_path = remote_path ? strdup(remote_path) : NULL;
    ret->size = SXC_UINT64_UNDEFINED;
    ret->remote_size = SXC_UINT64_UNDEFINED;
    ret->created_at = SXC_UINT64_UNDEFINED;
    ret->a_time = SXC_UINT64_UNDEFINED;
    ret->c_time = SXC_UINT64_UNDEFINED;
    ret->m_time = SXC_UINT64_UNDEFINED;
    ret->mode = SXC_UINT32_UNDEFINED;
    ret->uid = SXC_UINT32_UNDEFINED;
    ret->gid = SXC_UINT32_UNDEFINED;
    ret->meta = sxi_meta_dup(ret->sx, filemeta);
    ret->meta_fetched = meta_fetched;

    if(!ret->volume || (path && !ret->path) || (remote_path && !remote_path) || (revision && !ret->rev) || (filemeta && !ret->meta)) {
	CFGDEBUG("OOM duplicating item");
	cluster_err(SXE_EMEM, "Cannot create local file object: Out of memory");
	sxc_file_free(ret);
	return NULL;
    }

    return ret;
}

sxc_file_t *sxc_file_remote(sxc_cluster_t *cluster, const char *volume, const char *path, const char *revision) {
    return sxi_file_remote(cluster, volume, path ? path : "", NULL, revision, NULL, 0);
}

int sxc_file_is_sx(sxc_file_t *file)
{
    return file && file->cluster;
}

sxc_file_t *sxc_file_local(sxc_client_t *sx, const char *path) {
    return sxi_file_local(sx, path, NULL);
}

sxc_file_t *sxi_file_local(sxc_client_t *sx, const char *path, sxc_meta_t *meta) {
    sxc_file_t *ret;

    if(!(ret = calloc(1, sizeof(*ret)))) {
	SXDEBUG("OOM allocating results");
	sxi_seterr(sx, SXE_EMEM, "Cannot create local file object: Out of memory");
	return NULL;
    }

    ret->sx = sx;
    ret->cluster = NULL;
    ret->volume = NULL;
    ret->remote_path = NULL;
    ret->remote_size = SXC_UINT64_UNDEFINED;
    ret->created_at = SXC_UINT64_UNDEFINED;
    ret->a_time = SXC_UINT64_UNDEFINED;
    ret->c_time = SXC_UINT64_UNDEFINED;
    ret->m_time = SXC_UINT64_UNDEFINED;
    ret->mode = SXC_UINT32_UNDEFINED;
    ret->uid = SXC_UINT32_UNDEFINED;
    ret->gid = SXC_UINT32_UNDEFINED;

    ret->path = strdup(path);
    if(!ret->path) {
	SXDEBUG("OOM duplicating item");
	sxi_seterr(sx, SXE_EMEM, "Cannot create local file object: Out of memory");
	free(ret);
	return NULL;
    }

    if(meta)
        ret->meta = sxi_meta_dup(sx, meta);
    else
        ret->meta = sxc_meta_new(sx);
    if(!ret->meta) {
	SXDEBUG("OOM creating local file object");
	sxi_seterr(sx, SXE_EMEM, "Cannot create local file object: Out of memory");
        free(ret->path);
        free(ret);
	return NULL;
    }
    return ret;
}

sxc_file_t *sxc_file_from_url(sxc_client_t *sx, sxc_cluster_t **cluster, const char *url)
{
    sxc_uri_t *uri;
    if (!sx)
        return NULL;
    if (!url || !cluster) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxc_file_from_url");
        return NULL;
    }
    if (!sxi_uri_is_sx(sx, url))
        return sxc_file_local(sx, url);
    if(*cluster) {
        sxi_seterr(sx, SXE_EARG, "Cluster has already been loaded");
        return NULL;
    }
    uri = sxc_parse_uri(sx, url);
    if (!uri)
        return NULL;
    do {
        sxc_file_t *file;

        if (!uri->volume) {
            sxi_seterr(sx, SXE_EARG,"Bad path %s: Volume name expected", url);
            break;
        }

        *cluster = sxc_cluster_load_and_update(sx, uri->host, uri->profile);
        if (!*cluster)
            break;
	file = sxc_file_remote(*cluster, uri->volume, uri->path, NULL);
        sxc_free_uri(uri);
        return file;
    } while(0);
    sxc_free_uri(uri);
    return NULL;
}

sxc_cluster_t *sxc_file_get_cluster(const sxc_file_t *file)
{
    return file ? file->cluster : NULL;
}

const char *sxc_file_get_volume(const sxc_file_t *file)
{
    return file ? file->volume : NULL;
}

const char *sxc_file_get_path(const sxc_file_t *file)
{
    return file ? file->path : NULL;
}

const char *sxc_file_get_remote_path(const sxc_file_t *file)
{
    return file ? file->remote_path : NULL;
}

const char *sxc_file_get_revision(const sxc_file_t *file)
{
    return file ? file->rev : NULL;
}

int64_t sxc_file_get_size(const sxc_file_t *file)
{
    return file ? file->size : SXC_UINT64_UNDEFINED;
}

int64_t sxc_file_get_remote_size(const sxc_file_t *file)
{
    return file ? file->remote_size : SXC_UINT64_UNDEFINED;
}

time_t sxc_file_get_created_at(const sxc_file_t *file)
{
    return file ? file->created_at : SXC_UINT64_UNDEFINED;
}

time_t sxc_file_get_ctime(const sxc_file_t *file)
{
    return file ? file->c_time : SXC_UINT64_UNDEFINED;
}

time_t sxc_file_get_atime(const sxc_file_t *file)
{
    return file ? file->a_time : SXC_UINT64_UNDEFINED;
}

time_t sxc_file_get_mtime(const sxc_file_t *file)
{
    return file ? file->m_time : SXC_UINT64_UNDEFINED;
}

mode_t sxc_file_get_mode(const sxc_file_t *file)
{
    return file ? file->mode : SXC_UINT32_UNDEFINED;
}

uid_t sxc_file_get_uid(const sxc_file_t *file)
{
    return file ? file->uid : SXC_UINT32_UNDEFINED;
}

uid_t sxc_file_get_gid(const sxc_file_t *file)
{
    return file ? file->gid : SXC_UINT32_UNDEFINED;
}

int sxi_file_set_size(sxc_file_t *file, uint64_t size) {
    if(!file)
        return 1;
    file->size = size;
    return 0;
}

int sxi_file_set_mode(sxc_file_t *file, mode_t mode) {
    if(!file)
        return 1;
    file->mode = mode;
    return 0;
}

int sxi_file_set_uid(sxc_file_t *file, uid_t uid) {
    if(!file)
        return 1;
    file->uid = uid;
    return 0;
}

int sxi_file_set_gid(sxc_file_t *file, uid_t gid) {
    if(!file)
        return 1;
    file->gid = gid;
    return 0;
}

int sxi_file_set_ctime(sxc_file_t *file, time_t c_time) {
    if(!file)
        return 1;
    file->c_time = c_time;
    return 0;
}

int sxi_file_set_atime(sxc_file_t *file, time_t a_time) {
    if(!file)
        return 1;
    file->a_time = a_time;
    return 0;
}

int sxi_file_set_mtime(sxc_file_t *file, time_t m_time) {
    if(!file)
        return 1;
    file->m_time = m_time;
    return 0;
}

int sxi_file_set_remote_size(sxc_file_t *file, uint64_t remote_size) {
    if(!file)
        return 1;
    file->remote_size = remote_size;
    return 0;
}

int sxi_file_set_created_at(sxc_file_t *file, time_t created_at) {
    if(!file)
        return 1;
    file->created_at = created_at;
    return 0;
}

int sxc_file_set_path(sxc_file_t *file, const char *newpath)
{
    char *pt;
    if(!file || !newpath)
	return 1;
    pt = strdup(newpath);
    if(!pt) {
	sxi_setsyserr(file->sx, SXE_EMEM, "Cannot strdup newpath");
	return 1;
    }
    free(file->path);
    file->path = pt;

    /* Changed local path may need updating the remote path */
    free(file->remote_path);
    file->remote_path = NULL;
    return 0;
}

int sxi_file_set_remote_path(sxc_file_t *file, const char *newpath)
{
    char *pt;
    if(!file || !newpath)
        return 1;
    pt = strdup(newpath);
    if(!pt) {
        sxi_setsyserr(file->sx, SXE_EMEM, "Cannot strdup newpath");
        return 1;
    }
    free(file->remote_path);
    file->remote_path = pt;
    return 0;
}

int sxi_file_set_meta(sxc_file_t *file, sxc_meta_t *meta)
{
    if(!file || !meta)
        return 1;
    sxc_meta_free(file->meta);
    file->meta = sxi_meta_dup(file->sx, meta);
    if(!file->meta)
        return 1;
    return 0;
}

sxc_file_t *sxi_file_dup(sxc_file_t *file)
{
    sxc_file_t *ret;
    sxc_client_t *sx;
    if (!file)
        return NULL;
    sx = file->sx;
    ret = calloc(1, sizeof(*file));
    do {
        if (!ret)
            break;
        ret->sx = sx;
        ret->cluster = file->cluster;
        ret->size = file->size;
        ret->remote_size = file->remote_size;
        ret->created_at = file->created_at;
        ret->a_time = file->a_time;
        ret->c_time = file->c_time;
        ret->m_time = file->m_time;
        ret->uid = file->uid;
        ret->gid = file->gid;
        ret->mode = file->mode;
        if (file->volume && !(ret->volume = strdup(file->volume)))
            break;
        if (file->path && !(ret->path = strdup(file->path)))
            break;
        if (file->origpath && !(ret->origpath = strdup(file->origpath)))
            break;
        if (file->rev && !(ret->rev = strdup(file->rev)))
            break;
        if(file->remote_path && !(ret->remote_path = strdup(file->remote_path)))
            break;
        if(file->meta && !(ret->meta = sxi_meta_dup(sx, file->meta)))
            break;
        ret->meta_fetched = file->meta_fetched;
        return ret;
    } while(0);
    sxi_setsyserr(sx, SXE_EMEM, "Cannot dup file");
    sxc_file_free(ret);
    return NULL;
}

void sxc_file_free(sxc_file_t *sxfile) {
    if(!sxfile)
	return;
    free(sxfile->origpath);
    free(sxfile->volume);
    free(sxfile->path);
    free(sxfile->remote_path);
    free(sxfile->rev);
    sxc_meta_free(sxfile->meta);
    sxi_ht_free(sxfile->seen);
    free(sxfile);
}

static int sxi_same_local_file(sxc_client_t *sx, const char *source, const char *dest, int srcfd, int dstfd)
{
    struct stat sb1, sb2;
    /* make sure they are different files even in the presence of links */
    if (fstat(srcfd, &sb1)) {
	sxi_setsyserr(sx, SXE_EARG, "Copy failed: cannot stat source file");
        return 1;
    }
    if (fstat(dstfd, &sb2)) {
	sxi_setsyserr(sx, SXE_EARG, "Copy failed: cannot stat dest file");
        return 1;
    }
    if (sb1.st_dev == sb2.st_dev &&
        sb1.st_ino == sb2.st_ino &&
        sb1.st_mode == sb2.st_mode) {
	sxi_seterr(sx, SXE_EARG, "'%s' and '%s' are the same file", source, dest);
        return 1;
    }
    return 0;
}

static int file_to_file(sxc_client_t *sx, const char *source, const char *dest, const sxc_exclude_t *exclude)
{
    char buf[8192];
    FILE *f, *d;
    int r;

    if((r = is_excluded(sx, source, exclude)) > 0) {
        sxi_info(sx, "Skipping file: %s", source);
        return 0;
    } else if(r < 0)
        return 1;

    if(!(f = fopen(source, "rb"))) {
	SXDEBUG("failed to open source file %s", source);
	sxi_setsyserr(sx, SXE_EREAD, "Copy failed: Cannot open source file");
	return 1;
    }

    if(!(d = fopen(dest, "wb"))) {
	SXDEBUG("failed to open dest file %s", dest);
	sxi_setsyserr(sx, SXE_EWRITE, "Copy failed: Cannot open destination file '%s'", dest);
	fclose(f);
	return 1;
    }
    if (sxi_same_local_file(sx, source, dest, fileno(f), fileno(d))) {
	fclose(f);
	fclose(d);
        return 1;
    }

    while(1) {
	size_t l = fread(buf, 1, sizeof(buf), f);
	if(!l)
	    break;
	if(!fwrite(buf, l, 1, d))
	    break;
    }

    if(!feof(f) && ferror(f)) {
	SXDEBUG("error reading from source file");
	sxi_setsyserr(sx, SXE_EREAD, "Copy failed: Error reading source file");
	fclose(f);
	fclose(d);
	return 1;
    }
    fclose(f);

    if(ferror(d)) {
	SXDEBUG("error writing to destination file");
	sxi_setsyserr(sx, SXE_EWRITE, "Copy failed: Error writing destination file");
	fclose(d);
	return 1;
    }

    return fclose(d);
}

static int cat_local_file(sxc_file_t *source, int dest);
static int local_to_local(sxc_file_t *source, sxc_file_t *dest, const sxc_exclude_t *exclude) {
    if (strcmp(dest->origpath, dest->path)) {
        /* dest is a dir, we must only mkdir exactly the given dest, not
         * subdirs */
        if (mkdir(dest->origpath, 0777) == -1 && errno != EEXIST) {
            sxi_setsyserr(source->sx, SXE_EARG, "Cannot create directory '%s'", dest->origpath);
            return -1;
        }
    }
    return file_to_file(source->sx, source->path, dest->path, exclude);
}

static int load_hosts_for_hash(sxc_client_t *sx, FILE *f, const char *hash, sxi_hostlist_t *host_list, sxi_ht *host_table) {
    int main_host = 1;
    int sz;

    while((sz = fgetc(f))) {
	char ho[64], *hlist;

	if(sz == EOF || sz <= 0 || sz >= (int) sizeof(ho)) {
	    SXDEBUG("failed to read host size");
	    sxi_seterr(sx, SXE_ETMP, "Copy failed: Premature end of cache file");
	    return 1;
	}
	if(!fread(ho, sz, 1, f)) {
	    SXDEBUG("failed to read host");
	    sxi_setsyserr(sx, SXE_ETMP, "Copy failed: Cannot read from cache file");
	    return 1;
	}
	if(!host_list)
	    continue;

	ho[sz] = '\0';
	if(sxi_hostlist_add_host(sx, host_list, ho)) {
	    SXDEBUG("failed to add host %s to list", ho);
	    return 1;
	}

	if(!main_host || !host_table)
	    continue;

	main_host = 0;
	if(sxi_ht_get(host_table, ho, sz+1, (void **)&hlist)) {
	    hlist = calloc(1, 40 * BLOCKS_PER_TABLE + 1);
	    if(!hlist) {
		SXDEBUG("OOM allocating hash list");
		sxi_setsyserr(sx, SXE_EMEM, "Copy failed: Out of memory");
		return 1;
	    }
	    if(sxi_ht_add(host_table, ho, sz+1, hlist)) {
		SXDEBUG("failed to add host to table");
		free(hlist);
		return 1;
	    }
	} else
	    hlist += strlen(hlist);
	memcpy(hlist, hash, 40);
    }

    return 0;
}

/* files >= UPLOAD_THRESHOLD must have SX_BS_LARGE, and
 * UPLOAD_THRESHOLD should be multiple of UPLOAD_CHUNK_SIZE */
#define UPLOAD_PART_THRESHOLD (132 * 1024 * 1024)

struct checksum_offset {
    off_t offset;
    uint32_t checksum;
    uint32_t ref_checksum;
};

struct need_hash {
    struct checksum_offset off;
    sxi_hostlist_t upload_hosts;
    unsigned replica;
};

struct part_upload_ctx {
    const struct jparse_actions *acts;
    jparse_t *J;
    enum sxc_error_t err;
    FILE *f;
    char *token;
    struct checksum_offset *offsets;
    struct need_hash *needed;
    struct need_hash *current_need;
    sxi_ht *hashes;
    unsigned needed_cnt;
    sxi_ht *hostsmap;
    int ref;/* how many batches are outstanding */
    sxi_retry_t *retry;
};

struct file_upload_ctx {
    curlev_context_t *cbdata;
    sxi_job_t *job;
    sxi_jobs_t *jobs;
    sxi_hostlist_t *volhosts;
    sxc_cluster_t *cluster;
    int64_t uploaded;
    char *name;
    time_t mtime;
    off_t pos;
    off_t end;
    off_t size;
    off_t last_pos;
    uint32_t ref_checksum;
    int fd;
    long qret;
    unsigned blocksize;
    unsigned max_part_blocks;
    char buf[SX_BS_LARGE];
    int upload_started;
    struct timeval t1;
    struct timeval t2;
    struct part_upload_ctx current;
    char *host;
    unsigned ok;
    unsigned flush_ok;
    unsigned fail;
    unsigned all_fail;
    int loop_count;
    sxc_file_t *dest;
    sxc_meta_t *fmeta;
    sxi_query_t *query;
    char *cur_token;
    /* only one part upload active at any on time.
     * This is to keep uploaded blocks sorted properly
     */
};

struct host_upload_ctx {
    char buf[UPLOAD_CHUNK_SIZE];
    unsigned buf_used;
    struct need_hash *needed;
    unsigned i;
    unsigned n;
    unsigned last_successful;
    int in_use;
    struct file_upload_ctx *yctx;

    /* Current download information, updated on CURL callbacks */
    sxi_conns_t *conns;
    int64_t ul;
    int64_t to_ul;
};

/* Set information about current transfer upload value */
int sxi_host_upload_set_xfer_stat(struct host_upload_ctx* ctx, int64_t uploaded, int64_t to_upload) {
    int64_t ul_diff = 0;
    double timediff = 0;
    struct timeval now;
    sxc_xfer_stat_t *xfer_stat;

    /* This is not considered as error, ctx or cluster == NULL if we do not want to check progress */
    if(!ctx || !(xfer_stat = sxi_conns_get_xfer_stat(ctx->conns)))
        return SXE_NOERROR;

    gettimeofday(&now, NULL);
    timediff = sxi_timediff(&now, &xfer_stat->interval_timer);

    ctx->to_ul = to_upload;
    ul_diff = uploaded - ctx->ul;
    ctx->ul = uploaded;

    if(ul_diff > 0 || timediff >= XFER_PROGRESS_INTERVAL) {
        return sxi_set_xfer_stat(xfer_stat, 0, ul_diff, timediff);
    } else
        return SXE_NOERROR;
}

/* Get numner of bytes to be uploaded */
int64_t sxi_host_upload_get_xfer_to_send(const struct host_upload_ctx *ctx) {
    if(!ctx || !sxi_conns_get_xfer_stat(ctx->conns))
        return 0;

    return ctx->to_ul;
}

/* Get number of bytes already uploaded */
int64_t sxi_host_upload_get_xfer_sent(const struct host_upload_ctx *ctx) {
    if(!ctx || !sxi_conns_get_xfer_stat(ctx->conns))
        return 0;

    return ctx->ul;
}

/*
{
    "uploadToken":"TOKEN",
    "uploadData":{
       "block1":["host1", "host2"],
       "block2":["host3", "host1"]
    }
}
*/

static void cb_createfile_token(jparse_t *J, void *ctx, const char *string, unsigned int length) {
     struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;

     if(yactx->current.token) {
         sxi_jparse_cancel(J, "Multiple upload tokens received");
         yactx->current.err = SXE_ECOMM;
         return;
     }

     yactx->current.token = malloc(length + 1);
     if(!yactx->current.token) {
         sxi_jparse_cancel(J, "Out of memory processing upload token");
         yactx->current.err = SXE_EMEM;
         return;
     }
     memcpy(yactx->current.token, string, length);
     yactx->current.token[length] = '\0';
}

static void cb_createfile_host(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *block = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    int listpos = sxi_jpath_arraypos(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
    struct checksum_offset *off;
    char *address;

    if(listpos < 0) {
        sxi_jparse_cancel(J, "Internal error: array index %d out of bounds", listpos);
        yactx->current.err = SXE_ECOMM;
        return;
    }
    if(!listpos) {
        if(strlen(block) != SXI_SHA1_TEXT_LEN) {
            sxi_jparse_cancel(J, "Invalid block name '%s'", block);
            yactx->current.err = SXE_ECOMM;
            return;
        }

        if (!yactx->current.hashes || sxi_ht_get(yactx->current.hashes, block, SXI_SHA1_TEXT_LEN, (void**)&off)) {
            sxi_jparse_cancel(J, "Unknown block '%s' requested for upload", block);
            yactx->current.err = SXE_ECOMM;
            return;
        }
        if (yactx->current.needed_cnt >= yactx->max_part_blocks) {
            sxi_jparse_cancel(J, "Invalid block number");
            yactx->current.err = SXE_ECOMM;
            return;
        }

        CBDEBUG("need %d off: %lld", yactx->current.needed_cnt, (long long)off->offset);
        yactx->current.current_need = &yactx->current.needed[yactx->current.needed_cnt++];
        yactx->current.current_need->off = *off;
        yactx->current.current_need->replica = 0;
        sxi_hostlist_init(&yactx->current.current_need->upload_hosts);
    }

    if(!length) {
        sxi_jparse_cancel(J, "Empty node address revceived for block %s", block);
        yactx->current.err = SXE_ECOMM;
        return;
    }

    if(sxi_getenv("SX_DEBUG_SINGLEHOST")) {
        string = sxi_getenv("SX_DEBUG_SINGLEHOST");
        length = strlen(string);
    }

    address = malloc(length + 1);
    if(!address) {
        sxi_jparse_cancel(J, "Out of memory processing upload nodes");
        yactx->current.err = SXE_EMEM;
        return;
    }
    memcpy(address, string, length);
    address[length] = '\0';

    /* FIXME: leak */
    if (sxi_hostlist_add_host(sx, &yactx->current.current_need->upload_hosts, address)) {
        free(address);
        sxi_jparse_cancel(J, "Out of memory building list of source nodes");
        yactx->current.err = SXE_EMEM;
        return;
    }
    free(address);
}

static void cb_createfile_array_end(jparse_t *J, void *ctx) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    yactx->current.current_need = NULL;
}

static int createfile_setup_cb(curlev_context_t *cbdata, const char *host) {
    struct file_upload_ctx *yactx = sxi_cbdata_get_upload_ctx(cbdata);
    if(!yactx)
	return 1;

    yactx->cbdata = cbdata;
    sxi_jparse_destroy(yactx->current.J);
    yactx->current.err = SXE_ECOMM;
    
    if(!(yactx->current.J = sxi_jparse_create(yactx->current.acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
        sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Cannot create file: Out of memory");
        return 1;
    }

    free(yactx->current.token);
    yactx->current.token = NULL;
    if (yactx->host)
        free(yactx->host);
    yactx->host = strdup(host);
    if (!yactx->host) {
        sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Cannot allocate hostname");
        return 1;
    }
    if (yactx->current.f)
        rewind(yactx->current.f);
    return 0;
}

static int createfile_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size) {
    struct file_upload_ctx *yactx = sxi_cbdata_get_upload_ctx(cbdata);
    if(!yactx)
	return 1;

    if(sxi_jparse_digest(yactx->current.J, data, size)) {
        sxi_cbdata_seterr(yactx->cbdata, yactx->current.err, sxi_jparse_geterr(yactx->current.J));
	return 1;
    }

    return 0;
}

const struct jparse_actions createfile_acts = {
    JPACTS_STRING   (
                        JPACT(cb_createfile_token, JPKEY("uploadToken")),
                        JPACT(cb_createfile_host, JPKEY("uploadData"), JPANYKEY, JPANYITM)
                    ),
    JPACTS_ARRAY_END(
                        JPACT(cb_createfile_array_end, JPKEY("uploadData"), JPANYKEY)
                    )
};

static ssize_t pread_hard(int fd, void *buf, size_t count, off_t offset) {
    char *dest = (char *)buf;
    ssize_t ret = 0;

    while(count) {
	ssize_t r = pread(fd, dest, count, offset);
	if(r<0) {
	    if(errno == EINTR)
		continue;
	    return r;
	}
	if(!r)
	    break;;
	dest += r;
	count -= r;
	offset += r;
	ret += r;
    }
    return ret;
}

static ssize_t write_hard(int fd, const void *buf, size_t count)
{
    const uint8_t *wbuf = buf;
    size_t todo = count;
    ssize_t done;

    while(todo) {
	done = write(fd, wbuf, todo);
	if(done < 0) {
	    if(errno == EINTR)
		continue;
	    return -1;
	}
	todo -= done;
	wbuf += done;
    }

    return count;
}

struct hash_up_data_t {
    sxi_hostlist_t hosts;
    off_t offset;
};


int sxi_upload_block_from_buf_track(sxi_conns_t *conns, sxi_hostlist_t *hlist, const char *token, uint8_t *block, unsigned int block_size, int64_t upload_size, int track_xfer) {
    sxc_client_t *sx = sxi_conns_get_client(conns);
    char *url = malloc(sizeof(".data") + 32 + strlen(token) + 1);
    /* FIXME: we should share a define beween the server and the client, as it's pointless to alloc the url */
    int qret;

    if(!url) {
	SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Block upload failed: Out of memory");
	return -1;
    }
    sprintf(url, ".data/%u/%s", block_size, token);

    sxi_set_operation(sx, "upload file contents", NULL, NULL, NULL);
    qret = sxi_cluster_query_track(conns, hlist, REQ_PUT, url, block, upload_size, NULL, NULL, NULL, track_xfer);
    free(url);
    if(qret != 200) {
	SXDEBUG("query failed");
	return 1;
    }
    return 0;
}

int sxi_upload_block_from_buf(sxi_conns_t *conns, sxi_hostlist_t *hlist, const char *token, uint8_t *block, unsigned int block_size, int64_t upload_size) {
    return sxi_upload_block_from_buf_track(conns, hlist, token, block, block_size, upload_size, 0);
}

static sxi_job_t* flush_file_ev(sxc_cluster_t *cluster, const char *host, const char *token, const char *name, sxi_jobs_t *jobs) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_hostlist_t flush_host;
    sxi_query_t *proto;
    sxi_job_t *job;

    if(!token || !*token) {
	SXDEBUG("Null or empty token");
	sxi_seterr(sx, SXE_EARG, "Invalid token");
	return NULL;
    }

    sxi_hostlist_init(&flush_host);
    if(sxi_hostlist_add_host(sx, &flush_host, host)) {
	SXDEBUG("Failed to setup flush hostlist");
	return NULL;
    }

    proto = sxi_flushfile_proto(sx, token);
    if(!proto) {
	SXDEBUG("Cannot allocate reuquest");
	sxi_seterr(sx, SXE_EMEM, "Out of memory creating request");
	sxi_hostlist_empty(&flush_host);
	return NULL;
    }
    SXDEBUG("flushing token");
    /* token can get freed, don't use it in set_operation */
    sxi_set_operation(sx, "flush file", sxi_cluster_get_name(cluster), NULL, name);
    job = sxi_job_submit(sxi_cluster_get_conns(cluster), &flush_host, REQ_PUT, proto->path, name, proto->content, proto->content_len, NULL, jobs);
    sxi_query_free(proto);
    sxi_hostlist_empty(&flush_host);
    return job;
}

static void host_upload_free(struct host_upload_ctx *u)
{
    if (!u)
        return;
    free(u->needed);
    free(u);
}

static void part_free(struct part_upload_ctx *yctx)
{
    if (yctx->hostsmap) {
        struct host_upload_ctx *u;
        sxi_ht_enum_reset(yctx->hostsmap);
        while(!sxi_ht_enum_getnext(yctx->hostsmap, NULL, NULL, (const void **)&u)) {
            if(u)
                sxi_curlev_nullify_upload_context(u->conns, u);
            host_upload_free(u);
        }
        sxi_ht_free(yctx->hostsmap);
    }
    sxi_jparse_destroy(yctx->J);
    free(yctx->needed);
    free(yctx->offsets);
    sxi_ht_free(yctx->hashes);
    memset(yctx, 0, sizeof(*yctx));
}

static void multi_part_upload_blocks(curlev_context_t *ctx, const char* url);
static int part_wait_reset(struct file_upload_ctx *ctx)
{
    sxc_client_t *sx = sxi_cluster_get_client(ctx->cluster);
    struct part_upload_ctx *yctx = &ctx->current;
    unsigned i;
    int rc = 0;

    /* wait until uploads are finished for current part */
    while (ctx->current.ref > 0) {
        if (sxi_curlev_poll(sxi_conns_get_curlev(sxi_cluster_get_conns(ctx->cluster))) < 0) {
            SXDEBUG("curlev_poll failed");
            return -1;
        }
    }

    for (i=0;i<yctx->needed_cnt;i++) {
        sxi_hostlist_empty(&yctx->needed[i].upload_hosts);
    }
    free(ctx->cur_token);
    ctx->cur_token = yctx->token;
    yctx->token = NULL;
    sxi_query_free(ctx->query);
    ctx->query = NULL;
    if (yctx->retry && sxi_retry_done(&yctx->retry)) {
        SXDEBUG("retry_done failed");
        rc = -1;
    }
    part_free(yctx);
    return rc;
}

static int block_reply_cb(curlev_context_t *ctx, const unsigned char *data, size_t size)
{
    return 0;
}

static void upload_blocks_to_hosts(curlev_context_t *cbdata, struct file_upload_ctx *yctx, struct host_upload_ctx *uctx, int status, const char *url);
static void upload_blocks_to_hosts_uctx(curlev_context_t *ctx, const char *url)
{
    struct host_upload_ctx *uctx = sxi_cbdata_get_host_ctx(ctx);
    long status = 0;
    sxi_cbdata_result(ctx, NULL, NULL, &status);
    if (uctx)
        upload_blocks_to_hosts(ctx, uctx->yctx, uctx, status, url);
}

static int send_up_batch(struct file_upload_ctx *yctx, const char *host, struct host_upload_ctx *u)
{
    sxc_client_t *sx = sxi_cluster_get_client(yctx->cluster);
    sxi_conns_t *conns = sxi_cluster_get_conns(yctx->cluster);
    unsigned url_len = lenof(".data/18446744073709551615/") + strlen(yctx->current.token) + 1;
    char *url = malloc(url_len);
    if (!url) {
        SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return -1;
    }
    u->yctx = yctx;
    curlev_context_t *cbdata = sxi_cbdata_create_host(conns, upload_blocks_to_hosts_uctx, u);
    if (!cbdata) {
        SXDEBUG("OOM allocating cbdata");
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        free(url);
        return -1;
    }
    snprintf(url, url_len,".data/%u/%s", yctx->blocksize, yctx->current.token);
    SXDEBUG("buf_used: %d", u->buf_used);
    u->in_use = 1;
    yctx->uploaded += u->buf_used;
    sxi_cbdata_set_operation(cbdata, "upload file contents", NULL, NULL, NULL);
    if(sxi_cbdata_set_timeouts(cbdata, BLOCK_XFER_HARD_TIMEOUT, BLOCK_XFER_SOFT_TIMEOUT)) {
        SXDEBUG("Failed to set timeouts");
        free(url);
        sxi_cbdata_unref(&cbdata);
        return -1;
    }
    if (sxi_cluster_query_ev(cbdata,
                             sxi_cluster_get_conns(yctx->cluster),
                             host, REQ_PUT, url,
                             u->buf, u->buf_used, NULL, block_reply_cb) == -1) {
        SXDEBUG("cluster upload query failed");
        free(url);
        /* Do not leak cbdata and restore error message to global buffer */
        sxi_cbdata_unref(&cbdata);
        return -1;
    }
    sxi_cbdata_unref(&cbdata);
    free(url);
    yctx->current.ref++;
    u->buf_used = 0;
    return 0;
}

static void file_finish(struct file_upload_ctx *yctx)
{
    sxc_client_t *sx = sxi_cluster_get_client(yctx->cluster);
    off_t size;
    struct stat s;

    SXDEBUG("finished file");
    gettimeofday(&yctx->t2, NULL);
    if (!yctx->current.token) {
        SXDEBUG("fail incremented: no token?");
        yctx->fail++;
        return;
    }
    if(fstat(yctx->fd, &s)) {
        SXDEBUG("fail incremented: cannot stat file");
        yctx->fail++;
        return;
    }
    size = lseek(yctx->fd, 0L, SEEK_END);
    if(size != yctx->size || s.st_mtime != yctx->mtime)
        sxi_notice(sx, "WARNING: Source file has changed during upload");

    /*  TODO: multiplex flush_file */
    yctx->job = flush_file_ev(yctx->cluster, yctx->host, yctx->current.token, yctx->name, yctx->jobs);
    if (!yctx->job) {
        SXDEBUG("fail incremented due to !job");
        yctx->fail++;
    }
    else
        yctx->flush_ok++;
}

static int multi_part_upload_ev(struct file_upload_ctx *state);
static void last_part(struct file_upload_ctx *state)
{
    /* TODO:' call multi_part_upload_ev with last possible empty part */
    sxc_client_t *sx = sxi_cluster_get_client(state->cluster);
    /* TODO: sxi_cluster_query_ev should support streaming uploads,
     * so that we don't have to keep all hashes in memory */
    state->end = state->size;
    SXDEBUG("entered");
    if (multi_part_upload_ev(state) == -1) {
        SXDEBUG("fail incremented: failed to upload last part");
        state->fail++;
    }
}

static int batch_hashes_to_hosts(curlev_context_t *cbdata, struct file_upload_ctx *yctx, struct need_hash *needed, unsigned from, unsigned size, unsigned next_replica)
{
    unsigned i;
    sxc_client_t *sx = sxi_cluster_get_client(yctx->cluster);
    if (yctx->all_fail) {
        sxi_seterr(sx, SXE_ECOMM, "All replicas have previously failed");
        return -1;
    }

    if(sxi_cbdata_geterrnum(cbdata) == SXE_ABORT) {
        SXDEBUG("Transfer abort requested");
        yctx->all_fail = 1;
        yctx->fail++;
        return -1;
    }

    for (i=from;i<size;i++) {
        struct need_hash *need = &needed[i];
        const char *host = NULL;
        need->replica += next_replica;
        if(sxi_get_node_preference(sx) > 0.0)
            host = sxi_hostlist_get_optimal_host(sxi_cbdata_get_conns(cbdata), &need->upload_hosts, SXC_XFER_DIRECTION_UPLOAD);
        else
            host = sxi_hostlist_get_host(&need->upload_hosts, need->replica);
        if (!host) {
            sxi_cbdata_seterr(cbdata, SXE_ECOMM, "All replicas have failed");
            SXDEBUG("All replicas have failed");
            yctx->all_fail = 1;
            yctx->fail++;
            return -1;
        }
        if (sxi_retry_check(yctx->current.retry, need->replica) == -1) {
            SXDEBUG("retry_check failed");
            yctx->fail++;
            return -1;
        }
        sxi_cbdata_set_operation(cbdata, "file block upload", NULL, NULL, NULL);
        sxi_retry_msg(sx, yctx->current.retry, host);
        SXDEBUG("replica #%d: %s", need->replica, host);
        struct host_upload_ctx *u = NULL;

        if (sxi_ht_get(yctx->current.hostsmap, host, strlen(host)+1, (void**)&u)) {
            u = calloc(1, sizeof(*u));
            if (!u) {
                SXDEBUG("fail incremented: OOM allocating hostsmap");
		sxi_seterr(sx, SXE_EMEM, "Out of memory");
                yctx->fail++;
                return -1;
            }
            if (!(u->needed = malloc(sizeof(*u->needed) * yctx->current.needed_cnt))) {
                SXDEBUG("fail incremented: OOM allocing hostneed");
		sxi_seterr(sx, SXE_EMEM, "Out of memory");
                yctx->fail++;
		free(u);
                return -1;
            }
            u->conns = sxi_cluster_get_conns(yctx->cluster);
            if (sxi_ht_add(yctx->current.hostsmap, host, strlen(host)+1, u)) {
                SXDEBUG("fail incremented: error adding to hostsmap");
                yctx->fail++;
                return -1;
            }
        }
        u->needed[u->n++] = *need;
    }
    return 0;
}

static void upload_blocks_to_hosts(curlev_context_t *cbdata, struct file_upload_ctx *yctx, struct host_upload_ctx *uctx, int status, const char *url)
{
    const char *h;
    struct host_upload_ctx *u;
    sxc_client_t *sx = sxi_cluster_get_client(yctx->cluster);
    unsigned len;

    if (!yctx->upload_started) {
        SXDEBUG("starting upload");
        gettimeofday(&yctx->t1, NULL);
        yctx->upload_started = 1;
    }
    if (yctx->current.ref > 0)
        yctx->current.ref--;

    if (uctx)
        uctx->in_use = 0;
    SXDEBUG("upload_blocks_to_hosts");
    if (status != 200) {
        if(status == 0) { /* Query has not been sent yet, do not batch again to avoid infinite recursion loop */
            SXDEBUG("Failed to send .data query: %s", sxc_geterrmsg(sx));
            if (yctx->loop_count-- > 0) {
                SXDEBUG("allow retry (loop count: %d)", yctx->loop_count);
            } else {
                SXDEBUG("forbidding retry to avoid infinite loop");
                yctx->fail++;
                return;
            }
        }
        SXDEBUG("query failed: %d", status);
        if (uctx) {
            unsigned n = uctx->n;
            /* move to next replica: the last batch, and everything else
             * currently queued for this host */
            uctx->i = uctx->n = 0;
            if (batch_hashes_to_hosts(cbdata, yctx, uctx->needed, uctx->last_successful, n, 1)) {
                SXDEBUG("fail incremented");
                yctx->fail++;
                return;
            }
        }
        else {
            SXDEBUG("fail incremented due to !uctx");
            yctx->fail++;
            return;
        }
    } else if (uctx)
        uctx->last_successful = uctx->i;
    while(!sxi_ht_enum_getnext(yctx->current.hostsmap, (const void **)&h, &len, (const void **)&u)) {
        if (u->in_use)
            continue;
        if (u->buf_used < sizeof(u->buf)) {
            /* Reset currently uploaded size */
            u->ul = 0;
            for (;u->i < u->n;) {
                uint32_t checksum;
                struct need_hash *need = &u->needed[u->i++];
                SXDEBUG("adding data %d from pos %lld", u->i, (long long)need->off.offset);
                ssize_t n = pread_hard(yctx->fd, u->buf + u->buf_used, yctx->blocksize, need->off.offset);
                if (n < 0) {
                    SXDEBUG("fail incremented: error reading buffer");
                    sxi_seterr(sx, SXE_EREAD, "Copy failed: Unable to read source file");
                    yctx->fail++;
                    return;
                }
                if (!n) {
                    SXDEBUG("fail incremented: early EOF?");
                    sxi_seterr(sx, SXE_EREAD, "Copy failed: Source file changed while being read");
                    yctx->fail++;
                    return;
                }

                u->buf_used += n;
                if (n < yctx->blocksize) {
                    unsigned remaining = yctx->blocksize - n;
                    memset(u->buf + u->buf_used, 0, remaining);
                    u->buf_used += remaining;
                }
                /* Check the checksum for this block and bail out if its incorrect */
                checksum = sxi_checksum(need->off.ref_checksum, u->buf + u->buf_used - yctx->blocksize, yctx->blocksize);
                if(checksum != need->off.checksum) {
                    SXDEBUG("fail incremented: SXI_CHECKSUM mismatch");
                    sxi_seterr(sx, SXE_EREAD, "Copy failed: Source file changed while being read");
                    yctx->fail++;
                    return;
                }
                SXDEBUG("u: i:%d,n:%d", u->i, u->n);
                if (u->buf_used == sizeof(u->buf)) {
                    SXDEBUG("used: %d", u->buf_used);
                    if (send_up_batch(yctx, h, u) == -1) {
                        SXDEBUG("fail incremented: failed to upload chunk");
                        yctx->fail++;
                        return;
                    }
                    break;
                }
            }
        }
    }
    sxi_ht_enum_reset(yctx->current.hostsmap);
    while(!sxi_ht_enum_getnext(yctx->current.hostsmap, (const void **)&h, &len, (const void **)&u)) {
        if (u->in_use)
            continue;
        if (u->buf_used) {
            /* Reset currently uploaded size */
            u->ul = 0;
            SXDEBUG("u: i:%d,n:%d", u->i, u->n);
            if (send_up_batch(yctx, h, u) == -1) {
                SXDEBUG("fail incremented: failed to upload partial chunk");
                yctx->fail++;
                return;
            }
        }
    }
    yctx->ok++;
    SXDEBUG("batches, ok %d, fail %d, ref %d",
            yctx->ok, yctx->fail, yctx->current.ref);
    if (!yctx->fail && !yctx->current.ref) {
        yctx->ok++;
        SXDEBUG("upload status: %lld + %lld, %lld",
                (long long)yctx->pos, (long long)yctx->blocksize, (long long)yctx->size); 
        if (yctx->end >= yctx->size) {
            SXDEBUG("finished uploads: %lld, %lld >= %lld",
                    (long long)yctx->pos, (long long)yctx->end, (long long)yctx->size);
            if (yctx->pos == yctx->size)
                file_finish(yctx);
            else
                last_part(yctx);
        }
        return;
    }

    /* TODO: group by host and start uploading: */
     /* like with downloads have an iteration counter i.
      *  go through each hash
      *
      *   retrieve host_upload based on host
      *   queue to batch, increment pending queries
      *   if batch full, launch it, increment pending batches
      *  when done wait  until pending batches/queries all finish
      *  go back an increment i, taking host_i now to submit failed queries to
      *  next replica
      *  return whether any failed or succeeded */
}

static int cmp_hash(const void *a, const void *b)
{
    const struct need_hash *h1 = a;
    const struct need_hash *h2 = b;
    off_t diff = h1->off.offset - h2->off.offset;
    if (!diff)
        return 0;
    return diff < 0 ? -1 : 1;
}

static void multi_part_upload_blocks(curlev_context_t *ctx, const char *url)
{
    struct file_upload_ctx *yctx = sxi_cbdata_get_upload_ctx(ctx);
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(ctx));
    sxc_xfer_stat_t *xfer_stat = NULL;
    long status = 0;

    if (sxi_cbdata_result(ctx, NULL, NULL, &status) == -1 || status != 200) {
        SXDEBUG("query failed: %ld", status);
        yctx->fail++;
        yctx->qret = status;
        if (yctx->current.ref > 0)
            yctx->current.ref--;
        return;
    }
    SXDEBUG("in multi_part_upload_blocks");
    if(sxi_jparse_done(yctx->current.J)) {
        sxi_cbdata_seterr(ctx, yctx->current.err, "Copy failed: %s", sxi_jparse_geterr(yctx->current.J));
        SXDEBUG("fail incremented, after parse");
        yctx->fail++;
        if (yctx->current.ref > 0)
            yctx->current.ref--;
        return;
    }
    SXDEBUG("need: %d hashes", yctx->current.needed_cnt);

    xfer_stat = sxi_cluster_get_xfer_stat(yctx->cluster);
    if(xfer_stat) {
        int64_t to_skip = yctx->pos - yctx->last_pos - yctx->current.needed_cnt * (int64_t)yctx->blocksize;
        if(to_skip && skip_xfer(yctx->cluster, to_skip) != SXE_NOERROR) {
            SXDEBUG("Could not skip part of transfer");
            yctx->fail++;
            if (yctx->current.ref > 0)
                yctx->current.ref--;
            sxi_cbdata_seterr(ctx, SXE_ABORT, "Could not skip part of transfer");
            return;
        }
    }

    if (batch_hashes_to_hosts(ctx, yctx, yctx->current.needed, 0, yctx->current.needed_cnt, 0)) {
        SXDEBUG("fail incremented");
        yctx->fail++;
    }
    /* TODO: iterate and retry, see below */
    {
        struct host_upload_ctx *u = NULL;
        const char *h;
        unsigned len;
        /* sort by offset.
         * This speeds up downloads.
         * Must also ensure that we only have 1 upload connection to a host at a
         * time */
        while(!sxi_ht_enum_getnext(yctx->current.hostsmap, (const void **)&h, &len, (const void **)&u)) {
            qsort(u->needed, u->n, sizeof(*u->needed), cmp_hash);
        }
    } while(0);

    upload_blocks_to_hosts(ctx, yctx, NULL, status, url);
}

static int multi_part_compute_hash_ev(struct file_upload_ctx *yctx)
{
    sxc_client_t *sx = sxi_cluster_get_client(yctx->cluster);;
    ssize_t n;
    off_t start = yctx->pos;
    unsigned part_size = yctx->end - yctx->pos;
    sxc_meta_t *fmeta;
    yctx->last_pos = yctx->pos;

    if(yctx->pos == 0) {
	fmeta = yctx->fmeta;
	yctx->query = sxi_fileadd_proto_begin(sx, yctx->dest->volume, yctx->dest->remote_path, NULL, NULL, yctx->pos, yctx->blocksize, yctx->size);
        yctx->ref_checksum = sxi_checksum(0, NULL, 0);
    } else {
	fmeta = NULL;
	yctx->query = sxi_fileadd_proto_begin(sx, ".upload", yctx->cur_token, NULL, NULL, yctx->pos, yctx->blocksize, yctx->size);
        /* extend is only valid on the node that created the file
         * (same as with flush!) */
        sxi_hostlist_empty(yctx->volhosts);
        if (sxi_hostlist_add_host(sx, yctx->volhosts, yctx->host))
            return -1;
    }
    if(!yctx->query) {
        SXDEBUG("failed to allocate query");
        return -1;
    }

    /* TODO; for last partial block upload all hashes */
    do {
        /* hash_chunk -> finish cb -> hash_chunk ... */
        unsigned i, remaining;
        SXDEBUG("pos:%lld",(long long)yctx->pos);
        n = pread_hard(yctx->fd, yctx->buf, sizeof(yctx->buf), yctx->pos);
        if (n < 0) {
            SXDEBUG("failed to read from source file");
            sxi_setsyserr(sx, SXE_EREAD, "Block upload failed while reading source file");
            return -1;
        }
        /* set partial block to zero */
        remaining = yctx->blocksize - n % yctx->blocksize;
        if (remaining < yctx->blocksize)
            memset(yctx->buf + n, 0, remaining);
        yctx->pos += n;
        if (yctx->pos > yctx->end || (!n && yctx->pos != yctx->end)) {
            SXDEBUG("source file changed while being read");
            sxi_seterr(sx, SXE_EREAD, "Copy failed: Source file changed while being read");
            return -1;
        }
        for (i=0;i<n;i += yctx->blocksize) {
	    char hexhash[SXI_SHA1_TEXT_LEN+1];
            size_t block;

            if (sxi_cluster_hashcalc(yctx->cluster, yctx->buf + i, yctx->blocksize, hexhash)) {
                SXDEBUG("failed to compute hash for block");
                return -1;
            }
	    hexhash[SXI_SHA1_TEXT_LEN] = '\0';
	    yctx->query = sxi_fileadd_proto_addhash(sx, yctx->query, hexhash);
	    if(!yctx->query) {
		SXDEBUG("failed to add hash");
		return -1;
	    }

            off_t pos = yctx->pos - n + i;
            block = (pos - start) / yctx->blocksize;
            yctx->current.offsets[block].offset = pos;
            /* Calculate checksum for each block and store it for comparison later */
            yctx->current.offsets[block].checksum = sxi_checksum(yctx->ref_checksum, yctx->buf + i, yctx->blocksize);
            yctx->current.offsets[block].ref_checksum = yctx->ref_checksum;
            yctx->ref_checksum = yctx->current.offsets[block].checksum; /* Save reference checksum for next block */
            SXDEBUG("%p, hash %s: block %ld, %lld, checksum: %lu", (const void*)yctx, hexhash, (long)block, (long long)yctx->current.offsets[block].offset, (unsigned long)yctx->current.offsets[block].checksum);
            if(sxi_ht_add(yctx->current.hashes, hexhash, SXI_SHA1_TEXT_LEN, &yctx->current.offsets[block])) {
                SXDEBUG("failed to add hash offset");
                return -1;
            }
        }
    } while (n > 0 && yctx->pos < yctx->end);

    yctx->query = sxi_fileadd_proto_end(sx, yctx->query, fmeta);
    if(!yctx->query) {
        SXDEBUG("failed to allocate query");
        return -1;
    }

    yctx->current.J = NULL;
    yctx->current.err = SXE_ECOMM;
    yctx->current.acts = &createfile_acts;

    if (!(yctx->cbdata = sxi_cbdata_create_upload(sxi_cluster_get_conns(yctx->cluster), multi_part_upload_blocks, yctx))) {
        SXDEBUG("failed to allocate cbdata");
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return -1;
    }
    SXDEBUG("part size: %d/%d", part_size, UPLOAD_PART_THRESHOLD);
    /* TODO: state->end should be yctx->end */
    yctx->current.ref++;
    /* TODO: multiple volhost support */
    sxi_cbdata_set_operation(yctx->cbdata, "upload file content hashes", NULL, NULL, NULL);

    if(sxi_cluster_query_ev_retry(yctx->cbdata, sxi_cluster_get_conns(yctx->cluster), yctx->volhosts,
                                  yctx->query->verb, yctx->query->path, yctx->query->content, yctx->query->content_len,
                                  createfile_setup_cb, createfile_cb, yctx->jobs) == -1)
    {
        SXDEBUG("file create query failed");
        sxi_cbdata_unref(&yctx->cbdata);
        return -1;
    }
    sxi_cbdata_unref(&yctx->cbdata);
    return 0;
}

static int multi_part_upload_ev(struct file_upload_ctx *yctx)
{
    sxc_client_t *sx = sxi_cluster_get_client(yctx->cluster);;

    if (part_wait_reset(yctx) == -1) {
        SXDEBUG("part_wait_reset failed");
        return -1;
    }

    /* Check if upload is necessary */
    if(yctx->pos == yctx->end && yctx->size) {
        return 0;
    }
    do {
        if (!(yctx->current.hashes = sxi_ht_new(sx, yctx->max_part_blocks))) {
            SXDEBUG("failed to create size hashtable for %u entries", yctx->max_part_blocks);
            sxi_seterr(sx, SXE_EMEM, "Cannot allocate hashes table");
            break;
        }

        if (!(yctx->current.offsets = calloc(sizeof(*yctx->current.offsets), yctx->max_part_blocks))) {
            sxi_seterr(sx, SXE_EMEM, "Cannot allocate offsets buffer");
            break;
        }
        if (!(yctx->current.needed = calloc(sizeof(*yctx->current.needed), yctx->max_part_blocks))) {
            sxi_seterr(sx, SXE_EMEM, "Cannot allocate needed buffer");
            break;
        }
        if (!(yctx->current.hostsmap = sxi_ht_new(sx, 128))) {
            sxi_seterr(sx, SXE_EMEM, "Cannot allocate read buffer");
            break;
        }
        if (!(yctx->current.retry = sxi_retry_init(sx, RCTX_SX))) {
            sxi_seterr(sx, SXE_EMEM, "Could not allocate retry");
            SXDEBUG("retry_init failed");
            break;
        }
        sxi_ht_empty(yctx->current.hashes);
        if (multi_part_compute_hash_ev(yctx) == -1) {
            SXDEBUG("compute_hash_ev failed");
            break;
        }
        /* TODO: remove: its just for debugging */
/*        while (!sxi_curlev_poll(sxi_cluster_get_conns(state->cluster)->curlev)) {}*/
        /* yctx will be freed by callback */
        return 0;
    } while (0);
    return -1;
}

static sxi_job_t* multi_upload(struct file_upload_ctx *state, long *http_status)
{
    sxc_client_t *sx = sxi_cluster_get_client(state->cluster);;
    int ret = -1;
    do {
        state->end = state->pos + state->max_part_blocks * state->blocksize;
        if (state->end <= state->size) {
            /* upload full chunks */
            SXDEBUG("pos: %lld, end: %lld", (long long)state->pos, (long long)state->end);
            if (multi_part_upload_ev(state) == -1) {
                SXDEBUG("failed to upload first part");
                break;
            }


        }
        /* TODO: poll_immediate, check fails and bail out if anything failed */
        ret = 0;
    } while (state->end < state->size);
    if (!state->pos && !ret) {
        state->end = state->size;
        if (multi_part_upload_ev(state) == -1) {
            SXDEBUG("failed to upload only part");
            ret = -1;
        }
    }

    SXDEBUG("waiting for part");
    if (part_wait_reset(state) == -1) {
        SXDEBUG("part_wait_reset failed");
        ret = -1;
    }

    /* TODO: wait until parts_pending == parts_ok + parts_fail, and curlev_poll! */
    SXDEBUG("waiting");
    while (!ret && !state->fail && !state->flush_ok) {
        if (sxi_curlev_poll(sxi_conns_get_curlev(sxi_cluster_get_conns(state->cluster))) < 0) {
            SXDEBUG("curlev_poll failed");
            ret = -1;
            break;
        }
    }

    if (state->fail || ret) {
        SXDEBUG("fail is %d, ret is %d", state->fail, ret);
        ret = -1;
    }
    if (state->current.retry && sxi_retry_done(&state->current.retry)) {
        SXDEBUG("retry_done failed");
        ret = -1;
    }
    part_free(&state->current);
    free(state->cur_token);
    sxi_query_free(state->query);
    if (!ret)
        SXDEBUG("upload ok");
    else
        SXDEBUG("upload failed");
    if (ret == -1) {
        sxi_job_free(state->job);
        return NULL;
    }
    return state->job;
}

char *sxi_get_filter_dir(sxc_client_t *sx, const char *confdir, const char *uuid, const char *volume)
{
    char *fdir;
    int rc = 0;

    fdir = malloc(strlen(confdir) + strlen(uuid) + strlen(volume) + 11);
    if(!fdir) {
	sxi_seterr(sx, SXE_EMEM, "Can't allocate memory for filter config directory");
	return NULL;
    }
    sprintf(fdir, "%s/volumes/%s", confdir, volume);
    if(access(fdir, F_OK) && mkdir(fdir, 0700) == -1 && errno != EEXIST)
	rc = -1;
    sprintf(fdir, "%s/volumes/%s/%s", confdir, volume, uuid);
    if(access(fdir, F_OK)) {
	if(rc == -1 || (mkdir(fdir, 0700) == -1 && errno != EEXIST)) {
	    sxi_seterr(sx, SXE_EFILTER, "Can't create filter directory %s", fdir);
	    free(fdir);
	    return NULL;
	}
    }
    return fdir;
}

static int ends_with(const char *str, char c)
{
    unsigned n = strlen(str);
    return n > 0 && str[n-1] == c;
}

static const char *base(const char *str)
{
    const char *q = strrchr(str, '/');
    return q ? q + 1 : str;
}

static int maybe_append_path(sxc_file_t *dest, sxc_file_t *source, int recursive)
{
    char *path;
    const char *src_part;
    sxc_client_t *sx;
    unsigned n;
    if (!dest || !source)
        return -1;
    if (dest->cat_fd > 0)
        return 0;
    sx = dest->sx;
    if (!dest->origpath) {
        if (!(dest->origpath = strdup(dest->path))) {
            sxi_setsyserr(dest->sx, SXE_EMEM, "Cannot dup path");
            return -1;
        }
        SXDEBUG("origpath set to: %s", dest->origpath);
    }
    if (!recursive && *dest->path && !ends_with(dest->path, '/') && strcmp(dest->path,".")) {
        SXDEBUG("destination is a single file: %s", dest->path);
        return 0;/*destination is single file */
    }
    if (!strcmp(dest->path, "/dev/stdout"))
        return 0;
    if (!source->origpath) {
        SXDEBUG("NULL source->origpath pointer");
        sxi_seterr(dest->sx, SXE_EARG, "Invalid source original path");
        return -1;
    } else {
        /* we copy recursively */
        /* a/f*b/c?/<DIR>/<FILE> -> d/e/<DIR>/<FILE>
         * origpath=a/f*b/c?/ => origpath = d/e/
         * the / at end of origpath is optional...
         * */
        unsigned orig_slashes = sxi_count_slashes(source->origpath);
        if (source->volume)
            orig_slashes++;/* its a remote file vs a local file */
        if (!ends_with(source->origpath, '/') && !ends_with(dest->path, '/') && *source->origpath && *dest->path)
            orig_slashes++;
        src_part = sxi_ith_slash(source->path, orig_slashes);
        if (!src_part || !*src_part)
            src_part = base(source->path); /* it is a single file */
    }
    while (src_part && (*src_part == '/' || !strncmp(src_part, "./", 2) || !strncmp(src_part, "../", 3)))
        src_part++;

    /* the loop above checks for src_part not to be NULL, but it is used in strlen(src_part) below,
     * we'd better check for NULL here */
    if(!src_part) {
        SXDEBUG("NULL src_part pointer");
        sxi_seterr(dest->sx, SXE_EARG, "NULL source path part");
        return -1;
    }

    n = strlen(dest->origpath) + strlen(src_part) + 2;
    path = malloc(n);
    if (!path) {
        sxi_seterr(dest->sx, SXE_EMEM, "cannot allocate path");
        return -1;
    }

    snprintf(path, n, "%s%s%s", dest->origpath, ends_with(dest->origpath, '/') ? "" : "/", src_part);
    SXDEBUG("%s -> %s", source->path, path);
    n = strlen(src_part);
    if (!strncmp(src_part, "..", 2) ||
        (n > 2 && !memcmp(src_part + n-2, "..", 2)) ||
        strstr(src_part, "/../")) {
        sxi_seterr(dest->sx, SXE_EARG, "filename has '..': '%s'", source->path);
        free(path);
        return -1;
    }
    free(dest->path);
    dest->path = path;
    /* Reset previously stored remote path, it needs to be recalculated */
    free(dest->remote_path);
    dest->remote_path = NULL;
    return 0;
}

static int restore_path(sxc_file_t *dest)
{
    if (dest) {
        free(dest->path);
        dest->path = NULL;
        if (dest->origpath) {
            if (!(dest->path = strdup(dest->origpath))) {
                sxi_setsyserr(dest->sx, SXE_EMEM, "Cannot dup path");
                return 1;
            }

            /* Reset remote path, might need to be recalculated */
            free(dest->remote_path);
            dest->remote_path = NULL;
        }
        return 0;
    }
    return 1;
}

static sxi_job_t* local_to_remote_begin(sxc_file_t *source, sxc_file_t *dest, int recursive, long *http_status, sxi_jobs_t *jobs) {
    unsigned int blocksize;
    char *fname = NULL, *tempfname = NULL;
    struct stat st;
    uint8_t *buf = NULL;
    struct file_upload_ctx *yctx = NULL, *state = NULL;
    int s = -1;
    sxi_hostlist_t shost, volhosts;
    sxc_client_t *sx = dest->sx;
    int64_t fsz, orig_fsz;
    sxc_meta_t *vmeta = NULL, *cvmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    struct filter_handle *fh = NULL;
    long qret = -1;
    sxc_xfer_stat_t *xfer_stat = NULL;
    char *fdir = NULL;
    sxi_job_t *ret = NULL, *job;

    sxi_hostlist_init(&volhosts);
    sxi_hostlist_init(&shost);

    if (maybe_append_path(dest, source, recursive))
        return NULL;

    if(!(state = calloc(1, sizeof(*state)))) {
        sxi_seterr(sx, SXE_EMEM, "Copy failed: Out of memory");
        goto local_to_remote_err;
    }

    if (!(yctx = calloc(1, sizeof(*yctx)))) {
        sxi_seterr(sx, SXE_EMEM, "Copy failed: Out of memory");
        goto local_to_remote_err;
    }
    if(!(buf = malloc(UPLOAD_CHUNK_SIZE))) {
	SXDEBUG("OOM allocating the block buffer (%u bytes)", UPLOAD_CHUNK_SIZE);
	sxi_seterr(sx, SXE_EMEM, "Copy failed: Out of memory");
	goto local_to_remote_err;
    }

    if((s = open(source->path, O_RDONLY)) < 0) {
	SXDEBUG("failed to open source file");
	sxi_setsyserr(sx, SXE_EREAD, "Copy failed: Failed to open source file");
	goto local_to_remote_err;
    }

    if(fstat(s, &st)) {
	SXDEBUG("failed to stat source file");
	sxi_setsyserr(sx, SXE_EREAD, "Copy failed: Failed to stat source file");
	goto local_to_remote_err;
    }

    if(S_ISDIR(st.st_mode)) {
        sxi_seterr(sx, SXE_EARG, "Path '%s' is a directory and recursive mode is not enabled", source->path);
        goto local_to_remote_err;
    }

    if(!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode)) {
	sxc_file_t *tsource;
	if(!(fname = sxi_tempfile_track(source->sx, NULL, &yctx->current.f))) {
	    SXDEBUG("failed to generate stream dump file");
	    goto local_to_remote_err;
	}
	while(1) {
	    ssize_t got = read(s, buf, UPLOAD_CHUNK_SIZE);
	    if(got < 0) {
		if(errno == EINTR)
		    continue;
		SXDEBUG("failed to read from source stream");
		sxi_setsyserr(sx, SXE_EREAD, "Copy failed: Failed to read input stream");
		goto local_to_remote_err;
	    }
	    if(!got)
		break;
	    if(!fwrite(buf, got, 1, yctx->current.f)) {
		SXDEBUG("failed to write stream data to temporary file");
		sxi_setsyserr(sx, SXE_EWRITE, "Copy failed: Failed to copy input stream to temporary file");
		goto local_to_remote_err;
	    }
	}
        fflush(yctx->current.f);
	tsource = sxc_file_local(sx, fname);
	if(!tsource)
	    SXDEBUG("failed to create source file object for temporary input file");
	else {
	    ret = local_to_remote_begin(tsource, dest, recursive, http_status, jobs);
	    sxc_file_free(tsource);
	}
	goto local_to_remote_err; /* cleanup, not necessarily an error */
    }
    if(!(vmeta = sxc_meta_new(sx)))
	goto local_to_remote_err;
    if(!(cvmeta = sxc_meta_new(sx)))
	goto local_to_remote_err;
    /* TODO: multiplex the locate too! */
    orig_fsz = fsz = st.st_size;
    if(sxi_file_set_size(source, st.st_size) || sxi_file_set_atime(source, st.st_atime) || sxi_file_set_ctime(source, st.st_ctime) ||
       sxi_file_set_mtime(source, st.st_mtime) || sxi_file_set_uid(source, st.st_uid) || sxi_file_set_gid(source, st.st_gid) ||
       sxi_file_set_mode(source, st.st_mode) || sxi_file_set_created_at(source, st.st_ctime)) {
        SXDEBUG("Failed to set local file size");
        goto local_to_remote_err;
    }

    if ((qret = sxi_locate_volume(sxi_cluster_get_conns(dest->cluster), dest->volume, &volhosts, &fsz, vmeta, cvmeta))) {
	SXDEBUG("failed to locate destination volume");
	goto local_to_remote_err;
    }
    if(fsz < 1024 || fsz > UPLOAD_CHUNK_SIZE) {
	SXDEBUG("cannot handle the requested blocksize %lld", (long long int)fsz);
	goto local_to_remote_err;
    }
    blocksize = fsz;

    if(sxi_volume_cfg_check(sx, dest->cluster, vmeta, dest->volume)) {
        /* filters wrong: don't recurse */
        qret = 404;
	goto local_to_remote_err;
    }

    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
	    char inbuff[8192], outbuff[8192], filter_uuid[37], cfgkey[37 + 5];
	    ssize_t bread, bwrite;
	    sxf_action_t action = SXF_ACTION_NORMAL;
	    FILE *tempfile = NULL;
	    int td;
	    const void *cfgval = NULL;
	    unsigned int cfgval_len = 0;
	    const char *confdir = sxi_cluster_get_confdir(dest->cluster);
	    int fret;

	if(mval_len != 16) {
	    sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            qret = 404;
	    goto local_to_remote_err;
	}
	sxi_uuid_unparse(mval, filter_uuid);

	fh = sxi_filter_gethandle(sx, mval);
	if(!fh) {
	    SXDEBUG("Filter ID %s required by destination volume not found", filter_uuid);
	    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by destination volume not found", filter_uuid);
            qret = 404;
	    goto local_to_remote_err;
	}

	snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", filter_uuid);
	sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);
	if(cfgval_len && sxi_filter_add_cfg(fh, dest->volume, cfgval, cfgval_len))
	    goto local_to_remote_err;

	if(confdir) {
	    fdir = sxi_get_filter_dir(sx, confdir, filter_uuid, dest->volume);
	    if(!fdir) {
                qret = 404;
		goto local_to_remote_err;
            }
	}

        if(sxi_filemeta_process(sx, fh, fdir, source, cvmeta)) {
            SXDEBUG("Failed to process file meta %s", source->path);
            goto local_to_remote_err;
        }

        if(sxi_file_process(sx, fh, fdir, source, SXF_MODE_UPLOAD)) {
            SXDEBUG("Failed to process file %s", source->path);
            goto local_to_remote_err;
        }

        /* Store the metadata from the source file into dest */
        if(source->meta) {
            sxc_meta_free(dest->meta);
            dest->meta = sxi_meta_dup(sx, source->meta);
            if(!dest->meta) {
                SXDEBUG("Failed to duplicate source file metadata");
                sxi_notice(sx, "Failed to duplicate source file metadata");
                goto local_to_remote_err;
            }
        }
        dest->meta_fetched = source->meta_fetched;
        dest->size = st.st_size;

	if(fh->f->data_process) {
	    if(!(tempfname = sxi_tempfile_track(sx, NULL, &tempfile))) {
		SXDEBUG("Failed to generate filter temporary file");
		goto local_to_remote_err;
	    }
	    td = fileno(tempfile);

	    if(fh->f->data_prepare) {
                unsigned char chksum1[SXI_SHA1_BIN_LEN], chksum2[SXI_SHA1_BIN_LEN];

                if(sxi_meta_checksum(sx, cvmeta, chksum1)) {
                    SXDEBUG("Failed to compute custom volume meta checksum");
                    fclose(tempfile);
                    goto local_to_remote_err;
                }

		if(fh->f->data_prepare(fh, &fh->ctx, source->path, fdir, cfgval, cfgval_len, cvmeta, SXF_MODE_UPLOAD)) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
		    fclose(tempfile);
		    goto local_to_remote_err;
		}

                if(sxi_meta_checksum(sx, cvmeta, chksum2)) {
                    SXDEBUG("Failed to compute custom volume meta checksum");
                    fclose(tempfile);
                    goto local_to_remote_err;
                }

		if(memcmp(chksum1, chksum2, SXI_SHA1_BIN_LEN)) {
                    SXDEBUG("Checksums different, modifying volume %s\n", dest->volume);
		    if(sxc_volume_modify(dest->cluster, dest->volume, NULL, NULL, -1, -1, cvmeta)) {
			if(sxc_geterrnum(dest->sx) == SXE_EAUTH)
			    /* ignore error for non-owner */
			    sxc_clearerr(dest->sx);
			else {
                            fclose(tempfile);
			    goto local_to_remote_err;
                        }
		    }
		}
	    }

	    while((bread = read(s, inbuff, sizeof(inbuff))) > 0) {
		if(lseek(s, 0, SEEK_CUR) == st.st_size)
		    action = SXF_ACTION_DATA_END;
		do {
		    bwrite = fh->f->data_process(fh, fh->ctx, inbuff, bread, outbuff, sizeof(outbuff), SXF_MODE_UPLOAD, &action);
		    if(bwrite < 0) {
			sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process input data", filter_uuid);
			fclose(tempfile);
			if(fh->f->data_finish)
			    fh->f->data_finish(fh, &fh->ctx, SXF_MODE_UPLOAD);
			goto local_to_remote_err;
		    }
		    if(write_hard(td, outbuff, bwrite) == -1) {
			sxi_setsyserr(sx, SXE_EWRITE, "Filter failed: Can't write to temporary file");
			fclose(tempfile);
			if(fh->f->data_finish)
			    fh->f->data_finish(fh, &fh->ctx, SXF_MODE_UPLOAD);
			goto local_to_remote_err;
		    }
		} while(action == SXF_ACTION_REPEAT);
	    }
	    if(fclose(tempfile)) {
		sxi_setsyserr(sx, SXE_EWRITE, "Filter failed: Can't close temporary file");
		goto local_to_remote_err;
	    }
	    if(fh->f->data_finish) {
		if(fh->f->data_finish(fh, &fh->ctx, SXF_MODE_UPLOAD)) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to clean up itself", filter_uuid);
		    goto local_to_remote_err;
		}
	    }
	    if((td = open(tempfname, O_RDONLY)) < 0) {
		SXDEBUG("can't open temporary file");
		sxi_setsyserr(sx, SXE_EREAD, "Filter failed: Can't open temporary file");
		goto local_to_remote_err;
	    }
	    close(s);
	    s = td;
	    if(fstat(s, &st)) {
		SXDEBUG("failed to stat source file");
		sxi_setsyserr(sx, SXE_EREAD, "Copy failed: Failed to stat source file");
		goto local_to_remote_err;
	    }

            /* Update remote size of the processed file */
            if(sxi_file_set_remote_size(dest, st.st_size)) {
                SXDEBUG("Failed to set local file size");
                goto local_to_remote_err;
            }

	    if(st.st_size != orig_fsz) {
		fsz = st.st_size;
		if((qret = sxi_locate_volume(sxi_cluster_get_conns(dest->cluster), dest->volume, &volhosts, &fsz, NULL, NULL))) {
		    SXDEBUG("failed to locate destination volume");
		    goto local_to_remote_err;
		}
		if(fsz < 1024 || fsz > UPLOAD_CHUNK_SIZE) {
		    SXDEBUG("cannot handle the requested blocksize %lld", (long long int)fsz);
		    goto local_to_remote_err;
		}
		blocksize = fsz;
	    }
	}

	if(fh->f->file_update) {
	    fret = fh->f->file_update(fh, fh->ctx, cfgval, cfgval_len, SXF_MODE_UPLOAD, source, dest, recursive);
	    if(fret == 100) {
		ret = 0;
		goto local_to_remote_err;
	    } else if(fret) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process files", filter_uuid);
		goto local_to_remote_err;
	    }
	}
    }

    if(sxi_filemeta_process(sx, fh, fdir, dest, cvmeta)) {
        SXDEBUG("Failed to process dest filename");
        goto local_to_remote_err;
    }

    state->max_part_blocks = UPLOAD_PART_THRESHOLD / blocksize;
    state->cluster = dest->cluster;
    state->fd = s;
    state->blocksize = blocksize;
    state->volhosts = &volhosts;
    state->loop_count = sxi_hostlist_get_count(&volhosts);
    state->name = strdup(dest->path);
    if (!state->name) {
	sxi_seterr(sx, SXE_EMEM, "Cannot allocate filename: Out of memory");
        goto local_to_remote_err;
    }
    state->fmeta = dest->meta;
    state->dest = dest;
    state->size = st.st_size;
    state->mtime = st.st_mtime;

    xfer_stat = sxi_cluster_get_xfer_stat(dest->cluster);
    if(xfer_stat) {
        if(sxi_xfer_set_file(xfer_stat, source->path, state->size, blocksize, SXC_XFER_DIRECTION_UPLOAD)) {
            SXDEBUG("Could not set transfer information to file %s", source->path);
            goto local_to_remote_err;
        }
        if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
            SXDEBUG("Could not start transfer");
            sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
            goto local_to_remote_err;
        }
        xfer_stat->status = SXC_XFER_STATUS_RUNNING;
    }

    job = multi_upload(state, http_status);
    if (!job) {
        if (state->qret > 0)
            qret = state->qret;
        goto local_to_remote_err;
    }

    /* Update transfer information, but not when aborting */
    if(xfer_stat && sxc_geterrnum(sx) != SXE_ABORT) {
        /* Upload process is waiting for job to finish */
        xfer_stat->status = SXC_XFER_STATUS_WAITING;
        if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
            SXDEBUG("Could not finish transfer");
            sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
            goto local_to_remote_err;
        }
    }

    ret = job;
    local_to_remote_err:
    if (!ret && qret > 0 && http_status)
        *http_status = qret;
    SXDEBUG("returning job: %s, http status: %ld", ret ? sxi_job_get_id(ret) : "NULL", qret);
    if(yctx)
	sxi_jparse_destroy(yctx->current.J);

    if(yctx) {
	if(yctx->current.f) {
	    fclose(yctx->current.f);
	    if(fname)
		unlink(fname);
	}
        free(yctx->current.token);
	free(yctx);
    }

    if(fname)
	sxi_tempfile_untrack(sx, fname);

    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);

    if(s>=0)
	close(s);
    free(buf);
    free(fdir);

    if(tempfname) {
	unlink(tempfname);
	sxi_tempfile_untrack(sx, tempfname);
    }

    if(state) {
	free(state->name);
	free(state->host);
	free(state);
    }
    sxi_hostlist_empty(&shost);
    sxi_hostlist_empty(&volhosts);

    if(ret && fh && fh->f->file_notify)
	sxi_job_set_nf(ret, fh, fh->f->file_notify, source->path, sxc_cluster_get_sslname(dest->cluster), dest->volume, dest->path);

    if (restore_path(dest)) {
        sxi_job_free(ret);
        ret = NULL;
    }

    return ret;
}

static int local_to_remote_iterate(sxc_file_t *source, int recursive, int depth, int onefs, int ignore_errors, sxc_file_t *dest, const sxc_exclude_t *exclude, sxi_jobs_t *jobs, int *errors)
{
    struct dirent *entry;
    sxc_client_t *sx = source->sx;
    DIR *dir;
    unsigned n, n2;
    char *path = NULL, *destpath = NULL;
    struct stat sb;
    int ret = 0, r;
    dev_t sdev;
    long qret = -1;
    sxi_job_t *job = NULL;

    if (stat(source->path, &sb) == -1) {
        sxi_setsyserr(source->sx, SXE_EREAD, "Cannot stat '%s'", source->path);
        return -1;
    }
    sdev = sb.st_dev;
    if(!source->origpath) {
        source->origpath = strdup(source->path);
        if(!source->origpath) {
            sxi_seterr(source->sx, SXE_EMEM, "Out of memory");
            return -1;
        }
    }
    if (!recursive || !S_ISDIR(sb.st_mode)) {
        if((r = is_excluded(sx, source->path, exclude)) > 0) {
            sxi_info(sx, "Skipping file: %s", source->path);
            return 0;
        } else if(r < 0) {
            return r;
        }

        if(sxi_file_set_size(source, sb.st_size)) {
            SXDEBUG("Failed to set local file size");
            return -1;
        }

	job = local_to_remote_begin(source, dest, recursive, &qret, jobs);
        if (!job) {
            SXDEBUG("uploading one file failed");
            (*errors)++;
            return qret;
        }
        if (sxi_jobs_add(jobs, job)) {
            SXDEBUG("failed to add job to jobs context");
            sxi_job_free(job);
            (*errors)++;
            return ret;
        }
	return ret;
    }
    SXDEBUG("Iterating on %s", source->path);

    dir = opendir(source->path);
    if (!dir) {
        sxi_setsyserr(sx, SXE_EREAD, "Cannot open directory '%s'", source->path);
        free(path);
        free(destpath);
        return -1;
    }

    sxc_file_t *src = NULL;
    sxc_file_t *dst = NULL;
    /* FIXME: not thread-safe, should use readdir_r */
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
	n = strlen(source->path) + 2 + strlen(entry->d_name);
	n2 = strlen(dest->path) + 2 + strlen(entry->d_name);
	path = sxi_realloc(sx, path, n);
        if (!path) {
            ret = -1;
            break;
        }
	destpath = sxi_realloc(sx, destpath, n2);
        if (!destpath) {
            sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate destpathname");
            ret = -1;
            break;
        }

        snprintf(path, n, "%s%s%s", source->path,
                 ends_with(source->path, '/') ? "" : "/",
                 entry->d_name);
        if (lstat(path, &sb) == -1) {
            sxi_setsyserr(sx, SXE_EREAD, "Cannot stat '%s'", path);
            ret = -1;
            continue;
        }
	if(onefs && sb.st_dev != sdev)
	    continue;
        src = sxi_file_dup(source);
        dst = sxi_file_dup(dest);
        if (!src || !dst)
            break;
        free(src->path);
        src->path = path;
        path = NULL;
        snprintf(destpath, n2, "%s%s%s", dest->path,
                 ends_with(dest->path, '/') ? "" : "/",
                 entry->d_name);
        if (S_ISDIR(sb.st_mode)) {
            qret = local_to_remote_iterate(src, 1, depth+1, onefs, ignore_errors, dst, exclude, jobs, errors);
            if (qret) {
                SXDEBUG("failure in directory: %s", destpath);
                if (qret == 403 || qret == 404 || qret == 413) {
                    ret = qret;
                    break;
                }
                ret = -1;
                if (!ignore_errors)
                    break;
            }
        }
        else if (S_ISREG(sb.st_mode)) {
            if((r = is_excluded(sx, src->path, exclude)) > 0) {
                sxi_info(sx, "Skipping file: %s", src->path);
                sxc_file_free(src);
                sxc_file_free(dst);
                src = dst = NULL;
                continue;
            } else if(r < 0)
                break;
            SXDEBUG("Starting to upload %s", src->path);
            if (!(job = local_to_remote_begin(src, dst, 1, &qret, jobs))) {
                sxi_notice(sx, "%s: %s", src->path, sxc_geterrmsg(sx));
                SXDEBUG("failed to begin upload on %s", src->path);
                (*errors)++;
                if (qret == 403 || qret == 404 || qret == 413) {
                    ret = qret;
                    if (!ignore_errors)
                        break;
                }
                ret = -1;
                break;
            }
            if(sxi_jobs_add(jobs, job) == -1) {
                SXDEBUG("failed to add job to jobs context");
                sxi_job_free(job);
                ret = -1;
                (*errors)++;
                break;
            }
            job = NULL;
        } else if (S_ISLNK(sb.st_mode)) {
            sxi_notice(sx, "Skipped symlink %s", src->path);
        }
        sxc_file_free(src);
        sxc_file_free(dst);
        src = dst = NULL;
    }
    sxc_file_free(src);
    sxc_file_free(dst);
    src = dst = NULL;
    free(path);
    free(destpath);
    closedir(dir);

    if (!depth) {
        if (jobs && sxi_jobs_errors(jobs, NULL) + *errors > 1)
            sxi_seterr(sx, SXE_SKIP, "Failed to process %d file(s)", sxi_jobs_errors(jobs, NULL));
        if (sxc_geterrnum(sx) != SXE_NOERROR)
            ret = -1;
    }

    return ret;
}

/*
  {
  "blockSize":1024,
  "fileSize":9876,
  "createdAt":1234,
  "fileRevision":"FILEREV",
  "fileData":[
    { "block" : [ "host1", "host2" ] },
    ...
  ]
 */


struct cb_getfile_ctx {
    curlev_context_t *cbdata;
    jparse_t *J;
    const struct jparse_actions *acts;
    FILE *f;
    int64_t filesize, blocksize, created_at;
    unsigned int nblocks;
    enum sxc_error_t err;
};

static void cb_getfile_bs(jparse_t *J, void *ctx, int32_t num) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid block size requested");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->blocksize = num;
}
static void cb_getfile_size(jparse_t *J, void *ctx, int64_t num) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid file size");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->filesize = num;
}
static void cb_getfile_time(jparse_t *J, void *ctx, int64_t num) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid file modification time");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->created_at = num;
}

static void cb_getfile_blockinit(jparse_t *J, void *ctx) {
    const char *block = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;

    if(strlen(block) != SXI_SHA1_TEXT_LEN) {
	sxi_jparse_cancel(J, "Received block with invalid name '%s'", block);
	yactx->err = SXE_ECOMM;
	return;
    }
    if(!(fwrite(block, SXI_SHA1_TEXT_LEN, 1, yactx->f))) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
	sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	yactx->err = SXE_EWRITE;
	sxc_clearerr(sx);
	return;
    }
    yactx->nblocks++;
}


static void cb_getfile_host(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;

    if(sxi_getenv("SX_DEBUG_SINGLEHOST")) {
	string = sxi_getenv("SX_DEBUG_SINGLEHOST");
	length = strlen(string);
    }

    if(length < 2 || length > 40) {
	const char *block = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J))));
	sxi_jparse_cancel(J, "Received invalid address %.*s for block %s", length, string, block);
	yactx->err = SXE_ECOMM;
	return;
    }

    if(fputc(length, yactx->f) == EOF || !fwrite(string, length, 1, yactx->f)) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
	sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	yactx->err = SXE_EWRITE;
	sxc_clearerr(sx);
	return;
    }

}

static void cb_getfile_blockdone(jparse_t *J, void *ctx) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;

    if(fputc(0, yactx->f) == EOF) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
	sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	yactx->err = SXE_EWRITE;
	sxc_clearerr(sx);
	return;
    }
}

static int getfile_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to retrieve the blocks to download: Out of memory");
	return 1;
    }

    rewind(yactx->f);
    yactx->blocksize = 0;
    yactx->filesize = -1;
    yactx->nblocks = 0;
    yactx->created_at = -1;

    return 0;
}

static int getfile_cb(curlev_context_t *cctx, void *ctx, const void *data, size_t size) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

struct hash_down_data_t {
    sxi_hostlist_t hosts;
    off_t* offsets;
    size_t osize;
    long state;/* TRANSFER_*, or an http status code */
    unsigned int ocnt;
    char hash[SXI_SHA1_TEXT_LEN];
};

/*
 * TODO: Make this structure arrays allocatable to minimize memory.
 * Those arrays could contain one element for single_download function.
 */
typedef struct {
  sxi_ht *hashes;
  struct hash_down_data_t *hashdata[DOWNLOAD_MAX_BLOCKS];
  const char *hash[DOWNLOAD_MAX_BLOCKS];
  unsigned i;
  unsigned n;
  unsigned written;
} hashes_info_t;


static int pread_all(int fd, void *buf, size_t count, off_t offset) {
    char *dest = (char *)buf;

    while(count) {
	ssize_t r = pread(fd, dest, count, offset);
	if(r<0) {
	    if(errno == EINTR)
		continue;
	    return 1;
	}
	if(!r)
	    return 1;
	dest += r;
	count -= r;
	offset += r;
    }
    return 0;
}

static int pwrite_all(int fd, const void *buf, size_t count, off_t offset) {
    const char *src = (const char *)buf;

    while(count) {
	ssize_t r = pwrite(fd, src, count, offset);
	if(r<0) {
	    if(errno == EINTR)
		continue;
	    return 1;
	}
	src += r;
	count -= r;
	offset += r;
    }
    return 0;
}

struct cb_gethash_ctx {
    curlev_context_t *cbdata;
    uint8_t *base;
    off_t bsize;
    unsigned int at;
};

static int gethash_setup_cb_old(curlev_context_t *cbdata, void *ctx, const char *host) {
struct cb_gethash_ctx *yactx = (struct cb_gethash_ctx *)ctx;
yactx->at = 0;
yactx->cbdata = cbdata;
 return 0;
}
 
static int gethash_cb_old(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_gethash_ctx *yactx = (struct cb_gethash_ctx *)ctx;
    if(size + yactx->at > (size_t) yactx->bsize) {
       CBDEBUG("too much data received");
       return 1;
    }
    memcpy(yactx->base + yactx->at, data, size);
    yactx->at += size;
    return 0;
}

static int download_block_to_buf_track(sxc_cluster_t *cluster, sxi_hostlist_t *hostlist, const char *hash, uint8_t *buf, unsigned int blocksize, int track_xfer) {
    struct cb_gethash_ctx ctx;
    char url[6 + 64 + 40 + 1];
    int qret, l;

    sprintf(url, ".data/%u/", blocksize);
    l = strlen(url);
    memcpy(url + l, hash, 40);
    url[l + 40] = '\0';

    ctx.base = buf;
    ctx.at = 0;
    ctx.bsize = blocksize;
    sxi_set_operation(sxi_cluster_get_client(cluster), "download file contents", NULL, NULL, NULL);
    qret = sxi_cluster_query_track(sxi_cluster_get_conns(cluster), hostlist, REQ_GET, url, NULL, 0,
                             gethash_setup_cb_old, gethash_cb_old, &ctx, track_xfer);
    if(qret != 200) {
       CFGDEBUG("Failed to retrieve %s - status: %d", url, qret);
       return 1;
    }
    return 0;
}

static int download_block_to_buf(sxc_cluster_t *cluster, sxi_hostlist_t *hostlist, const char *hash, uint8_t *buf, unsigned int blocksize) {
    return download_block_to_buf_track(cluster, hostlist, hash, buf, blocksize, 0);
}

struct file_download_ctx {
    hashes_info_t hashes;
    int fd;
    unsigned skip;
    unsigned blocksize;
    int64_t filesize;
    unsigned char *buf;
    sxi_md_ctx *ctx;
    unsigned int *dldblks;
    unsigned int *queries_finished;

    /* Current download information, updated on CURL callbacks */
    sxi_conns_t *conns;
    int64_t dl;
    int64_t to_dl;
};


/* Set information about current transfer download value */
int sxi_file_download_set_xfer_stat(struct file_download_ctx* ctx, int64_t downloaded, int64_t to_download) {
    int64_t dl_diff = 0;
    double timediff = 0;
    struct timeval now;
    sxc_xfer_stat_t *xfer_stat;

    /* This is not considered as error, ctx or cluster == NULL if we do not want to check progress */
    if(!ctx || !(xfer_stat = sxi_conns_get_xfer_stat(ctx->conns)))
        return SXE_NOERROR;

    gettimeofday(&now, NULL);
    timediff = sxi_timediff(&now, &xfer_stat->interval_timer);

    ctx->to_dl = to_download;
    dl_diff = downloaded - ctx->dl;
    ctx->dl = downloaded;

    if(dl_diff > 0 || timediff >= XFER_PROGRESS_INTERVAL)
        return sxi_set_xfer_stat(xfer_stat, dl_diff, 0, timediff);
    else 
        return SXE_NOERROR;
}

/* Get numner of bytes to be downloaded */
int64_t sxi_file_download_get_xfer_to_send(const struct file_download_ctx *ctx) {
    if(!ctx || !sxi_conns_get_xfer_stat(ctx->conns))
        return 0;

    return ctx->to_dl;
}

/* Get number of bytes already downloaded */
int64_t sxi_file_download_get_xfer_sent(const struct file_download_ctx *ctx) {
    if(!ctx || !sxi_conns_get_xfer_stat(ctx->conns))
        return 0;

    return ctx->dl;
}


static int process_block(sxi_conns_t *conns, curlev_context_t *cctx)
{
    unsigned j;
    struct hash_down_data_t *hashdata;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct file_download_ctx *ctx = sxi_cbdata_get_download_ctx(cctx);

    if(!ctx)
	return -1;
    if (ctx->hashes.i > ctx->hashes.n) {
        SXDEBUG("out of range hash count: %d,%d", ctx->hashes.i, ctx->hashes.n);
        return -1;
    }
    hashdata = ctx->hashes.hashdata[ctx->hashes.i-1];
    /* got a full block */
    for(j=0; j<hashdata->ocnt; j++) {
        /* write out hash */
        off_t writesz;
        if(j==ctx->skip)
            continue;

        if(hashdata->offsets[j] + ctx->blocksize > ctx->filesize)
            writesz = ctx->filesize - hashdata->offsets[j];
        else
            writesz = ctx->blocksize;
        if(pwrite_all(ctx->fd, ctx->buf, writesz, hashdata->offsets[j])) {
            sxi_cbdata_setsyserr(cctx, SXE_EWRITE, "write");
            SXDEBUG("Failed to write block at offset %llu", (long long unsigned)hashdata->offsets[j]);
            return -1;
        }
    }
#if 0
    const char *hash;
    char chash[41];
    /* check that hash is correct */
    hash = ctx->hashes.hash[ctx->hashes.i-1];
    if (!hash) {
        SXDEBUG("Null argument to gethash_cb");
        return -1;
    }
    if (sxi_cluster_hashcalc(cluster, ctx->buf, ctx->blocksize, chash)) {
        SXDEBUG("failed to calculate hash");
        return -1;
    }
    if (memcmp(chash, hash, 40)) {
        SXDEBUG("Downloaded hash mismatch: %.*s != %.*s", 40, chash, 40, hash);
        return -1;/* TODO: should retry on another node */
    }
#endif
    ctx->hashes.written = 0;
    return 0;
}

static int gethash_cb(curlev_context_t *cctx, const unsigned char *data, size_t size)
{
    struct file_download_ctx *ctx = sxi_cbdata_get_download_ctx(cctx);
    sxi_conns_t *conns = sxi_cbdata_get_conns(cctx);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    while (size > 0) {
        unsigned len, remaining;
        struct hash_down_data_t *hashdata = ctx->hashes.hashdata[ctx->hashes.i];

        if (!hashdata) {
            SXDEBUG("Null argument to gethash_cb");
            return -1;
        }

        if (ctx->hashes.written == ctx->blocksize)
            if (process_block(conns, cctx) == -1)
                return -1;/* write out previous block */
        remaining = ctx->blocksize - ctx->hashes.written;
        len = size < remaining ? size : remaining;
        memcpy(ctx->buf + ctx->hashes.written, data, len);
        ctx->hashes.written += len;
        size -= len;
        data = data + len;
        if (ctx->hashes.written < ctx->blocksize)
            continue;
        ctx->hashes.i++;
    }
    return 0;
}

static void dctx_free(struct file_download_ctx *ctx)
{
    if (!ctx)
        return;
    sxi_md_cleanup(&ctx->ctx);
    free(ctx->buf);
    free(ctx);
}

static void gethash_finish(curlev_context_t *cctx, const char *url)
{
    sxi_conns_t *conns = sxi_cbdata_get_conns(cctx);
    sxc_client_t *sx = conns ? sxi_conns_get_client(conns) : NULL;
    struct file_download_ctx *ctx = sxi_cbdata_get_download_ctx(cctx);
    unsigned i;
    long status = 0;

    sxi_md_cleanup(&ctx->ctx);
    sxi_cbdata_result(cctx, NULL, NULL, &status);
    if (status== 200 && ctx->dldblks)
        (*ctx->dldblks) += ctx->hashes.i;
    SXDEBUG("finished %d hashes with code %ld", ctx->hashes.i, status);
    if (ctx->queries_finished)/* finished, not necesarely successfully */
        (*ctx->queries_finished) += ctx->hashes.n;
    if (ctx->hashes.written == ctx->blocksize)
        if (process_block(conns, cctx) == -1)/* write out last block */ {
            SXDEBUG("failed to write block");
        }

    for (i=0;i<ctx->hashes.i;i++) {
        struct hash_down_data_t *hashdata = ctx->hashes.hashdata[i];
        hashdata->state = status;
        /* do not check ctx->rc, there might be a curl error about a partial
         * transfer, but we know that hashes.i blocks were completely transferred */
        if (hashdata->state == 200) {
            sxi_hostlist_empty(&hashdata->hosts);
            sxi_ht_del(ctx->hashes.hashes, ctx->hashes.hash[i], 40);
            ctx->hashes.hashdata[i] = NULL;
            ctx->hashes.hash[i] = NULL;
        }
    }
    for (i=ctx->hashes.i;i<ctx->hashes.n;i++) {
        /* batch got truncated, mark the rest of the hashes as failed,
         * even if the reply itself was 200 */
        struct hash_down_data_t *hashdata = ctx->hashes.hashdata[i];
        hashdata->state = 404;
    }
    if (ctx->hashes.i != ctx->hashes.n)
        SXDEBUG("batch truncated, %d hashes not transferred", ctx->hashes.n - ctx->hashes.i);
    dctx_free(ctx);
}

static int path_is_root(const char *path)
{
    do {
        while (*path == '/') path++;
        while (path[0] == '.' && (path[1] == '/' || !path[1])) path++;
    } while (*path == '/');
    return !*path;
}

static int hashes_to_download(sxc_file_t *source, sxi_hostlist_t *volnodes, FILE **tf, char **tfname, unsigned int *blocksize, int64_t *filesize, int64_t *created_at) {
    const struct jparse_actions acts = {
	JPACTS_INT32(
		     JPACT(cb_getfile_bs, JPKEY("blockSize"))
		     ),
	JPACTS_INT64(
		     JPACT(cb_getfile_size, JPKEY("fileSize")),
		     JPACT(cb_getfile_time, JPKEY("createdAt"))
		     ),
	JPACTS_STRING(
		      JPACT(cb_getfile_host, JPKEY("fileData"), JPANYITM, JPANYKEY, JPANYITM)
		      ),
	JPACTS_ARRAY_BEGIN(
			   JPACT(cb_getfile_blockinit, JPKEY("fileData"), JPANYITM, JPANYKEY)
			   ),
	JPACTS_ARRAY_END(
			 JPACT(cb_getfile_blockdone, JPKEY("fileData"), JPANYITM, JPANYKEY)
			 )
    };
    char *enc_vol = NULL, *enc_path = NULL, *url = NULL, *enc_rev = NULL, *hsfname = NULL;
    struct cb_getfile_ctx yctx;
    sxc_client_t *sx = source->sx;
    unsigned int urlen;
    int ret = 1;

    memset(&yctx, 0, sizeof(yctx));
    yctx.acts = &acts;

    if (path_is_root(source->path)) {
        sxi_seterr(source->sx, SXE_EARG, "Invalid path");
        goto hashes_to_download_err;
    }
    if(!(enc_vol = sxi_urlencode(source->sx, source->volume, 0))) {
	SXDEBUG("failed to encode volume %s", source->volume);
	goto hashes_to_download_err;
    }

    if(!(enc_path = sxi_urlencode(source->sx, source->remote_path, 0))) {
	SXDEBUG("failed to encode path %s", source->path);
	goto hashes_to_download_err;
    }

    urlen = strlen(enc_vol) + 1 + strlen(enc_path) + 1;
    if(source->rev) {
	if(!(enc_rev = sxi_urlencode(source->sx, source->rev, 0))) {
	    SXDEBUG("failed to encode revision %s", source->rev);
	    goto hashes_to_download_err;
	}
	urlen += lenof("?rev=") + strlen(enc_rev);
    }

    url = malloc(urlen);
    if(!url) {
	SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve the blocks to download: Out of memory");
	goto hashes_to_download_err;
    }

    if(enc_rev)
	sprintf(url, "%s/%s?rev=%s", enc_vol, enc_path, enc_rev);
    else
	sprintf(url, "%s/%s", enc_vol, enc_path);

    if(!(hsfname = sxi_tempfile_track(source->sx, NULL, &yctx.f))) {
	SXDEBUG("failed to generate results file");
	goto hashes_to_download_err;
    }

    sxi_set_operation(sx, "download file content hashes", sxi_cluster_get_name(source->cluster), source->volume, source->path);
    if(sxi_cluster_query(sxi_cluster_get_conns(source->cluster), volnodes, REQ_GET, url, NULL, 0, getfile_setup_cb, getfile_cb, &yctx) != 200) {
	SXDEBUG("file get query failed");
	goto hashes_to_download_err;
    }
    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	goto hashes_to_download_err;
    }

    if(!yctx.blocksize || yctx.filesize < 0 || yctx.blocksize * yctx.nblocks < yctx.filesize || yctx.blocksize * yctx.nblocks >= yctx.filesize + yctx.blocksize) {
	SXDEBUG("bad reply from cluster");
	sxi_seterr(sx, SXE_ECOMM, "Failed to retrieve the blocks to download: Communication error");
	goto hashes_to_download_err;
    }

    rewind(yctx.f);
    *tf = yctx.f;
    *tfname = hsfname;
    *blocksize = yctx.blocksize;
    *filesize = yctx.filesize;
    if (created_at)
        *created_at = yctx.created_at;
    ret = 0;

hashes_to_download_err:
    sxi_jparse_destroy(yctx.J);
    free(url);
    if(ret) {
	if(hsfname) {
	    if(yctx.f)
		fclose(yctx.f);
	    unlink(hsfname);
	    sxi_tempfile_untrack(sx, hsfname);
	}
    }
    free(enc_rev);
    free(enc_path);
    free(enc_vol);
    return ret;
}

#define TRANSFER_PENDING (-100)
#define TRANSFER_FAILCONN (-1)
#define TRANSFER_NOT_STARTED 0
#define TRANSFER_NOT_NECESSARY 1 /* already have the hash */

static char zerobuf[SX_BS_LARGE];

static struct file_download_ctx *dctx_new(sxc_client_t *sx)
{
    sxi_md_ctx *mdctx = sxi_md_init();
    if (!mdctx)
        return NULL;
    struct file_download_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
	sxi_md_cleanup(&mdctx);
        return NULL;
    }
    ctx->ctx = mdctx;
    return ctx;
}

/* version of download_block() that just checks already existing data */
static int check_block(sxc_cluster_t *cluster, sxi_ht *hashes, const char *zerohash,
                       const char *hash, struct hash_down_data_t *hashdata,
                       int fd, off_t filesize,
                       unsigned char *buf, unsigned blocksize)
{
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    struct file_download_ctx *dctx;
    curlev_context_t *cbdata;
    unsigned i;
    char chash[41];

    for(i=0;i<hashdata->ocnt; i++) {
	if(filesize - hashdata->offsets[i] >= blocksize) {
	    if(pread_all(fd, buf, blocksize, hashdata->offsets[i]))
		continue;
	} else {
	    off_t canread = filesize - hashdata->offsets[i];
	    if(pread_all(fd, buf, canread, hashdata->offsets[i]))
		continue;
	    memset(buf+canread, 0, blocksize - canread);
	}

        if (!memcmp(buf, zerobuf, blocksize)) {
            /* block all zero, check if that is what we need here */
            if (!memcmp(zerohash, hash, 40))
                break;
            /* it is not what we need, no need to calculate hash */
            continue;
        }
	if(sxi_cluster_hashcalc(cluster, buf, blocksize, chash)) {
	    CFGDEBUG("Failed to compute hash for block");
	    return -1;
	}
	if(!memcmp(hash, chash, 40))
	    break;
    }

    if(i == hashdata->ocnt)
        return 0;
    dctx = dctx_new(sxi_conns_get_client(conns));
    if(!dctx) {
        cluster_err(SXE_EMEM, "failed to allocate dctx");
        return -1;
    }
    dctx->buf = malloc(blocksize);
    if (!dctx->buf) {
        cluster_err(SXE_EMEM, "failed to allocate buffer");
        dctx_free(dctx);
        return -1;
    }
    /* do not set finish_callback to avoid freeing stacked data */
    dctx->blocksize = blocksize;
    dctx->hashes.hashes = hashes;
    dctx->hashes.n = 1;
    dctx->hashes.hashdata[0] = hashdata;
    dctx->hashes.hash[0] = hash;
    dctx->fd = fd;
    dctx->filesize = filesize;
    dctx->skip = i;
    if (!(cbdata = sxi_cbdata_create_download(conns, NULL, dctx))) {
        dctx_free(dctx);
        return -1;
    }
    sxi_cbdata_set_result(cbdata, 200);
    gethash_cb(cbdata, buf, blocksize);
    gethash_finish(cbdata, NULL);
    sxi_cbdata_unref(&cbdata);

    return 1;
}

static int send_batch(sxi_ht *hostsmap, sxi_conns_t *conns,
                      const char *host, curlev_context_t **cbdata, unsigned *requested)
{
    unsigned i, n;
    int rc;
    char url[4096];
    const char *end = url + sizeof(url);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct file_download_ctx *dctx = sxi_cbdata_get_download_ctx(*cbdata);
    char *q;
    SXDEBUG("sending batch of %d", dctx->hashes.n);

    snprintf(url, sizeof(url), ".data/%u/", dctx->blocksize);
    q = url + strlen(url);
    for (i=0;i<dctx->hashes.n;i++) {
        if (q + 40 > end) {
            SXDEBUG("url overflowed");
            sxi_ht_del(hostsmap, host, strlen(host)+1);
            sxi_cbdata_unref(cbdata);
            return -1;
        }
        memcpy(q, dctx->hashes.hash[i], 40);
        q += 40;
    }
    *q = 0;
    sxi_cbdata_set_operation(*cbdata, "download file contents", NULL, NULL, NULL);
    n = dctx->hashes.n;
    rc = sxi_cluster_query_ev(*cbdata, conns, host, REQ_GET, url, NULL, 0,
                              NULL, gethash_cb);
    sxi_cbdata_unref(cbdata);
    sxi_ht_del(hostsmap, host, strlen(host)+1);
    if (rc == -1) {
        if (sxc_geterrnum(sx) == SXE_NOERROR)
            sxi_seterr(sx, SXE_ECOMM, "Failed to query cluster");
        SXDEBUG("returning with failure");
        return -1;
    }
    *requested += n;
    return 0;
}

struct batch_hashes {
    sxi_ht *hashes;
    struct hash_down_data_t *hashdata;
    unsigned i;
    unsigned n;
};

static curlev_context_t *create_download(sxc_cluster_t *cluster, unsigned int blocksize, int fd, off_t filesize) {
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct file_download_ctx *dctx;
    curlev_context_t *ret;

    if(!conns || !sx)
        return NULL;

    dctx = dctx_new(sx);
    if (!dctx) {
        sxi_seterr(sx, SXE_EMEM, "Cannot download file: Out of emory");
        return NULL;
    }

    ret = sxi_cbdata_create_download(conns, gethash_finish, dctx);
    if (!ret) {
        sxi_seterr(sx, SXE_EMEM, "Cannot download file: Out of memory");
        dctx_free(dctx);
        return NULL;
    }

    if(sxi_cbdata_set_timeouts(ret, BLOCK_XFER_HARD_TIMEOUT, BLOCK_XFER_SOFT_TIMEOUT)) {
        SXDEBUG("Failed to set timeouts");
        sxi_cbdata_unref(&ret);
        dctx_free(dctx);
        return NULL;
    }

    dctx->buf = malloc(blocksize);
    if (!dctx->buf) {
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate buffer");
        sxi_cbdata_unref(&ret);
        dctx_free(dctx);
        return NULL;
    }

    dctx->fd = fd;
    dctx->filesize = filesize;
    dctx->skip = -1;
    dctx->blocksize = blocksize;
    dctx->conns = sxi_cluster_get_conns(cluster);

    return ret;
}

static int single_download(struct batch_hashes *bh, const char *dstname,
                          unsigned blocksize, sxc_cluster_t *cluster,
                          int fd, off_t filesize) {
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    sxi_retry_t *retry;
    unsigned int i;
    int ret = 1;

    sxc_clearerr(sx);
    retry = sxi_retry_init(sx, RCTX_SX);
    if (!retry) {
        cluster_err(SXE_EMEM, "Cannot allocate retry");
        return 1;
    }

    /* Iterate over all hashes */
    for(i = 0; i < bh->i; i++) {
        struct hash_down_data_t *hashdata = &bh->hashdata[i];
        const char *hash = hashdata->hash;
        unsigned int j;
        unsigned int hostcount = sxi_hostlist_get_count(&hashdata->hosts);

        /* Check if we want to download given hash taking into account its status */
        if (hashdata->state == TRANSFER_PENDING || hashdata->state == TRANSFER_NOT_NECESSARY ||
            hashdata->state == 200) {
            SXDEBUG("[%.8s] Transfer not necessary: %ld", hashdata->hash, hashdata->state);
            continue;
        }

        /*
         * Check if host list is not empty for given hash. If so, we have an error, because if status is not OK,
         * this list should not be cleared.
         */
        if(hostcount == 0) {
            SXDEBUG("[%.8s] 0 hosts available", hashdata->hash);
            cluster_err(SXE_EARG, "Empty list of hosts when transfer status is not OK");
            break;
        }

        for(j = 0; j < hostcount; j++) {
            struct file_download_ctx *dctx;
            curlev_context_t *cbdata;
            unsigned int finished = 0;
            char url[4096];
            char *q;
            const char *host;
            int rc;

            cbdata = create_download(cluster, blocksize, fd, filesize);
            if (!cbdata)
                break;

            dctx = sxi_cbdata_get_download_ctx(cbdata);
            dctx->dldblks = NULL;
            dctx->queries_finished = &finished;
            dctx->hashes.hashes = bh->hashes;
            dctx->hashes.n = 1;
            /* We only use one block */
            dctx->hashes.hash[0] = hash;
            dctx->hashes.hashdata[0] = hashdata;

            snprintf(url, sizeof(url), ".data/%u/", dctx->blocksize);
            q = url + strlen(url);
            memcpy(q, hash, 40);
            q[40] = '\0';

            host = sxi_hostlist_get_host(&hashdata->hosts, j);

            sxi_retry_check(retry, j);
            sxi_retry_msg(sx, retry, host);

            sxi_cbdata_set_operation(cbdata, "download file contents", NULL, NULL, NULL);
            rc = sxi_cluster_query_ev(cbdata, conns, host, REQ_GET, url, NULL, 0, NULL, gethash_cb);

            if(rc) {
                SXDEBUG("[%.8s] Could not add %s query: %s", hash, url, sxi_cbdata_geterrmsg(cbdata));
                do {
                    rc = sxi_curlev_poll(sxi_conns_get_curlev(conns));
                } while (!rc);
                sxi_cbdata_unref(&cbdata);
                goto single_download_fail;
            }

            sxi_cbdata_unref(&cbdata);

            while (finished != 1 && !rc) {
                rc = sxi_curlev_poll(sxi_conns_get_curlev(conns));
            }

            /* We successfully finished this block download */
            if(!rc && finished == 1 && hashdata->state == 200)
                break;
        }

        if(hashdata->state != 200) {
            cluster_err(SXE_ECOMM, "Could not download hash %s: %s", hashdata->hash, sxc_geterrmsg(sx));
            break;
        }
    }

    if(sxc_geterrnum(sx) != SXE_NOERROR)
	ret = 1;
    else if(i == bh->i) /* Loop went successfully through all blocks, we are happy */
	ret = 0;

    single_download_fail:

    if (sxi_retry_done(&retry))
        CFGDEBUG("retry_done failed");

    return ret;
}

static int multi_download(struct batch_hashes *bh, const char *dstname,
                          unsigned blocksize, sxc_cluster_t *cluster,
                          int fd, off_t filesize)
{
    struct hash_down_data_t *hashdata;
    const char *hash;
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    unsigned int requested = 0;
    unsigned int finished = 0;
    unsigned int transferred = 0;
    unsigned long total_hashes;
    unsigned long total_downloaded;
    char zerohash[41];
    sxi_ht *hostsmap;
    const char *host = NULL;
    unsigned char *buf;
    curlev_context_t *cbdata = NULL;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    unsigned hostcount = 0;
    struct file_download_ctx *dctx;
    unsigned i;
    unsigned loop = 0;
    unsigned outstanding=0;

    if (sxi_cluster_hashcalc(cluster, zerobuf, blocksize, zerohash)) {
        CFGDEBUG("Failed to compute hash of zero");
        return 1;
    }

    buf = malloc(blocksize);
    if (!buf) {
        cluster_err(SXE_EMEM, "Cannot allocate hash buffer");
        return 1;
    }

    total_hashes = bh->i;
    total_downloaded = 0;
    requested = -1;

    hostsmap = sxi_ht_new(sxi_cluster_get_client(cluster), 128);
    if (!hostsmap) {
        cluster_err(SXE_EMEM, "Cannot allocate hosts hash");
        free(buf);
        return 1;
    }
    requested = finished = transferred = 0;
    for (i=0;i<bh->i;i++) {
        unsigned dctxn;
        int rc;

        hashdata = &bh->hashdata[i];
        hash = hashdata->hash;
	loop++;
        if (hashdata->state == TRANSFER_PENDING || hashdata->state == TRANSFER_NOT_NECESSARY ||
            hashdata->state == 200)
            continue;
        hostcount = sxi_hostlist_get_count(&hashdata->hosts);
        if (!hostcount) {
            CFGDEBUG("No hosts available for hash %.*s!", 40, hash);
            break;
        }

        if(sxi_get_node_preference(sx) > 0.0) {
            /* Get optimal node for hash, learn from previous connection statistics */
            host = sxi_hostlist_get_optimal_host(conns, &hashdata->hosts, SXC_XFER_DIRECTION_DOWNLOAD);
        } else {
            /* Default way to get a host for hash is to get first node proposed by server */
            host = sxi_hostlist_get_host(&hashdata->hosts, 0);
        }

        if (!host) {
            CFGDEBUG("Ran out of hosts for hash: (last HTTP code %ld)", hashdata->state);
            /* TODO: set err and break */
            break;
        }
        hashdata->state = TRANSFER_PENDING;
        sxi_set_operation(sx, "file block download", NULL, NULL, NULL);

        rc = check_block(cluster, bh->hashes, zerohash, hash, hashdata, fd, filesize, buf, blocksize);
        if (rc == -1) {
            CFGDEBUG("checking block failed");
            break;
        }
        if (rc) {
            sxc_xfer_stat_t *xfer_stat = NULL;
            CFGDEBUG("Got the hash!");
            total_downloaded++;
            sxi_hostlist_empty(&hashdata->hosts);
            sxi_ht_del(bh->hashes, hash, 40);

            xfer_stat = sxi_cluster_get_xfer_stat(cluster);
            if(xfer_stat && skip_xfer(cluster, (int64_t)blocksize * hashdata->ocnt) != SXE_NOERROR) {
                CFGDEBUG("Could not skip %u bytes of transfer", blocksize * hashdata->ocnt);
                sxi_seterr(sx, SXE_ABORT, "Could not skip %u bytes of transfer", blocksize * hashdata->ocnt);
                break;
            }

            continue;/* we've got the hash */
        }

        if (sxi_ht_get(hostsmap, host, strlen(host)+1, (void**)&cbdata)) {
            /* host not found -> new host */
            cbdata = create_download(cluster, blocksize, fd, filesize);
            if (!cbdata)
                break;
            dctx = sxi_cbdata_get_download_ctx(cbdata);
            dctx->dldblks = &transferred;
            dctx->queries_finished = &finished;
            dctx->hashes.hashes = bh->hashes; 
        } else
            dctx = sxi_cbdata_get_download_ctx(cbdata);

        if(!dctx) {
            CFGDEBUG("Null cbdata");
            sxi_seterr(sx, SXE_EMEM, "Null cbdata");
            break;
        }

        dctx->hashes.hash[dctx->hashes.n] = hash;
        dctx->hashes.hashdata[dctx->hashes.n] = hashdata;
        outstanding++;
        dctxn = ++dctx->hashes.n;
        if (dctxn >= DOWNLOAD_MAX_BLOCKS) {
            if (send_batch(hostsmap, conns, host, &cbdata, &requested) == -1)
                break;

	    outstanding -= dctxn;
        } else {
            if (sxi_ht_add(hostsmap, host, strlen(host)+1, cbdata)) {
                /* it failed */
                CFGDEBUG("failed to add to hosts hashtable");
                break;
            }
        }
	SXDEBUG("loop: %d, host:%s, n:%d, outstanding:%d, requested: %d", loop, host, dctxn,outstanding, requested);
    }
    sxi_ht_enum_reset(hostsmap);
    SXDEBUG("looped: %d; requested: %d", loop, requested);
    while(/*sxc_geterrnum(sx) == SXE_NOERROR &&*/
          !sxi_ht_enum_getnext(hostsmap, (const void **)&host, NULL, (const void **)&cbdata)) {
        send_batch(hostsmap, conns, host, &cbdata, &requested);
    }
    sxi_cbdata_unref(&cbdata);
    if (1 /*sxc_geterrnum(sx) == SXE_NOERROR*/) {
        int rc = 0;
        while (finished != requested && !rc) {
            CFGDEBUG("finished: %d, requested: %d, rc: %d",
                     finished, requested, rc);
            rc = sxi_curlev_poll(sxi_conns_get_curlev(conns));
        }
        CFGDEBUG("loop out: finished: %d, requested: %d, rc: %d",
                 finished, requested, rc);
        if (transferred != finished) {
            CFGDEBUG("Not all hashes could be downloaded: %d(%d) != %d",
                     transferred, finished,requested);
            if (sxc_geterrnum(sx) == SXE_NOERROR)
                sxi_seterr(sx, SXE_ECOMM, "%d hashes could not be downloaed",
                           finished - transferred);
        }
    }
    total_downloaded += transferred;
    sxi_ht_free(hostsmap);

    free(buf);
    if (total_downloaded != total_hashes) {
        CFGDEBUG("Not all hashes were downloaded: %ld != %ld",
                 total_downloaded, total_hashes);
        if (sxc_geterrnum(sx) == SXE_NOERROR)
            sxi_seterr(sx, SXE_ECOMM, "%ld hashes were not downloaded",
                       total_hashes - total_downloaded);
        return 1;
    } else if (sxc_geterrnum(sx) == SXE_NOERROR) {
        CFGDEBUG("All good: %ld hashes", total_hashes);
    }

    return sxc_geterrnum(sx) != SXE_NOERROR;
}

static void batch_hashes_free(struct batch_hashes *bh)
{
    unsigned i;
    sxi_ht_free(bh->hashes);
    if (bh->hashdata) {
        for (i=0;i<bh->i;i++) {
	    sxi_hostlist_empty(&bh->hashdata[i].hosts);
            free(bh->hashdata[i].offsets);
        }
        free(bh->hashdata);
    }
    bh->hashes = NULL;
    bh->hashdata = NULL;
}

static int sxi_seen(sxc_client_t *sx, sxc_file_t *dest)
{
    if (!dest) {
        sxi_seterr(sx, SXE_EARG, "null argument to sxi_seen");
        return -1;
    }
    if (!strcmp(dest->path, "/dev/stdout"))
        return 0;
    if (!dest->seen) {
        dest->seen = sxi_ht_new(sx, 16);
        if (!dest->seen)
            return -1;
    }
    if (sxi_ht_get(dest->seen, dest->path, strlen(dest->path), NULL)) {
        /* return value of 1 means failure: it was NOT found */
        if (sxi_ht_add(dest->seen, dest->path, strlen(dest->path), NULL))
            return -1;
        return 0;/* ok, file was not seen yet */
    } else {
        /* file was already seen */
        return 1;
    }
}

static int cat_remote_file(sxc_file_t *source, int dest);
static int remote_to_local(sxc_file_t *source, sxc_file_t *dest, int recursive) {
    char *hashfile = NULL, *tempdst = NULL, *tempfilter = NULL;
    sxi_ht *hosts = NULL;
    struct hash_down_data_t *hashdata;
    uint8_t *buf = NULL;
    sxc_client_t *sx = source->sx;
    struct stat st;
    int64_t filesize;
    int ret = 1, rd = -1, d = -1, fail = 0, fret;
    unsigned int blocksize;
    off_t curoff = 0;
    FILE *hf = NULL, *tf;
    const char *dstname;
    int dstexisted;
    sxf_action_t action = SXF_ACTION_NORMAL;
    struct filter_handle *fh = NULL;
    char filter_uuid[37], filter_cfgkey[37 + 5], *filter_cfgdir = NULL;
    char outbuff[8192];
    const char *confdir;
    sxc_meta_t *vmeta = NULL, *cvmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;
    struct batch_hashes bh;
    int64_t created_at;
    sxi_hostlist_t volnodes;

    memset(&bh, 0, sizeof(bh));
    if(!(vmeta = sxc_meta_new(sx)))
	return 1;
    if(!(cvmeta = sxc_meta_new(sx))) {
        sxc_meta_free(vmeta);
        return 1;
    }
    sxi_hostlist_init(&volnodes);
    if(sxi_locate_volume(sxi_cluster_get_conns(source->cluster), source->volume, &volnodes, NULL, vmeta, cvmeta)) {
        SXDEBUG("failed to locate destination file");
        goto remote_to_local_err;
    }

    if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume))
        goto remote_to_local_err;
    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        if(mval_len != 16) {
            sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            goto remote_to_local_err;
        }
        sxi_uuid_unparse(mval, filter_uuid);
        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by source volume not found", filter_uuid);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by source volume not found", filter_uuid);
            goto remote_to_local_err;
        }

        snprintf(filter_cfgkey, sizeof(filter_cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, filter_cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, source->volume, cfgval, cfgval_len))
            goto remote_to_local_err;

        confdir = sxi_cluster_get_confdir(source->cluster);
        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, source->volume);
            if(!filter_cfgdir)
                goto remote_to_local_err;
        }
    }

    if(sxi_filemeta_process(sx, fh, filter_cfgdir, source, cvmeta)) {
        SXDEBUG("Failed to process source filename");
        goto remote_to_local_err;
    }

    if(hashes_to_download(source, &volnodes, &hf, &hashfile, &blocksize, &filesize, &created_at)) {
        SXDEBUG("failed to retrieve hash list");
        goto remote_to_local_err;
    }

    /* Store remote file size and created_at fields */
    source->remote_size = filesize;
    source->created_at = created_at;
    dest->remote_size = filesize;
    source->created_at = created_at;

    if(!(buf = malloc(blocksize))) {
	SXDEBUG("OOM allocating the block buffer (%u bytes)", blocksize);
	sxi_seterr(sx, SXE_ECOMM, "Download failed: Out of memory");
	goto remote_to_local_err;
    }

    dstname = dest->path;
    dstexisted = !access(dstname, F_OK);
    switch(sxi_seen(sx, dest)) {
        case 1:
            sxi_seterr(sx, SXE_SKIP, "Not overwriting just-downloaded file");
            goto remote_to_local_err;
        case -1:
            goto remote_to_local_err;
        default:
            break;
    }
    if (!strcmp(dest->path, "/dev/stdout")) {
        d = STDOUT_FILENO;
    } else if((d = open(dest->path, O_RDWR|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH))<0) {
	if(errno == EISDIR)
	    ret = 2;
	SXDEBUG("failed to create destination file");
	sxi_setsyserr(sx, SXE_EWRITE, "Cannot open destination file %s", dstname);
	goto remote_to_local_err;
    }
    if(fstat(d, &st)) {
	SXDEBUG("failed to stat destination file");
	sxi_setsyserr(sx, SXE_EREAD, "failed to stat destination file %s", dstname);
	goto remote_to_local_err;
    }
    if(strcmp(dest->path, "/dev/stdout") && (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode) || !strcmp(dest->path, "/dev/null"))) {
        /* regular files, block devices, and not stdout: write directly */
	if(strcmp(dest->path, "/dev/null") && ftruncate(d, filesize)) {
	    SXDEBUG("failed to set destination file size to %llu", (long long unsigned)filesize);
	    sxi_setsyserr(sx, SXE_EWRITE, "cannot write to destination file %s", dstname);
	    goto remote_to_local_err;
	}
    } else {
        /* stdout and other devices: use tempfile */
	if(!(tempdst = sxi_tempfile_track(dest->sx, NULL, &tf))) {
	    SXDEBUG("failed to generate intermediate file");
	    goto remote_to_local_err;
	}
	rd = d;
	d = fileno(tf);
    }

    if(fh && tempdst && fh->f->data_prepare) {
        unsigned char chksum1[SXI_SHA1_BIN_LEN], chksum2[SXI_SHA1_BIN_LEN];

        if(sxi_meta_checksum(sx, cvmeta, chksum1)) {
            SXDEBUG("Failed to compute custom volume meta checksum");
            goto remote_to_local_err;
        }

        if(fh->f->data_prepare(fh, &fh->ctx, source->path, filter_cfgdir, cfgval, cfgval_len, cvmeta, SXF_MODE_DOWNLOAD)) {
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
            goto remote_to_local_err;
        }

        if(sxi_meta_checksum(sx, cvmeta, chksum2)) {
            SXDEBUG("Failed to compute custom volume meta checksum");
            goto remote_to_local_err;
        }

        if(memcmp(chksum1, chksum2, SXI_SHA1_BIN_LEN)) {
            SXDEBUG("Checksums different, modifying volume %s\n", dest->volume);
            if(sxc_volume_modify(source->cluster, source->volume, NULL, NULL, -1, -1, cvmeta)) {
                if(sxc_geterrnum(source->sx) == SXE_EAUTH)
                    /* ignore error for non-owner */
                    sxc_clearerr(source->sx);
                else
                    goto remote_to_local_err;
            }
        }
    }

    if(fh) {
        if(fh->f->file_update) {
            fret = fh->f->file_update(fh, fh->ctx, cfgval, cfgval_len, SXF_MODE_DOWNLOAD, source, dest, recursive);
            if(fret == 100) {
                ret = 0;
                goto remote_to_local_err;
            } else if(fret) {
                sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process files", filter_uuid);
                goto remote_to_local_err;
            }
        }
    }

    if(!(hosts = sxi_ht_new(dest->sx, INITIAL_HASH_ITEMS))) {
	SXDEBUG("failed to create hosts table");
	goto remote_to_local_err;
    }

    while(!feof(hf)) {
	sxi_hostlist_t *hostlist;
	char ha[42];
	unsigned int i;
	off_t shiftoff = tempdst ? curoff : 0;
        unsigned nhashes = MIN(BLOCKS_PER_TABLE, (filesize + blocksize - 1)/ blocksize);
        sxc_xfer_stat_t *xfer_stat = NULL;

        batch_hashes_free(&bh);
        bh.i = bh.n = 0;
        if(!(bh.hashes = sxi_ht_new(source->sx, nhashes*6/5))) {
            SXDEBUG("failed to create hash table");
            goto remote_to_local_err;
        }
        bh.n = nhashes;
        if (!(bh.hashdata = calloc(sizeof(*bh.hashdata), nhashes))) {
            SXDEBUG("failed to create hashdata table");
	    sxi_seterr(sx, SXE_EMEM, "Out of memory");
            goto remote_to_local_err;
        }

	for(i=0; i<BLOCKS_PER_TABLE; i++) {
	    if(!fread(ha, 40, 1, hf)) {
		if(ferror(hf)) {
		    SXDEBUG("failed to read hash");
		    sxi_setsyserr(sx, SXE_ETMP, "Download failed: Cannot read from cache file");
		    fail = 1;
		}
		break;
	    }

	    if(sxi_ht_get(bh.hashes, ha, SXI_SHA1_TEXT_LEN, (void **)&hashdata)) {
                if (bh.i >= bh.n) {
		    SXDEBUG("overflow allocating hash data container: %d, %d",bh.i,bh.n);
                    fail = 1;
                    break;
                }
                hashdata = &bh.hashdata[bh.i++];
		hostlist = &hashdata->hosts;
		sxi_hostlist_init(hostlist);
		hashdata->ocnt = 0;
                hashdata->state = TRANSFER_NOT_STARTED;
		if(sxi_ht_add(bh.hashes, ha, SXI_SHA1_TEXT_LEN, hashdata)) {
		    SXDEBUG("failed to add a new entry to the hash table");
		    fail = 1;
		    break;
		}
                memcpy(hashdata->hash, ha, SXI_SHA1_TEXT_LEN);
	    } else
		hostlist = NULL;

            if (hashdata->ocnt == hashdata->osize) {
                size_t size;
                hashdata->osize = !hashdata->osize ? 1 : hashdata->osize + 64;
                size = sizeof(*hashdata->offsets) * hashdata->osize;
                if (!(hashdata->offsets = sxi_realloc(sx, hashdata->offsets, size))) {
                    SXDEBUG("OOM growing offsets buffer");
                    sxi_seterr(sx, SXE_EMEM, "Copy failed: Out of memory");
                    fail = 1;
                    break;
                }
            }
	    hashdata->offsets[hashdata->ocnt++] = curoff - shiftoff;
	    curoff += blocksize;

	    if(load_hosts_for_hash(sx, hf, ha, hostlist, hosts)) {
		SXDEBUG("failed to load hosts for %.40s", ha);
		fail = 1;
		break;
	    }
	}

	if(fail)
	    break;

        xfer_stat = sxi_cluster_get_xfer_stat(source->cluster);
        if(xfer_stat) {
            /* Set information about new file download */
            if(sxi_xfer_set_file(xfer_stat, source->path, filesize, blocksize, SXC_XFER_DIRECTION_DOWNLOAD)) {
                SXDEBUG("Could not set transfer information to file %s", dstname);
                fail = 1;
                break;
            }

            if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
                SXDEBUG("Could not start transfer");
                sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
                fail = 1;
                break;
            }
            xfer_stat->status = SXC_XFER_STATUS_RUNNING;
        }

        fail = multi_download(&bh, dstname, blocksize, source->cluster, d, filesize - shiftoff);

        if(fail) {
            SXDEBUG("multi_download failed, trying single download");
            fail = single_download(&bh, dstname, blocksize, source->cluster, d, filesize - shiftoff);
        }

        /* Update information about transfers, but not when aborting */
        if(xfer_stat && sxc_geterrnum(sx) != SXE_ABORT) {
            xfer_stat->status = SXC_XFER_STATUS_PART_FINISHED;
            if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
                SXDEBUG("Could not finish transfer");
                sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
                fail = 1;
                break;
            }
        }


	if(fail)
	    break;

	if(tempdst) {
	    ssize_t got, done;
	    ssize_t f_size, f_got = 0;
	    f_size = lseek(d, 0, SEEK_END);
	    lseek(d, 0, SEEK_SET);
	    while(!fail) {
		uint8_t *buff = buf;
		got = read(d, buff, blocksize);
		if(!got)
		    break;
		if(got<0) {
		    if(errno == EINTR)
			continue;
		    SXDEBUG("Failed to read intermediate file");
		    sxi_setsyserr(sx, SXE_ETMP, "Download failed: Cannot read from intermediate file");
		    fail = 1;
		    break;
		}
		f_got += got;
		if(f_got == f_size)
		    action = SXF_ACTION_DATA_END;
		while(got) {
		    if(fh && fh->f->data_process) {
			do {
			    done = fh->f->data_process(fh, fh->ctx, buff, got, outbuff, sizeof(outbuff), SXF_MODE_DOWNLOAD, &action);
			    if(done < 0) {
				sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process input data", filter_uuid);
				fail = 1;
				break;
			    }
			    done = write_hard(rd, outbuff, done);
			    if(done < 0) {
				SXDEBUG("Failed to write output file");			
				sxi_setsyserr(sx, SXE_EWRITE, "Download failed: Cannot write to output file");
				fail = 1;
				break;
			    }
			} while(action == SXF_ACTION_REPEAT);
			got = 0;
		    } else {
			done = write_hard(rd, buff, got);
			if(done < 0) {
			    SXDEBUG("Failed to write output file");			
			    sxi_setsyserr(sx, SXE_EWRITE, "Download failed: Cannot write to output file");
			    fail = 1;
			    break;
			}
			got -= done;
			buff += done;
		    }
		}
	    }

	    if(fail)
		break;

	    lseek(d, 0, SEEK_SET);
	    if(ftruncate(d, 0)) {
		SXDEBUG("Failed to truncate intermediate file");
		sxi_setsyserr(sx, SXE_ETMP, "Download failed: Cannot truncate intermediate file");
		fail = 1;
		break;
	    }
	}
    }
    if(fh && fh->f->data_finish && tempdst) {
	if(fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD)) {
	    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to clean up itself", filter_uuid);
	    goto remote_to_local_err;
	}
    }

    if(fail)
	goto remote_to_local_err;

    if(fh && fh->f->data_process && !tempdst) {
	char inbuff[8192], *destpath;
	ssize_t bread, bwrite;
	FILE *tempfile = NULL;
	ssize_t f_size, f_got = 0;
        /* FIXME: filter processing should be done once the download has
         * finished!! */

	destpath = strdup(dest->path);
	if(!destpath) {
	    SXDEBUG("OOM strdup(dest->path)");
	    sxi_setsyserr(sx, SXE_EMEM, "Filter failed: OOM");
	    goto remote_to_local_err;
	}
	if(!(tempfilter = sxi_tempfile_track(sx, dirname(destpath), &tempfile))) {
	    SXDEBUG("Failed to generate filter temporary file");
	    free(destpath);
	    goto remote_to_local_err;
	}
	free(destpath);
	if(fh->f->data_prepare) {
            unsigned char chksum1[SXI_SHA1_BIN_LEN], chksum2[SXI_SHA1_BIN_LEN];

            if(sxi_meta_checksum(sx, cvmeta, chksum1)) {
                SXDEBUG("Failed to compute custom volume meta checksum");
                fclose(tempfile);
                goto remote_to_local_err;
            }

	    if(fh->f->data_prepare(fh, &fh->ctx, source->path, filter_cfgdir, cfgval, cfgval_len, cvmeta, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
		fclose(tempfile);
		goto remote_to_local_err;
	    }

            if(sxi_meta_checksum(sx, cvmeta, chksum2)) {
                SXDEBUG("Failed to compute custom volume meta checksum");
                fclose(tempfile);
                goto remote_to_local_err;
            }

            if(memcmp(chksum1, chksum2, SXI_SHA1_BIN_LEN)) {
                SXDEBUG("Checksums different, modifying volume %s\n", dest->volume);
		if(sxc_volume_modify(source->cluster, source->volume, NULL, NULL, -1, -1, cvmeta)) {
		    if(sxc_geterrnum(source->sx) == SXE_EAUTH)
			/* ignore error for non-owner */
			sxc_clearerr(source->sx);
		    else {
                        fclose(tempfile);
			goto remote_to_local_err;
                    }
		}
	    }
	}
	f_size = lseek(d, 0, SEEK_END);
	lseek(d, 0, SEEK_SET);
	while((bread = read(d, inbuff, sizeof(inbuff))) > 0) {
	    f_got += bread;
	    if(f_got == f_size)
		action = SXF_ACTION_DATA_END;

	    do {
		bwrite = fh->f->data_process(fh, fh->ctx, inbuff, bread, outbuff, sizeof(outbuff), SXF_MODE_DOWNLOAD, &action);
		if(bwrite < 0) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process input data", filter_uuid);
		    fclose(tempfile);
		    if(fh->f->data_finish)
			fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD);
		    goto remote_to_local_err;
		}
		if(fwrite(outbuff, 1, bwrite, tempfile) != (size_t) bwrite) {
		    sxi_setsyserr(sx, SXE_EWRITE, "Filter ID %s failed: Can't write to temporary file", filter_uuid);
		    fclose(tempfile);
		    if(fh->f->data_finish)
			fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD);
		    goto remote_to_local_err;
		}
	    } while(action == SXF_ACTION_REPEAT);
	}
	if(fclose(tempfile)) {
	    sxi_seterr(sx, SXE_EWRITE, "Filter ID %s failed: Can't close temporary file", filter_uuid);
	    goto remote_to_local_err;
	}
	if(fh->f->data_finish) {
	    if(fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to clean up itself", filter_uuid);
		goto remote_to_local_err;
	    }
	}

        if (d != STDOUT_FILENO)
            close(d);
	d = -1;
	if(dstexisted && stat(dest->path, &st) == -1) {
	    sxi_setsyserr(sx, SXE_EREAD, "failed to stat destination file %s", dest->path);
	    goto remote_to_local_err;
	}
	if(!dstexisted || S_ISREG(st.st_mode)) {
	    if(rename(tempfilter, dest->path)) {
		SXDEBUG("can't rename temporary file");
		sxi_setsyserr(sx, SXE_EWRITE, "Filter ID %s failed: Can't rename temporary file", filter_uuid);
		goto remote_to_local_err;
	    }
	} else {
            /* FIXME: this doesn't preserve attributes */
	    if(file_to_file(sx, tempfilter, dest->path, NULL))
		goto remote_to_local_err;
	    unlink(tempfilter);
	}
	sxi_tempfile_untrack(sx, tempfilter);
	tempfilter = NULL;
    }
    if (created_at >= 0 && !tempdst) {
        struct utimbuf tb;
        tb.modtime = created_at;
        tb.actime = time(NULL);
        if (utime(dest->path, &tb)) {
            struct sxi_fmt fmt;
            sxi_fmt_start(&fmt);
            sxi_fmt_syserr(&fmt, "utime failed on %s", dest->path);
            sxi_info(sx, "%s",fmt.buf);
        } else {
            SXDEBUG("Set mtime to @%ld", tb.modtime);
        }
    }

    if(fh && fh->f->file_process) {
        if(dstexisted && stat(dest->path, &st) == -1) {
            sxi_setsyserr(sx, SXE_EREAD, "failed to stat destination file %s", dest->path);
            goto remote_to_local_err;
        }
        if(!dstexisted || (S_ISREG(st.st_mode) && st.st_uid == getuid())) {
            if(sxi_file_process(sx, fh, filter_cfgdir, dest, SXF_MODE_DOWNLOAD)) {
                SXDEBUG("Failed to process dest file meta");
                goto remote_to_local_err;
            }
	}
    }

    if(sxi_getenv("SX_DEBUG_DELAY")) sleep(atoi(sxi_getenv("SX_DEBUG_DELAY")));

    ret = 0;

    if(fh && fh->f->file_notify)
	fh->f->file_notify(fh, fh->ctx, sxi_filter_get_cfg(fh, source->volume), sxi_filter_get_cfg_len(fh, source->volume), SXF_MODE_DOWNLOAD, sxc_cluster_get_sslname(source->cluster), source->volume, source->path, NULL, NULL, dest->path);

remote_to_local_err:

    batch_hashes_free(&bh);

    if(hosts) {
	char *hlist;
	sxi_ht_enum_reset(hosts);
	while(!sxi_ht_enum_getnext(hosts, NULL, NULL, (const void **)&hlist)) {
	    free(hlist);
	}
	sxi_ht_free(hosts);
    }

    sxi_hostlist_empty(&volnodes);
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    free(filter_cfgdir);

    if(tempdst) {
	fclose(tf);
	unlink(tempdst);
	sxi_tempfile_untrack(sx, tempdst);
	d = rd;
    }

    if(d>=0 && d != STDOUT_FILENO)
	close(d);

    if(tempfilter) {
	unlink(tempfilter);
	sxi_tempfile_untrack(sx, tempfilter);
    }

    if (hf)
        fclose(hf);
    if (hashfile)
        unlink(hashfile);
    sxi_tempfile_untrack(sx, hashfile);

    free(buf);
    return ret;
}

sxi_sxfs_data_t *sxi_sxfs_download_init(sxc_file_t *source)
{
    int i = 0, ha_i = 0;
    off_t curoff = 0;
    char *hashfile = NULL;
    sxc_client_t *sx;
    sxc_meta_t *vmeta = NULL, *cvmeta = NULL;
    struct batch_hashes *bh = NULL;
    struct hash_down_data_t *hashdata;
    sxi_ht *hosts = NULL;
    sxi_sxfs_data_t *ret = NULL, *sxfs;
    FILE *hfd = NULL;
    sxi_hostlist_t volnodes;

    char filter_uuid[37], filter_cfgkey[37 + 5], *filter_cfgdir = NULL;
    const char *confdir;
    const void *mval;
    unsigned int mval_len;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;
    struct filter_handle *fh = NULL;

    if(!source)
        return ret;
    sxi_hostlist_init(&volnodes);

    sx = source->sx;
    sxfs = (sxi_sxfs_data_t*)calloc(1, sizeof(sxi_sxfs_data_t));
    if(!sxfs) {
	SXDEBUG("failed to create sxfs data structure");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return ret;
    }

    bh = (struct batch_hashes*)calloc(1, sizeof(struct batch_hashes));
    if(!bh) {
        SXDEBUG("failed to create hashes container");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_sxfs_download_init_err;
    }
    sxfs->bh = (void*)bh;

    if(!(vmeta = sxc_meta_new(sx)))
        goto sxi_sxfs_download_init_err;
    if(!(cvmeta = sxc_meta_new(sx)))
        goto sxi_sxfs_download_init_err;

    if(sxi_locate_volume(sxi_cluster_get_conns(source->cluster), source->volume, &volnodes, NULL, vmeta, cvmeta)) {
        SXDEBUG("failed to locate destination file");
        goto sxi_sxfs_download_init_err;
    }

    if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume))
        goto sxi_sxfs_download_init_err;
    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        if(mval_len != 16) {
            sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            goto sxi_sxfs_download_init_err;
        }
        sxi_uuid_unparse(mval, filter_uuid);
        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by source volume not found", filter_uuid);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by source volume not found", filter_uuid);
            goto sxi_sxfs_download_init_err;
        }

        snprintf(filter_cfgkey, sizeof(filter_cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, filter_cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, source->volume, cfgval, cfgval_len))
            goto sxi_sxfs_download_init_err;

        confdir = sxi_cluster_get_confdir(source->cluster);
        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, source->volume);
            if(!filter_cfgdir)
                goto sxi_sxfs_download_init_err;
        }
    }

    if(sxi_filemeta_process(sx, fh, filter_cfgdir, source, cvmeta)) {
        SXDEBUG("Failed to process source filename");
        goto sxi_sxfs_download_init_err;
    }

    sxfs->sourcepath = strdup(source->remote_path);
    if(!sxfs->sourcepath) {
        SXDEBUG("failed to duplicate source path");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_sxfs_download_init_err;
    }

    if(hashes_to_download(source, &volnodes, &hfd, &hashfile, &sxfs->blocksize, &sxfs->filesize, NULL)) {
	SXDEBUG("failed to retrieve hash list");
	goto sxi_sxfs_download_init_err;
    }

    sxfs->nhashes = bh->n = (sxfs->filesize + sxfs->blocksize - 1) / sxfs->blocksize;
    sxfs->ha = (char**)calloc(sxfs->nhashes, sizeof(char*));
    if(!sxfs->ha) {
	SXDEBUG("failed to create hash list");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_sxfs_download_init_err;
    }
    for(i=0; i<sxfs->nhashes; i++) {
        sxfs->ha[i] = (char*)calloc(1, SXI_SHA1_TEXT_LEN + 1);
        if(!sxfs->ha[i]) {
            SXDEBUG("failed to create hash list entry");
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            goto sxi_sxfs_download_init_err;
        }
    }
    if(!(bh->hashes = sxi_ht_new(sx, bh->n*6/5))) {
        SXDEBUG("failed to create hash table");
        goto sxi_sxfs_download_init_err;
    }

    if(!(bh->hashdata = calloc(sizeof(*bh->hashdata), bh->n))) {
        SXDEBUG("failed to create hashdata table");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxi_sxfs_download_init_err;
    }
    if(!(hosts = sxi_ht_new(sx, INITIAL_HASH_ITEMS))) {
	SXDEBUG("failed to create hosts table");
	goto sxi_sxfs_download_init_err;
    }
    if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume))
	goto sxi_sxfs_download_init_err;
    /* TODO: filters handling */
    
    while(!feof(hfd)) {
	char ha[42];
	sxi_hostlist_t *hostlist;
        
        if(!fread(ha, 40, 1, hfd)) {
            if(ferror(hfd)) {
                SXDEBUG("failed to read hash");
                sxi_setsyserr(sx, SXE_ETMP, "Download failed: Cannot read from cache file");
            }
            break;
        }
        memcpy(sxfs->ha[ha_i++], ha, SXI_SHA1_TEXT_LEN);

        if(sxi_ht_get(bh->hashes, ha, SXI_SHA1_TEXT_LEN, (void **)&hashdata)) {
            if(bh->i >= bh->n) {
                SXDEBUG("overflow allocating hash data container: %d, %d", bh->i, bh->n);
                goto sxi_sxfs_download_init_err;
            }
            hashdata = &bh->hashdata[bh->i++];
            hostlist = &hashdata->hosts;
            sxi_hostlist_init(hostlist);
            hashdata->ocnt = 0;
            hashdata->state = TRANSFER_NOT_STARTED;
            if(sxi_ht_add(bh->hashes, ha, SXI_SHA1_TEXT_LEN, hashdata)) {
                SXDEBUG("failed to add a new entry to the hash table");
                goto sxi_sxfs_download_init_err;
            }
            memcpy(hashdata->hash, ha, SXI_SHA1_TEXT_LEN);
        } else
            hostlist = NULL;

        if(hashdata->ocnt == hashdata->osize) {
            size_t size;
            hashdata->osize = !hashdata->osize ? 1 : hashdata->osize + 64;
            size = sizeof(*hashdata->offsets) * hashdata->osize;
            if(!(hashdata->offsets = sxi_realloc(sx, hashdata->offsets, size))) {
                SXDEBUG("OOM growing offsets buffer");
                sxi_seterr(sx, SXE_EMEM, "Copy failed: Out of memory");
                goto sxi_sxfs_download_init_err;
            }
        }
        hashdata->offsets[hashdata->ocnt++] = curoff;
        curoff += sxfs->blocksize;

        if(load_hosts_for_hash(sx, hfd, ha, hostlist, hosts)) {
            SXDEBUG("failed to load hosts for %.40s", ha);
            goto sxi_sxfs_download_init_err;
        }
    }

    ret = sxfs;
sxi_sxfs_download_init_err:
    if(!ret) {
        if(bh)
            free(bh);
        if(sxfs->sourcepath)
            free(sxfs->sourcepath);
        if(sxfs->ha) {
            for(i=0; i<sxfs->nhashes; i++)
                if(sxfs->ha[i])
                    free(sxfs->ha[i]);
            free(sxfs->ha);
        }
        free(sxfs);
    }
    if(hosts) {
	char *hlist;
	sxi_ht_enum_reset(hosts);
	while(!sxi_ht_enum_getnext(hosts, NULL, NULL, (const void **)&hlist)) {
	    free(hlist);
	}
	sxi_ht_free(hosts);
    }
    if(hfd)
        fclose(hfd);
    if(hashfile) {
        unlink(hashfile);
        sxi_tempfile_untrack(sx, hashfile);
    }
    free(filter_cfgdir);
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    sxi_hostlist_empty(&volnodes);
    return ret;
}

int sxi_sxfs_download_run(sxi_sxfs_data_t *sxfs, sxc_cluster_t *cluster, sxc_file_t *dest, off_t offset, long int size) {
    int i, ret = 1, fd, fail = 0;
    long int blocks;
    char ha[42];
    off_t blocks_i, curoff = 0;
    sxc_client_t *sx;
    sxc_xfer_stat_t *xfer_stat = NULL;
    struct batch_hashes bh, *full_bh;
    struct hash_down_data_t *hashdata, *full_hd;

    if(!dest)
        return ret;
    sx = dest->sx;
    if(!sxfs || !cluster || offset < 0 || size < 0) {
	SXDEBUG("invalid argument");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return ret;
    }
    full_bh = (struct batch_hashes*)sxfs->bh;
    memset(&bh, 0, sizeof(bh));
    if((fd = open(dest->path, O_RDWR|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH))<0) {
	SXDEBUG("failed to create destination file");
	sxi_setsyserr(sx, SXE_EWRITE, "Cannot open destination file %s", dest->path);
        return ret;
    }
    blocks_i = offset / sxfs->blocksize;
    if(offset + size > sxfs->filesize)
        blocks = (sxfs->filesize + sxfs->blocksize - 1) / sxfs->blocksize - blocks_i;
    else
        blocks = (offset + size + sxfs->blocksize - 1) / sxfs->blocksize - blocks_i;

    while(blocks) {
        batch_hashes_free(&bh);
        bh.i = 0;
        bh.n = MIN(BLOCKS_PER_TABLE, blocks);
        if(!(bh.hashes = sxi_ht_new(sx, bh.n*6/5))) {
            SXDEBUG("failed to create hash table");
            goto sxi_sxfs_download_run_err;
        }
        if(!(bh.hashdata = calloc(sizeof(*bh.hashdata), bh.n))) {
            SXDEBUG("failed to create hashdata table");
	    sxi_seterr(sx, SXE_EMEM, "Out of memory");
            goto sxi_sxfs_download_run_err;
        }

        for(i=0; blocks && i<BLOCKS_PER_TABLE; i++, blocks--) {
            memcpy(ha, sxfs->ha[blocks_i++], SXI_SHA1_TEXT_LEN);
	    if(sxi_ht_get(full_bh->hashes, ha, SXI_SHA1_TEXT_LEN, (void **)&full_hd)) {
                SXDEBUG("failed to get entry from hash table");
                goto sxi_sxfs_download_run_err;
            }
	    if(sxi_ht_get(bh.hashes, ha, SXI_SHA1_TEXT_LEN, (void **)&hashdata)) {
                if(bh.i >= bh.n) {
		    SXDEBUG("overflow allocating hash data container: %d, %d", bh.i, bh.n);
                    goto sxi_sxfs_download_run_err;
                }
                hashdata = &bh.hashdata[bh.i++];
		hashdata->ocnt = 0;
                hashdata->state = TRANSFER_NOT_STARTED;
		if(sxi_ht_add(bh.hashes, ha, SXI_SHA1_TEXT_LEN, hashdata)) {
		    SXDEBUG("failed to add a new entry to the hash table");
                    goto sxi_sxfs_download_run_err;
		}
                memcpy(hashdata->hash, ha, SXI_SHA1_TEXT_LEN);
            }
            if(hashdata->ocnt == hashdata->osize) {
                size_t size;
                hashdata->osize = !hashdata->osize ? 1 : hashdata->osize + 64;
                size = sizeof(*hashdata->offsets) * hashdata->osize;
                if(!(hashdata->offsets = sxi_realloc(sx, hashdata->offsets, size))) {
                    SXDEBUG("OOM growing offsets buffer");
                    sxi_seterr(sx, SXE_EMEM, "Copy failed: Out of memory");
                    break;
                }
            }
	    hashdata->offsets[hashdata->ocnt++] = curoff;
	    curoff += sxfs->blocksize;
            sxi_hostlist_add_list(sx, &hashdata->hosts, &full_hd->hosts);
        }

        xfer_stat = sxi_cluster_get_xfer_stat(cluster);
        if(xfer_stat) {
            /* Set information about new file download */
            if(sxi_xfer_set_file(xfer_stat, sxfs->sourcepath, sxfs->filesize, sxfs->blocksize, SXC_XFER_DIRECTION_DOWNLOAD)) {
                SXDEBUG("Could not set transfer information to file %s", dest->path);
                goto sxi_sxfs_download_run_err;
            }

            if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
                SXDEBUG("Could not start transfer");
                sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
                goto sxi_sxfs_download_run_err;
            }
            xfer_stat->status = SXC_XFER_STATUS_RUNNING;
        }

        fail = multi_download(&bh, dest->path, sxfs->blocksize, cluster, fd, sxfs->filesize);
        if(fail) {
            SXDEBUG("multi_download failed, trying single download");
            fail = single_download(&bh, dest->path, sxfs->blocksize, cluster, fd, sxfs->filesize);
        }

        /* Update information about transfers, but not when aborting */
        if(xfer_stat && sxc_geterrnum(sx) != SXE_ABORT) {
            xfer_stat->status = SXC_XFER_STATUS_PART_FINISHED;
            if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
                SXDEBUG("Could not finish transfer");
                sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
                goto sxi_sxfs_download_run_err;
            }
        }
    }
    /* TODO: filter cleanup */
    if(fail)
	goto sxi_sxfs_download_run_err;
    /* TODO: filter processing */
    if(sxi_getenv("SX_DEBUG_DELAY"))
        sleep(atoi(sxi_getenv("SX_DEBUG_DELAY")));

    ret = 0;
sxi_sxfs_download_run_err:
    close(fd);
    batch_hashes_free(&bh);
    return ret;
}

void sxi_sxfs_download_finish(sxi_sxfs_data_t *sxfs) {
    int i;
    if(!sxfs)
        return;
    if(sxfs->sourcepath)
        free(sxfs->sourcepath);
    if(sxfs->ha) {
        for(i=0; i<sxfs->nhashes; i++)
            if(sxfs->ha[i])
                free(sxfs->ha[i]);
        free(sxfs->ha);
    }
    if(sxfs->bh) {
        batch_hashes_free((struct batch_hashes*)sxfs->bh);
        free(sxfs->bh);
    }
    free(sxfs);
}

static sxi_job_t* remote_to_remote_fast(sxc_file_t *source, sxc_file_t *dest) {
    char *src_hashfile = NULL, *rcur, ha[42];
    sxi_ht *src_hashes = NULL;
    sxc_client_t *sx = source->sx;
    struct file_upload_ctx *yctx;
    unsigned int blocksize;
    sxi_hostlist_t volhosts;
    int64_t filesize;
    uint8_t *buf = NULL;
    FILE *hf = NULL;
    sxi_query_t *query = NULL;
    sxi_job_t *job = NULL;
    sxc_xfer_stat_t *xfer_stat;
    unsigned int i;
    int64_t to_skip;
    long http_status = 0;
    sxi_hostlist_t src_hosts;
    curlev_context_t *cbdata = NULL;
    sxc_meta_t *vmeta = NULL, *cvmeta = NULL;
    struct filter_handle *fh = NULL;
    char *filter_cfgdir = NULL;

    char filter_uuid[37], filter_cfgkey[37 + 5];
    const void *mval;
    unsigned int mval_len;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;
    sxi_hostlist_init(&volhosts);
    sxi_hostlist_init(&src_hosts);
    yctx = calloc(1, sizeof(*yctx));
    if(!yctx) {
        SXDEBUG("Out of memory allocating context");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    vmeta = sxc_meta_new(sx);
    if(!vmeta) {
        SXDEBUG("Out of memory allocating volume meta");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        free(yctx);
        return NULL;
    }

    cvmeta = sxc_meta_new(sx);
    if(!cvmeta) {
        SXDEBUG("Out of memory allocating volume meta");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        sxc_meta_free(vmeta);
        free(yctx);
        return NULL;
    }

    if(sxi_locate_volume(sxi_cluster_get_conns(source->cluster), source->volume, &volhosts, NULL, vmeta, cvmeta)) {
        SXDEBUG("failed to locate destination file");
        goto remote_to_remote_fast_err;
    }

    if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume))
        goto remote_to_remote_fast_err;
    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        const char *confdir;

        if(mval_len != 16) {
            sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            goto remote_to_remote_fast_err;
        }
        sxi_uuid_unparse(mval, filter_uuid);
        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by source volume not found", filter_uuid);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by source volume not found", filter_uuid);
            goto remote_to_remote_fast_err;
        }

        snprintf(filter_cfgkey, sizeof(filter_cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, filter_cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, source->volume, cfgval, cfgval_len))
            goto remote_to_remote_fast_err;
        confdir = sxi_cluster_get_confdir(source->cluster);
        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, source->volume);
            if(!filter_cfgdir)
                goto remote_to_remote_fast_err;
        }

    }

    free(dest->remote_path);
    dest->remote_path = NULL;

    /* Dest path could be changed */
    if(sxi_filemeta_process(sx, fh, filter_cfgdir, dest, cvmeta)) {
        SXDEBUG("Failed to process source filename");
        goto remote_to_remote_fast_err;
    }

    if(hashes_to_download(source, &volhosts, &hf, &src_hashfile, &blocksize, &filesize, NULL)) {
	SXDEBUG("failed to retrieve hash list");
        goto remote_to_remote_fast_err;
    }

    query = sxi_fileadd_proto_begin(dest->sx, dest->volume, dest->remote_path, NULL, NULL, 0, blocksize, filesize);
    if(!query)
	goto remote_to_remote_fast_err;

    if(!(src_hashes = sxi_ht_new(source->sx, filesize / blocksize))) {
	SXDEBUG("failed to create source hashtable for %u entries", (unsigned)(filesize / blocksize));
	goto remote_to_remote_fast_err;
    }

    while(!feof(hf)) {
	struct checksum_offset *hoff;
	int sz;

	if(!fread(ha, 40, 1, hf)) {
	    if(ferror(hf)) {
		SXDEBUG("failed to read hash");
		sxi_setsyserr(sx, SXE_ETMP, "Transfer failed: Failed to read from cache file");
		goto remote_to_remote_fast_err;
	    }
	    break;
	}
	ha[40] = '\0';
	query = sxi_fileadd_proto_addhash(dest->sx, query, ha);
	if(!query)
	    goto remote_to_remote_fast_err;

	if(sxi_ht_get(src_hashes, ha, 40, (void **)&hoff)) {
	    hoff = malloc(sizeof(*hoff));
	    if(!hoff) {
		SXDEBUG("OOM allocating offset storage");
		sxi_seterr(sx, SXE_EMEM, "Transfer failed: Out of memory");
		goto remote_to_remote_fast_err;
	    }
	    hoff->offset = ftell(hf);
            hoff->checksum = 0;
            hoff->ref_checksum = 0;
	    if(sxi_ht_add(src_hashes, ha, 40, hoff)) {
		SXDEBUG("failed to add a new entry to the hash table");
		free(hoff);
		goto remote_to_remote_fast_err;
	    }
	}
	while((sz = fgetc(hf))) {
	    char ho[64];

	    if(sz == EOF || sz >= (int) sizeof(ho)) {
		SXDEBUG("failed to read host size");
		sxi_seterr(sx, SXE_ETMP, "Transfer failed: Failed to read from cache file");
		goto remote_to_remote_fast_err;
	    }
            fseek(hf, sz, SEEK_CUR);
	}
    }

    query = sxi_fileadd_proto_end(dest->sx, query, dest->meta);
    if(!query)
	goto remote_to_remote_fast_err;

    sxi_hostlist_empty(&volhosts);
    if(sxi_locate_volume(sxi_cluster_get_conns(dest->cluster), dest->volume, &volhosts, NULL, NULL, NULL)) {
        SXDEBUG("failed to locate destination file");
        goto remote_to_remote_fast_err;
    }

    yctx->max_part_blocks = sxi_ht_count(src_hashes);
    yctx->current.J = NULL;
    yctx->current.err = SXE_ECOMM;
    yctx->current.acts = &createfile_acts;
    yctx->blocksize = blocksize;
    yctx->name = strdup(dest->remote_path);
    if(!yctx->name) {
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate destination path buffer");
        goto remote_to_remote_fast_err;
    }

    yctx->current.hashes = src_hashes;
    if (!(yctx->current.needed = calloc(sizeof(*yctx->current.needed), sxi_ht_count(src_hashes)))) {
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate needed buffer");
        goto remote_to_remote_fast_err;
    }
    sxi_set_operation(sxi_cluster_get_client(dest->cluster), "upload file content hashes",
                      sxi_cluster_get_name(dest->cluster), dest->volume, dest->path);
    cbdata = sxi_cbdata_create_upload(sxi_cluster_get_conns(dest->cluster), NULL, yctx);
    if (!cbdata)
        goto remote_to_remote_fast_err;
    if(sxi_cbdata_set_timeouts(cbdata, BLOCK_XFER_HARD_TIMEOUT, BLOCK_XFER_SOFT_TIMEOUT)) {
        SXDEBUG("Failed to set timeouts");
        goto remote_to_remote_fast_err;
    }
    if(sxi_cluster_query_ev_retry(cbdata, sxi_cluster_get_conns(dest->cluster), &volhosts, query->verb, query->path, query->content, query->content_len, createfile_setup_cb, createfile_cb, NULL)) {
	SXDEBUG("file create query failed");
	goto remote_to_remote_fast_err;
    }

    if (sxi_cbdata_wait(cbdata, sxi_conns_get_curlev(sxi_cluster_get_conns(dest->cluster)), &http_status) || http_status != 200) {
	SXDEBUG("file create query failed");
	goto remote_to_remote_fast_err;
    }

    if(sxi_jparse_done(yctx->current.J)) {
	SXDEBUG("JSON parsing failed");
	sxi_cbdata_seterr(cbdata, yctx->current.err, "Transfer failed: %s", sxi_jparse_geterr(yctx->current.J));
	goto remote_to_remote_fast_err;
    }

    sxi_jparse_destroy(yctx->current.J);
    yctx->current.J = NULL;

    if(!(buf = malloc(blocksize))) {
	SXDEBUG("OOM allocating the block buffer (%u bytes)", blocksize);
	sxi_seterr(sx, SXE_EMEM, "Transfer failed: Out of memory");
	goto remote_to_remote_fast_err;
    }

    xfer_stat = sxi_cluster_get_xfer_stat(source->cluster);
    if(xfer_stat) {
        if(sxi_xfer_set_file(xfer_stat, source->path, filesize, blocksize, SXC_XFER_DIRECTION_BOTH)) {
            SXDEBUG("Could not set transfer information to file %s", source->path);
            goto remote_to_remote_fast_err;
        }
        if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
            SXDEBUG("Could not start transfer");
            sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
            goto remote_to_remote_fast_err;
        }
        xfer_stat->status = SXC_XFER_STATUS_RUNNING;
    }

    to_skip = filesize - (int64_t)yctx->current.needed_cnt * (int64_t)blocksize;
    if(xfer_stat && sxc_geterrnum(sx) != SXE_ABORT) {
        if(to_skip && skip_xfer(source->cluster, to_skip) != SXE_NOERROR) {
            SXDEBUG("Could not skip part of transfer");
            sxi_seterr(sx, SXE_ABORT, "Could not skip part of transfer");
            goto remote_to_remote_fast_err;
        }
    }

    for(i = 0; i < yctx->current.needed_cnt; i++) {
        struct need_hash *need = &yctx->current.needed[i];
        int sz;

        fseek(hf, need->off.offset - 40, SEEK_SET);
        if(!fread(ha, 40, 1, hf)) {
            SXDEBUG("Could not read hash at offset %ld", need->off.offset - 40);
            goto remote_to_remote_fast_err;
        }

        sxi_hostlist_empty(&src_hosts);
        while((sz = fgetc(hf))) {
            char ho[64];

            if(sz == EOF || sz >= (int) sizeof(ho)) {
                SXDEBUG("failed to read host size");
                sxi_seterr(sx, SXE_ETMP, "Transfer failed: Failed to read from cache file");
                goto remote_to_remote_fast_err;
            }
            if(!fread(ho, sz, 1, hf)) {
                SXDEBUG("failed to read host");
                sxi_setsyserr(sx, SXE_ETMP, "Transfer failed: Failed to read from cache file");
                goto remote_to_remote_fast_err;
            }

            ho[sz] = '\0';
            if(sxi_hostlist_add_host(sx, &src_hosts, ho)) {
                SXDEBUG("failed to add host");
                goto remote_to_remote_fast_err;
            }
        }

        if(download_block_to_buf_track(source->cluster, &src_hosts, ha, buf, blocksize, 1)) {
            SXDEBUG("failed to download hash %.40s", ha);
            goto remote_to_remote_fast_err;
        }

        if(sxi_upload_block_from_buf_track(sxi_cluster_get_conns(dest->cluster), &need->upload_hosts, yctx->current.token, buf, blocksize, blocksize, 1)) {
            SXDEBUG("failed to upload hash %.40s", ha);
            goto remote_to_remote_fast_err;
        }
    }

    if (!(job = flush_file_ev(dest->cluster, yctx->host, yctx->current.token, yctx->name, NULL)))
        goto remote_to_remote_fast_err;

    /* Update transfer information, but not when aborting */
    if(xfer_stat && sxc_geterrnum(sx) != SXE_ABORT) {
        /* Upload process is waiting for job to finish */
        xfer_stat->status = SXC_XFER_STATUS_PART_FINISHED;
        if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
            SXDEBUG("Could not finish transfer");
            sxi_seterr(sx, SXE_ABORT, "Transfer aborted");
            goto remote_to_remote_fast_err;
        }
    }

remote_to_remote_fast_err:
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    if(src_hashes) {
	sxi_ht_enum_reset(src_hashes);
	while(!sxi_ht_enum_getnext(src_hashes, NULL, NULL, (const void **)&rcur))
	    free(rcur);
	sxi_ht_free(src_hashes);
    }
    sxi_cbdata_unref(&cbdata);
    sxi_query_free(query);

    free(buf);

    free(yctx->name);
    free(yctx->current.token);
    for(i = 0; i < yctx->current.needed_cnt; i++)
        sxi_hostlist_empty(&yctx->current.needed[i].upload_hosts);
    free(yctx->current.needed);
    free(yctx->host);
    sxi_jparse_destroy(yctx->current.J);

    if (hf)
        fclose(hf);
    if(src_hashfile) {
        unlink(src_hashfile);
        sxi_tempfile_untrack(sx, src_hashfile);
    }
    sxi_hostlist_empty(&volhosts);
    sxi_hostlist_empty(&src_hosts);
    free(yctx);
    free(filter_cfgdir);

    return job;
}

static sxi_job_t* remote_to_remote(sxc_file_t *source, sxc_file_t *dest, int fail_same_file, sxi_jobs_t *jobs) {
    const char *suuid=sxc_cluster_get_uuid(source->cluster), *duuid=sxc_cluster_get_uuid(dest->cluster);
    sxc_client_t *sx = source->sx;
    sxc_file_t *cache;
    char *tmpname;
    int nofast = 0;
    sxi_job_t *ret = NULL;
    FILE *f;

    if(!suuid || !duuid) {
	SXDEBUG("internal error / invalid config");
	return NULL;
    }
    if(fail_same_file &&
       !strcmp(suuid, duuid) && !strcmp(source->volume, dest->volume) &&
       !strcmp(source->rev ? source->rev : "", dest->rev ? dest->rev : "")) {
        const char *src = source->path;
        const char *dst = dest->path;
        do {
            /* ignore leading slashes */
            while (*src == '/') src++;
            while (*dst == '/') dst++;
            /* equal path component until next slash */
            while (*src && *dst && *src != '/' && *src == *dst) {
                src++; dst++;
            }
            /* ignore duplicate slashes, but a/b is not equal to ab */
            if (*src == '/' && *dst == '/') {
                while (*src == '/') src++;
                while (*dst == '/') dst++;
            }
        } while (*src && *dst && *src == *dst);
        if (!*src && !*dst) {
            sxi_seterr(sx, SXE_SKIP, "'%s/%s' and '%s/%s' are the same remote file",
                    source->volume, source->path,
                    dest->volume, dest->path);
            return NULL;
        }
    }

    if(strcmp(source->volume, dest->volume)) {
	const void *mval;
	unsigned int mval_len;
	sxc_meta_t *vmeta = sxc_volumemeta_new(source);

	if(!vmeta)
	    return NULL;
	if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume)) {
	    sxc_meta_free(vmeta);
	    return NULL;
	}
	if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
	    if(mval_len != 16) {
		sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata (source)");
		sxc_meta_free(vmeta);
		return NULL;
	    }
	    nofast = 1;
	}
	sxc_meta_free(vmeta);

	if(!nofast) {
	    if(!(vmeta = sxc_volumemeta_new(dest)))
		return NULL;
	    if(sxi_volume_cfg_check(sx, dest->cluster, vmeta, dest->volume)) {
		sxc_meta_free(vmeta);
		return NULL;
	    }
	    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
		if(mval_len != 16) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata (dest)");
		    sxc_meta_free(vmeta);
		    return NULL;
		}
		nofast = 1;
	    }
	    sxc_meta_free(vmeta);
	}
    }

    if(!nofast && !strcmp(suuid, duuid)) {
	ret = remote_to_remote_fast(source, dest);
	return ret;
    }

    if(!(tmpname = sxi_tempfile_track(dest->sx, NULL, &f))) {
	SXDEBUG("failed to create local cache file");
	return NULL;
    }
    fclose(f);

    if(!(cache = sxi_file_local(source->sx, tmpname, source->meta)))
	goto remote_to_remote_err;

    if(remote_to_local(source, cache, 0)) {
        SXDEBUG("failed to download source file");
        goto remote_to_remote_err;
    }

    free(dest->remote_path);
    dest->remote_path = NULL;
    sxc_meta_free(cache->meta);
    cache->meta = NULL;
    sxc_meta_empty(dest->meta); /* meta is not cleared when destination is undelete filter */

    if(!(ret = local_to_remote_begin(cache, dest, 0, NULL, jobs))) {
	SXDEBUG("failed to upload destination file");
	goto remote_to_remote_err;
    }

remote_to_remote_err:
    sxc_file_free(cache);
    unlink(tmpname);
    sxi_tempfile_untrack(sx, tmpname);
    return ret;
}

static int mkdir_parents(sxc_client_t *sx, const char *path);
static sxi_job_t* remote_copy_ev(sxc_file_t *pattern, sxc_file_t *source, sxc_file_t *dest, int recursive, int show_errors, unsigned int *errors, int fail_same_file, sxi_jobs_t *jobs)
{
    sxi_job_t *job;
    free(source->origpath);
    if (!(source->origpath = strdup(pattern->path))) {
        sxi_setsyserr(source->sx, SXE_EMEM, "Cannot dup path");
        return NULL;
    }
    if (maybe_append_path(dest, source, recursive))
        return NULL;
    if(!is_remote(dest)) {
        int ret;
        if (recursive)
            mkdir_parents(dest->sx, dest->path);
        if (dest->cat_fd > 0)
            ret = cat_remote_file(source, dest->cat_fd);
        else
            ret = remote_to_local(source, dest, recursive);
        if (show_errors && sxc_geterrnum(source->sx) != SXE_NOERROR) {
	    if(dest->path)
		sxi_notice(source->sx, "ERROR: %s: %s", dest->path, sxc_geterrmsg(source->sx));
	    else
		sxi_notice(source->sx, "ERROR: %s", sxc_geterrmsg(source->sx));
        }
        if (sxc_geterrnum(source->sx) == SXE_SKIP) {
            ret = 0;
            sxc_clearerr(source->sx);
        }
	if(recursive && ret == 2) { /* EISDIR */
	    (*errors)++;
	    ret = 0;
            sxc_clearerr(source->sx);
        }
        if (ret) {
            (void)restore_path(dest);
            return NULL;
        }
        job = &JOB_NONE;
    } else
       job = remote_to_remote(source, dest, fail_same_file, jobs);
    if (restore_path(dest)) {
        sxi_job_free(job);
        return NULL;
    }
    return job;
}

static int mkdir_parents(sxc_client_t *sx, const char *path)
{
    int ret;
    const char *end = strrchr(path, '/');
    if (!end)
        return -1;
    char *parent = malloc(end - path + 1);
    if (!parent) {
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return -1;
    }
    memcpy(parent, path, end - path);
    parent[end-path] = '\0';
    ret = sxi_mkdir_hier(sx, parent, 0777);
    free(parent);
    return ret;
}

int sxc_copy_single(sxc_file_t *source, sxc_file_t *dest, int recursive, int onefs, int ignore_errors, const sxc_exclude_t *exclude, int fail_same_file) {
    int ret;
    sxc_client_t *sx = source->sx;
    sxc_file_list_t *lst = sxc_file_list_new(sx, recursive, ignore_errors);
    sxc_file_t *dup;
    if(!lst) {
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate file list");
        return 1;
    }

    if(!(dup = sxi_file_dup(source))) {
        sxc_file_list_free(lst);
        return 1;
    }
    if(sxc_file_list_add(lst, dup, 1)) {
        sxi_seterr(sx, SXE_EMEM, "Failed to add file to file list");
        sxc_file_list_free(lst);
        sxc_file_free(dup);
        return 1;
    }
    ret = sxc_copy(lst, dest, recursive, onefs, exclude, fail_same_file);
    sxc_file_list_free(lst);
    return ret;
}

int sxc_mass_rename(sxc_cluster_t *cluster, sxc_file_t *source, sxc_file_t *dest, int recursive) {
    sxc_client_t *sx;
    sxi_conns_t *conns;
    char *url;
    unsigned int len, slen, dlen;
    char *vol_enc = NULL, *src_enc = NULL, *dst_enc = NULL;
    sxi_hostlist_t hosts;
    const char *p, *d;
    char *dest_final;
    sxc_meta_t *vmeta;
    const void *mval;
    unsigned int mval_len;
    struct filter_handle *fh;
    char filter_uuid[37];

    if(!cluster)
        return -1;
    sx = sxi_cluster_get_client(cluster);
    conns = sxi_cluster_get_conns(cluster);
    if(!source || !source->path || !dest || !dest->path) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return -1;
    }

    if(sxi_reject_dots(dest->path) || !strncmp(dest->path, "../", 3) || !strncmp(dest->path, "./", 2)) {
        sxi_seterr(sx, SXE_EARG, "Destination with '.' or '..' is not accepted");
        return -1;
    }
    if(!(vmeta = sxc_meta_new(sx)))
        return -1;
    sxi_hostlist_init(&hosts);
    if(sxi_locate_volume(conns, source->volume, &hosts, NULL, vmeta, NULL)) {
        sxc_meta_free(vmeta);
        return -1;
    }

    if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume)) {
        sxi_hostlist_empty(&hosts);
        sxc_meta_free(vmeta);
        return -1;
    }
    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        if(mval_len != 16) {
            sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            sxi_hostlist_empty(&hosts);
            sxc_meta_free(vmeta);
            return -1;
        }
        sxi_uuid_unparse(mval, filter_uuid);
        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by source volume not found", filter_uuid);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by source volume not found", filter_uuid);
            sxi_hostlist_empty(&hosts);
            sxc_meta_free(vmeta);
            return -1;
        }

        if(fh->f->filemeta_process) {
            SXDEBUG("Mass rename operation requested on a volume with filename processing filter");
            sxi_seterr(sx, SXE_ECFG, "Cannot use mass operation while using filename processing filter");
            sxi_hostlist_empty(&hosts);
            sxc_meta_free(vmeta);
            return -2; /* Special case: possible fallback usage */
        }
    }

    sxc_meta_free(vmeta);

    vol_enc = sxi_urlencode(sx, source->volume, 0);
    if(!vol_enc) {
        sxi_hostlist_empty(&hosts);
        sxi_seterr(sx, SXE_EMEM, "Failed to encode volume name");
        return -1;
    }

    if(!*source->path)
        p = "/";
    else
        p = source->path;
    slen = strlen(p);

    if(!*dest->path)
        d = "/";
    else
        d = dest->path;
    dlen = strlen(d);

    if(slen && p[slen-1] == '/' && dlen && d[dlen-1] != '/') {
        /* dir -> file, append slash to dest */
        dest_final = malloc(dlen+2);
        if(!dest_final) {
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            sxi_hostlist_empty(&hosts);
            free(vol_enc);
            return -1;
        }
        snprintf(dest_final, dlen+2, "%s/", d);
    } else {
        dest_final = strdup(d);
        if(!dest_final) {
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            sxi_hostlist_empty(&hosts);
            free(vol_enc);
            return -1;
        }
    }

    dst_enc = sxi_urlencode(sx, dest_final, 0);
    free(dest_final);
    if(!dst_enc) {
        sxi_seterr(sx, SXE_EMEM, "Failed to encode target file name");
        sxi_hostlist_empty(&hosts);
        free(vol_enc);
        return -1;
    }

    src_enc = sxi_urlencode(sx, p, 0);
    if(!src_enc) {
        sxi_seterr(sx, SXE_EMEM, "Failed to encode source file name");
        sxi_hostlist_empty(&hosts);
        free(vol_enc);
        free(dst_enc);
        return -1;
    }

    len = strlen(vol_enc) + lenof("?source=") + strlen(src_enc) + lenof("&dest=") + strlen(dst_enc) + 1;
    if(recursive)
        len += lenof("&recursive");
    url = malloc(len);
    if(!url) {
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate query");
        sxi_hostlist_empty(&hosts);
        free(dst_enc);
        free(src_enc);
        free(vol_enc);
        return -1;
    }

    snprintf(url, len, "%s?source=%s&dest=%s%s", vol_enc, src_enc, dst_enc, recursive ? "&recursive" : "");
    free(dst_enc);
    free(src_enc);
    free(vol_enc);
    sxi_set_operation(sx, "rename files", NULL, NULL, NULL);
    if(sxi_job_submit_and_poll(conns, &hosts, REQ_PUT, url, NULL, 0)) {
        sxi_hostlist_empty(&hosts);
        free(url);
        return -1;
    }

    free(url);
    sxi_hostlist_empty(&hosts);
    return 0;
}

static int cat_remote_file(sxc_file_t *source, int dest) {
    char *hashfile, ha[42];
    uint8_t *buf, *fbuf = NULL;
    sxi_hostlist_t hostlist, volnodes;
    int64_t filesize;
    FILE *hf;
    int ret = 1;
    unsigned int blocksize;
    sxc_client_t *sx = source->sx;
    ssize_t bwrite;
    sxf_action_t action = SXF_ACTION_NORMAL;
    struct filter_handle *fh = NULL;
    char filter_uuid[37], filter_cfgkey[37 + 5], *filter_cfgdir = NULL;
    const char *confdir;
    sxc_meta_t *vmeta = NULL, *cvmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;

    sxi_hostlist_init(&hostlist);
    sxi_hostlist_init(&volnodes);
    if(sxi_locate_volume(sxi_cluster_get_conns(source->cluster), source->volume, &volnodes, NULL, vmeta, cvmeta)) {
        SXDEBUG("failed to locate destination file");
        sxi_hostlist_empty(&volnodes);
        return 1;
    }

    if(hashes_to_download(source, &volnodes, &hf, &hashfile, &blocksize, &filesize, NULL)) {
	SXDEBUG("failed to retrieve hash list");
        sxi_hostlist_empty(&volnodes);
	return 1;
    }

    if(!(buf = malloc(blocksize))) {
	SXDEBUG("OOM allocating the block buffer (%u bytes)", blocksize);
	sxi_seterr(sx, SXE_ECOMM, "Download failed: Out of memory");
	goto sxc_cat_fail;
    }

    if(!(vmeta = sxc_volumemeta_new(source)))
	goto sxc_cat_fail;
    if(sxi_volume_cfg_check(sx, source->cluster, vmeta, source->volume))
	goto sxc_cat_fail;
    if(vmeta && !sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
	if(mval_len != 16) {
	    sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
	    goto sxc_cat_fail;
	}
	sxi_uuid_unparse(mval, filter_uuid);

	fh = sxi_filter_gethandle(sx, mval);
	if(!fh) {
	    SXDEBUG("Filter ID %s required by source volume not found", filter_uuid);
	    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by source volume not found", filter_uuid);
	    goto sxc_cat_fail;
	}

	snprintf(filter_cfgkey, sizeof(filter_cfgkey), "%s-cfg", filter_uuid);
	sxc_meta_getval(vmeta, filter_cfgkey, &cfgval, &cfgval_len);
	if(cfgval_len && sxi_filter_add_cfg(fh, source->volume, cfgval, cfgval_len))
	    goto sxc_cat_fail;

	confdir = sxi_cluster_get_confdir(source->cluster);
	if(confdir) {
	    filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, source->volume);
	    if(!filter_cfgdir)
		goto sxc_cat_fail;
	}

	if(fh->f->data_prepare) {
            unsigned char chksum1[SXI_SHA1_BIN_LEN], chksum2[SXI_SHA1_BIN_LEN];

	    if(!(cvmeta = sxc_custom_volumemeta_new(source)))
		goto sxc_cat_fail;
            if(sxi_meta_checksum(sx, cvmeta, chksum1)) {
                SXDEBUG("Failed to compute custom volume meta checksum");
                goto sxc_cat_fail;
            }

	    if(fh->f->data_prepare(fh, &fh->ctx, source->path, filter_cfgdir, cfgval, cfgval_len, cvmeta, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
		goto sxc_cat_fail;
	    }
            if(sxi_meta_checksum(sx, cvmeta, chksum2)) {
                SXDEBUG("Failed to compute custom volume meta checksum");
                goto sxc_cat_fail;
            }

            if(memcmp(chksum1, chksum2, SXI_SHA1_BIN_LEN)) {
                SXDEBUG("Checksums different, modifying volume %s\n", source->volume);
		if(sxc_volume_modify(source->cluster, source->volume, NULL, NULL, -1, -1, cvmeta)) {
		    if(sxc_geterrnum(source->sx) == SXE_EAUTH)
			/* ignore error for non-owner */
			sxc_clearerr(source->sx);
		    else
			goto sxc_cat_fail;
		}
	    }
	}
	if(!(fbuf = malloc(blocksize))) {
	    SXDEBUG("OOM allocating the filter buffer (%u bytes)", blocksize);
	    sxi_seterr(sx, SXE_ECOMM, "Download failed: Out of memory");
	    goto sxc_cat_fail;
	}
    }

    while(fread(ha, 40, 1, hf)) {
	unsigned int todo;
	const uint8_t *wbuf = buf;

	if(load_hosts_for_hash(sx, hf, ha, &hostlist, NULL)) {
	    SXDEBUG("failed to load hosts for %.40s", ha);
	    goto sxc_cat_fail;
	}
	if(download_block_to_buf(source->cluster, &hostlist, ha, buf, blocksize)) {
	    SXDEBUG("failed to download hash %.40s", ha);
	    goto sxc_cat_fail;
	}

	todo = MIN(filesize, blocksize);
	filesize -= todo;

	if(!filesize)
	    action = SXF_ACTION_DATA_END;

	if(fh && fh->f->data_process) {
	    do {
		bwrite = fh->f->data_process(fh, fh->ctx, wbuf, todo, fbuf, blocksize, SXF_MODE_DOWNLOAD, &action);
		if(bwrite < 0) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process input data", filter_uuid);
		    if(fh->f->data_finish)
			fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD);
		    goto sxc_cat_fail;
		}
		if(write_hard(dest, fbuf, bwrite) == -1) {
		    sxi_setsyserr(sx, SXE_EWRITE, "Filter failed: Can't write to fd %d", dest);
		    if(fh->f->data_finish)
			fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD);
		    goto sxc_cat_fail;
		}
	    } while(action == SXF_ACTION_REPEAT);
	} else {
	    if(write_hard(dest, wbuf, todo) == -1)
		goto sxc_cat_fail;
	}
	sxi_hostlist_empty(&hostlist);
    }

    if(fh && fh->f->data_finish) {
	if(fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD)) {
	    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to clean up itself", filter_uuid);
	    goto sxc_cat_fail;
	}
    }
    if(ferror(hf)) {
	SXDEBUG("failed to read hash");
	sxi_setsyserr(sx, SXE_ETMP, "Download failed: Cannot read from cache file");
	goto sxc_cat_fail;
    }

    ret = 0;

    sxc_cat_fail:
    free(buf);
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    free(fbuf);
    if (hf)
        fclose(hf);
    free(filter_cfgdir);
    unlink(hashfile);
    sxi_tempfile_untrack(sx, hashfile);
    sxi_hostlist_empty(&volnodes);
    return ret;
}

static int cat_local_file(sxc_file_t *source, int dest) {
    char buf[4096];
    int src;
    sxc_client_t *sx = source->sx;

    if((src = open(source->path, O_RDONLY)) < 0) {
	SXDEBUG("failed to open input file %s", source->path);
	sxi_setsyserr(sx, SXE_EREAD, "Failed to open %s", source->path);
	return 1;
    }
    if (sxi_same_local_file(sx, source->path, "-", src, dest)) {
	close(src);
        return 1;
    }

    while(1) {
	ssize_t got = read(src, buf, sizeof(buf));
	if(!got)
	    break;
	if(got < 0) {
	    if(errno == EINTR)
		continue;
	    SXDEBUG("failed to read from input file %s", source->path);
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to read from %s", source->path);
	    close(src);
	    return 1;
	}
	if(write_hard(dest, buf, got) == -1) {
	    SXDEBUG("failed to write to output stream");
	    sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to output stream");
	    close(src);
	    return 1;
	}
    }
    close(src);
    return 0;
}

int sxc_cat(sxc_file_t *source, int dest) {
    int rc;
    sxc_file_t *destfile = calloc(1, sizeof(*destfile));
    if (!destfile) {
        sxi_setsyserr(source->sx, SXE_EMEM, "OOM allocating file");
        return 1;
    }
    destfile->cat_fd = dest;
    if (!dest) {
        sxi_seterr(source->sx, SXE_EARG, "Cannot write to stdin");
        rc = 1;
    } else
        rc = sxc_copy_single(source, destfile, 0, 0, 0, NULL, 1);
    sxc_file_free(destfile);
    return rc;
}

int sxc_update_filemeta(sxc_file_t *file, sxc_meta_t *newmeta)
{
    const void *value;
    unsigned int i, value_len;
    const char *key;
    sxc_meta_t *fmeta;
    sxc_client_t *sx;
    sxi_job_t *job;
    sxi_jobs_t *jobs;

    if(!file || !newmeta)
        return -1;
    sx = file->sx;
    if(!is_remote(file)) {
	sxi_seterr(sx, SXE_EARG, "Called with local source file");
	return -1;
    }

    jobs = sxi_jobs_new(sxi_cluster_get_client(file->cluster), 0);
    if(!jobs) {
        SXDEBUG("Failed to allocate jobs context");
        return -1;
    }

    if(!(fmeta = sxc_filemeta_new(file)))
        return -1;
    for(i=0; i<sxc_meta_count(newmeta); i++) {
        if(sxc_meta_getkeyval(newmeta, i, &key, &value, &value_len)) {
            SXDEBUG("failed to retrieve meta entry");
            sxc_meta_free(fmeta);
            return -1;
        }
        if(sxc_meta_setval(fmeta, key, value, value_len)) {
            SXDEBUG("failed to set meta entry");
            sxc_meta_free(fmeta);
            return -1;
        }
    }
    sxc_meta_free(file->meta);
    file->meta = fmeta;

    if(!(job = remote_to_remote_fast(file, file)))
        return -1;
    
    if(sxi_jobs_add(jobs, job)) {
        SXDEBUG("Failed to add job to jobs context");
        sxi_job_free(job);
        return -1;
    }

    if(sxi_jobs_wait(jobs, sxi_cluster_get_conns(file->cluster))) {
        SXDEBUG("Failed to wait for job");
        sxi_jobs_free(jobs);
        return -1;
    }

    sxi_jobs_free(jobs);
    return 0;
}

struct cb_metadata_ctx {
    curlev_context_t *cbdata;
    jparse_t *J;
    const struct jparse_actions *acts;
    sxc_meta_t *meta;
    enum sxc_error_t err;
};

/* {"<meta_key>":{"key1":"value1", "key2":"value2"}}                    *
 * where <meta_key> can be fileMeta, clusterMeta or clusterSettings,    *
 * the expected value is stored as meta_key field in above structure    */

static void cb_metadata(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_metadata_ctx *yactx = (struct cb_metadata_ctx *)ctx;

    if(sxc_meta_setval_fromhex(yactx->meta, key, string, length)) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
	if(sxc_geterrnum(sx) == SXE_EARG) {
	    sxi_jparse_cancel(J, "Invalid metadata received");
	    yactx->err = SXE_ECOMM;
	} else {
	    sxi_jparse_cancel(J, "Out of memory processing metadata");
	    yactx->err = SXE_EMEM;
	}
	sxc_clearerr(sx);
	return;
    }
}

static int metadata_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_metadata_ctx *yactx = (struct cb_metadata_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to retrieve object metadata");
	return 1;
    }

    sxc_meta_empty(yactx->meta);
    return 0;
}

static int metadata_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_metadata_ctx *yactx = (struct cb_metadata_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}


static int volmeta_new_common(sxc_file_t *file, sxc_meta_t **meta, sxc_meta_t **custom_meta) {
    sxi_hostlist_t volnodes;
    sxc_client_t *sx;

    if(!file || (!meta && !custom_meta))
        return -1;
    sx = file->sx;
    if(!is_remote(file)) {
        sxi_seterr(sx, SXE_EARG, "Called with local file");
        return -1;
    }

    if(meta) {
        if(!(*meta = sxc_meta_new(sx)))
            return -1;
    }

    if(custom_meta) {
        if(!(*custom_meta = sxc_meta_new(sx))) {
            if(meta) {
                sxc_meta_free(*meta);
                *meta = NULL;
            }
            return -1;
        }
    }

    sxi_hostlist_init(&volnodes);
    if(sxi_locate_volume(sxi_cluster_get_conns(file->cluster), file->volume, &volnodes, NULL, meta ? *meta : NULL, custom_meta ? *custom_meta : NULL)) {
        SXDEBUG("failed to locate volume");
        if(meta) {
            sxc_meta_free(*meta);
            *meta = NULL;
        }
        if(custom_meta) {
            sxc_meta_free(*custom_meta);
            *custom_meta = NULL;
        }
        return -1;
    }

    sxi_hostlist_empty(&volnodes);
    return 0;
}

sxc_meta_t *sxc_custom_volumemeta_new(sxc_file_t *file) {
    sxc_meta_t *custom_meta = NULL;
    if(volmeta_new_common(file, NULL, &custom_meta))
        return NULL;
    return custom_meta;
}

sxc_meta_t *sxc_volumemeta_new(sxc_file_t *file) {
    sxc_meta_t *meta = NULL;
    if(volmeta_new_common(file, &meta, NULL))
        return NULL;
    return meta;
}

sxc_meta_t *sxc_clustermeta_new(sxc_cluster_t *cluster) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_metadata, JPKEY("clusterMeta"), JPANYKEY))
    };
    sxc_meta_t *meta = NULL;
    struct cb_metadata_ctx yctx;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);

    yctx.J = NULL;
    yctx.acts = &acts;
    yctx.meta = sxc_meta_new(sx);
    if(!yctx.meta)
        goto sxc_clustermeta_begin_err;

    sxi_set_operation(sx, "get cluster metadata", NULL, NULL, NULL);
    if(sxi_cluster_query(conns, NULL, REQ_GET, "?clusterMeta", NULL, 0, metadata_setup_cb, metadata_cb, &yctx) != 200) {
        SXDEBUG("file get query failed");
        goto sxc_clustermeta_begin_err;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	goto sxc_clustermeta_begin_err;
    }

    meta = yctx.meta;
    yctx.meta = NULL;

sxc_clustermeta_begin_err:
    sxi_jparse_destroy(yctx.J);
    sxc_meta_free(yctx.meta);

    return meta;
}

sxc_meta_t *sxc_cluster_settings_new(sxc_cluster_t *cluster, const char *key) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_metadata, JPKEY("clusterSettings"), JPANYKEY))
    };
    sxc_meta_t *meta = NULL;
    struct cb_metadata_ctx yctx;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    char *url = NULL, *key_enc = NULL;
    unsigned int len;

    yctx.J = NULL;
    yctx.acts = &acts;
    yctx.meta = sxc_meta_new(sx);
    if(!yctx.meta)
        goto sxc_cluster_settings_new_err;

    len = lenof(".clusterSettings") + 1;
    if(key && strcmp(key, "ALL")) {
        key_enc = sxi_urlencode(sx, key, 1);
        if(!key_enc) {
            SXDEBUG("Failed to urlencode key");
            goto sxc_cluster_settings_new_err;
        }
    }
    if(key_enc)
        len += lenof("?key=") + strlen(key_enc);
    url = malloc(len);
    if(!url) {
        SXDEBUG("OOM allocating query url");
        goto sxc_cluster_settings_new_err;
    }
    snprintf(url, len, ".clusterSettings%s%s", key_enc ? "?key=" : "", key_enc ? key_enc : "");
    sxi_set_operation(sx, "get cluster settings", NULL, NULL, NULL);
    if(sxi_cluster_query(conns, NULL, REQ_GET, url, NULL, 0, metadata_setup_cb, metadata_cb, &yctx) != 200) {
        SXDEBUG("file get query failed");
        goto sxc_cluster_settings_new_err;
    }

    if(sxi_jparse_done(yctx.J)) {
  	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
        goto sxc_cluster_settings_new_err;
    }

    meta = yctx.meta;
    yctx.meta = NULL;

sxc_cluster_settings_new_err:
    free(key_enc);
    free(url);
    sxi_jparse_destroy(yctx.J);
    sxc_meta_free(yctx.meta);

    return meta;
}

sxc_meta_t *sxc_filemeta_new(sxc_file_t *file) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_metadata, JPKEY("fileMeta"), JPANYKEY))
    };
    sxi_hostlist_t volnodes;
    sxc_client_t *sx;
    char *enc_vol = NULL, *enc_path = NULL, *enc_rev = NULL, *url = NULL;
    struct cb_metadata_ctx yctx;
    sxc_meta_t *ret = NULL;
    sxc_meta_t *vmeta = NULL, *cvmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    char *filter_cfgdir = NULL;
    struct filter_handle *fh = NULL;
    unsigned int len;

    if(!file)
	return NULL;
    sx = file->sx;
    if(!is_remote(file)) {
	sxi_seterr(sx, SXE_EARG, "Called with local file");
	return NULL;
    }

    /* Check if meta needs to be fetched, we can skip redundant query then */
    if(file->meta_fetched) {
        SXDEBUG("File meta has already been obtained");
        return sxi_meta_dup(sx, file->meta);
    }

    memset(&yctx, 0, sizeof(yctx));
    sxi_hostlist_init(&volnodes);

    vmeta = sxc_meta_new(sx);
    if(!vmeta) {
        SXDEBUG("Failed to allocate volume meta");
        goto filemeta_begin_err;
    }

    cvmeta = sxc_meta_new(sx);
    if(!cvmeta) {
        SXDEBUG("Failed to allocate custom volume meta");
        goto filemeta_begin_err;
    }

    if(sxi_locate_volume(sxi_cluster_get_conns(file->cluster), file->volume, &volnodes, NULL, vmeta, cvmeta)) {
	SXDEBUG("failed to locate file");
	goto filemeta_begin_err;
    }

    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        char filter_uuid[37], cfgkey[37 + 5];
        const void *cfgval = NULL;
        unsigned int cfgval_len = 0;
        const char *confdir;
        if(mval_len != 16) {
            SXDEBUG("Filter(s) enabled but can't handle metadata");
            goto filemeta_begin_err;
        }
        sxi_uuid_unparse(mval, filter_uuid);
        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by destination volume not found", filter_uuid);
            goto filemeta_begin_err;
        }
        snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, file->volume, cfgval, cfgval_len))
            goto filemeta_begin_err;

        confdir = sxi_cluster_get_confdir(file->cluster);
        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, file->volume);
            if(!filter_cfgdir)
                goto filemeta_begin_err;
        }
    }

    if(!file->remote_path && sxi_filemeta_process(sx, fh, filter_cfgdir, file, cvmeta)) {
        SXDEBUG("failed to process filemeta");
        goto filemeta_begin_err;
    }

    if(!(enc_vol = sxi_urlencode(file->sx, file->volume, 0))) {
	SXDEBUG("failed to encode volume %s", file->volume);
	goto filemeta_begin_err;
    }

    if(!(enc_path = sxi_urlencode(file->sx, file->remote_path, 0))) {
	SXDEBUG("failed to encode path %s", file->path);
	goto filemeta_begin_err;
    }

    len = strlen(enc_vol) + 1 + strlen(enc_path) + sizeof("?fileMeta");
    if(file->rev) {
        if(!(enc_rev = sxi_urlencode(file->sx, file->rev, 0))) {
            SXDEBUG("failed to encode revision %s", file->rev);
            goto filemeta_begin_err;
        }

        len += lenof("&rev=") + strlen(enc_rev);
    }
    url = malloc(len);
    if(!url) {
	SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve file metadata: Out of memory");
	goto filemeta_begin_err;
    }
    sprintf(url, "%s/%s?fileMeta%s%s", enc_vol, enc_path, enc_rev ? "&rev=" : "", enc_rev ? enc_rev : "");
    free(enc_vol);
    free(enc_path);
    enc_vol = enc_path = NULL;

    yctx.J = NULL;
    yctx.acts = &acts;
    yctx.meta = sxc_meta_new(sx);
    if(!yctx.meta)
	goto filemeta_begin_err;

    sxi_set_operation(sxi_cluster_get_client(file->cluster), "get file metadata",
                      sxi_cluster_get_name(file->cluster), file->volume, file->path);
    if(sxi_cluster_query(sxi_cluster_get_conns(file->cluster), &volnodes, REQ_GET, url, NULL, 0, metadata_setup_cb, metadata_cb, &yctx) != 200) {
	SXDEBUG("file get query failed");
	goto filemeta_begin_err;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	goto filemeta_begin_err;
    }

    ret = yctx.meta;
    yctx.meta = NULL;

 filemeta_begin_err:
    sxi_hostlist_empty(&volnodes);
    free(enc_vol);
    free(enc_path);
    free(enc_rev);
    free(url);
    sxi_jparse_destroy(yctx.J);
    sxc_meta_free(yctx.meta);
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    free(filter_cfgdir);
    return ret;
}

/* --- file list ---- */
struct sxc_file_entry {
    sxc_file_t *pattern;
    int glob;
    int recursive;
    unsigned nfiles;
};

struct _sxc_file_list_t {
    sxc_client_t *sx;
    struct sxc_file_entry *entries;
    unsigned n;
    unsigned recursive;
    sxi_jobs_t *jobs;
    int ignore_errors;
    /* Errors counter, accumulates errors which cannot be handled with jobs context (when creating a new job fails for some reason) */
    int errors;
};


unsigned sxc_file_list_get_total(const sxc_file_list_t *lst)
{
    if (!lst)
        return 0;
    return sxi_jobs_total(lst->jobs, NULL);
}

unsigned sxc_file_list_get_successful(const sxc_file_list_t *lst)
{
    if (!lst)
        return 0;
    return sxi_jobs_successful(lst->jobs, NULL);
}

sxc_file_list_t *sxc_file_list_new(sxc_client_t *sx, int recursive, int ignore_errors)
{
    sxc_file_list_t *lst = calloc(1, sizeof(*lst));
    if (!lst) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate file list");
        return NULL;
    }
    lst->sx = sx;
    lst->recursive = recursive;
    lst->ignore_errors = ignore_errors;

    lst->jobs = sxi_jobs_new(sx, ignore_errors);
    if(!lst->jobs) {
        SXDEBUG("Failed to allocate jobs context");
        free(lst);
        return NULL;
    }
    return lst;
}

int sxc_file_list_add(sxc_file_list_t *lst, sxc_file_t *file, int allow_glob)
{
    struct sxc_file_entry *entry;
    if (!lst)
        return -1;
    if (!file) {
        sxi_seterr(lst->sx, SXE_EARG, "Null file");
        return -1;
    }
    if (file->sx != lst->sx) {
        sxi_seterr(lst->sx, SXE_EARG, "Cannot mix different sxc_client_t* in file list");
        return -1;
    }

    if (lst->recursive && !allow_glob) {
        /* FIXME: escape wildcards and allow this */
        sxi_seterr(file->sx, SXE_EARG, "Recursion requires globbing");
        return -1;
    }

    lst->n++;
    lst->entries = sxi_realloc(lst->sx, lst->entries, sizeof(*lst->entries) * lst->n);
    if (!lst->entries) {
        lst->n = 0;
        return -1;
    }
    entry = &lst->entries[lst->n - 1];
    if (allow_glob && !lst->recursive && !strchr(file->path, '*') && !strchr(file->path,'?') && !strchr(file->path,'[') && !ends_with(file->path, '/'))
        allow_glob = 0;/* disable globbing if no glob pattern, even if globbing would be otherwise allowed */
    entry->pattern = file;
    entry->glob = allow_glob;
    entry->nfiles = 0;
    return 0;
}

void sxc_file_list_free(sxc_file_list_t *lst)
{
    unsigned i;
    if (lst) {
        for (i=0;i<lst->n;i++) {
            struct sxc_file_entry *entry = &lst->entries[i];
            sxc_file_free(entry->pattern);
        }
        free(lst->entries);
        sxi_jobs_free(lst->jobs);
        free(lst);

    }
}

static int file_list_process(sxc_file_list_t *target, sxc_file_t *pattern,
                                        file_list_cb_t cb, sxi_hostlist_t *hlist, sxc_meta_t *cvmeta, sxc_file_t *file,
                                        void *ctx, struct filter_handle *fh, const char *filter_cfgdir, int ignore_errors)
{
    if(is_remote(file)) {
        if(sxi_filemeta_process(target->sx, fh, filter_cfgdir, file, cvmeta)) {
            sxi_seterr(target->sx, SXE_EARG, "Failed to process remote filename");
            return 1;
        }

        /* Process listed file properties before calling list callback */
        if(sxi_file_process(target->sx, fh, filter_cfgdir, file, SXF_MODE_LIST)) {
            sxi_seterr(target->sx, SXE_EARG, "Failed to process remote file");
            return 1;
        }
    }

    return cb(target, pattern, hlist, cvmeta, file, ctx, fh, filter_cfgdir);
}

static int sxi_file_list_foreach_wait(sxc_file_list_t *target)
{
    int ret;
    int errors;
    sxc_client_t *sx = target->sx;

    SXDEBUG("Waiting for %d jobs", sxi_jobs_total(target->jobs, NULL));
    ret = sxi_jobs_wait(target->jobs, NULL);
    errors = target->errors + sxi_jobs_errors(target->jobs, NULL);
    if (!ret && errors) {
        if (target->ignore_errors && errors) {
            sxc_clearerr(sx);
            sxi_seterr(sx, SXE_SKIP, "Failed to process %d file(s)", errors);
        }
        return 1;
    }
    return ret;
}

static int is_single_file_match(const char *pattern, unsigned pattern_slashes, const char *filename)
{
    /*  /a/b/? can match /a/b/x which is a file, but it can also match
     *  /a/b/y/o which is a file in the y directory */
    unsigned file_slashes = sxi_count_slashes(filename);
    return pattern_slashes == file_slashes &&
        (!ends_with(pattern, '/') || ends_with(filename, '/'));
}

static int sxi_file_list_foreach(sxc_file_list_t *target, multi_cb_t multi_cb, file_list_cb_t cb, int need_locate, int batched, void *ctx, const sxc_exclude_t *exclude)
{
    int rc = -1, ret = 0;
    unsigned i, j;
    sxc_client_t *sx;
    if (!target)
        return -1;
    sx = target->sx;

    if (!target->n)
        return 0;
    if (!target->entries) {
        sxi_seterr(target->sx, SXE_EARG, "Entries is not initialized");
        return -1;
    }
    if (target->n > 1 && multi_cb && multi_cb(target, ctx)) {
        SXDEBUG("multiple sources rejected by callback");
        return -1;
    }
    for (i=0;i<target->n;i++) {
        struct sxc_file_entry *entry = &target->entries[i];
        sxc_file_t *pattern = entry->pattern;
        sxc_cluster_lf_t *lst = NULL;
        sxi_hostlist_t volhosts_storage;
        /*sxi_hostlist_t *volhosts = need_locate ? &volhosts_storage : NULL;*/
        sxi_hostlist_t *volhosts = &volhosts_storage;
        char *filter_cfgdir = NULL;
        sxc_cluster_t *cluster = pattern->cluster;

        if (!target->recursive && (!*pattern->path || (pattern->path[0] == '/' && !pattern->path[1]))) {
            sxi_seterr(target->sx, SXE_EARG, "Cannot operate on volume root in non-recursive mode: '/%s'", pattern->volume);
            break;
        }

        if (volhosts)
            sxi_hostlist_init(volhosts);
        do {
            uint64_t single_files = 0;
            uint64_t files_in_dir = 0;
            struct timeval t0, t1;
	    const void *mval;
	    unsigned int mval_len;
	    sxc_meta_t *vmeta, *cvmeta = NULL;
	    struct filter_handle *fh = NULL;

            gettimeofday(&t0, NULL);

            /* When file on the list is local, use remote_to_local function */
            if(!is_remote(pattern)) {
                if(!(rc = is_excluded(target->sx, pattern->path, exclude))) {
                    rc = file_list_process(target, pattern, cb, volhosts, cvmeta, pattern, ctx, fh, filter_cfgdir, target->ignore_errors);
                } else if(rc > 0) {
                    rc = 0;
                    sxi_info(target->sx, "Skipping file: %s", pattern->path);
                }
                sxc_meta_free(cvmeta);
                if(rc && target->ignore_errors)
                    sxi_notice(sx, "ERROR: Failed to complete operation for '%s': %s", pattern->path, sxc_geterrmsg(sx));
                break;
            }

	    if(!(vmeta = sxc_meta_new(target->sx))) {
		rc = -1;
		break;
	    }
            if(!(cvmeta = sxc_meta_new(target->sx))) {
                rc = -1;
                sxc_meta_free(vmeta);
                break;
            }
            if(volhosts && sxi_locate_volume(sxi_cluster_get_conns(cluster), pattern->volume, volhosts, NULL, vmeta, cvmeta)) {
                CFGDEBUG("failed to locate volume %s", pattern->volume);
		sxc_meta_free(vmeta);
                sxc_meta_free(cvmeta);
                break;
            }

            if(sxi_volume_cfg_check(target->sx, cluster, vmeta, pattern->volume)) {
                CFGDEBUG("Failed to check volume configuration");
                sxc_meta_free(vmeta);
                sxc_meta_free(cvmeta);
                break;
            }
	    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
		char filter_uuid[37], cfgkey[37 + 5];
		const void *cfgval = NULL;
		unsigned int cfgval_len = 0;
                const char *confdir;
		if(mval_len != 16) {
		    CFGDEBUG("Filter(s) enabled but can't handle metadata");
		    rc = -1;
		    sxc_meta_free(vmeta);
                    sxc_meta_free(cvmeta);
		    break;
		}
		sxi_uuid_unparse(mval, filter_uuid);
		fh = sxi_filter_gethandle(target->sx, mval);
		if(!fh) {
		    CFGDEBUG("Filter ID %s required by destination volume not found", filter_uuid);
		    rc = -1;
		    sxc_meta_free(vmeta);
                    sxc_meta_free(cvmeta);
		    break;
		}
		snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", filter_uuid);
		sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);
		if(cfgval_len && sxi_filter_add_cfg(fh, pattern->volume, cfgval, cfgval_len)) {
		    rc = -1;
		    sxc_meta_free(vmeta);
                    sxc_meta_free(cvmeta);
		    break;
		}

                confdir = sxi_cluster_get_confdir(cluster);
                if(confdir) {
                    filter_cfgdir = sxi_get_filter_dir(target->sx, confdir, filter_uuid, pattern->volume);
                    if(!filter_cfgdir) {
                        rc = -1;
                        sxc_meta_free(vmeta);
                        sxc_meta_free(cvmeta);
                        break;
                    }
                }
	    }
	    sxc_meta_free(vmeta);
            if ((!entry->glob && !(fh && fh->f->filemeta_process)) || batched) {
                if(fh && fh->f->filemeta_process && batched && *pattern->path && (pattern->path[0] != '/' || pattern->path[1])) {
                    sxi_seterr(target->sx, SXE_EARG, "Cannot use mass operation while using filename processing filter");
                    rc = -1;
                    sxc_meta_free(cvmeta);
                    break;
                }
                if(!(rc = is_excluded(target->sx, pattern->path, exclude))) {
                    rc = file_list_process(target, pattern, cb, volhosts, cvmeta, pattern, ctx, fh, filter_cfgdir, target->ignore_errors);
                } else if(rc > 0) {
                    rc = 0;
                    sxi_info(target->sx, "Skipping file: %s", pattern->path);
                }
                sxc_meta_free(cvmeta);
                break;
            }
            /* glob */
            if(!target->recursive && ends_with(pattern->path, '/')) {
                /* Dummy error message reported when pattern ends with slash and */
                sxi_seterr(sx, SXE_EARG, "Failed to list files: Not Found");
                sxc_meta_free(cvmeta);
                break;
            }
            CFGDEBUG("Listing using glob pattern '%s'", pattern->path);
            lst = sxc_cluster_listfiles(cluster, pattern->volume, pattern->path, target->recursive || (fh && fh->f->filemeta_process), &entry->nfiles, 0);
            if (!lst) {
                CFGDEBUG("Cannot list files");
                sxc_meta_free(cvmeta);
                break;
            }
            gettimeofday(&t1, NULL);
            CFGDEBUG("Glob pattern '%s' matched %d files", pattern->path, entry->nfiles);
            rc = 0;
            unsigned pattern_slashes = sxi_count_slashes(pattern->path);
            /* When pattern has been achieved via remote listing, it can contain leading slash already. Add 1 only when leading slash is not present. */
            if(*pattern->path != '/')
                pattern_slashes++;
            for (j=0;j<entry->nfiles && !rc;j++) {
                sxc_file_t *remote_file = NULL;
                if (sxc_cluster_listfiles_next(cluster, pattern->volume, lst, &remote_file) <= 0) {
                    CFGDEBUG("Failed to list file %d/%d", j, entry->nfiles);
                    break;
                }
                if (is_single_file_match(pattern->path, pattern_slashes, remote_file->path))
                    single_files++;
                else
                    files_in_dir++;
                sxc_file_free(remote_file);
            }
            if (!target->recursive)
                files_in_dir = 0;/* omitted */
            CFGDEBUG("Single files: %lld, files in dir: %lld", (long long)single_files, (long long)files_in_dir);
            if ((single_files > 1 || files_in_dir > 0) && multi_cb && multi_cb(target, ctx)) {
                CFGDEBUG("multiple source file rejected by callback");
                rc = -1;
                sxc_meta_free(cvmeta);
                break;
            }
            for (j=0;j<entry->nfiles && !rc;j++) {
                sxc_file_t *remote_file = NULL;
                if(sxc_cluster_listfiles_prev(cluster, pattern->volume, lst, &remote_file) <= 0) {
                    CFGDEBUG("Failed to list file %d/%d", j, entry->nfiles);
                    break;
                }
                if (!target->recursive && !is_single_file_match(pattern->path, pattern_slashes, remote_file->path)) {
                    char *q = sxi_ith_slash(remote_file->path, pattern_slashes+1);
                    /* Truncate the filename in order to make the message unique across different filters */
                    if(q && *q == '/')
                        *++q = '\0';
                    sxi_notice(target->sx, "Omitting (file in) directory: %s", remote_file->path);
                } else {
                    CFGDEBUG("Processing file '%s/%s'", pattern->volume, remote_file->path);
                    if(!(rc = is_excluded(target->sx, remote_file->path+1, exclude))) {
                        rc = file_list_process(target, pattern, cb, volhosts, cvmeta, remote_file, ctx, fh, filter_cfgdir, target->ignore_errors);
                    } else if(rc > 0) {
                        sxi_info(target->sx, "Skipping file: %s", remote_file->path);
                        rc = 0;
                    }
                }
                sxc_file_free(remote_file);
            }
            if (!entry->nfiles && (entry->glob || (fh && fh->f->filemeta_process))) {
                if (*pattern->path) {
                    sxc_clearerr(target->sx);
                    sxi_seterr(target->sx, SXE_EARG, "Failed to list files: Not Found");
                    rc = -1;
                }
            }
            free(filter_cfgdir);
            filter_cfgdir = NULL;
            sxc_meta_free(cvmeta);
        } while(0);
        if (volhosts)
            sxi_hostlist_empty(volhosts);
        if (lst)
            sxc_cluster_listfiles_free(lst);
        free(filter_cfgdir);
        if (rc) {
            ret = rc;
            if(!target->ignore_errors)
                break;
            else
                sxc_clearerr(sx);
        }
    }
    if(sxi_file_list_foreach_wait(target))
        ret = 1;
    return ret;
}

/* --- file list END ---- */

static int sxi_rm_cb(sxc_file_list_t *target, sxc_file_t *pattern, sxi_hostlist_t *hlist, sxc_meta_t *cvmeta, sxc_file_t *file, void *ctx, struct filter_handle *fh, const char *filter_cfgdir)
{
    sxi_query_t *query;
    sxi_job_t *job;
    long http_code;
    int mass = 0;
    if (!hlist || !file || !ctx)
        return 1;

    if(ctx)
        mass = *(int*)ctx;
    if(fh && fh->f->file_update) {
        int ret;

        /* Filter cannot be updated when batched delete operation is being performed */
        if(mass) {
            sxi_seterr(target->sx, SXE_EARG, "Cannot use mass delete functionality with \"%s\" filter", fh->f->shortname);
            return 1;
        }

        if(sxi_filemeta_process(target->sx, fh, filter_cfgdir, file, cvmeta)) {
            sxc_file_free(file);
            return 1;
        }

	ret = fh->f->file_update(fh, fh->ctx, sxi_filter_get_cfg(fh, file->volume), sxi_filter_get_cfg_len(fh, file->volume), SXF_MODE_DELETE, file, NULL, target->recursive);
	if(ret == 100)
	    return 0;
	else if(ret) {
	    sxi_seterr(target->sx, SXE_EFILTER, "Filter failed to process files");
	    return 1;
	}
    }

    if(mass)
        query = sxi_massdel_proto(target->sx, file->volume, file->remote_path, target->recursive);
    else
        query = sxi_filedel_proto(target->sx, file->volume, file->remote_path, NULL);
    if (!query)
        return 1;
    sxi_hostlist_shuffle(hlist);
    sxi_set_operation(target->sx, "remove files", sxi_cluster_get_name(file->cluster), query->path, NULL);
    job = sxi_job_submit(sxi_cluster_get_conns(file->cluster), hlist, query->verb, query->path, file->path, NULL, 0, &http_code, target->jobs);
    sxi_query_free(query);
    if(job && fh && fh->f->file_notify) {
        /* Filter cannot be notified when mass delete operation is being performed */
        if(mass) {
            sxi_seterr(target->sx, SXE_EARG, "Cannot use mass delete functionality with \"%s\" filter", fh->f->shortname);
            return 1;
        }

	fh->f->file_notify(fh, fh->ctx, sxi_filter_get_cfg(fh, file->volume), sxi_filter_get_cfg_len(fh, file->volume), SXF_MODE_DELETE, sxi_cluster_get_name(file->cluster), file->volume, file->path, NULL, NULL, NULL);
    }
    if (!job && http_code == 404)
        return 0;
    return sxi_jobs_add(target->jobs, job);
}

int sxc_rm(sxc_file_list_t *target, int mass) {
    int ctx = mass;

    if (!target)
        return -1;

    sxc_clearerr(target->sx);
    return sxi_file_list_foreach(target, NULL, sxi_rm_cb, 1, mass, &ctx, NULL);
}

/*struct remote_iter {
    sxc_file_t *dest;
    int recursive;
    int ignore_errors;
    unsigned int errors;
    int fail_same_file;
};*/

struct sxc_copy_ctx {
    sxc_file_t *dest;
    int recursive;
    unsigned int errors;
    int fail_same_file;
    int onefs;
    const sxc_exclude_t *exclude;
    unsigned int skipped;
};

static int different_file(const char *path1, const char *path2)
{
    while (*path1 == '/') path1++;
    while (*path2 == '/') path2++;
    return strcmp(path1, path2);
}

static sxi_job_t *remote_copy_cb(sxc_file_list_t *target, sxc_file_t *pattern, sxi_hostlist_t *hlist,
                                 sxc_meta_t *cvmeta, sxc_file_t *file, void *ctx, struct filter_handle *fh, const char *filter_cfgdir)
{
    struct sxc_copy_ctx *it = ctx;
    sxi_job_t *ret;
    int is_different;

    /* Calculate remote filename if not done yet. Happens when first list element is being copied via
     * this callback. Following function would not unnecessarily call filter callbacks if filename had
     * been already processed. */
    if(sxi_filemeta_process(target->sx, fh, filter_cfgdir, it->dest, cvmeta))
        return NULL;

    if(!file->meta) {
        /* In case meta is not available, fetch remote file meta */
        file->meta = sxc_filemeta_new(file);
        if(!file->meta) {
            sxi_seterr(target->sx, SXE_EMEM, "Failed to fetch source file meta");
            return NULL;
        }
        file->meta_fetched = 1;
    }

    /* Destination file should derive meta from the source file. If dest file is stored on a volume
     * with different filter, it will be reset later. */
    sxc_meta_free(it->dest->meta);
    it->dest->meta = sxi_meta_dup(target->sx, file->meta);
    if(!it->dest->meta) {
        sxi_seterr(target->sx, SXE_EMEM, "Failed to duplicate source file meta");
        return NULL;
    }
    it->dest->meta_fetched = file->meta_fetched;
    it->dest->remote_size = file->remote_size;

    /* Process destination file, because its properties have changed. */
    if(sxi_file_process(target->sx, fh, filter_cfgdir, it->dest, SXF_MODE_LIST))
        return NULL;

    /* we could support parallelization for remote_to_remote and
     * remote_to_remote_fast if they would just return a job ... */
    is_different = different_file(file->path, pattern->path);
    ret = remote_copy_ev(pattern, file, it->dest, it->recursive && is_different, target->ignore_errors && is_different, &it->errors, it->fail_same_file, target->jobs);

    return ret;
}

int sxc_file_has_glob(sxc_file_t *file) {
    if(!file || !file->path)
        return -1;
    return sxi_str_has_glob(file->path);
}

int sxc_file_is_remote_dir(sxc_file_t *file) {
    if(!file || !file->path)
        return -1;
    if(sxc_file_is_sx(file)) {
        if(ends_with(file->path, '/'))
            return 1; /* fakedir */
        else if(!*file->path)
            return 1; /* root of the volume */
    }
    return 0;
}

int sxc_file_require_dir(sxc_file_t *file)
{
    struct stat sb;
    if (!file || !file->path)
        return 1;
    sxc_clearerr(file->sx);
    if (sxc_file_is_sx(file)) {
        if (ends_with(file->path, '/') || !*file->path)
            return 0;
        sxi_seterr(file->sx, SXE_EARG, "remote target '/%s/%s' must have a trailing slash", file->volume, file->path);
        return -1;
    }
    /* local path */
    /* require it be an existing directory */
    if (stat(file->path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        unsigned n;
        char *path;
	if(access(file->path, X_OK | W_OK)) {
	    sxi_seterr(file->sx, SXE_EARG, "Cannot access %s: %s", file->path, strerror(errno));
            return -1;
        }
        /* modify path to have trailing slash */
        n = strlen(file->path) + 2;
        path = malloc(n);
        if (!path) {
	    sxi_seterr(file->sx, SXE_EMEM, "Out of memory");
            return -1;
	}
        snprintf(path, n, "%s/", file->path);
        free(file->path);
        file->path = path;
        return 0;
    } else if (strcmp(file->path, "/dev/stdout")) {
        sxi_seterr(file->sx, SXE_EARG, "target '%s' must be an existing directory", file->path);
        return -1;
    }
    return 0;
}

static int multi_cb(sxc_file_list_t *target, void *ctx)
{
    struct sxc_copy_ctx *it = ctx;
    sxc_file_t *dest = it->dest;
    if (!dest->path)
        return 0;
    if ((target->recursive || ends_with(dest->path,'/')) && !is_remote(dest)) {
        if (mkdir(dest->path, 0777) == -1 && errno != EEXIST) {
            sxi_setsyserr(target->sx, SXE_EARG, "Cannot create directory '%s'", dest->path);
            return -1;
        }
    }
    if (target->recursive && is_remote(dest))
        return 0;/* allow copying sx://cluster/vol/a to sx://cluster/vol/b, when 'a' is a dir */
    return sxc_file_require_dir(dest);
}

/* Main callback invoked on file list iteration, may call remote_copy_cb or local_copy_cb (or download_cb?) */
static int sxc_copy_cb(sxc_file_list_t *target, sxc_file_t *pattern, sxi_hostlist_t *hlist,
                                 sxc_meta_t *cvmeta, sxc_file_t *file, void *ctx, struct filter_handle *fh, const char *filter_cfgdir)
{
    struct sxc_copy_ctx *it = ctx;
    sxi_job_t *job = NULL;

    if(!target || !it || !it->dest || !file) {
        sxi_seterr(target->sx, SXE_EARG, "NULL argument");
        return -1;
    }

    if(is_remote(it->dest)) { /* Destination file is remote */
        if(is_remote(file)) /* Source file is remote */
            job = remote_copy_cb(target, pattern, hlist, cvmeta, file, ctx, fh, filter_cfgdir);
        else /* Source file is local */
            return local_to_remote_iterate(file, target->recursive, 0, it->onefs, target->ignore_errors, it->dest, it->exclude, target->jobs, &target->errors);
    } else {/* Destination file is local */
        if(is_remote(file)) { /* Source file is remote */
            job = remote_copy_cb(target, pattern, hlist, cvmeta, file, ctx, fh, filter_cfgdir);
        } else  {/* Source file is local */
            if(it->dest->cat_fd > 0) {
                return cat_local_file(file, it->dest->cat_fd);
            } else { /* Local files copy */
                int ret = maybe_append_path(it->dest, file, 0);
                if(!ret)
                    ret = local_to_local(file, it->dest, it->exclude);
                if(restore_path(it->dest))
                    return 1;
                return ret;
            }
        }
    }

    /* Add obtained job reference to jobs array */
    if(job && sxi_jobs_add(target->jobs, job)) {
        sxc_client_t *sx = target->sx;
        SXDEBUG("Failed to add job to jobs table");
        sxi_job_free(job);
        return 1;
    }

    return job ? 0 : 1;
}

/* New version of sxc_copy, takes a list of source files and one destination */
int sxc_copy(sxc_file_list_t *source, sxc_file_t *dest, int recursive, int onefs, const sxc_exclude_t *exclude, int fail_same_file) {
    struct sxc_copy_ctx ctx;

    if (!source || !dest)
        return -1;

    sxc_clearerr(source->sx); /* do not fail because of previously set error, temporary workaround for bb#1814 */
    memset(&ctx, 0, sizeof(ctx));
    ctx.dest = dest;
    ctx.onefs = onefs;
    ctx.exclude = exclude;
    ctx.recursive = recursive;
    ctx.fail_same_file = fail_same_file;
    return sxi_file_list_foreach(source, multi_cb, sxc_copy_cb, 1, 0, &ctx, exclude);
}

// {"fileRevisions":{"rev#1":{"blockSize":1234,"fileSize":4567,"createdAt":12345}, "rev#2":{"blockSize":1234,"fileSize":4567,"createdAt":12345}}}

struct cb_filerev_ctx {
    curlev_context_t *cbdata;
    sxc_cluster_t *cluster;
    const char *volume;
    const char *remote_path;
    jparse_t *J;
    const struct jparse_actions *acts;
    sxc_revision_t **revs;
    unsigned int nrevs;
    enum sxc_error_t err;
};

static void cb_filerev_revinit(jparse_t *J, void *ctx) {
    const char *revname = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_filerev_ctx *yactx = (struct cb_filerev_ctx *)ctx;
    sxc_revision_t *rev = malloc(sizeof(*rev));
    unsigned int nrevs = yactx->nrevs;

    if(!rev) {
	sxi_jparse_cancel(J, "Out of memory processing file revisions");
	yactx->err = SXE_EMEM;
	return;
    }

    rev->file = sxi_file_remote(yactx->cluster, yactx->volume, NULL, yactx->remote_path, revname, NULL, 0);
    if(!rev->file) {
        free(rev);
        sxi_jparse_cancel(J, "Out of memory allocating remote file");
        yactx->err = SXE_EMEM;
        return;
    }
    rev->block_size = 0;

    rev->block_size = 0;
    if(!(nrevs & 0xf)) {
	sxc_revision_t **nurevs = realloc(yactx->revs, (nrevs+16) *sizeof(*nurevs));
	if(!nurevs) {
	    sxi_jparse_cancel(J, "Out of memory processing file revisions");
	    yactx->err = SXE_EMEM;
	    free(rev);
	    return;
	}
	yactx->revs = nurevs;
    }
    yactx->revs[nrevs] = rev;
    yactx->nrevs++;
}

static sxc_revision_t *getcurrev(jparse_t *J, struct cb_filerev_ctx *yactx) {
    unsigned int curev;
    if(!yactx || !yactx->revs || !(curev = yactx->nrevs) || !yactx->revs[curev-1]) {
	sxi_jparse_cancel(J, "Internal error detected processing file revisions");
	return NULL;
    }
    return yactx->revs[curev-1];
}

static void cb_filerev_bs(jparse_t *J, void *ctx, int32_t num) {
    struct cb_filerev_ctx *yactx = (struct cb_filerev_ctx *)ctx;
    sxc_revision_t *rev = getcurrev(J, ctx);

    if(!rev)
	return;
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid block size found on revision '%s'", sxc_file_get_revision(rev->file));
	yactx->err = SXE_ECOMM;
	return;
    }

    rev->block_size = num;
}

static void cb_filerev_size(jparse_t *J, void *ctx, int64_t num) {
    struct cb_filerev_ctx *yactx = (struct cb_filerev_ctx *)ctx;
    sxc_revision_t *rev = getcurrev(J, ctx);

    if(!rev)
	return;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid file size found on revision '%s'", sxc_file_get_revision(rev->file));
	yactx->err = SXE_ECOMM;
	return;
    }

    rev->file->size = num;
}

static void cb_filerev_time(jparse_t *J, void *ctx, int64_t num) {
    struct cb_filerev_ctx *yactx = (struct cb_filerev_ctx *)ctx;
    sxc_revision_t *rev = getcurrev(J, ctx);

    if(!rev)
	return;
    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid file modification time found on revision '%s'", sxc_file_get_revision(rev->file));
	yactx->err = SXE_ECOMM;
	return;
    }

    rev->file->created_at = num;
}

static int filerev_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_filerev_ctx *yactx = (struct cb_filerev_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to retrieve file revisions: Out of memory");
	return 1;
    }

    if(yactx->revs) {
	unsigned int i;
	for(i=0; i<yactx->nrevs; i++) {
            sxc_file_free(yactx->revs[i]->file);
	    free(yactx->revs[i]);
        }
	free(yactx->revs);
	yactx->revs = NULL;
    }
    yactx->nrevs = 0;
    return 0;
}

static int filerev_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_filerev_ctx *yactx = (struct cb_filerev_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

static int cmprevdsc(const void *a, const void *b) {
    const sxc_revision_t *ra = *(const sxc_revision_t **)a;
    const sxc_revision_t *rb = *(const sxc_revision_t **)b;

    return strcmp(rb->file->rev, ra->file->rev);
}

sxc_revlist_t *sxc_revisions(sxc_file_t *file) {
    const struct jparse_actions acts = {
	JPACTS_INT32(
		     JPACT(cb_filerev_bs, JPKEY("fileRevisions"), JPANYKEY, JPKEY("blockSize"))
		     ),
	JPACTS_INT64(
		     JPACT(cb_filerev_size, JPKEY("fileRevisions"), JPANYKEY, JPKEY("fileSize")),
		     JPACT(cb_filerev_time, JPKEY("fileRevisions"), JPANYKEY, JPKEY("createdAt"))
		     ),
	JPACTS_MAP_BEGIN(
			 JPACT(cb_filerev_revinit, JPKEY("fileRevisions"), JPANYKEY)
			 )
    };
    sxi_hostlist_t volnodes;
    sxc_client_t *sx;
    char *enc_vol = NULL, *enc_path = NULL, *url = NULL;
    struct cb_filerev_ctx yctx;
    sxc_revlist_t *ret = NULL;
    sxc_meta_t *vmeta = NULL;
    sxc_meta_t *cvmeta = NULL;
    char *filter_cfgdir = NULL;
    struct filter_handle *fh = NULL;
    const void *mval;
    unsigned int mval_len;
    unsigned int i;

    if(!file)
	return NULL;
    sx = file->sx;
    if(!is_remote(file)) {
	sxi_seterr(sx, SXE_EARG, "Called with local file");
	return NULL;
    }

    memset(&yctx, 0, sizeof(yctx));
    yctx.acts = &acts;
    sxi_hostlist_init(&volnodes);

    vmeta = sxc_meta_new(sx);
    if(!vmeta) {
        SXDEBUG("Out of memory");
        goto frev_err;
    }

    cvmeta = sxc_meta_new(sx);
    if(!cvmeta) {
        SXDEBUG("Out of memory");
        goto frev_err;
    }

    if(sxi_locate_volume(sxi_cluster_get_conns(file->cluster), file->volume, &volnodes, NULL, vmeta, cvmeta)) {
	SXDEBUG("failed to locate file");
	goto frev_err;
    }

    if(sxi_volume_cfg_check(sx, file->cluster, vmeta, file->volume)) {
        SXDEBUG("Failed to check volume config");
        goto frev_err;
    }

    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        char filter_uuid[37], cfgkey[37 + 5];
        const void *cfgval = NULL;
        unsigned int cfgval_len = 0;
        const char *confdir = sxi_cluster_get_confdir(file->cluster);

        if(mval_len != 16) {
            sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            goto frev_err;
        }
        sxi_uuid_unparse(mval, filter_uuid);

        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by destination volume not found", filter_uuid);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by destination volume not found", filter_uuid);
            goto frev_err;
        }

        snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, file->volume, cfgval, cfgval_len))
            goto frev_err;

        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, file->volume);
            if(!filter_cfgdir)
                goto frev_err;
        }
    }

    if(sxi_filemeta_process(sx, fh, filter_cfgdir, file, cvmeta)) {
        SXDEBUG("Failed to process filemeta");
        goto frev_err;
    }

    if(sxi_file_process(file->sx, fh, filter_cfgdir, file, SXF_MODE_LIST)) {
        SXDEBUG("Failed to process revision file");
        goto frev_err;
    }

    yctx.cluster = file->cluster;
    yctx.remote_path = file->remote_path;
    yctx.volume = file->volume;

    if(!(enc_vol = sxi_urlencode(file->sx, file->volume, 0))) {
	SXDEBUG("failed to encode volume %s", file->volume);
	goto frev_err;
    }

    if(!(enc_path = sxi_urlencode(file->sx, file->remote_path, 0))) {
	SXDEBUG("failed to encode path %s", file->path);
	goto frev_err;
    }

    url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + sizeof("?fileRevisions"));
    if(!url) {
	SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve file revisions: Out of memory");
	goto frev_err;
    }
    sprintf(url, "%s/%s?fileRevisions", enc_vol, enc_path);
    free(enc_vol);
    free(enc_path);
    enc_vol = enc_path = NULL;

    sxi_set_operation(sxi_cluster_get_client(file->cluster), "list file revisions", sxi_cluster_get_name(file->cluster), file->volume, file->path);
    if(sxi_cluster_query(sxi_cluster_get_conns(file->cluster), &volnodes, REQ_GET, url, NULL, 0, filerev_setup_cb, filerev_cb, &yctx) != 200) {
	SXDEBUG("rev list query failed");
	goto frev_err;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	goto frev_err;
    }

    for(i = 0; i < yctx.nrevs; i++) {
        sxc_file_t *rev = yctx.revs[i]->file;

        if(sxi_filemeta_process(file->sx, fh, filter_cfgdir, rev, cvmeta)) {
            SXDEBUG("Failed to process revision metadata");
            goto frev_err;
        }

        if(!rev->meta) {
            rev->meta = sxc_filemeta_new(rev);
            if(!rev->meta) {
                SXDEBUG("Failed to obtain revision '%s' meta", rev->rev);
                goto frev_err;
            }
        }

        if(sxi_file_process(file->sx, fh, filter_cfgdir, rev, SXF_MODE_LIST)) {
            SXDEBUG("Failed to process revision file");
            goto frev_err;
        }
    }

    qsort(yctx.revs, yctx.nrevs, sizeof(yctx.revs[0]), cmprevdsc);
    ret = malloc(sizeof(*ret));
    if(!ret) {
	SXDEBUG("OOM allocating results");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve file revisions: Out of memory");
	goto frev_err;
    }

    ret->revisions = yctx.revs;
    ret->count = yctx.nrevs;

 frev_err:
    if(!ret) {
	for(i=0; i<yctx.nrevs; i++) {
            sxc_file_free(yctx.revs[i]->file);
	    free(yctx.revs[i]);
        }
	free(yctx.revs);
    }

    sxi_hostlist_empty(&volnodes);
    free(enc_vol);
    free(enc_path);
    free(url);
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    free(filter_cfgdir);
    sxi_jparse_destroy(yctx.J);

    return ret;
}

void sxc_revisions_free(sxc_revlist_t *revlist) {
    if(!revlist)
	return;
    while(revlist->count--) {
        sxc_file_free(revlist->revisions[revlist->count]->file);
	free(revlist->revisions[revlist->count]);
    }
    free(revlist->revisions);
    free(revlist);
}

int sxc_remove_sxfile(sxc_file_t *file) {
    sxi_hostlist_t volnodes;
    sxi_query_t *query = NULL;
    sxc_client_t *sx = file->sx;
    int ret = -1;
    sxc_meta_t *vmeta = NULL;
    sxc_meta_t *cvmeta = NULL;
    char *filter_cfgdir = NULL;
    struct filter_handle *fh = NULL;
    const void *mval;
    unsigned int mval_len;

    if(!is_remote(file)) {
	sxi_seterr(sx, SXE_EARG, "Called with local file");
	return -1;
    }

    sxi_hostlist_init(&volnodes);

    vmeta = sxc_meta_new(sx);
    if(!vmeta) {
        SXDEBUG("Out of memory");
        goto rmfile_err;
    }

    cvmeta = sxc_meta_new(sx);
    if(!cvmeta) {
        SXDEBUG("Out of memory");
        goto rmfile_err;
    }

    if(sxi_locate_volume(sxi_cluster_get_conns(file->cluster), file->volume, &volnodes, NULL, vmeta, cvmeta)) {
        SXDEBUG("failed to locate file");
        goto rmfile_err;
    }

    if(sxi_volume_cfg_check(sx, file->cluster, vmeta, file->volume)) {
        SXDEBUG("Failed to check volume config");
        goto rmfile_err;
    }

    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        char filter_uuid[37], cfgkey[37 + 5];
        const void *cfgval = NULL;
        unsigned int cfgval_len = 0;
        const char *confdir = sxi_cluster_get_confdir(file->cluster);

        if(mval_len != 16) {
            sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
            goto rmfile_err;
        }
        sxi_uuid_unparse(mval, filter_uuid);

        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by destination volume not found", filter_uuid);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by destination volume not found", filter_uuid);
            goto rmfile_err;
        }

        snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, file->volume, cfgval, cfgval_len))
            goto rmfile_err;

        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, file->volume);
            if(!filter_cfgdir)
                goto rmfile_err;
        }
    }

    if(sxi_filemeta_process(sx, fh, filter_cfgdir, file, cvmeta)) {
        SXDEBUG("Failed to process filemeta");
        goto rmfile_err;
    }

    if(sxi_file_process(file->sx, fh, filter_cfgdir, file, SXF_MODE_LIST)) {
        SXDEBUG("Failed to process revision file");
        goto rmfile_err;
    }

    if(!(query = sxi_filedel_proto(sx, file->volume, file->remote_path, file->rev)))
        goto rmfile_err;
    sxi_set_operation(sx, "remove files", sxi_cluster_get_name(file->cluster), query->path, NULL);
    if(sxi_job_submit_and_poll(sxi_cluster_get_conns(file->cluster), &volnodes, query->verb, query->path, NULL, 0))
	goto rmfile_err;

    ret = 0;

 rmfile_err:
    sxi_query_free(query);
    sxi_hostlist_empty(&volnodes);
    sxc_meta_free(vmeta);
    sxc_meta_free(cvmeta);
    free(filter_cfgdir);

    return ret;
}

int sxc_copy_sxfile(sxc_file_t *source, sxc_file_t *dest, int fail_same_file) {
    sxc_client_t *sx = dest->sx;

    if(!is_remote(source)) {
	sxi_seterr(sx, SXE_EARG, "Called with local source file");
	return -1;
    }

    if(is_remote(dest)) {
        int ret;
        sxi_job_t *job;
        sxi_jobs_t *jobs = sxi_jobs_new(sxi_cluster_get_client(source->cluster), 0);
        if(!jobs) {
            SXDEBUG("Failed to allocate jobs context");
            return -1;
        }
        dest->size = source->size;
        job = remote_to_remote(source, dest, fail_same_file, jobs);
        if(!job) {
            SXDEBUG("Failed to copy files: NULL job");
            return -1;
        }

        if(sxi_jobs_add(jobs, job)) {
            SXDEBUG("Failed to add job to jobs context");
            sxi_job_free(job);
            return -1;
        }
        ret = sxi_jobs_wait(jobs, sxi_cluster_get_conns(source->cluster));
        sxi_jobs_free(jobs);
        return ret;
    } else {
        if(source->meta) {
            sxc_meta_free(dest->meta);
            dest->meta = sxi_meta_dup(source->sx, source->meta);
            if(!dest->meta) {
                SXDEBUG("Failed to duplicate remote file meta");
                return -1;
            }
        }
	return remote_to_local(source, dest, 0);
    }
}

/* Retrieve remote filename when filter is given. Converts local path to its remote representation and the other way around.
 * This function does nothing when both paths are already initialised. At least either file->path or file->remote_path must
 * be initialised in order to proceed. If filter does not implement filename_process() callback, then remote path is a copy
 * of local path (and the other way accordingly). */
int sxi_filemeta_process(sxc_client_t *sx, struct filter_handle *fh, const char *cfgdir, sxc_file_t *file, sxc_meta_t *custom_volume_meta) {
    const char *src;
    char *dest = NULL, *output;
    unsigned int nslashes = 0;

    if(!file || (!file->path && !file->remote_path && !file->cat_fd)) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }

    /* Process filename only when one of the paths is not set */
    if(file->remote_path && file->path)
        return 0;
    /* Support sxc_cat: in this situation file will not get the path */
    if(file->cat_fd)
        return 0;
    if(file->path)
        src = file->path;
    else
        src = file->remote_path;

    while(src[nslashes] == '/')
        nslashes++;

    if(fh && fh->f && fh->f->filemeta_process && *src && !ends_with(src, '/')) {
        unsigned char chksum1[SXI_SHA1_BIN_LEN], chksum2[SXI_SHA1_BIN_LEN];
        /* Remote file can be processed without initial listing. */
        if(!file->meta) {
            if(!file->path) {/* If filename is remote, we have to obtain remote file meta */
                file->meta = sxc_filemeta_new(file);
                file->meta_fetched = 1;
            } else
                file->meta = sxc_meta_new(sx);
            if(!file->meta) {
                SXDEBUG("Failed to allocate file meta");
                return -1;
            }
        }

        if(sxi_meta_checksum(sx, custom_volume_meta, chksum1)) {
            SXDEBUG("Failed to compute custom volume meta checksum");
            return -1;
        }

        if(fh->f->filemeta_process(fh, &fh->ctx, cfgdir, fh->cfg ? fh->cfg->cfg : NULL, fh->cfg ? fh->cfg->cfg_len : 0, file, file->path ? SXF_FILEMETA_LOCAL : SXF_FILEMETA_REMOTE, src + nslashes, &dest, file->meta, custom_volume_meta) || !dest){
            char uuid_str[37];
            sxi_uuid_unparse(fh->uuid_bin, uuid_str);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process files", uuid_str);
            free(dest);
            return -1;
        }

        if(sxi_meta_checksum(sx, custom_volume_meta, chksum2)) {
            SXDEBUG("Failed to compute custom volume meta checksum");
            return -1;
        }

        if(memcmp(chksum1, chksum2, SXI_SHA1_BIN_LEN)) {
            SXDEBUG("Checksums different, modifying volume %s\n", file->volume);
            if(sxc_volume_modify(file->cluster, file->volume, NULL, NULL, -1, -1, custom_volume_meta)) {
                if(sxc_geterrnum(sx) == SXE_EAUTH)
                    /* ignore error for non-owner */
                    sxc_clearerr(sx);
                else {
                    free(dest);
                    return -1;
                }
            }
        }
    } else {
        dest = strdup(src + nslashes);
        if(!dest) {
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            return -1;
        }
    }

    if(!nslashes)
        output = dest;
    else {
        output = malloc(nslashes + strlen(dest) + 1);
        if(!output) {
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            free(dest);
            return -1;
        }
        snprintf(output + nslashes, strlen(dest) + 1, "%s", dest);
        for(;nslashes > 0; nslashes--)
            output[nslashes-1] = '/';
        free(dest);
    }

    if(file->path)
        file->remote_path = output;
    else
        file->path = output;

    return 0;
}

int sxi_file_process(sxc_client_t *sx, struct filter_handle *fh, const char *cfgdir, sxc_file_t *file, sxf_mode_t mode) {
    if(!file) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }

    if(is_remote(file) && ends_with(file->remote_path, '/'))
        return 0;

    if(fh && fh->f && fh->f->file_process) {
        sxc_meta_t *meta = sxi_meta_dup(sx, file->meta);
        int meta_fetched = file->meta_fetched;
        if(!meta && file->meta) {
            SXDEBUG("Failed to duplicate file meta");
            return 1;
        }

        if(!meta) {
            if(mode == SXF_MODE_LIST || !is_remote(file))
                meta = sxc_meta_new(sx);
            else {
                meta = sxc_filemeta_new(file);
                meta_fetched = 1;
            }
            if(!meta) {
                SXDEBUG("Failed to create dummy file meta");
                return -1;
            }
        }

        if(fh->f->file_process(fh, fh->ctx, file, meta, cfgdir, fh->cfg ? fh->cfg->cfg : NULL, fh->cfg ? fh->cfg->cfg_len : 0, mode)){
            char uuid_str[37];
            sxi_uuid_unparse(fh->uuid_bin, uuid_str);
            sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process files", uuid_str);
            sxc_meta_free(meta);
            return -1;
        }

        /* When not in listing mode, save the file meta as the created one.
         * NOTE: this is a fallback solution for old servers which are not able to return file meta with the list of files */
        if(mode != SXF_MODE_LIST) {
            sxc_meta_free(file->meta);
            file->meta = meta;
            file->meta_fetched = meta_fetched;
        } else
            sxc_meta_free(meta);
    }

    /* Check file sizes and assume default in case */
    if(file->size != SXC_UINT64_UNDEFINED && file->remote_size == SXC_UINT64_UNDEFINED && sxi_file_set_remote_size(file, file->size)) {
        sxi_seterr(sx, SXE_EMEM, "Failed to set remote size");
        return -1;
    } else if(file->size == SXC_UINT64_UNDEFINED && file->remote_size != SXC_UINT64_UNDEFINED && sxi_file_set_size(file, file->remote_size)) {
        sxi_seterr(sx, SXE_EMEM, "Failed to set local size");
        return -1;
    }

    /* Note: both local and remote size of the file can be left uninitialized (hold SXC_UINT64_UNDEFINED value) and that is 
     * perfectly normal situation. This happens for regular downloads when pattern does not have a globbing character and does not
     * end with slash, effectively pointing to at most one single file. Then file can be processed before it would get the
     * remote size from filter and before it is remotely listed. */

    return 0;
}
