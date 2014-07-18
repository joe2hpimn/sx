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

#include "sx.h"
#include "misc.h"
#include "hostlist.h"
#include "clustcfg.h"
#include "yajlwrap.h"
#include "filter.h"
#include "volops.h"
#include "sxproto.h"
#include "jobpoll.h"
#include "libsx-int.h"
#include "curlevents.h"
#include "vcrypto.h"

struct _sxc_file_t {
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    sxi_job_t *job;
    sxi_jobs_t *jobs;
    char *volume;
    char *path;
    char *origpath;
    sxi_ht *seen;
    int cat_fd;
};

sxc_xfer_stat_t* sxi_cluster_xfer_new(sxc_client_t *sx, sxc_xfer_callback xfer_callback, void *ctx) {
    sxc_xfer_stat_t *xfer_stat = NULL;
    if(!sx || !xfer_callback)
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

void sxi_cluster_xfer_free(sxc_xfer_stat_t *xfer) {
    free(xfer);
}

/* Rate at wchich progress function should call external progress handler */
#define XFER_PROGRESS_INTERVAL 0.5

static int set_xfer_stat(sxc_xfer_stat_t *xfer_stat, int64_t bytes) {
    double timediff = 0;
    struct timeval now;
    if(!xfer_stat || !xfer_stat->xfer_callback)
        return SXE_ABORT;

    /* Increase current file counter */
    xfer_stat->current_xfer.sent += bytes;

    /* Increase total counters */
    if(xfer_stat->current_xfer.direction == SXC_XFER_DIRECTION_DOWNLOAD)
        xfer_stat->total_dl += bytes;
    else
        xfer_stat->total_ul += bytes;

    gettimeofday(&now, NULL);
    if((timediff = sxi_timediff(&now, &xfer_stat->interval_timer)) >= XFER_PROGRESS_INTERVAL 
        || xfer_stat->current_xfer.to_send <= xfer_stat->current_xfer.sent) {
        memcpy(&xfer_stat->interval_timer, &now, sizeof(struct timeval));

        /* Update total transfer time */
        xfer_stat->total_time += timediff;
        xfer_stat->current_xfer.total_time = sxi_timediff(&now, &xfer_stat->current_xfer.start_time);

        /* Invoke callback */
        return xfer_stat->xfer_callback(xfer_stat);
    }

    return SXE_NOERROR;
}

static int sxi_xfer_set_file(sxc_xfer_stat_t *xfer_stat, const char *file_name, int64_t file_size, unsigned int blocksize, sxc_xfer_direction_t xfer_direction) {
    if(!xfer_stat)
        return 1;

    switch(xfer_direction) {
        case SXC_XFER_DIRECTION_DOWNLOAD: {
            xfer_stat->total_to_dl += file_size;
            xfer_stat->total_data_dl += file_size;
        } break;
        case SXC_XFER_DIRECTION_UPLOAD: {
            xfer_stat->total_to_ul += file_size;
            xfer_stat->total_data_ul += file_size;
        } break;
    }

    xfer_stat->current_xfer.file_name = file_name;
    xfer_stat->current_xfer.file_size = file_size;
    xfer_stat->current_xfer.blocksize = blocksize;
    xfer_stat->current_xfer.direction = xfer_direction;
    xfer_stat->current_xfer.to_send = file_size;
    xfer_stat->current_xfer.sent = 0;
    gettimeofday(&xfer_stat->current_xfer.start_time, NULL);

    xfer_stat->status = SXC_XFER_STATUS_PART_STARTED;
    return 0;
}

/* Skip part of transfer data */
static int skip_xfer(sxc_cluster_t *cluster, int64_t bytes) {
    sxc_xfer_stat_t *xfer_stat = sxi_cluster_get_xfer_stat(cluster);

    if(!xfer_stat || !xfer_stat->xfer_callback) 
        return SXE_ABORT;

    xfer_stat->current_xfer.to_send -= bytes;

    switch(xfer_stat->current_xfer.direction) {
        case SXC_XFER_DIRECTION_DOWNLOAD: {
            xfer_stat->total_to_dl -= bytes;
        } break;
        case SXC_XFER_DIRECTION_UPLOAD: {
            xfer_stat->total_to_ul -= bytes;
        } break;
    }

    /* Invoke callback to allow client side to present skipped blocks */
    return xfer_stat->xfer_callback(xfer_stat);
}

/* Download table is at most 5MB and allows for up to 128GB of uniq content */
#define BLOCKS_PER_TABLE 131072
#define INITIAL_HASH_ITEMS MIN(BLOCKS_PER_TABLE, 256)
#define cluster_err(...) sxi_seterr(sxi_cluster_get_client(cluster), __VA_ARGS__)
#define cluster_syserr(...) sxi_setsyserr(sxi_cluster_get_client(cluster), __VA_ARGS__)

static int is_remote(sxc_file_t *f) {
    return f->cluster != NULL;
}

sxc_file_t *sxc_file_remote(sxc_cluster_t *cluster, const char *volume, const char *path) {
    sxc_file_t *ret;

    if(!cluster || !sxi_is_valid_cluster(cluster))
	return NULL;

    if(!volume) {
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
    ret->path = path ? strdup(path) : strdup("");

    if(!ret->volume || !ret->path) {
	CFGDEBUG("OOM duplicating item");
	cluster_err(SXE_EMEM, "Cannot create remote file object: Out of memory");
	sxc_file_free(ret);
	return NULL;
    }
    return ret;
}

int sxc_file_is_sx(sxc_file_t *file)
{
    return file && file->cluster;
}

sxc_file_t *sxc_file_local(sxc_client_t *sx, const char *path) {
    sxc_file_t *ret;

    if(!(ret = calloc(1, sizeof(*ret)))) {
	SXDEBUG("OOM allocating results");
	sxi_seterr(sx, SXE_EMEM, "Cannot create local file object: Out of memory");
	return NULL;
    }

    ret->sx = sx;
    ret->cluster = NULL;
    ret->volume = NULL;
    ret->path = strdup(path);
    if(!ret->path) {
	SXDEBUG("OOM duplicating item");
	sxi_seterr(sx, SXE_EMEM, "Cannot create local file object: Out of memory");
	free(ret);
	return NULL;
    }

    return ret;
}

sxc_file_t *sxc_file_from_url(sxc_client_t *sx, sxc_cluster_t **cluster, const char *confdir, const char *url)
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
    uri = sxc_parse_uri(sx, url);
    if (!uri)
        return NULL;
    do {
        sxc_file_t *file;

        if (!uri->volume) {
            sxi_seterr(sx, SXE_EARG,"Bad path %s: Volume name expected", url);
            break;
        }
        /* if it is a different (or the first) cluster, load its config */
        if (!*cluster || strcmp(sxi_cluster_get_name(*cluster), uri->host)) {
	    sxc_cluster_free(*cluster);
            *cluster = sxc_cluster_load_and_update(sx, confdir, uri->host, uri->profile);
	}
        if (!*cluster) {
/*            sxi_notice(sx, "Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));*/
            break;
        }
	file = sxc_file_remote(*cluster, uri->volume, uri->path);
        sxc_free_uri(uri);
        return file;
    } while(0);
    sxc_free_uri(uri);
    return NULL;
}

static sxc_file_t *sxi_file_dup(sxc_file_t *file)
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
        ret->job = file->job;
        ret->jobs = file->jobs;
        if (file->volume && !(ret->volume = strdup(file->volume)))
            break;
        if (file->path && !(ret->path = strdup(file->path)))
            break;
        if (file->origpath && !(ret->origpath = strdup(file->origpath)))
            break;
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
    sxi_ht_free(sxfile->seen);
    free(sxfile);
}

static int file_to_file(sxc_client_t *sx, const char *source, const char *dest)
{
    char buf[8192];
    FILE *f, *d;

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
    fclose(d);

    return 0;
}

static int cat_local_file(sxc_file_t *source, int dest);
static int local_to_local(sxc_file_t *source, sxc_file_t *dest) {
    if (strcmp(dest->origpath, dest->path)) {
        /* dest is a dir, we must only mkdir exactly the given dest, not
         * subdirs */
        if (mkdir(dest->origpath, 0700) == -1 && errno != EEXIST) {
            sxi_setsyserr(source->sx, SXE_EARG, "Cannot create directory '%s'", dest->origpath);
            return -1;
        }
    }
    return file_to_file(source->sx, source->path, dest->path);
}

static int load_hosts_for_hash(sxc_client_t *sx, FILE *f, const char *hash, sxi_hostlist_t *host_list, sxi_ht *host_table) {
    int main_host = 1;
    int sz;

    while((sz = fgetc(f))) {
	char ho[64], *hlist;

	if(sz == EOF || sz >= (int) sizeof(ho)) {
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

struct need_hash {
    off_t off;
    sxi_hostlist_t upload_hosts;
    unsigned replica;
};

struct part_upload_ctx {
    yajl_callbacks yacb;
    FILE *f;
    char *token;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    enum createfile_state { CF_ERROR, CF_BEGIN, CF_MAIN, CF_BS, CF_TOK, CF_DATA, CF_HASH, CF_HOSTS, CF_HOST, CF_COMPLETE } state;
    off_t *offsets;
    struct need_hash *needed;
    struct need_hash *current_need;
    sxi_ht *hashes;
    unsigned needed_cnt;
    sxi_ht *hostsmap;
    int ref;/* how many batches are outstanding */
    sxi_retry_t *retry;
};

struct file_upload_ctx {
    sxc_client_t *sx;
    sxi_job_t *job;
    sxi_hostlist_t *volhosts;
    sxc_cluster_t *cluster;
    int64_t uploaded;
    char *name;
    off_t pos;
    off_t end;
    off_t size;
    off_t last_pos;
    int fd;
    int qret;
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
    sxc_cluster_t *cluster;
    int64_t ul;
    int64_t to_ul;
};

/* Set information about current transfer upload value */
int sxi_host_upload_set_xfer_stat(struct host_upload_ctx* ctx, int64_t uploaded, int64_t to_upload) {
    int64_t ul_diff = 0;

    /* This is not considered as error, ctx or cluster == NULL if we do not want to check progress */
    if(!ctx || !sxi_cluster_get_xfer_stat(ctx->cluster))
        return SXE_NOERROR;

    ctx->to_ul = to_upload;
    ul_diff = uploaded - ctx->ul;
    ctx->ul = uploaded;

    if(ul_diff > 0) {
        return set_xfer_stat(sxi_cluster_get_xfer_stat(ctx->cluster), ul_diff);
    } else
        return SXE_NOERROR;
}

/* Get numner of bytes to be uploaded */
int64_t sxi_host_upload_get_xfer_to_send(const struct host_upload_ctx *ctx) {
    if(!ctx || !sxi_cluster_get_xfer_stat(ctx->cluster)) 
        return 0;

    return ctx->to_ul;
}

/* Get number of bytes already uploaded */
int64_t sxi_host_upload_get_xfer_sent(const struct host_upload_ctx *ctx) {
    if(!ctx || !sxi_cluster_get_xfer_stat(ctx->cluster))
        return 0;

    return ctx->ul;
}

static int yacb_createfile_start_map(void *ctx) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->current.state != CF_BEGIN && yactx->current.state != CF_DATA) {
	CBDEBUG("bad state %d", yactx->current.state);
	return 0;
    }
    yactx->current.state++;
    return 1;
}

static int yacb_createfile_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    if(!ctx)
	return 0;
    sxc_client_t *sx = yactx->sx;
    if (yactx->current.state == CF_ERROR)
        return yacb_error_map_key(&yactx->current.errctx, s, l);
    if (yactx->current.state == CF_MAIN) {
        if (ya_check_error(yactx->sx, &yactx->current.errctx, s, l)) {
            yactx->current.state = CF_ERROR;
            return 1;
        }
    }
    if(yactx->current.state == CF_MAIN) {
	if(l == lenof("blockSize") && !memcmp(s, "blockSize", lenof("blockSize")))
	    yactx->current.state = CF_BS;
	else if(l == lenof("uploadToken") && !memcmp(s, "uploadToken", lenof("uploadToken")))
	    yactx->current.state = CF_TOK;
	else if(l == lenof("uploadData") && !memcmp(s, "uploadData", lenof("uploadData")))
	    yactx->current.state = CF_DATA;
	else {
	    CBDEBUG("unknown key %.*s", (int)l, s);
	    return 0;
	}
	return 1;
    }

    if(yactx->current.state == CF_HASH) {
        off_t *off;
	if(l != SXI_SHA1_TEXT_LEN) {
	    CBDEBUG("unexpected hash length %u", (unsigned)l);
	    return 0;
	}
        if (!yactx->current.hashes) {
	    CBDEBUG("%p hash lookup failed for %.40s", (const void*)yactx, s);
	    sxi_seterr(yactx->sx, SXE_ECOMM, "Copy failed: remote2remote-fast cannot locate block");
            return 0;
        }
        if (sxi_ht_get(yactx->current.hashes, s, SXI_SHA1_TEXT_LEN, (void**)&off)) {
	    CBDEBUG("%p hash lookup failed for %.40s", (const void*)yactx, s);
	    sxi_seterr(yactx->sx, SXE_ECOMM, "Copy failed: Cannot locate block");
            return 0;
        }
        SXDEBUG("need %d off: %lld", yactx->current.needed_cnt, (long long)*off);
        yactx->current.current_need = &yactx->current.needed[yactx->current.needed_cnt++];
        yactx->current.current_need->off = *off;
        yactx->current.current_need->replica = 0;
        sxi_hostlist_init(&yactx->current.current_need->upload_hosts);
	yactx->current.state++;
	return 1;
    }

    CBDEBUG("bad state %d", yactx->current.state);
    return 0;
}

static int yacb_createfile_number(void *ctx, const char *s, size_t l) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    char numb[24], *enumb;
    int64_t nnumb;

    if(!ctx)
	return 0;
    if(l > 20) {
	CBDEBUG("number too long (%u bytes)", (unsigned)l);
	return 0;
    }
    if(yactx->current.state != CF_BS) {
	CBDEBUG("bad state %d, expecting %d", yactx->current.state, CF_BS);
	return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    nnumb = strtoll(numb, &enumb, 10);
    if(*enumb || yactx->blocksize != nnumb) {
	CBDEBUG("failed to parse number %.*s", (int)l, s);
	return 0;
    }

    yactx->current.state = CF_MAIN;
    return 1;
}

static int yacb_createfile_string(void *ctx, const unsigned char *s, size_t l) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->current.state == CF_ERROR)
        return yacb_error_string(&yactx->current.errctx, s, l);
    if(yactx->current.state == CF_TOK) {
	if(yactx->current.token) {
	    CBDEBUG("token is already set");
	    return 0;
	}

	/* FIXME check l is 80 chars ? */
	yactx->current.token = malloc(l+1);
	if(!yactx->current.token) {
	    CBDEBUG("OOM duplicating token");
	    sxi_seterr(yactx->sx, SXE_EMEM, "Out of memory");
	    return 0;
	}

	memcpy(yactx->current.token, s, l);
	yactx->current.token[l] = '\0';
	yactx->current.state = CF_MAIN;
	return 1;
    }

    if(yactx->current.state == CF_HOST) {
        char ip[41];
        /* TODO: do we want to allow DNS names or only IPs? */
	if(l < 2 || l > 40) {
	    CBDEBUG("bad host '%.*s'", (int)l, s);
	    return 0;
	}
        memcpy(ip, s, l);
        ip[l] = '\0';
        /* FIXME: leak */
        if (sxi_hostlist_add_host(yactx->sx, &yactx->current.current_need->upload_hosts, ip)) {
            CBDEBUG("failed to add host to hash hostlist");
            return 0;
        }
	return 1;
    }

    CBDEBUG("bad state %d", yactx->current.state);
    return 0;
}

static int yacb_createfile_start_array(void *ctx) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->current.state != CF_HOSTS) {
	CBDEBUG("bad state %d, expected %d", yactx->current.state, CF_HOSTS);
	return 0;
    }

    yactx->current.state++;
    return 1;
}

static int yacb_createfile_end_array(void *ctx) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->current.state != CF_HOST)
	return 0;
    yactx->current.current_need = NULL;
    yactx->current.state = CF_HASH;
    return 1;
}

static int yacb_createfile_end_map(void *ctx) {
    struct file_upload_ctx *yactx = (struct file_upload_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->current.state == CF_ERROR)
        return yacb_error_end_map(&yactx->current.errctx);
    if(yactx->current.state == CF_MAIN)
	yactx->current.state = CF_COMPLETE;
    else if(yactx->current.state == CF_HASH)
	yactx->current.state = CF_MAIN;
    else {
	CBDEBUG("bad state %d", yactx->current.state);
	return 0;
    }
    return 1;
}

static int createfile_setup_cb(curlev_context_t *ctx, const char *host) {
    struct file_upload_ctx *yactx = sxi_cbdata_get_upload_ctx(ctx);
    sxi_conns_t *conns = sxi_cbdata_get_conns(ctx);
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->current.yh)
	yajl_free(yactx->current.yh);

    if(!(yactx->current.yh = yajl_alloc(&yactx->current.yacb, NULL, yactx))) {
	SXDEBUG("OOM allocating yajl context");
	sxi_seterr(sx, SXE_EMEM, "Cannot create file: Out of memory");
	return 1;
    }

    yactx->sx = sx;
    yactx->current.state = CF_BEGIN;
    free(yactx->current.token);
    yactx->current.token = NULL;
    if (yactx->host)
        free(yactx->host);
    yactx->host = strdup(host);
    if (!yactx->host) {
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate hostname");
        return 1;
    }
    if (yactx->current.f)
        rewind(yactx->current.f);
    return 0;
}

static int createfile_cb(curlev_context_t *ctx, const unsigned char *data, size_t size) {
    struct file_upload_ctx *yactx = sxi_cbdata_get_upload_ctx(ctx);
    sxi_conns_t *conns = sxi_cbdata_get_conns(ctx);
    if(yajl_parse(yactx->current.yh, data, size) != yajl_status_ok) {
        if (yactx->current.state != CF_ERROR) {
            CBDEBUG("failed to parse JSON data");
            sxi_seterr(sxi_conns_get_client(conns), SXE_ECOMM, "communication error");
        }
	return 1;
    }

    return 0;
}

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

struct hash_up_data_t {
    sxi_hostlist_t hosts;
    off_t offset;
};


int sxi_upload_block_from_buf(sxi_conns_t *conns, sxi_hostlist_t *hlist, const char *token, uint8_t *block, unsigned int block_size, int64_t upload_size) {
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
    qret = sxi_cluster_query(conns, hlist, REQ_PUT, url, block, upload_size, NULL, NULL, NULL);
    free(url);
    if(qret != 200) {
	SXDEBUG("query failed");
	return 1;
    }
    return 0;
}

static sxi_job_t* flush_file_ev(sxc_cluster_t *cluster, const char *host, const char *token, const char *name, sxi_jobs_t *jobs) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_hostlist_t flush_host;
    sxi_query_t *proto;
    sxi_job_t *job;

    sxc_clearerr(sx);

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
                sxi_curlev_nullify_upload_context(sxi_cluster_get_conns(u->cluster), u);
            host_upload_free(u);
        }
        sxi_ht_free(yctx->hostsmap);
    }
    if (yctx->yh)
        yajl_free(yctx->yh);
    free(yctx->needed);
    free(yctx->offsets);
    sxi_ht_free(yctx->hashes);
    memset(yctx, 0, sizeof(*yctx));
}

static void multi_part_upload_blocks(curlev_context_t *ctx, const char* url);
static int part_wait_reset(struct file_upload_ctx *ctx)
{
    sxc_client_t *sx = ctx->sx;
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

static void upload_blocks_to_hosts(struct file_upload_ctx *yctx, struct host_upload_ctx *uctx, int status, const char *url);
static void upload_blocks_to_hosts_uctx(curlev_context_t *ctx, const char *url)
{
    struct host_upload_ctx *uctx = sxi_cbdata_get_host_ctx(ctx);
    int status = sxi_cbdata_result(ctx, NULL);
    if (uctx)
        upload_blocks_to_hosts(uctx->yctx, uctx, status, url);
}

static int send_up_batch(struct file_upload_ctx *yctx, const char *host, struct host_upload_ctx *u)
{
    sxc_client_t *sx = yctx->sx;
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
    sxi_set_operation(sx, "upload file contents", NULL, NULL, NULL);
    if (sxi_cluster_query_ev(cbdata,
                             sxi_cluster_get_conns(yctx->cluster),
                             host, REQ_PUT, url,
                             u->buf, u->buf_used, NULL, block_reply_cb) == -1) {
        SXDEBUG("cluster upload query failed");
        free(url);
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
    sxc_client_t *sx = yctx->sx;
    SXDEBUG("finished file");
    gettimeofday(&yctx->t2, NULL);
    if (!yctx->current.token) {
        SXDEBUG("fail incremented: no token?");
        yctx->fail++;
        return;
    }
    /*  TODO: multiplex flush_file */
    yctx->job = flush_file_ev(yctx->cluster, yctx->host, yctx->current.token, yctx->name, yctx->dest->jobs);
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
    sxc_client_t *sx = state->sx;
    /* TODO: sxi_cluster_query_ev should support streaming uploads,
     * so that we don't have to keep all hashes in memory */
    state->end = state->size;
    SXDEBUG("entered");
    if (multi_part_upload_ev(state) == -1) {
        SXDEBUG("fail incremented: failed to upload last part");
        state->fail++;
    }
}

static int batch_hashes_to_hosts(struct file_upload_ctx *yctx, struct need_hash *needed, unsigned from, unsigned size, unsigned next_replica)
{
    unsigned i;
    sxc_client_t *sx = yctx->sx;
    if (yctx->all_fail) {
        sxi_seterr(sx, SXE_ECOMM, "All replicas have previously failed");
        return -1;
    }
    for (i=from;i<size;i++) {
        struct need_hash *need = &needed[i];
        const char *host = NULL;
        need->replica += next_replica;
        host = sxi_hostlist_get_host(&need->upload_hosts, need->replica);
        if (!host) {
            sxi_seterr(sx, SXE_ECOMM, "All replicas have failed");
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
        sxi_set_operation(sx, "file block upload", NULL, NULL, NULL);
        sxi_retry_msg(yctx->current.retry, host);
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
            u->cluster = yctx->cluster;
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

static void upload_blocks_to_hosts(struct file_upload_ctx *yctx, struct host_upload_ctx *uctx, int status, const char *url)
{
    const char *h;
    struct host_upload_ctx *u;
    sxc_client_t *sx = yctx->sx;
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
        SXDEBUG("query failed: %d", status);
        if (uctx) {
            unsigned n = uctx->n;
            /* move to next replica: the last batch, and everything else
             * currently queued for this host */
            uctx->i = uctx->n = 0;
            if (batch_hashes_to_hosts(yctx, uctx->needed, uctx->last_successful, n, 1)) {
                SXDEBUG("fail incremented");
                yctx->fail++;
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
            for (;u->i < u->n;) {
                struct need_hash *need = &u->needed[u->i++];
                SXDEBUG("adding data %d from pos %lld", u->i, (long long)need->off);
                ssize_t n = pread_hard(yctx->fd, u->buf + u->buf_used, yctx->blocksize, need->off);
                if (n < 0) {
                    SXDEBUG("fail incremented: error reading buffer");
                    yctx->fail++;
                    return;
                }
                if (!n) {
                    SXDEBUG("fail incremented: early EOF?");
                    yctx->fail++;
                    return;
                }
                u->buf_used += n;
                if (n < yctx->blocksize) {
                    unsigned remaining = yctx->blocksize - n;
                    memset(u->buf + u->buf_used, 0, remaining);
                    u->buf_used += remaining;
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
    off_t diff = h1->off - h2->off;
    if (!diff)
        return 0;
    return diff < 0 ? -1 : 1;
}

static void multi_part_upload_blocks(curlev_context_t *ctx, const char *url)
{
    struct file_upload_ctx *yctx = sxi_cbdata_get_upload_ctx(ctx);
    sxc_client_t *sx = yctx->sx;
    sxc_xfer_stat_t *xfer_stat = NULL;

    int status = sxi_cbdata_result(ctx, NULL);
    if (status != 200) {
        SXDEBUG("query failed: %d", status);
        yctx->fail++;
        yctx->qret = status;
        if (yctx->current.ref > 0)
            yctx->current.ref--;
        return;
    }
    SXDEBUG("in multi_part_upload_blocks");
    if(yajl_complete_parse(yctx->current.yh) != yajl_status_ok || yctx->current.state != CF_COMPLETE) {
        if (yctx->current.state != CF_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Copy failed: Failed to parse cluster response");
        }
        SXDEBUG("fail incremented, after parse");
        yctx->fail++;
        if (yctx->current.ref > 0)
            yctx->current.ref--;
        return;
    }
    SXDEBUG("need: %d hashes", yctx->current.needed_cnt);

    xfer_stat = sxi_cluster_get_xfer_stat(yctx->cluster);
    if(xfer_stat) {
        int64_t to_skip = yctx->pos - yctx->last_pos - yctx->current.needed_cnt * yctx->blocksize; 
        if(to_skip && skip_xfer(yctx->cluster, to_skip) != SXE_NOERROR) {
            SXDEBUG("Could not skip part of transfer");
            sxi_seterr(sx, SXE_ABORT, "Could not skip part of transfer");
            return;
        }
    }

    if (batch_hashes_to_hosts(yctx, yctx->current.needed, 0, yctx->current.needed_cnt, 0)) {
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

    upload_blocks_to_hosts(yctx, NULL, status, url);
}

static int multi_part_compute_hash_ev(struct file_upload_ctx *yctx)
{
    struct curlev_context *cbdata;
    yajl_callbacks *yacb = &yctx->current.yacb;
    sxc_client_t *sx = yctx->sx;
    ssize_t n;
    off_t start = yctx->pos;
    unsigned part_size = yctx->end - yctx->pos;
    sxc_meta_t *fmeta;
    yctx->last_pos = yctx->pos;

    if(yctx->pos == 0) {
	fmeta = yctx->fmeta;
	yctx->query = sxi_fileadd_proto_begin(sx, yctx->dest->volume, yctx->dest->path, NULL, yctx->pos, yctx->blocksize, yctx->size);
    } else {
	fmeta = NULL;
	yctx->query = sxi_fileadd_proto_begin(sx, ".upload", yctx->cur_token, NULL, yctx->pos, yctx->blocksize, yctx->size);
        /* extend is only valid on the node that created the file
         * (same as with flush!) */
        sxi_hostlist_empty(yctx->volhosts);
        sxi_hostlist_add_host(sx, yctx->volhosts, yctx->host);
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
            yctx->current.offsets[block] = pos;
            SXDEBUG("%p, hash %s: block %ld, %lld", (const void*)yctx, hexhash, (long)block, (long long)yctx->current.offsets[block]);
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

    ya_init(yacb);
    yacb->yajl_start_map = yacb_createfile_start_map;
    yacb->yajl_map_key = yacb_createfile_map_key;
    yacb->yajl_number = yacb_createfile_number;
    yacb->yajl_start_array = yacb_createfile_start_array;
    yacb->yajl_string = yacb_createfile_string;
    yacb->yajl_end_array = yacb_createfile_end_array;
    yacb->yajl_end_map = yacb_createfile_end_map;
    yctx->blocksize = yctx->blocksize;
    yctx->current.yh = NULL;

    if (!(cbdata = sxi_cbdata_create_upload(sxi_cluster_get_conns(yctx->cluster), multi_part_upload_blocks, yctx))) {
        SXDEBUG("failed to allocate cbdata");
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return -1;
    }
    SXDEBUG("part size: %d/%d", part_size, UPLOAD_PART_THRESHOLD);
    /* TODO: state->end should be yctx->end */
    yctx->current.ref++;
    /* TODO: multiple volhost support */
    sxi_set_operation(sx, "upload file content hashes", NULL, NULL, NULL);

    if(sxi_cluster_query_ev_retry(cbdata, sxi_cluster_get_conns(yctx->cluster), yctx->volhosts,
                                  yctx->query->verb, yctx->query->path, yctx->query->content, yctx->query->content_len,
                                  createfile_setup_cb, createfile_cb, yctx->dest->jobs) == -1)
    {
        SXDEBUG("file create query failed");
        return -1;
    }
    sxi_cbdata_unref(&cbdata);
    return 0;
}

static int multi_part_upload_ev(struct file_upload_ctx *yctx)
{
    sxc_client_t *sx = yctx->sx;

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
        if (!(yctx->current.retry = sxi_retry_init(sx))) {
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

static sxi_job_t* multi_upload(struct file_upload_ctx *state)
{
    sxc_client_t *sx = state->sx;
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

static char *get_filter_dir(sxc_client_t *sx, const char *confdir, const char *uuid, const char *volume)
{
    char *fdir;

    fdir = malloc(strlen(confdir) + strlen(uuid) + strlen(volume) + 11);
    if(!fdir) {
	sxi_seterr(sx, SXE_EMEM, "Can't allocate memory for filter config directory");
	return NULL;
    }
    sprintf(fdir, "%s/volumes/%s", confdir, volume);
    if(access(fdir, F_OK))
	mkdir(fdir, 0700);
    sprintf(fdir, "%s/volumes/%s/%s", confdir, volume, uuid);
    if(access(fdir, F_OK)) {
	if(mkdir(fdir, 0700) == -1) {
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
        /* TODO: set source->origpath everywhere */
        src_part = base(source->path);
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
    while (src_part && *src_part == '/') src_part++;

    unsigned n = strlen(dest->origpath) + strlen(src_part) + 2;
    path = malloc(n);
    if (!path) {
        sxi_seterr(dest->sx, SXE_EMEM, "cannot allocate path");
        return -1;
    }

    if (!*dest->origpath) {
        if ((src_part[0] == '.' && src_part[1] == '/'))
            src_part += 2;
        else if (src_part[0] == '.' && src_part[1] == '.' && src_part[2] == '/')
            src_part += 3;
    }

    snprintf(path, n, "%s/%s", dest->origpath, src_part);
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
        }
        return 0;
    }
    return 1;
}

static int local_to_remote_begin(sxc_file_t *source, sxc_meta_t *fmeta, sxc_file_t *dest, int recursive) {
    unsigned int blocksize;
    char *fname = NULL, *tempfname = NULL;
    sxi_ht *hosts = NULL, *hashes = NULL;
    struct stat st;
    uint8_t *buf = NULL;
    struct file_upload_ctx *yctx = NULL, *state = NULL;
    struct hash_up_data_t *hashdata;
    int ret = 1, s = -1;
    sxi_hostlist_t shost, volhosts;
    sxc_client_t *sx = dest->sx;
    int64_t fsz, orig_fsz;
    sxc_meta_t *vmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    int qret = -1;
    sxc_xfer_stat_t *xfer_stat = NULL;

    sxi_hostlist_init(&volhosts);
    sxi_hostlist_init(&shost);

    if (maybe_append_path(dest, source, recursive))
        return 1;

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
	close(s);
	free(buf);
	fclose(yctx->current.f);
	tsource = sxc_file_local(sx, fname);
	if(!tsource)
	    SXDEBUG("failed to create source file object for temporary input file");
	else {
	    ret = local_to_remote_begin(tsource, fmeta, dest, recursive);
	    sxc_file_free(tsource);
	}
	unlink(fname);
	sxi_tempfile_untrack(sx, fname);
        if (restore_path(dest))
            ret = 1;
	return ret;
    }

    if(!(vmeta = sxc_meta_new(sx)))
	goto local_to_remote_err;
    /* TODO: multiplex the locate too! */
    orig_fsz = fsz = st.st_size;
    if ((qret = sxi_volume_info(dest->cluster, dest->volume, &volhosts, &fsz, vmeta))) {
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
	    struct filter_handle *fh;
	    FILE *tempfile = NULL;
	    int td;
	    const void *cfgval = NULL;
	    unsigned int cfgval_len = 0;
	    const char *confdir = sxi_cluster_get_confdir(dest->cluster);
	    char *fdir = NULL;

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

	if(confdir) {
	    fdir = get_filter_dir(sx, confdir, filter_uuid, dest->volume);
	    if(!fdir) {
                qret = 404;
		goto local_to_remote_err;
            }
	}

	if(fh->f->file_process) {
	    if(fh->f->file_process(fh, fh->ctx, source->path, fmeta, fdir, cfgval, cfgval_len, SXF_MODE_UPLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process source file", filter_uuid);
		free(fdir);
		goto local_to_remote_err;
	    }
	}

	if(fh->f->data_process) {
	    if(!(tempfname = sxi_tempfile_track(sx, NULL, &tempfile))) {
		SXDEBUG("Failed to generate filter temporary file");
		free(fdir);
		goto local_to_remote_err;
	    }
	    td = fileno(tempfile);

	    if(fh->f->data_prepare) {
		if(fh->f->data_prepare(fh, &fh->ctx, source->path, fdir, cfgval, cfgval_len, SXF_MODE_UPLOAD)) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
                    free(fdir);
		    goto local_to_remote_err;
		}
	    }
	    free(fdir);
	    fdir = NULL;

	    while((bread = read(s, inbuff, sizeof(inbuff))) > 0) {
		if(lseek(s, 0, SEEK_CUR) == st.st_size)
		    action = SXF_ACTION_DATA_END;
		do {
		    bwrite = fh->f->data_process(fh, fh->ctx, inbuff, bread, outbuff, sizeof(outbuff), SXF_MODE_UPLOAD, &action);
		    if(bwrite < 0) {
			sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process input data", filter_uuid);
			if(fh->f->data_finish)
			    fh->f->data_finish(fh, &fh->ctx, SXF_MODE_UPLOAD);
			goto local_to_remote_err;
		    }
		    if(write(td, outbuff, bwrite) != bwrite) {
			sxi_setsyserr(sx, SXE_EWRITE, "Filter failed: Can't write to temporary file");
			fclose(tempfile);
			if(fh->f->data_finish)
			    fh->f->data_finish(fh, &fh->ctx, SXF_MODE_UPLOAD);
			goto local_to_remote_err;
		    }
		} while(action == SXF_ACTION_REPEAT);
	    }
	    if(fh->f->data_finish) {
		if(fh->f->data_finish(fh, &fh->ctx, SXF_MODE_UPLOAD)) {
		    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to clean up itself", filter_uuid);
		    goto local_to_remote_err;
		}
	    }
	    fclose(tempfile);

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

	    if(st.st_size != orig_fsz) {
		fsz = st.st_size;
		if((qret = sxi_volume_info(dest->cluster, dest->volume, &volhosts, &fsz, NULL))) {
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
	free(fdir);
    }

    state->max_part_blocks = UPLOAD_PART_THRESHOLD / blocksize;
    state->cluster = dest->cluster;
    state->fd = s;
    state->blocksize = blocksize;
    state->volhosts = &volhosts;
    state->sx = sx;
    state->name = strdup(dest->path);
    if (!state->name) {
	sxi_seterr(sx, SXE_EMEM, "Cannot allocate filename: Out of memory");
        goto local_to_remote_err;
    }
    state->fmeta = fmeta;
    state->dest = dest;
    state->size = st.st_size;

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

    dest->job = multi_upload(state);
    if (!dest->job) {
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

    ret = 0;
    local_to_remote_err:
    if (ret > 0 && qret > 0)
        ret = qret;
    SXDEBUG("returning %d", ret);
    if(yctx && yctx->current.yh)
	yajl_free(yctx->current.yh);

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

    if(hosts) {
	char *hlist;
	sxi_ht_enum_reset(hosts);
	while(!sxi_ht_enum_getnext(hosts, NULL, NULL, (const void **)&hlist))
	    free(hlist);
	sxi_ht_free(hosts);
    }
    if(hashes) {
	sxi_ht_enum_reset(hashes);
	while(!sxi_ht_enum_getnext(hashes, NULL, NULL, (const void **)&hashdata)) {
	    sxi_hostlist_empty(&hashdata->hosts);
	    free(hashdata);
	}
	sxi_ht_free(hashes);
    }
    if(s>=0)
	close(s);
    free(buf);

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
    if (restore_path(dest))
        ret = 1;
    return ret;
}

static int sxi_jobs_add(sxc_client_t *sx, sxi_jobs_t *jobs, sxi_job_t *job)
{
    if (job == &JOB_NONE)
        return 0;/* successful, but no job to add */
    if (!jobs || !job) {
        sxi_seterr(sx, SXE_EARG, "jobs_add called with NULL");
        return -1;
    }
    jobs->jobs = sxi_realloc(sx, jobs->jobs, ++jobs->n * sizeof(*jobs->jobs));
    if (!jobs->jobs) {
        sxi_job_free(job);
        return -1;
    }
    jobs->jobs[jobs->n-1] = job;
    return 0;
}

static int sxi_jobs_wait_one(sxc_file_t *file, sxi_job_t *job)
{
    sxi_jobs_t jobs;
    int ret;
    memset(&jobs, 0, sizeof(jobs));

    if (!file || !job || sxi_jobs_add(file->sx, &jobs, job))
        return -1;
    ret = sxi_job_wait(sxi_cluster_get_conns(file->cluster), &jobs);
    free(jobs.jobs);

    return ret;
}


static int local_to_remote(sxc_file_t *source, sxc_meta_t *fmeta, sxc_file_t *dest) {
    int rc = local_to_remote_begin(source, fmeta, dest, 0);
    if (rc)
        return rc;
    return sxi_jobs_wait_one(dest, dest->job);
}

static int local_to_remote_iterate(sxc_file_t *source, int recursive, int depth, int onefs, sxc_file_t *dest)
{
    struct dirent *entry;
    sxc_client_t *sx = source->sx;
    DIR *dir;
    unsigned n, n2;
    char *path;
    char *destpath;
    struct stat sb;
    int ret = 0, qret = -1;
    sxc_meta_t *emptymeta = sxc_meta_new(sx);
    dev_t sdev;

    if(!emptymeta) {
        SXDEBUG("emptymeta is NULL");
	return -1;
    }
    if (stat(source->path, &sb) == -1) {
        sxi_setsyserr(source->sx, SXE_EREAD, "Cannot stat '%s'", source->path);
	sxc_meta_free(emptymeta);
        return -1;
    }
    sdev = sb.st_dev;

    if (!recursive || !S_ISDIR(sb.st_mode)) {
	ret = local_to_remote(source, emptymeta, dest);
	sxc_meta_free(emptymeta);
        if (ret)
            SXDEBUG("uploading one file failed");
	return ret;
    }
    SXDEBUG("Iterating on %s", source->path);

    n = strlen(source->path) + 2 + sizeof(entry->d_name);
    n2 = strlen(dest->path) + 2 + sizeof(entry->d_name);
    path = malloc(n);
    if (!path) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate pathname");
	sxc_meta_free(emptymeta);
        return -1;
    }
    destpath = malloc(n2);
    if (!destpath) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate destpathname");
	sxc_meta_free(emptymeta);
        free(path);
        return -1;
    }

    dir = opendir(source->path);
    if (!dir) {
        sxi_setsyserr(sx, SXE_EREAD, "Cannot open directory '%s'", source->path);
	sxc_meta_free(emptymeta);
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
        snprintf(path, n, "%s/%s", source->path, entry->d_name);
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
        if (!(src->path = strdup(path))) {
            sxi_setsyserr(sx, SXE_EMEM, "Cannot dup path");
            break;
        }
        snprintf(destpath, n2, "%s/%s", dest->path, entry->d_name);
        if (S_ISDIR(sb.st_mode)) {
            if ((qret = local_to_remote_iterate(src, 1, depth+1, onefs, dst))) {
                SXDEBUG("failure in directory: %s", destpath);
                if (qret == 403 || qret == 404) {
                    ret = qret;
                    break;
                }
                ret = -1;
            }
            dest->jobs = dst->jobs;
        }
        else if (S_ISREG(sb.st_mode)) {
            SXDEBUG("Starting to upload %s", path);
            if ((qret = local_to_remote_begin(src, emptymeta, dst, 1)) != 0) {
                sxi_notice(sx, "%s: %s", path, sxc_geterrmsg(sx));
                SXDEBUG("failed to begin upload on %s", path);
                if (qret == 403 || qret == 404) {
                    ret = qret;
                    break;
                }
                ret = -1;
            }
            sxc_meta_empty(emptymeta);
            if (!dest->jobs) {
                dest->jobs = calloc(1, sizeof(*dest->jobs));
                if (!dest->jobs) {
                    sxi_setsyserr(sx, SXE_EMEM, "cannot allocated jobs");
                    ret = -1;
                    break;
                }
                gettimeofday(&dest->jobs->tv, NULL);
            }
            if (dst->job && sxi_jobs_add(sx, dest->jobs, dst->job) == -1) {
                SXDEBUG("failed to job_add");
                ret = -1;
                break;
            }
        } else if (S_ISLNK(sb.st_mode)) {
            sxi_notice(sx, "Skipped symlink %s", path);
        }
        sxc_file_free(src);
        sxc_file_free(dst);
        src = dst = NULL;
    }
    sxc_file_free(src);
    sxc_file_free(dst);
    src = dst = NULL;
    sxc_meta_free(emptymeta);
    free(path);
    free(destpath);
    closedir(dir);

    if (!depth) {
        int failed = sxc_geterrnum(sx) != SXE_NOERROR;

        if (dest->jobs) {
            SXDEBUG("waiting for %d jobs", dest->jobs->n);
            ret = sxi_job_wait(sxi_cluster_get_conns(dest->cluster), dest->jobs);
            if (ret) {
                SXDEBUG("job_wait failed");
                failed = 1;
            }
            free(dest->jobs->jobs);
            free(dest->jobs);
            dest->jobs = NULL;
        }
        if (failed)
            ret = -1;
    }

    return ret;
}

struct cb_getfile_ctx {
    sxc_client_t *sx;
    yajl_callbacks yacb;
    struct cb_error_ctx errctx;
    FILE *f;
    int64_t filesize, blocksize;
    unsigned int nblocks;
    yajl_handle yh;
    enum getfile_state { GF_ERROR, GF_BEGIN, GF_MAIN, GF_BLOCKSIZE, GF_FILESIZE, GF_DATA, GF_CONTENT, GF_BLOCK, GF_HOSTS, GF_HOST, GF_ENDBLOCK, GF_COMPLETE } state;
};

static int yacb_getfile_start_map(void *ctx) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state != GF_BEGIN && yactx->state != GF_CONTENT) {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
    yactx->state++;
    return 1;
}

static int yacb_getfile_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == GF_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == GF_MAIN) {
        if (ya_check_error(yactx->sx, &yactx->errctx, s, l)) {
            yactx->state = GF_ERROR;
            return 1;
        }
    }
    if(yactx->state == GF_MAIN) {
	if(l == lenof("blockSize") && !memcmp(s, "blockSize", lenof("blockSize")))
	    yactx->state = GF_BLOCKSIZE;
	else if(l == lenof("fileSize") && !memcmp(s, "fileSize", lenof("fileSize")))
	    yactx->state = GF_FILESIZE;
	else if(l == lenof("fileData") && !memcmp(s, "fileData", lenof("fileData")))
	    yactx->state = GF_DATA;
	else {
	    CBDEBUG("unknown key %.*s", (int)l, s);
	    return 0;
	}
	return 1;
    }

    if(yactx->state == GF_BLOCK) {
	if(l != 40) {
	    CBDEBUG("unexpected hash length %u", (unsigned)l);
	    return 0;
	}
	if(!(fwrite(s, 40, 1, yactx->f))) {
	    CBDEBUG("failed to write hash to results file");
	    sxi_setsyserr(yactx->sx, SXE_EWRITE, "Failed to write to temporary file");
	    return 0;
	}
	yactx->nblocks++;
	yactx->state++;
	return 1;
    }

    CBDEBUG("bad state %d", yactx->state);
    return 0;
}

static int yacb_getfile_number(void *ctx, const char *s, size_t l) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    char numb[24], *enumb;
    int64_t nnumb;

    if(!ctx)
	return 0;
    if(l > 20) {
	CBDEBUG("number too long (%u bytes)", (unsigned)l);
	return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    nnumb = strtoll(numb, &enumb, 10);
    if(*enumb) {
	CBDEBUG("failed to parse number %.*s", (int)l, s);
	return 0;
    }

    if(yactx->state == GF_BLOCKSIZE) {
	if(yactx->blocksize) { /* FIXME: reset */
	    CBDEBUG("blockSize duplicated");
	    return 0;
	}
	yactx->blocksize = nnumb;
    } else if(yactx->state == GF_FILESIZE) {
	if(yactx->filesize >= 0) { /* FIXME: reset */
	    CBDEBUG("fileSize duplicated");
	    return 0;
	}
	yactx->filesize = nnumb;
    } else {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }

    yactx->state = GF_MAIN;
    return 1;
}

static int yacb_getfile_start_array(void *ctx) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state != GF_DATA && yactx->state != GF_HOSTS) {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }

    yactx->state++;
    return 1;
}

static int yacb_getfile_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->state == GF_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    if(yactx->state != GF_HOST) {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }

    if(l < 2 || l > 40) {
	CBDEBUG("bad host '%.*s'", (int)l, s);
	return 0;
    }

    if(getenv("SX_DEBUG_SINGLEHOST")) {
	s = (unsigned char*)getenv("SX_DEBUG_SINGLEHOST");
	l = strlen((const char *)s);
    }

    if(fputc(l, yactx->f) == EOF) {
	CBDEBUG("failed to write host length to results file");
	return 0;
    }
    if(!fwrite(s, l, 1, yactx->f)) {
	CBDEBUG("failed to write host to results file");
	sxi_setsyserr(yactx->sx, SXE_EWRITE, "Failed to write temporary file");
	return 0;
    }

    return 1;
}

static int yacb_getfile_end_array(void *ctx) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state == GF_HOST) {
	yactx->state = GF_ENDBLOCK;
	if(fputc(0, yactx->f) == EOF) {
	    CBDEBUG("failed to write host to results file");
	    return 0;
	}
    } else if(yactx->state == GF_CONTENT)
	yactx->state = GF_MAIN;
    else {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
    return 1;
}

static int yacb_getfile_end_map(void *ctx) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->state == GF_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == GF_ENDBLOCK)
	yactx->state = GF_CONTENT;
    else if(yactx->state == GF_MAIN)
	yactx->state = GF_COMPLETE;
    else {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
    return 1;
}

static int getfile_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("OOM allocating yajl context");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve the blocks to download: Out of memory");
	return 1;
    }

    yactx->sx = sx;
    yactx->state = GF_BEGIN;
    rewind(yactx->f);
    yactx->blocksize = 0;
    yactx->filesize = -1;
    yactx->nblocks = 0;

    return 0;
}

static int getfile_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_getfile_ctx *yactx = (struct cb_getfile_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != GF_ERROR) {
            CBDEBUG("failed to parse JSON data");
            sxi_seterr(sxi_conns_get_client(conns), SXE_ECOMM, "communication error");
        }
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
    sxc_client_t *sx;
    uint8_t *base;
    off_t bsize;
    unsigned int at;
};

static int gethash_setup_cb_old(sxi_conns_t *conns, void *ctx, const char *host) {
struct cb_gethash_ctx *yactx = (struct cb_gethash_ctx *)ctx;
yactx->at = 0;
 return 0;
}
 
static int gethash_cb_old(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_gethash_ctx *yactx = (struct cb_gethash_ctx *)ctx;
    if(size + yactx->at > (size_t) yactx->bsize) {
       CBDEBUG("too much data received");
       return 1;
    }
    memcpy(yactx->base + yactx->at, data, size);
    yactx->at += size;
    return 0;
}

static int download_block_to_buf(sxc_cluster_t *cluster, sxi_hostlist_t *hostlist, const char *hash, uint8_t *buf, unsigned int blocksize) {
    struct cb_gethash_ctx ctx;
    char url[6 + 64 + 40 + 1];
    int qret, l;

    sprintf(url, ".data/%u/", blocksize);
    l = strlen(url);
    memcpy(url + l, hash, 40);
    url[l + 40] = '\0';

    ctx.sx = sxi_cluster_get_client(cluster);
    ctx.base = buf;
    ctx.at = 0;
    ctx.bsize = blocksize;
    sxi_set_operation(sxi_cluster_get_client(cluster), "download file contents", NULL, NULL, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), hostlist, REQ_GET, url, NULL, 0,
                             gethash_setup_cb_old, gethash_cb_old, &ctx);
    if(qret != 200) {
       CFGDEBUG("Failed to retrieve %s - status: %d", url, qret);
       return 1;
    }
    return 0;
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
    sxc_cluster_t *cluster;
    int64_t dl;
    int64_t to_dl;
};


/* Set information about current transfer download value */
int sxi_file_download_set_xfer_stat(struct file_download_ctx* ctx, int64_t downloaded, int64_t to_download) {
    int64_t dl_diff = 0;

    /* This is not considered as error, ctx or cluster == NULL if we do not want to check progress */
    if(!ctx || !sxi_cluster_get_xfer_stat(ctx->cluster))
        return SXE_NOERROR;

    ctx->to_dl = to_download;
    dl_diff = downloaded - ctx->dl;
    ctx->dl = downloaded;
    if(dl_diff > 0)
        return set_xfer_stat(sxi_cluster_get_xfer_stat(ctx->cluster), dl_diff);
    else 
        return SXE_NOERROR;
}

/* Get numner of bytes to be downloaded */
int64_t sxi_file_download_get_xfer_to_send(const struct file_download_ctx *ctx) {
    if(!ctx || !sxi_cluster_get_xfer_stat(ctx->cluster))
        return 0;

    return ctx->to_dl;
}

/* Get number of bytes already downloaded */
int64_t sxi_file_download_get_xfer_sent(const struct file_download_ctx *ctx) {
    if(!ctx || !sxi_cluster_get_xfer_stat(ctx->cluster)) 
        return 0;

    return ctx->dl;
}


static int process_block(sxi_conns_t *conns, curlev_context_t *cctx)
{
    unsigned j;
    struct hash_down_data_t *hashdata;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct file_download_ctx *ctx = sxi_cbdata_get_download_ctx(cctx);

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
/*            SXDEBUG("writing hash%d @%lld - %lld",i,
                (long long)hashdata->offsets[j], (long long)hashdata->offsets[j] + writesz);*/
        if(pwrite_all(ctx->fd, ctx->buf, writesz, hashdata->offsets[j])) {
            sxi_setsyserr(sx, SXE_EWRITE, "write");
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
    int status;

    sxi_md_cleanup(&ctx->ctx);
    status = sxi_cbdata_result(cctx, NULL);
    if (status== 200 && ctx->dldblks)
        (*ctx->dldblks) += ctx->hashes.i;
    SXDEBUG("finished %d hashes with code %d", ctx->hashes.i, status);
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

static int hashes_to_download(sxc_file_t *source, FILE **tf, char **tfname, unsigned int *blocksize, int64_t *filesize, sxc_meta_t *vmeta) {
    char *enc_vol = NULL, *enc_path = NULL, *url = NULL, *hsfname = NULL;
    struct cb_getfile_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxi_hostlist_t volnodes;
    sxc_client_t *sx = source->sx;
    int ret = 1;

    memset(&yctx, 0, sizeof(yctx));
    sxi_hostlist_init(&volnodes);
    if (path_is_root(source->path)) {
        sxi_seterr(source->sx, SXE_EARG, "Invalid path");
        goto hashes_to_download_err;
    }
    if(sxi_volume_info(source->cluster, source->volume, &volnodes, NULL, vmeta)) {
	SXDEBUG("failed to locate destination file");
	goto hashes_to_download_err;
    }

    if(!(enc_vol = sxi_urlencode(source->sx, source->volume, 0))) {
	SXDEBUG("failed to encode volume %s", source->volume);
	goto hashes_to_download_err;
    }

    if(!(enc_path = sxi_urlencode(source->sx, source->path, 0))) {
	SXDEBUG("failed to encode path %s", source->path);
	goto hashes_to_download_err;
    }

    url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + 1);
    if(!url) {
	SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve the blocks to download: Out of memory");
	goto hashes_to_download_err;
    }
    sprintf(url, "%s/%s", enc_vol, enc_path);

    if(!(hsfname = sxi_tempfile_track(source->sx, NULL, &yctx.f))) {
	SXDEBUG("failed to generate results file");
	goto hashes_to_download_err;
    }

    ya_init(yacb);
    yacb->yajl_start_map = yacb_getfile_start_map;
    yacb->yajl_map_key = yacb_getfile_map_key;
    yacb->yajl_number = yacb_getfile_number;
    yacb->yajl_start_array = yacb_getfile_start_array;
    yacb->yajl_string = yacb_getfile_string;
    yacb->yajl_end_array = yacb_getfile_end_array;
    yacb->yajl_end_map = yacb_getfile_end_map;

    yctx.yh = NULL;

    sxi_set_operation(sx, "download file content hashes", sxi_cluster_get_name(source->cluster), source->volume, source->path);
    if(sxi_cluster_query(sxi_cluster_get_conns(source->cluster), &volnodes, REQ_GET, url, NULL, 0, getfile_setup_cb, getfile_cb, &yctx) != 200) {
	SXDEBUG("file get query failed");
	goto hashes_to_download_err;
    }
    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != GF_COMPLETE) {
        if (yctx.state != GF_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Failed to retrieve the blocks to download: Communication error");
        }
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
    ret = 0;

hashes_to_download_err:
    if(yctx.yh)
	yajl_free(yctx.yh);

    free(url);
    if(ret) {
	if(hsfname) {
	    if(yctx.f)
		fclose(yctx.f);
	    unlink(hsfname);
	    sxi_tempfile_untrack(sx, hsfname);
	}
    }
    sxi_hostlist_empty(&volnodes);
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
    if (!ctx)
        return NULL;
    ctx->ctx = mdctx;
    ctx->dl = 0;
    ctx->cluster = NULL;
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
    dctx->buf = malloc(blocksize);
    if (!dctx->buf) {
        cluster_err(SXE_EMEM, "failed to allocate buffer");
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
    sxi_set_operation(sx, "download file contents", NULL, NULL, NULL);
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
    unsigned int host_retry;
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
    sxi_retry_t *retry = NULL;

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
    retry = sxi_retry_init(sx);
    if (!retry) {
        cluster_err(SXE_EMEM, "Cannot allocate retry");
        free(buf);
        return 1;
    }

    for(host_retry=0;retry && requested;host_retry++) {
      unsigned i;
      unsigned loop = 0;
      unsigned outstanding=0;

      /* save&clear previous errors */
      sxi_retry_check(retry, host_retry);
      /* then grab by hash */
      CFGDEBUG("hash retrieve loop #%d", host_retry);
      hostsmap = sxi_ht_new(sxi_cluster_get_client(cluster), 128);
      if (!hostsmap) {
          cluster_err(SXE_EMEM, "Cannot allocate hosts hash");
          break;
      }
      requested = finished = transferred = 0;
      for (i=0;i<bh->i;i++) {
        unsigned dctxn;
        hashdata = &bh->hashdata[i];
        hash = hashdata->hash;
	loop++;
        if (hashdata->state == TRANSFER_PENDING || hashdata->state == TRANSFER_NOT_NECESSARY ||
            hashdata->state == 200)
            continue;
        hostcount = sxi_hostlist_get_count(&hashdata->hosts);
        if (hostcount <= host_retry) {
            CFGDEBUG("All hosts have failed for hash %.*s!", 40, hash);
            break;
        }
        host = sxi_hostlist_get_host(&hashdata->hosts, host_retry);
        if (!host) {
            CFGDEBUG("Ran out of hosts for hash: (last HTTP code %ld)", hashdata->state);
            /* TODO: set err and break */
            break;
        }
        hashdata->state = TRANSFER_PENDING;
        sxi_set_operation(sx, "file block download", NULL, NULL, NULL);
        sxi_retry_msg(retry, host);

        if (!host_retry) {
            int rc = check_block(cluster, bh->hashes, zerohash, hash, hashdata, fd, filesize, buf, blocksize);
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
                if(xfer_stat && skip_xfer(cluster, blocksize * hashdata->ocnt) != SXE_NOERROR) {
                    CFGDEBUG("Could not skip %u bytes of transfer", blocksize * hashdata->ocnt);
                    sxi_seterr(sx, SXE_ABORT, "Could not skip %u bytes of transfer", blocksize * hashdata->ocnt);
                    break;
                }

                continue;/* we've got the hash */
            }
        }

        if (sxi_ht_get(hostsmap, host, strlen(host)+1, (void**)&cbdata)) {
            /* host not found -> new host */
            dctx = dctx_new(sx);
            if (!dctx) {
                cluster_err(SXE_EMEM, "Cannot download file: Out of emory");
                break;
            }
            cbdata = sxi_cbdata_create_download(conns, gethash_finish, dctx);
            if (!cbdata) {
                cluster_err(SXE_EMEM, "Cannot download file: Out of memory");
                dctx_free(dctx);
                break;
            }
            dctx->buf = malloc(blocksize);
            if (!dctx->buf) {
                cluster_err(SXE_EMEM, "Cannot allocate buffer");
                sxi_cbdata_unref(&cbdata);
                /* dctx_free(dctx) ?? */
                break;
            }
            dctx->fd = fd;
            dctx->filesize = filesize;
            dctx->skip = -1;
            dctx->dldblks = &transferred;
            dctx->queries_finished = &finished;
            dctx->blocksize = blocksize;
            dctx->hashes.hashes = bh->hashes; 
        } else
            dctx = sxi_cbdata_get_download_ctx(cbdata);

        if(dctx)
            dctx->cluster = cluster;
        if (!dctx)
            break;

/*        snprintf(url, sizeof(url), ".data/%u/%.*s", blocksize, 40, hash);*/
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
    }

    if (sxi_retry_done(&retry))
        CFGDEBUG("retry_done failed");
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
static int remote_to_local(sxc_file_t *source, sxc_file_t *dest) {
    char *hashfile = NULL, *tempdst = NULL, *tempfilter = NULL;
    sxi_ht *hosts = NULL;
    struct hash_down_data_t *hashdata;
    uint8_t *buf = NULL;
    sxc_client_t *sx = source->sx;
    struct stat st;
    int64_t filesize;
    int ret = 1, rd = -1, d = -1, fail = 0;
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
    sxc_meta_t *vmeta = NULL;
    sxc_meta_t *fmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;
    struct batch_hashes bh;

    memset(&bh, 0, sizeof(bh));
    if(!(vmeta = sxc_meta_new(sx)))
	return 1;
    if(hashes_to_download(source, &hf, &hashfile, &blocksize, &filesize, vmeta)) {
	SXDEBUG("failed to retrieve hash list");
	goto remote_to_local_err;
    }

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

    if(!(hosts = sxi_ht_new(dest->sx, INITIAL_HASH_ITEMS))) {
	SXDEBUG("failed to create hosts table");
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

	confdir = sxi_cluster_get_confdir(source->cluster);
	if(confdir) {
	    filter_cfgdir = get_filter_dir(sx, confdir, filter_uuid, source->volume);
	    if(!filter_cfgdir)
		goto remote_to_local_err;
	}

	if(tempdst && fh->f->data_prepare) {
	    if(fh->f->data_prepare(fh, &fh->ctx, source->path, filter_cfgdir, cfgval, cfgval_len, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
		goto remote_to_local_err;
	    }
	}

	fmeta = sxc_filemeta_new(source);
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
			    done = write(rd, outbuff, done);
			    if(done < 0) {
				if(errno == EINTR)
				    continue;
				SXDEBUG("Failed to write output file");			
				sxi_setsyserr(sx, SXE_EWRITE, "Download failed: Cannot write to output file");
				fail = 1;
				break;
			    }
			} while(action == SXF_ACTION_REPEAT);
			got = 0;
		    } else {
			done = write(rd, buff, got);
			if(done < 0) {
			    if(errno == EINTR)
				continue;
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
	    if(fh->f->data_prepare(fh, &fh->ctx, source->path, filter_cfgdir, cfgval, cfgval_len, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
		fclose(tempfile);
		goto remote_to_local_err;
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
	fclose(tempfile);
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
	    if(file_to_file(sx, tempfilter, dest->path))
		goto remote_to_local_err;
	    unlink(tempfilter);
	}
	sxi_tempfile_untrack(sx, tempfilter);
	tempfilter = NULL;
    }

    if(fh && fh->f->file_process && fmeta) {
	if(dstexisted && stat(dest->path, &st) == -1) {
	    sxi_setsyserr(sx, SXE_EREAD, "failed to stat destination file %s", dest->path);
	    goto remote_to_local_err;
	}
	if(!dstexisted || (S_ISREG(st.st_mode) && st.st_uid == getuid())) {
	    if(fh->f->file_process(fh, fh->ctx, dest->path, fmeta, filter_cfgdir, cfgval, cfgval_len, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to process destination file", filter_uuid);
		goto remote_to_local_err;
	    }
	}
    }

    if(getenv("SX_DEBUG_DELAY")) sleep(atoi(getenv("SX_DEBUG_DELAY")));

    ret = 0;

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

    sxc_meta_free(vmeta);
    sxc_meta_free(fmeta);
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

struct hash_fastcopy_data_t {
    sxi_hostlist_t src_hosts;
    sxi_hostlist_t dst_hosts;
};

static sxi_job_t* remote_to_remote_fast(sxc_file_t *source, sxc_meta_t *fmeta, sxc_file_t *dest) {
    char *src_hashfile, *dst_hashfile = NULL, *rcur, ha[42];
    sxi_ht *src_hashes = NULL, *dst_hashes = NULL, *dst_hosts = NULL;
    struct hash_fastcopy_data_t *hashdata;
    sxc_client_t *sx = source->sx;
    struct file_upload_ctx yctx;
    yajl_callbacks *yacb = &yctx.current.yacb;
    unsigned int blocksize;
    sxi_hostlist_t volhosts, flushost;
    int64_t filesize;
    uint8_t *buf = NULL;
    FILE *hf;
    sxi_query_t *query = NULL;
    sxi_job_t *job = NULL;

    sxi_hostlist_init(&volhosts);
    sxi_hostlist_init(&flushost);
    memset(&yctx, 0, sizeof(yctx));

    if(hashes_to_download(source, &hf, &src_hashfile, &blocksize, &filesize, NULL)) {
	SXDEBUG("failed to retrieve hash list");
	return NULL;
    }

    query = sxi_fileadd_proto_begin(dest->sx, dest->volume, dest->path, NULL, 0, blocksize, filesize);
    if(!query)
	goto remote_to_remote_fast_err;

    if(!(src_hashes = sxi_ht_new(source->sx, filesize / blocksize))) {
	SXDEBUG("failed to create source hashtable for %u entries", (unsigned)(filesize / blocksize));
	goto remote_to_remote_fast_err;
    }

    while(!feof(hf)) {
	long *hoff;
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
	    *hoff = ftell(hf);
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
	    if(!fread(ho, sz, 1, hf)) {
		SXDEBUG("failed to read host");
		sxi_setsyserr(sx, SXE_ETMP, "Transfer failed: Failed to read from cache file");
		goto remote_to_remote_fast_err;
	    }
	}
    }

    query = sxi_fileadd_proto_end(dest->sx, query, fmeta);
    if(!query)
	goto remote_to_remote_fast_err;

    if(sxi_locate_volume(dest->cluster, dest->volume, &volhosts, NULL)) {
	SXDEBUG("failed to locate destination file");
	goto remote_to_remote_fast_err;
    }

    if(!(dst_hashfile = sxi_tempfile_track(dest->sx, NULL, &yctx.current.f))) {
	SXDEBUG("failed to generate results file");
	goto remote_to_remote_fast_err;
    }
    ya_init(yacb);
    yacb->yajl_start_map = yacb_createfile_start_map;
    yacb->yajl_map_key = yacb_createfile_map_key;
    yacb->yajl_number = yacb_createfile_number;
    yacb->yajl_start_array = yacb_createfile_start_array;
    yacb->yajl_string = yacb_createfile_string;
    yacb->yajl_end_array = yacb_createfile_end_array;
    yacb->yajl_end_map = yacb_createfile_end_map;

    yctx.current.yh = NULL;
    yctx.blocksize = blocksize;
    yctx.name = strdup(dest->path);

    sxi_set_operation(sxi_cluster_get_client(dest->cluster), "upload file content hashes",
                      sxi_cluster_get_name(dest->cluster), dest->volume, dest->path);
    curlev_context_t *cbdata = sxi_cbdata_create_upload(sxi_cluster_get_conns(dest->cluster), NULL, &yctx);
    if (!cbdata)
        goto remote_to_remote_fast_err;
    if(sxi_cluster_query_ev_retry(cbdata, sxi_cluster_get_conns(dest->cluster), &volhosts, query->verb, query->path, query->content, query->content_len, createfile_setup_cb, createfile_cb, NULL)) {
	SXDEBUG("file create query failed");
	goto remote_to_remote_fast_err;
    }
    sxi_cbdata_wait(cbdata, sxi_conns_get_curlev(sxi_cluster_get_conns(dest->cluster)), NULL);
    if (sxi_cbdata_result(cbdata, NULL) != 200) {
	SXDEBUG("file create query failed");
	goto remote_to_remote_fast_err;
    }
    sxi_cbdata_unref(&cbdata);
    sxi_query_free(query);
    query = NULL;

    if(yajl_complete_parse(yctx.current.yh) != yajl_status_ok || yctx.current.state != CF_COMPLETE) {
	SXDEBUG("JSON parsing failed");
	sxi_seterr(sx, SXE_ECOMM, "Transfer failed: Communication error");
	goto remote_to_remote_fast_err;
    }

    if(yctx.current.yh)
	yajl_free(yctx.current.yh);
    yctx.current.yh = NULL;

    if(!(buf = malloc(blocksize))) {
	SXDEBUG("OOM allocating the block buffer (%u bytes)", blocksize);
	sxi_seterr(sx, SXE_EMEM, "Transfer failed: Out of memory");
	goto remote_to_remote_fast_err;
    }

    if(!(dst_hashes = sxi_ht_new(dest->sx, INITIAL_HASH_ITEMS))) {
	SXDEBUG("failed to create dest hashtable");
	goto remote_to_remote_fast_err;
    }

    if(!(dst_hosts = sxi_ht_new(dest->sx, INITIAL_HASH_ITEMS))) {
	SXDEBUG("failed to create hosts table");
	goto remote_to_remote_fast_err;
    }
    rewind(yctx.current.f);
    while(!feof(yctx.current.f)) {
	const char *cur_host;
	char *hash_list;
	unsigned int i;

	for(i=0;i<BLOCKS_PER_TABLE;i++) {
	    long *hfoff;

	    if(!fread(ha, 40, 1, yctx.current.f))
		break;

	    if(sxi_ht_get(dst_hashes, ha, 40, NULL)) {
		hashdata = malloc(sizeof(*hashdata));
		if(!hashdata) {
		    SXDEBUG("OOM allocating hash container");
		    sxi_seterr(sx, SXE_EMEM, "Transfer failed: Out of memory");
		    goto remote_to_remote_fast_err;
		}
		sxi_hostlist_init(&hashdata->src_hosts);
		sxi_hostlist_init(&hashdata->dst_hosts);
		if(sxi_ht_add(dst_hashes, ha, 40, hashdata)) {
		    SXDEBUG("failed to add hash %.40s to dest table", ha);
		    free(hashdata);
		    goto remote_to_remote_fast_err;
		}
		if(sxi_ht_get(src_hashes, ha, 40, (void **)&hfoff)) {
		    SXDEBUG("hash lookup failed for %.40s", ha);
		    sxi_seterr(sx, SXE_ECOMM, "Transfer failed: Unable to find hash");
		    goto remote_to_remote_fast_err;
		}
		fseek(hf, *hfoff, SEEK_SET);
		free(hfoff);
		sxi_ht_del(src_hashes, ha, 40);
		if(load_hosts_for_hash(sx, hf, ha, &hashdata->src_hosts, NULL)) {
		    SXDEBUG("failed to add src hosts for %.40s", ha);
		    goto remote_to_remote_fast_err;
		}
	    } else 
		hashdata = NULL;

	    if(load_hosts_for_hash(sx, yctx.current.f, ha, hashdata ? &hashdata->dst_hosts : NULL, dst_hosts)) {
		SXDEBUG("failed to load dest hosts for %.40s", ha);
		goto remote_to_remote_fast_err;
	    }
	}

	sxi_ht_enum_reset(dst_hosts);
	while(!sxi_ht_enum_getnext(dst_hosts, (const void **)&cur_host, &i, (const void **)&hash_list)) {
	    char *curhash;
	    for(curhash = hash_list; *curhash; curhash += 40) {
		if(sxi_ht_get(dst_hashes, curhash, 40, (void **)&hashdata))
		    continue;

		if(download_block_to_buf(source->cluster, &hashdata->src_hosts, curhash, buf, blocksize)) {
		    SXDEBUG("failed to download hash %.40s", curhash);
		    goto remote_to_remote_fast_err;
		}

		if(sxi_upload_block_from_buf(sxi_cluster_get_conns(dest->cluster), &hashdata->dst_hosts, yctx.current.token, buf, blocksize, blocksize)) {
		    SXDEBUG("failed to upload hash %.40s", curhash);
		    goto remote_to_remote_fast_err;
		}

		sxi_hostlist_empty(&hashdata->src_hosts);
		sxi_hostlist_empty(&hashdata->dst_hosts);
		free(hashdata);
		sxi_ht_del(dst_hashes, curhash, 40);
	    }

	    free(hash_list);
	    sxi_ht_del(dst_hosts, cur_host, i);
	}
    }

    if (!(job = flush_file_ev(dest->cluster, yctx.host, yctx.current.token, yctx.name, NULL)))
	goto remote_to_remote_fast_err;

remote_to_remote_fast_err:
    if(dst_hosts) {
	sxi_ht_enum_reset(dst_hosts);
	while(!sxi_ht_enum_getnext(dst_hosts, NULL, NULL, (const void **)&rcur))
	    free(rcur);
	sxi_ht_free(dst_hosts);
    }

    if(dst_hashes) {
	sxi_ht_enum_reset(dst_hashes);
	while(!sxi_ht_enum_getnext(dst_hashes, NULL, NULL, (const void **)&hashdata)) {
	    sxi_hostlist_empty(&hashdata->src_hosts);
	    sxi_hostlist_empty(&hashdata->dst_hosts);
	    free(hashdata);
	}
	sxi_ht_free(dst_hashes);
    }

    if(src_hashes) {
	sxi_ht_enum_reset(src_hashes);
	while(!sxi_ht_enum_getnext(src_hashes, NULL, NULL, (const void **)&rcur))
	    free(rcur);
	sxi_ht_free(src_hashes);
    }

    free(buf);

    free(yctx.name);
    free(yctx.current.token);
    if(yctx.current.yh)
	yajl_free(yctx.current.yh);

    if(dst_hashfile) {
	fclose(yctx.current.f);
	unlink(dst_hashfile);
	sxi_tempfile_untrack(sx, dst_hashfile);
    }

    sxi_query_free(query);

    if (hf)
        fclose(hf);
    unlink(src_hashfile);
    sxi_tempfile_untrack(sx, src_hashfile);
    sxi_hostlist_empty(&flushost);
    sxi_hostlist_empty(&volhosts);
    return job;
}

static sxi_job_t* remote_to_remote(sxc_file_t *source, sxc_file_t *dest) {
    const char *suuid=sxc_cluster_get_uuid(source->cluster), *duuid=sxc_cluster_get_uuid(dest->cluster);
    sxc_client_t *sx = source->sx;
    sxc_file_t *cache;
    char *tmpname;
    int nofast = 0;
    sxc_meta_t *fmeta;
    sxi_job_t *ret = NULL;
    FILE *f;

    if(!suuid || !duuid) {
	SXDEBUG("internal error / invalid config");
	return NULL;
    }

    if(strcmp(source->volume, dest->volume)) {
	const void *mval;
	unsigned int mval_len;
	sxc_meta_t *vmeta = sxc_volumemeta_new(source);

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
	    vmeta = sxc_volumemeta_new(dest);
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

    fmeta = sxc_filemeta_new(source);
    if(!fmeta)
	return NULL;

    if(!nofast && !strcmp(suuid, duuid)) {
	ret = remote_to_remote_fast(source, fmeta, dest);
	sxc_meta_free(fmeta);
	return ret;
    }

    if(!(tmpname = sxi_tempfile_track(dest->sx, NULL, &f))) {
	SXDEBUG("failed to create local cache file");
	sxc_meta_free(fmeta);
	return NULL;
    }
    fclose(f);

    if(!(cache = sxc_file_local(source->sx, tmpname)))
	goto remote_to_remote_err;

    if(remote_to_local(source, cache)) {
	SXDEBUG("failed to download source file");
	goto remote_to_remote_err;
    }

    if(local_to_remote_begin(cache, fmeta, dest, 0)) {
	SXDEBUG("failed to upload destination file");
	goto remote_to_remote_err;
    }
    ret = dest->job;

remote_to_remote_err:
    sxc_meta_free(fmeta);
    sxc_file_free(cache);
    unlink(tmpname);
    sxi_tempfile_untrack(sx, tmpname);
    return ret;
}

static int mkdir_parents(sxc_client_t *sx, const char *path);
static sxi_job_t* remote_copy_ev(sxc_file_t *pattern, sxc_file_t *source, sxc_file_t *dest, int recursive, unsigned int *errors)
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
            ret = remote_to_local(source, dest);
        if (sxc_geterrnum(source->sx) != SXE_NOERROR) {
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
       job = remote_to_remote(source, dest);
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
    ret = sxi_mkdir_hier(sx, parent);
    free(parent);
    return ret;
}

static int remote_iterate(sxc_file_t *source, int recursive, int onefs, sxc_file_t *dest);
int sxc_copy(sxc_file_t *source, sxc_file_t *dest, int recursive, int onefs) {
    int ret;
    sxc_xfer_stat_t *xfer_stat = NULL;
    sxc_cluster_t *remote_cluster = NULL;

/* FIXME: Drop this code if there are no side effects of turning it off
    if (!is_remote(dest)) {
        struct stat sb;
	if(recursive) {
	    if(sxc_file_require_dir(dest))
		return 1;
	} else if (dest->path && ends_with(dest->path, '/')) {
            if (stat(dest->path, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
                sxi_seterr(source->sx, SXE_EARG, "'%s' must be an existing directory", dest->path);
                return 1;
            }
	    if(access(dest->path, X_OK | W_OK)) {
                sxi_seterr(source->sx, SXE_EARG, "Cannot access %s", dest->path);
                return 1;
            }
        }
    }
*/

    if(!is_remote(source)) {
	if(!is_remote(dest)) {
            if (dest->cat_fd > 0) {
                ret = cat_local_file(source, dest->cat_fd);
            } else {
                ret = maybe_append_path(dest, source, 0);
                if (!ret)
                    ret = local_to_local(source, dest);
                if (restore_path(dest))
                    ret = 1;
            }
        } else {
            if (!(source->origpath = strdup(source->path))) {
                sxi_setsyserr(source->sx, SXE_EMEM, "Cannot dup path");
                ret = 1;
            } else 
                ret = local_to_remote_iterate(source, recursive, 0, onefs, dest);
        }
    } else {
        ret = remote_iterate(source, recursive, onefs, dest);
    }

    if(is_remote(dest)) {
        remote_cluster = dest->cluster;
    } else {
        if(is_remote(source)) {
            remote_cluster = source->cluster;
        }
    }
    xfer_stat = sxi_cluster_get_xfer_stat(remote_cluster);
    if(xfer_stat && sxc_geterrnum(source->sx) != SXE_ABORT) {
        xfer_stat->status = (ret ? SXC_XFER_STATUS_FINISHED_ERROR : SXC_XFER_STATUS_FINISHED);
        if(xfer_stat->xfer_callback(xfer_stat) != SXE_NOERROR) {
            sxi_seterr(source->sx, SXE_ABORT, "Transfer aborted");
            ret = 1;
        }
    }

    return ret;
}

static int cat_remote_file(sxc_file_t *source, int dest) {
    char *hashfile, ha[42];
    uint8_t *buf, *fbuf = NULL;
    sxi_hostlist_t hostlist;
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
    sxc_meta_t *vmeta = NULL;
    const void *mval;
    unsigned int mval_len;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;

    sxi_hostlist_init(&hostlist);
    if(hashes_to_download(source, &hf, &hashfile, &blocksize, &filesize, NULL)) {
	SXDEBUG("failed to retrieve hash list");
	return 1;
    }

    if(!(buf = malloc(blocksize))) {
	SXDEBUG("OOM allocating the block buffer (%u bytes)", blocksize);
	sxi_seterr(sx, SXE_ECOMM, "Download failed: Out of memory");
	goto sxc_cat_fail;
    }

    vmeta = sxc_volumemeta_new(source);
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
	confdir = sxi_cluster_get_confdir(source->cluster);
	if(confdir) {
	    filter_cfgdir = get_filter_dir(sx, confdir, filter_uuid, source->volume);
	    if(!filter_cfgdir)
		goto sxc_cat_fail;
	}

	if(fh->f->data_prepare) {
	    if(fh->f->data_prepare(fh, &fh->ctx, source->path, filter_cfgdir, cfgval, cfgval_len, SXF_MODE_DOWNLOAD)) {
		sxi_seterr(sx, SXE_EFILTER, "Filter ID %s failed to initialize itself", filter_uuid);
		goto sxc_cat_fail;
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
		if(write(dest, fbuf, bwrite) != bwrite) {
		    sxi_setsyserr(sx, SXE_EWRITE, "Filter failed: Can't write to fd %d", dest);
		    if(fh->f->data_finish)
			fh->f->data_finish(fh, &fh->ctx, SXF_MODE_DOWNLOAD);
		    goto sxc_cat_fail;
		}
	    } while(action == SXF_ACTION_REPEAT);
	} else {
	    while(todo) {
		ssize_t done;
		done = write(dest, wbuf, todo);
		if(done < 0) {
		    if(errno == EINTR)
			continue;
		    sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to fd %d", dest);
		    break;
		}
		todo -= done;
		wbuf += done;
	    }

	    if(todo)
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
    free(fbuf);
    if (hf)
        fclose(hf);
    free(filter_cfgdir);
    unlink(hashfile);
    sxi_tempfile_untrack(sx, hashfile);
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

    while(1) {
	ssize_t got = read(src, buf, sizeof(buf));
	char *curbuf;
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

	curbuf = buf;
	while(got) {
	    ssize_t wrote = write(dest, curbuf, got);
	    if(wrote < 0) {
		if(errno == EINTR)
		    continue;
		SXDEBUG("failed to write to output stream");
		sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to output stream");
		close(src);
		return 1;
	    }
	    got -= wrote;
	    curbuf += wrote;
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
        rc = sxc_copy(source, destfile, 0, 0);
    sxc_file_free(destfile);
    return rc;
}

struct cb_filemeta_ctx {
    sxc_client_t *sx;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    sxc_meta_t *meta;
    yajl_callbacks yacb;
    char *nextk;
    enum filemeta_state { FM_ERROR, FM_BEGIN, FM_FM, FM_ITEMS, FM_KEY, FM_VAL, FM_DONE, FM_COMPLETE } state;
};

/* {"fileMeta":{"key1":"value1", "key2":"value2"}} */

static int yacb_filemeta_start_map(void *ctx) {
    struct cb_filemeta_ctx *yactx = (struct cb_filemeta_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state != FM_BEGIN && yactx->state != FM_ITEMS) {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
    yactx->state++;
    return 1;
}

static int yacb_filemeta_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_filemeta_ctx *yactx = (struct cb_filemeta_ctx *)ctx;

    if (yactx->state == FM_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == FM_FM) {
        if (ya_check_error(yactx->sx, &yactx->errctx, s, l)) {
            yactx->state = FM_ERROR;
            return 1;
        }
    }
    if(yactx->state == FM_FM) {
	yactx->state++;
	if(l != lenof("fileMeta") || memcmp(s, "fileMeta", lenof("fileMeta"))) {
	    CBDEBUG("expected fileMeta, recevived %.*s", (int)l, s);
	    return 0;
	}
	return 1;
    }

    if(yactx->state != FM_KEY) {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }

    if(yactx->nextk) {
	CBDEBUG("called out of order");
	return 0;
    }
    yactx->nextk = malloc(l+1);
    if(!yactx->nextk) {
	CBDEBUG("OOM duplicating meta key");
	sxi_seterr(yactx->sx, SXE_EMEM, "Out of memory");
	return 0;
    }
    memcpy(yactx->nextk, s, l);
    yactx->nextk[l] = '\0';
    yactx->state++;

    return 1;
}


static int yacb_filemeta_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_filemeta_ctx *yactx = (struct cb_filemeta_ctx *)ctx;
    unsigned int binlen = l / 2;
    void *value;

    if (yactx->state == FM_ERROR)
	return yacb_error_string(&yactx->errctx, s, l);
    if(yactx->state != FM_VAL) {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }

    if(!yactx->nextk) {
	CBDEBUG("called out of order");
	return 0;
    }

    value = malloc(binlen);
    if(!value) {
	CBDEBUG("OOM duplicating meta value");
	sxi_seterr(yactx->sx, SXE_EMEM, "Out of memory");
	return 0;
    }

    if(sxi_hex2bin((const char *)s, l, value, binlen)) {
	CBDEBUG("received bad hex value %.*s", (int)l, s);
	free(value);
	return 0;
    }

    if(sxc_meta_setval(yactx->meta, yactx->nextk, value, binlen)) {
	CBDEBUG("failed to add key to list");
	free(value);
	return 0;
    }

    free(value);
    free(yactx->nextk);
    yactx->nextk = NULL;

    yactx->state--;
    return 1;
}

static int yacb_filemeta_end_map(void *ctx) {
    struct cb_filemeta_ctx *yactx = (struct cb_filemeta_ctx *)ctx;

    if (yactx->state == FM_ERROR)
	return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == FM_KEY)
	yactx->state = FM_DONE;
    else if(yactx->state == FM_DONE)
	yactx->state = FM_COMPLETE;
    else {
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
    return 1;
}

static int filemeta_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_filemeta_ctx *yactx = (struct cb_filemeta_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->yh)
	yajl_free(yactx->yh);

    sxc_meta_empty(yactx->meta);
    free(yactx->nextk);
    yactx->nextk = NULL;

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("OOM allocating yajl context");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve the blocks to download: Out of memory");
	return 1;
    }

    yactx->sx = sx;
    yactx->state = FM_BEGIN;

    return 0;
}

static int filemeta_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_filemeta_ctx *yactx = (struct cb_filemeta_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
	if (yactx->state != FM_ERROR) {
	    CBDEBUG("failed to parse JSON data");
            sxi_seterr(sxi_conns_get_client(conns), SXE_ECOMM, "communication error");
        }
	return 1;
    }

    return 0;
}

sxc_meta_t *sxc_volumemeta_new(sxc_file_t *file) {
    sxi_hostlist_t volnodes;
    sxc_meta_t *meta = NULL;
    sxc_client_t *sx;

    if(!file)
	return NULL;
    sx = file->sx;
    if(!is_remote(file)) {
	sxi_seterr(sx, SXE_EARG, "Called with local file");
	return NULL;
    }

    if(!(meta = sxc_meta_new(sx)))
	return NULL;

    sxi_hostlist_init(&volnodes);
    if(sxi_volume_info(file->cluster, file->volume, &volnodes, NULL, meta)) {
	SXDEBUG("failed to locate volume");
	sxc_meta_free(meta);
	meta = NULL;
    }

    sxi_hostlist_empty(&volnodes);
    return meta;
}

sxc_meta_t *sxc_filemeta_new(sxc_file_t *file) {
    sxi_hostlist_t volnodes;
    sxc_client_t *sx;
    char *enc_vol = NULL, *enc_path = NULL, *url = NULL;
    struct cb_filemeta_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_meta_t *ret = NULL;

    if(!file)
	return NULL;
    sx = file->sx;
    if(!is_remote(file)) {
	sxi_seterr(sx, SXE_EARG, "Called with local file");
	return NULL;
    }

    memset(&yctx, 0, sizeof(yctx));
    sxi_hostlist_init(&volnodes);
    if(sxi_locate_volume(file->cluster, file->volume, &volnodes, NULL)) {
	SXDEBUG("failed to locate file");
	goto filemeta_begin_err;
    }

    if(!(enc_vol = sxi_urlencode(file->sx, file->volume, 0))) {
	SXDEBUG("failed to encode volume %s", file->volume);
	goto filemeta_begin_err;
    }

    if(!(enc_path = sxi_urlencode(file->sx, file->path, 0))) {
	SXDEBUG("failed to encode path %s", file->path);
	goto filemeta_begin_err;
    }

    url = malloc(strlen(enc_vol) + 1 + strlen(enc_path) + sizeof("?fileMeta"));
    if(!url) {
	SXDEBUG("OOM allocating url");
	sxi_seterr(sx, SXE_EMEM, "Failed to retrieve file metadata: Out of memory");
	goto filemeta_begin_err;
    }
    sprintf(url, "%s/%s?fileMeta", enc_vol, enc_path);
    free(enc_vol);
    free(enc_path);
    enc_vol = enc_path = NULL;

    ya_init(yacb);
    yacb->yajl_start_map = yacb_filemeta_start_map;
    yacb->yajl_map_key = yacb_filemeta_map_key;
    yacb->yajl_string = yacb_filemeta_string;
    yacb->yajl_end_map = yacb_filemeta_end_map;

    yctx.yh = NULL;
    yctx.nextk = NULL;
    yctx.meta = sxc_meta_new(sx);
    if(!yctx.meta)
	goto filemeta_begin_err;

    sxi_set_operation(sxi_cluster_get_client(file->cluster), "get file metadata",
                      sxi_cluster_get_name(file->cluster), file->volume, file->path);
    if(sxi_cluster_query(sxi_cluster_get_conns(file->cluster), &volnodes, REQ_GET, url, NULL, 0, filemeta_setup_cb, filemeta_cb, &yctx) != 200) {
	SXDEBUG("file get query failed");
	goto filemeta_begin_err;
    }

    ret = yctx.meta;
    yctx.meta = NULL;

 filemeta_begin_err:
    sxi_hostlist_empty(&volnodes);
    free(enc_vol);
    free(enc_path);
    free(url);
    if(yctx.yh)
	yajl_free(yctx.yh);
    free(yctx.nextk);
    if(yctx.meta)
	sxc_meta_free(yctx.meta);

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
    unsigned total;
    unsigned error;
    sxc_cluster_t *cluster;
    unsigned recursive;
    sxi_jobs_t jobs;
    int multi;
};


unsigned sxc_file_list_get_total(const sxc_file_list_t *lst)
{
    if (!lst)
        return 0;
    return lst->total;
}

unsigned sxc_file_list_get_successful(const sxc_file_list_t *lst)
{
    if (!lst)
        return 0;
    return sxi_jobs_get_successful(&lst->jobs);
}

sxc_file_list_t *sxc_file_list_new(sxc_client_t *sx, int recursive)
{
    sxc_file_list_t *lst = calloc(1, sizeof(*lst));
    if (!lst) {
        sxi_setsyserr(sx, SXE_EMEM, "Cannot allocate file list");
        return NULL;
    }
    lst->sx = sx;
    lst->recursive = recursive;
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
    if (!sxc_file_is_sx(file)) {
        sxi_seterr(lst->sx, SXE_EARG, "Can only process remote files in a filelist");
        return -1;
    }
    if (!lst->cluster) {
        lst->cluster = file->cluster;
    } else {
        const char *clust1 = sxi_cluster_get_name(lst->cluster);
        const char *clust2 = sxi_cluster_get_name(file->cluster);
        if (strcmp(clust1, clust2)) {
            sxi_seterr(lst->sx, SXE_EARG,"Cannot mix file lists from different clusters: %s and %s",
                       clust1, clust2);
            return -1;
        }
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
    if (allow_glob && !lst->recursive && !strchr(file->path, '*') && !strchr(file->path,'?'))
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
        free(lst);
    }
}

static sxi_job_t* sxi_file_list_process(sxc_file_list_t *target, sxc_file_t *pattern, sxc_cluster_t *cluster,
                                        file_list_cb_t cb, sxi_hostlist_t *hlist, const char *vol, const char *path,
                                        void *ctx)
{
    sxi_job_t *job = NULL;
    do {
        job = cb(target, pattern, cluster, hlist, vol, path, ctx);
        if (!job)
            target->total++;
    } while(0);
    return job;
}

static int sxi_file_list_foreach_wait(sxc_file_list_t *target, sxc_cluster_t *cluster)
{
    unsigned i;
    int ret;
    sxc_client_t *sx = target->sx;

    SXDEBUG("Waiting for %d jobs", target->jobs.n);
    ret = sxi_job_wait(sxi_cluster_get_conns(cluster), &target->jobs);
    for (i=0;i < target->jobs.n; i++) {
        sxi_job_free(target->jobs.jobs[i]);
    }
    free(target->jobs.jobs);
    target->jobs.jobs = NULL;
    return ret;
}

int sxi_file_list_foreach(sxc_file_list_t *target, sxc_cluster_t *wait_cluster, multi_cb_t multi_cb, file_list_cb_t cb, int need_locate, void *ctx)
{
    sxc_cluster_t *cluster;
    sxi_job_t *job;
    int rc = -1;
    unsigned i, j;
    if (!target)
        return -1;

    cluster = target->cluster;
    if (!target->n)
        return 0;
    if (!target->entries) {
        sxi_seterr(target->sx, SXE_EARG, "Entries is not initialized");
        return -1;
    }
    if (target->n > 1 && multi_cb && multi_cb(target, ctx)) {
        CFGDEBUG("multiple sources rejected by callback");
        return -1;
    }
    for (i=0;i<target->n;i++) {
        struct sxc_file_entry *entry = &target->entries[i];
        char *filename = NULL;
        sxc_file_t *pattern = entry->pattern;
        sxc_cluster_lf_t *lst = NULL;
        sxi_hostlist_t volhosts_storage;
        sxi_hostlist_t *volhosts = need_locate ? &volhosts_storage : NULL;

        if (volhosts)
            sxi_hostlist_init(volhosts);
        do {
            int64_t size;
            unsigned replica;
            struct timeval t0, t1;

            gettimeofday(&t0, NULL);

            if(volhosts && sxi_locate_volume(cluster, pattern->volume, volhosts, NULL)) {
                CFGDEBUG("failed to locate volume %s", pattern->volume);
                break;
            }
            if (!entry->glob) {
                job = sxi_file_list_process(target, pattern, cluster, cb, volhosts, pattern->volume, pattern->path, ctx);
                rc = sxi_jobs_add(target->sx, &target->jobs, job);
                break;
            }
            /* glob */
            CFGDEBUG("Listing using glob pattern '%s'", pattern->path);
            lst = sxc_cluster_listfiles(cluster, pattern->volume, pattern->path, target->recursive, &size, &replica, &entry->nfiles, 1);
            if (!lst) {
                CFGDEBUG("Cannot list files");
                break;
            }
            gettimeofday(&t1, NULL);
            /*sxi_info(target->sx, "Received list of %d files in %.1fs", entry->nfiles, sxi_timediff(&t1, &t0));*/
            CFGDEBUG("Glob pattern matched %d files", entry->nfiles);
            if (entry->nfiles > 1 && multi_cb && multi_cb(target, ctx)) {
                CFGDEBUG("multiple source file rejected by callback");
                break;
            }
            rc = 0;
            for (j=0;j<entry->nfiles && !rc;j++) {
                time_t t;
                if (sxc_cluster_listfiles_next(lst, &filename, &size, &t) <= 0) {
                    CFGDEBUG("Failed to list file %d/%d", j, entry->nfiles);
                    break;
                }
                CFGDEBUG("Processing file '%s/%s'", pattern->volume, filename);
                if (filename && *filename && filename[strlen(filename)-1] == '/')
                    continue;/* attempt to delete only files, not dirs */
                job = sxi_file_list_process(target, pattern, cluster, cb, volhosts, pattern->volume, filename, ctx);
                rc = sxi_jobs_add(target->sx, &target->jobs, job);
                free(filename);
                filename = NULL;
            }
            if (!entry->nfiles) {
                if (*pattern->path) {
                    sxi_seterr(target->sx, SXE_EARG, "%s/%s: Not found", pattern->volume, pattern->path);
                    rc = -1;
                }
            }
        } while(0);
        if (volhosts)
            sxi_hostlist_empty(volhosts);
        if (lst)
            sxc_cluster_listfiles_free(lst);
        if (rc)
            break;
    }
    if(sxi_file_list_foreach_wait(target, wait_cluster))
        rc = -1;
    return rc;
}

/* --- file list END ---- */

static sxi_job_t* sxi_rm_cb(sxc_file_list_t *target, sxc_file_t *pattern, sxc_cluster_t *cluster, sxi_hostlist_t *hlist, const char *vol, const char *path, void *ctx)
{
    sxi_query_t *query;
    sxi_job_t *job;
    int http_code;
    if (!cluster || !hlist || !vol || !path)
        return NULL;
    query = sxi_filedel_proto(target->sx, vol, path, NULL);
    if (!query)
        return NULL;
    sxi_set_operation(target->sx, "remove files", sxi_cluster_get_name(cluster), query->path, NULL);
    job = sxi_job_submit(sxi_cluster_get_conns(cluster), hlist, query->verb, query->path, path, NULL, 0, &http_code, &target->jobs);
    if (!job && http_code == 404)
        job = &JOB_NONE;
    sxi_query_free(query);
    return job;
}

int sxc_rm(sxc_file_list_t *target) {
    if (!target)
        return -1;
    sxc_clearerr(target->sx);
    return sxi_file_list_foreach(target, target->cluster, NULL, sxi_rm_cb, 1, NULL);
}

struct remote_iter {
    sxc_file_t *dest;
    int recursive;
    unsigned int errors;
};

static int different_file(const char *path1, const char *path2)
{
    while (*path1 == '/') path1++;
    while (*path2 == '/') path2++;
    return strcmp(path1, path2);
}

static sxi_job_t *remote_copy_cb(sxc_file_list_t *target, sxc_file_t *pattern, sxc_cluster_t *cluster, sxi_hostlist_t *hlist,
                                 const char *vol, const char *path, void *ctx)
{
    sxc_file_t source;
    sxc_client_t *sx = target->sx;
    struct remote_iter *it = ctx;
    sxi_job_t *ret;

    source.sx = sx;
    source.cluster = cluster;
    source.origpath = NULL;
    if (!(source.volume = strdup(vol))) {
        sxi_setsyserr(sx, SXE_EMEM, "cannot allocate volume name");
        return NULL;
    }
    if (!(source.path = strdup(path))) {
	free(source.volume);
        sxi_setsyserr(sx, SXE_EMEM, "cannot allocate path name");
        return NULL;
    }

    /* we could support parallelization for remote_to_remote and
     * remote_to_remote_fast if they would just return a job ... */
    ret = remote_copy_ev(pattern, &source, it->dest, it->recursive && different_file(source.path, pattern->path), &it->errors);
    free(source.volume);
    free(source.path);
    free(source.origpath);
    return ret;
}

int sxc_file_require_dir(sxc_file_t *file)
{
    struct stat sb;
    if (!file)
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
    } else if (file->path && strcmp(file->path, "/dev/stdout")) {
        sxi_seterr(file->sx, SXE_EARG, "target '%s' must be an existing directory", file->path);
        return -1;
    }
    return 0;
}

static int multi_cb(sxc_file_list_t *target, void *ctx)
{
    struct remote_iter *it = ctx;
    sxc_file_t *dest = it->dest;
    target->multi = 1;
    if (target->recursive && !is_remote(dest)) {
        if (mkdir(dest->path, 0700) == -1 && errno != EEXIST) {
            sxi_setsyserr(target->sx, SXE_EARG, "Cannot create directory '%s'", dest->path);
            return -1;
        }
    }
    return sxc_file_require_dir(dest);
}

static int remote_iterate(sxc_file_t *source, int recursive, int onefs, sxc_file_t *dest)
{
    sxc_file_list_t *lst;
    int ret;
    struct remote_iter it;

    it.dest = dest;
    it.recursive = recursive;
    it.errors = 0;

    lst = sxc_file_list_new(source->sx, recursive);
    if (!lst)
        return -1;
    if (sxc_file_list_add(lst, source, 1)) {
        ret = -1;
    } else {
        ret = sxi_file_list_foreach(lst, dest->cluster, multi_cb, remote_copy_cb, 0, &it);
        if (!ret) {
            /* create dest dir if successful list of empty volume */
            if (!is_remote(dest) && recursive && mkdir(dest->path, 0700) == -1 && errno != EEXIST) {
                sxi_setsyserr(source->sx, SXE_EARG, "Cannot create directory '%s'", dest->path);
                ret = 1;
            }
        }
        lst->entries[0].pattern = NULL;
    }

    sxc_file_list_free(lst);
    if(!ret && recursive && it.errors) {
	sxi_seterr(source->sx, SXE_EWRITE, "Failed to download %u file(s)", it.errors);
	return 1;
    }

    return ret;
}
