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

#ifndef CURLEVENTS_DETAIL_H
#define CURLEVENTS_DETAIL_H
/* depends on curl.h, that is why it is split off from curlevents.h/cluster.h */
#include <openssl/evp.h>
#include "curlevents.h"
#include "cluster.h"
#include "misc.h"
#include "default.h"
#include "jobpoll.h"
struct hash_down_data_t;

typedef struct {
  sxi_ht *hashes;
  struct hash_down_data_t *hashdata[DOWNLOAD_MAX_BLOCKS];
  const char *hash[DOWNLOAD_MAX_BLOCKS];
  unsigned i;
  unsigned n;
  unsigned written;
} hashes_info_t;
struct cb_createfile_ctx;
#define ERRBUF_SIZE 512
struct curlev_context {
    sxi_conns_t *conns;
    const char *dstname;
    const char *url;
    void *context;
    cluster_datacb cb;
    char *reason;
    char errbuf[ERRBUF_SIZE+1];
    int cluster_uuid_ok;
    int fail;
    long reply_status;
    long finished;
    int rc;
    unsigned reasonsz;
    hashes_info_t hashes;
    int fd;
    off_t filesize;
    int skip;
    unsigned blocksize;
    finish_cb_t finish_callback;
    unsigned int *dldblks;
    unsigned int *queries_finished;
    const char *zerohash;
    const char *zerobuf;
    const char *host;
    EVP_MD_CTX ctx;
    unsigned char *buf;
    struct file_upload_ctx *yctx;
    struct host_upload_ctx *uctx;
    /* jobs to poll when we get throttled */
    sxi_jobs_t *jobs;
    finish_cb_t finish_callback_last;
    const sxi_hostlist_t *hlist;
    unsigned int hostidx;
    enum sxi_cluster_verb verb;
    char *query;
    void *content;
    size_t content_size;
    cluster_setupcb setup_callback;
    cluster_datacb data_callback;
    unsigned int retries;
    void *ctxretry;
};

#endif
