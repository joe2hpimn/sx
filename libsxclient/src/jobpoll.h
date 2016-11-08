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

#ifndef _JOBPOLL_H
#define _JOBPOLL_H

#include <sys/time.h>

typedef struct _sxi_job_t sxi_job_t;
typedef enum _jobstatus_t {
        JOBST_UNDEF,
        JOBST_ERROR,
        JOBST_OK,
        JOBST_PENDING
} sxi_job_status_t;
typedef struct _sxi_jobs_t sxi_jobs_t;

/* used where a sxi_job_t would be required but we're not job based */
extern sxi_job_t JOB_NONE;

/* Create a new jobs context */
sxi_jobs_t *sxi_jobs_new(sxc_client_t *sx, int ignore_errors);
/* Destroy jobs context */
void sxi_jobs_free(sxi_jobs_t *jobs);
/* Add a job to the context */
int sxi_jobs_add(sxi_jobs_t *jobs, sxi_job_t *job);

/* Get basic job statistics, when conns is provided return statistics only for particular cluster connection */
unsigned int sxi_jobs_total(const sxi_jobs_t *jobs, const sxi_conns_t *conns);
unsigned int sxi_jobs_errors(const sxi_jobs_t *jobs, const sxi_conns_t *conns);
unsigned int sxi_jobs_successful(const sxi_jobs_t *jobs, const sxi_conns_t *conns);
unsigned int sxi_jobs_pending(const sxi_jobs_t *jobs, const sxi_conns_t *conns);

/* Submit a new job, the job is not added to jobs context (use sxi_jobs_add()) */
sxi_job_t *sxi_job_submit(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb, const char *query, const char *name, void *content, size_t content_size, long *http_code, sxi_jobs_t *jobs);
/* Free the submitted job (use it directly only if the job has not been added to jobs context, sxi_jobs_free() will take care of it) */
void sxi_job_free(sxi_job_t *job);

/* Wait for all jobs. If conns is not NULL, wait only for jobs for a particular cluster */
int sxi_jobs_wait(sxi_jobs_t *jobs, sxi_conns_t *conns);

int sxi_job_submit_and_poll(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size);
int sxi_job_submit_and_poll_err(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size, long *http_err);

/* temporary notify filter hack */
typedef void (*nf_fn_t)(const sxf_handle_t *handle, void *ctx, const void *cfgdata, unsigned int cfgdata_len, sxf_mode_t mode, const char *source_cluster, const char *source_volume, const char *source_path, const char *dest_cluster, const char *dest_volume, const char *dest_path);

void sxi_job_set_nf(sxi_job_t *job, struct filter_handle *nf_fh, nf_fn_t nf_fn, const char *nf_src_path, const char *nf_dst_clust, const char *nf_dst_vol, const char *nf_dst_path);
const char *sxi_job_get_id(const sxi_job_t *job);
int sxi_job_query_ev(sxi_conns_t *conns, sxi_job_t *yres, unsigned *finished);
sxi_job_t *sxi_job_new(sxi_conns_t *conns, const char *id, enum sxi_cluster_verb verb, const char *host);
curlev_context_t *sxi_job_cbdata(const sxi_job_t *job);
sxi_job_status_t sxi_job_status(const sxi_job_t *job);
const char *sxi_job_message(const sxi_job_t *job);
curlev_context_t *sxi_job_submit_ev(sxi_conns_t *conns, const char *host, enum sxi_cluster_verb verb, const char *query, const char *name, void *content, size_t content_size);
sxi_job_t *sxi_job_submit_ev_wait(curlev_context_t *cbdata, long *http_status);

#endif
