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
typedef struct _sxi_jobs_t {
    sxi_job_t **jobs;
    unsigned n;
    unsigned successful;
    struct timeval tv;
} sxi_jobs_t;

/* used where a sxi_job_t would be required but we're not job based */
extern sxi_job_t JOB_NONE;

sxi_job_t *sxi_job_submit(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb, const char *query, const char *name, void *content, size_t content_size, int *http_code, sxi_jobs_t *jobs);

void sxi_job_free(sxi_job_t *job);

int sxi_job_wait(sxi_conns_t *conn, sxi_jobs_t *jobs);

int sxi_job_submit_and_poll(sxi_conns_t *conns, sxi_hostlist_t *hlist, const char *query, void *content, size_t content_size);

/* Return number of successfully finished jobs */
unsigned sxi_jobs_get_successful(const sxi_jobs_t *jobs);

#endif
