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

#include "default.h"
#include <string.h>
#include <unistd.h>

#include "cluster.h"
#include "clustcfg.h"
#include "hostlist.h"
#include "jobpoll.h"
#include "curlevents.h"
#include "filter.h"
#include "jparse.h"

#define POLL_INTERVAL 30.0
#define PROGRESS_INTERVAL 6.0
#define JOB_POLL_MORE 1
#define JOB_POLL_MSG 2

struct job_ctx {
    unsigned *queries_finished;
    sxi_job_t *yactx;
};

struct _sxi_job_t {
    sxc_client_t *sx;
    jparse_t *J;
    enum sxi_cluster_verb verb;
    struct timeval last_reached;
    int fails;/* failed to get job status, i.e. failed to connect etc. */
    curlev_context_t *cbdata;
    struct job_ctx ctx;
    char *resquery;
    int poll_min_delay, poll_max_delay;
    char *job_host;
    char *message;
    char *name;
    char *job_id;
    unsigned finished;
    long http_err;
    sxi_job_status_t status;
    /* temporary notify filter hack */
    struct filter_handle *nf_fh;
    nf_fn_t nf_fn;
    char *nf_src_path, *nf_dst_clust, *nf_dst_vol, *nf_dst_path;
    enum sxc_error_t err;
};

/* Batch of jobs scheduled to one cluster */
struct jobs_batch {
    sxi_conns_t *conns;
    sxi_job_t **jobs;
    unsigned int length; /* Number of elements in jobs array */

    /* Counters */
    unsigned int total; /* Total number of jobs scheduled */
    unsigned int pending; /* Total number of running jobs */
    unsigned int successful; /* Number of successful jobs scheduled */
    unsigned int errors; /* Number of errors occured */

    /* Stores time of first job creation */
    struct timeval tv;
};

/* Stores list of jobs per cluster */
struct _sxi_jobs_t {
    sxc_client_t *sx;

    /* Stores a hashtable of job arrays (job batches per cluster) */
    sxi_ht *ht;

    /* Couters */
    unsigned int total; /* Total number of jobs scheduled */
    unsigned int pending; /* Total number of running jobs */
    unsigned int successful; /* Number of successful jobs */
    unsigned int errors; /* Number of jobs failed */

    /* Config */
    int ignore_errors;

    /* Stores time of first the structure creation */
    struct timeval created;
};

typedef enum { JOBS_NO_WAIT, JOBS_WAIT_ALL, JOBS_WAIT_SLOT } jobs_wait_kind_t;

sxi_jobs_t *sxi_jobs_new(sxc_client_t *sx, int ignore_errors) {
    sxi_jobs_t *jobs;

    jobs = calloc(1, sizeof(*jobs));
    if(!jobs) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    jobs->ht = sxi_ht_new(sx, 128);
    if(!jobs->ht) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        free(jobs);
        return NULL;
    }

    gettimeofday(&jobs->created, NULL);
    jobs->sx = sx;
    jobs->ignore_errors = ignore_errors;

    return jobs;
}

static void jobs_batch_free(struct jobs_batch *batch) {
    unsigned int i;

    if(!batch)
        return;
    for(i = 0; i < batch->length; i++)
        sxi_job_free(batch->jobs[i]);
    free(batch->jobs);
    free(batch);
}

void sxi_jobs_free(sxi_jobs_t *jobs) {
    const char *uuid = NULL;
    unsigned int uuid_len = 0;
    struct jobs_batch *batch = NULL;
    sxc_client_t *sx;

    if(!jobs)
        return;
    sx = jobs->sx;
    sxi_ht_enum_reset(jobs->ht);
    /* TODO: enum returns cons void**, it is modified with free, work it around. */
    while(!sxi_ht_enum_getnext(jobs->ht, (const void**)&uuid, &uuid_len, (const void**)&batch)) {
        if(!uuid || uuid_len != UUID_LEN || !batch)
            SXDEBUG("Invalid jobs hashtable content");
        jobs_batch_free(batch);
    }
    sxi_ht_free(jobs->ht);
    free(jobs);
}

unsigned int sxi_jobs_total(const sxi_jobs_t *jobs, const sxi_conns_t *conns) {
    sxc_client_t *sx;

    if(!jobs)
        return 0;
    sx = jobs->sx;

    if(conns) {
        struct jobs_batch *batch = NULL;

        if(!sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void**)&batch)) {
            if(!batch) {
                SXDEBUG("Invalid jobs hashtable content");
                return 0;
            }
            return batch->total;
        }
        SXDEBUG("No jobs for cluster %s", sxi_conns_get_uuid(conns));
    } else
        return jobs->total;
    return 0;
}

unsigned int sxi_jobs_successful(const sxi_jobs_t *jobs, const sxi_conns_t *conns) {
    sxc_client_t *sx;

    if(!jobs)
        return 0;
    sx = jobs->sx;

    if(conns) {
        struct jobs_batch *batch = NULL;

        if(!sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void**)&batch)) {
            if(!batch) {
                SXDEBUG("Invalid jobs hashtable content");
                return 0;
            }
            return batch->successful;
        }
        SXDEBUG("No jobs for cluster %s", sxi_conns_get_uuid(conns));
    } else
        return jobs->successful;
    return 0;
}

unsigned int sxi_jobs_errors(const sxi_jobs_t *jobs, const sxi_conns_t *conns) {
    sxc_client_t *sx;

    if(!jobs)
        return 0;
    sx = jobs->sx;

    if(conns) {
        struct jobs_batch *batch = NULL;

        if(!sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void**)&batch)) {
            if(!batch) {
                SXDEBUG("Invalid jobs hashtable content");
                return 0;
            }
            return batch->errors;
        }
        SXDEBUG("No jobs for cluster %s", sxi_conns_get_uuid(conns));
    } else
        return jobs->errors;
    return 0;
}

unsigned int sxi_jobs_pending(const sxi_jobs_t *jobs, const sxi_conns_t *conns) {
    sxc_client_t *sx;

    if(!jobs)
        return 0;
    sx = jobs->sx;

    if(conns) {
        struct jobs_batch *batch = NULL;

        if(!sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void**)&batch)) {
            if(!batch) {
                SXDEBUG("Invalid jobs hashtable content");
                return 0;
            }
            return batch->pending;
        }
        SXDEBUG("No jobs for cluster %s", sxi_conns_get_uuid(conns));
    } else
        return jobs->pending;
    return 0;
}

static int jobs_batch_add_job(struct jobs_batch *batch, sxi_job_t *job) {
    sxc_client_t *sx;
    unsigned int i;

    if(!batch)
        return 1;
    sx = sxi_conns_get_client(batch->conns);

    if(!job) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }
    for(i = 0; i < batch->length; i++) {
        if(!batch->jobs[i]) {
            SXDEBUG("Reusing existing slot for job %s", sxi_job_get_id(job));
            batch->jobs[i] = job;
            break;
        }
    }

    if(i >= batch->length) {
        unsigned int newlen = batch->length * 2;
        /* Could not find a slot for the job, make space for next jobs */
        batch->jobs = sxi_realloc(sx, batch->jobs, newlen * sizeof(*batch->jobs));
        if (!batch->jobs) {
            sxi_seterr(sx, SXE_EMEM, "Failed to allocate space for a new job");
            return 1;
        }
        memset(&batch->jobs[batch->length], 0, batch->length * sizeof(*batch->jobs));
        batch->jobs[batch->length] = job;
        batch->length = newlen;
    }

    batch->total++;
    batch->pending++;
    return 0;
}

static struct jobs_batch *jobs_batch_new(sxi_jobs_t *jobs, sxi_conns_t *conns) {
    struct jobs_batch *batch;
    sxc_client_t *sx;

    if(!conns)
        return NULL;
    sx = sxi_conns_get_client(conns);

    if(!jobs) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    batch = calloc(1, sizeof(*batch));
    if(!batch) {
        SXDEBUG("Failed to allocate jobs batch");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        return NULL;
    }

    batch->length = 16;
    batch->jobs = calloc(batch->length, sizeof(*batch->jobs));
    if(!batch->jobs) {
        SXDEBUG("Failed to allocate jobs array for jobs batch");
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        free(batch);
        return NULL;
    }

    batch->conns = conns;
    gettimeofday(&batch->tv, NULL);

    if(sxi_ht_add(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, batch)) {
        SXDEBUG("Failed to add jobs batch to hashtable");
        free(batch->jobs);
        free(batch);
        return NULL;
    }

    return batch;
}

int sxi_jobs_add(sxi_jobs_t *jobs, sxi_job_t *job)
{
    sxc_client_t *sx;
    sxi_conns_t *conns;
    struct jobs_batch *batch = NULL;

    if(!jobs)
        return 1;
    sx = jobs->sx;
    if (job == &JOB_NONE)
        return 0;/* successful, but no job to add */
    if (!job || !job->cbdata) {
        SXDEBUG("Invalid argument: NULL job or cbdata context");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    conns = sxi_cbdata_get_conns(job->cbdata);
    if(!conns) {
        SXDEBUG("Invalid argument: NULL conns pointer");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }
    if(sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void **)&batch)) {
        /* No jobs batch stored in hash table yet, allocate a new one */
        if(!(batch = jobs_batch_new(jobs, conns))) {
            SXDEBUG("Failed to add jobs batch to hashtable");
            free(batch);
            return 1;
        }
    } else if(!batch) {
        SXDEBUG("Successfully obtained jobs batch, but it is a NULL pointer");
        return 1;
    }

    if(jobs_batch_add_job(batch, job)) {
        SXDEBUG("Failed to add job to jobs batch");
        return 1;
    }
    jobs->total++;
    jobs->pending++;

    return 0;
}

/*
{
    "requestId":"REQID",
    "requestStatus":"OK"|"PENDING"|"ERROR",
    "requestMessage":"WASSUP"
}
*/

static void cb_jobres_id(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;
    if(length != strlen(yactx->job_id) || memcmp(yactx->job_id, string, length)) {
	sxi_jparse_cancel(J, "Request ID mismatch");
	yactx->err = SXE_ECOMM;
	return;
    }
}

static void cb_jobres_st(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;

    if(length == lenof("OK") && !memcmp(string, "OK", lenof("OK")))
	yactx->status = JOBST_OK;
    else if(length == lenof("PENDING") && !memcmp(string, "PENDING", lenof("PENDING")))
	yactx->status = JOBST_PENDING;
    else if(length == lenof("ERROR") && !memcmp(string, "ERROR", lenof("ERROR")))
	yactx->status = JOBST_ERROR;
    else {
	sxi_jparse_cancel(J, "Received unknown status '%.*s'", length, string);
	yactx->err = SXE_ECOMM;
	return;
    }
}

static void cb_jobres_msg(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;

    if(yactx->message)
	return; /* I'll just take the first one */

    yactx->message = malloc(length + 1);
    if(!yactx->message) {
	sxi_jparse_cancel(J, "Out of memory processing request results");
	yactx->err = SXE_EMEM;
	return;
    }
    memcpy(yactx->message, string, length);
    yactx->message[length] = '\0';
}

const struct jparse_actions jobres_acts = {
    JPACTS_STRING(
		  JPACT(cb_jobres_id, JPKEY("requestId")),
		  JPACT(cb_jobres_st, JPKEY("requestStatus")),
		  JPACT(cb_jobres_msg, JPKEY("requestMessage"))
		  )
};

static int jobres_setup_cb(curlev_context_t *cbdata, const char *host) {
    struct job_ctx *jctx = sxi_cbdata_get_job_ctx(cbdata);
    sxi_job_t *yactx;

    if(!jctx)
	return 1;
    yactx = jctx->yactx;
    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(&jobres_acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to retrieve the request result");
	return 1;
    }

    free(yactx->message);
    yactx->message = NULL;
    yactx->status = JOBST_UNDEF;
    return 0;
}

static int jobres_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size) {
    struct job_ctx *jctx = sxi_cbdata_get_job_ctx(cbdata);
    sxi_job_t *yactx;
    if(!jctx)
	return 1;
    yactx = jctx->yactx;
    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

void sxi_job_free(sxi_job_t *yres)
{
    if (!yres || yres == &JOB_NONE)
        return;
    free(yres->resquery);
    free(yres->message);
    free(yres->name);
    free(yres->job_id);
    free(yres->job_host);
    sxi_jparse_destroy(yres->J);
    sxi_cbdata_unref(&yres->cbdata);

    free(yres->nf_src_path);
    free(yres->nf_dst_clust);
    free(yres->nf_dst_vol);
    free(yres->nf_dst_path);

    free(yres);
}

struct cb_jobget_ctx {
    curlev_context_t *cbdata;
    jparse_t *J;
    char *job_id;
    int poll_min_delay, poll_max_delay;
    const char *job_host;
};

/*
  This is actually quite bogus, but let's pretend
  {
  "requestId":"REQUID",
  "minPollInterval":3,
  "maxPollInterval":120
  }
*/


static void cb_jobget_id(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;

    if(yactx->job_id) {
	sxi_jparse_cancel(J, "Multiple job ID's received");
	return;
    }
    yactx->job_id = malloc(length + 1);
    if(!yactx->job_id) {
	sxi_jparse_cancel(J, "Out of memory processing job results");
	return;
    }

    memcpy(yactx->job_id, string, length);
    yactx->job_id[length] = '\0';
}

static void cb_jobget_min(jparse_t *J, void *ctx, int32_t num) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid poll interval '%d'", num);
	return;
    }
    yactx->poll_min_delay = num;
}

static void cb_jobget_max(jparse_t *J, void *ctx, int32_t num) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid poll interval '%d'", num);
	return;
    }
    yactx->poll_max_delay = num;
}

const struct jparse_actions jobget_acts = {
    JPACTS_STRING(
		  JPACT(cb_jobget_id, JPKEY("requestId"))
		  ),
    JPACTS_INT32(
		 JPACT(cb_jobget_min, JPKEY("minPollInterval")),
		 JPACT(cb_jobget_max, JPKEY("maxPollInterval"))
		 )
};

static int jobget_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(&jobget_acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to retrieve the request details");
	return 1;
    }

    free(yactx->job_id);
    yactx->job_id = NULL;
    yactx->job_host = host;
    yactx->poll_min_delay = 0;
    yactx->poll_max_delay = 0;

    return 0;
}

static int jobget_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

static void jobres_finish(curlev_context_t *ctx, const char *url)
{
    struct job_ctx *jctx = sxi_cbdata_get_job_ctx(ctx);
    if (jctx && jctx->queries_finished) /* finished, not necessarily successfully */
        (*jctx->queries_finished)++;
}

/* Return jobs batch for a particular cluster */
static struct jobs_batch *get_jobs_batch(sxi_jobs_t *jobs, sxi_conns_t *conns) {
    sxc_client_t *sx;
    struct jobs_batch *batch = NULL;

    if(!jobs)
        return NULL;
    sx = jobs->sx;
    if(!conns) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return NULL;
    }

    if(!sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void**)&batch) && !batch) {
        sxi_seterr(sx, SXE_EARG, "Failed to obtain jobs batch for cluster %s", sxi_conns_get_uuid(conns));
        return NULL;
    }

    return batch;
}

static unsigned job_min_delay(sxi_job_t *poll)
{
    unsigned ret;

    if (!poll)
        return 0;
    ret = poll->poll_min_delay;
    poll->poll_min_delay *= 2;
    if(poll->poll_min_delay > poll->poll_max_delay)
        poll->poll_min_delay = poll->poll_max_delay;
    return ret;
}

static int job_status_ev(sxi_jobs_t *jobs, struct jobs_batch *batch, sxi_job_t **job);
static int job_result(sxi_jobs_t *jobs, struct jobs_batch *batch, sxi_job_t **yres);

static int poll_jobs(sxi_conns_t *conns, sxi_jobs_t *jobs, jobs_wait_kind_t wait)
{
    unsigned finished;
    unsigned alive;
    unsigned pending;
    unsigned errors;
    long delay = 0;
    unsigned i;
    struct timeval tv0, tv1;
    struct timeval t0, t;
    int ret = 0;
    int rc = 0;
    sxc_client_t *sx;
    struct jobs_batch *batch;

    if(!conns)
        return 1;
    sx = sxi_conns_get_client(conns);
    if(!jobs) {
        SXDEBUG("NULL jobs argument");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    /* Obtain jobs batch for given cluster */
    batch = get_jobs_batch(jobs, conns);
    if(!batch && !(batch = jobs_batch_new(jobs, conns))) {
        SXDEBUG("No jobs batch stored for cluster %s, but failed to create a new one", sxi_conns_get_uuid(conns));
        return 1;
    }

    gettimeofday(&t0, NULL);
    while(1) {
        int msg_printed = 0;
        gettimeofday(&tv0, NULL);

        for(i=0;i<batch->length;i++) {
            /* Check if job has already been finished and freed */
            if(!batch->jobs[i])
                continue;
            delay = job_min_delay(batch->jobs[i]);
            rc = job_status_ev(jobs, batch, &batch->jobs[i]);
            if (rc < 0) {
                ret = -1;
                SXDEBUG("job_status_ev failed: %s", batch->jobs[i] ? batch->jobs[i]->message : "(null job)");
                if (!jobs->ignore_errors)
                    break;
                continue;
            }

            /* When not ignoring errors first failed job should cause a fail */
            if(!jobs->ignore_errors && batch->errors)
                break;
            if (rc >= JOB_POLL_MORE) {
                if (rc == JOB_POLL_MSG) {
                    if (!msg_printed) {
                        /* there might be tens of jobs being polled at any time,
                         * print the message only once per loop */
                        sxi_info(sx, "%s, retrying job poll on %s ...", sxc_geterrmsg(sx),
                                 batch->jobs[i]->job_host);
                        msg_printed = 1;
                    }
                }
                /* Check if the finished variable is used */
                if (sxi_job_query_ev(conns, batch->jobs[i], &finished) == -1)
                    ret = -1;
            }
        }
        /* finish callback might be called even if sending the query failed
         * early in some situations, so count the number of still alive queries in
         * a separate loop */
        finished = alive = pending = errors = 0;
        rc = 0;
        for (i=0;i<batch->length;i++) {
            if (batch->jobs[i]) {
                if (!sxi_cbdata_is_finished(batch->jobs[i]->cbdata))
                    alive++;
            }
        }
        /* If there are still alive jobs, poll before checking their status */
        if (alive) {
            while (finished != alive && !rc) {
                rc = sxi_curlev_poll(sxi_conns_get_curlev(conns));
                if (finished > alive) {
                    sxi_notice(sx, "counters out of sync in job_wait: %d > %d", finished, alive);
                    break;
                }
            }
            if (rc) {
                ret = rc;
                break;
            }
        }
        if (!jobs->ignore_errors && batch->errors)
            break;

        /* Check jobs statuses */
        for (i=0;i<batch->length;i++) {
            if (batch->jobs[i]) {
                if (!sxi_cbdata_is_finished(batch->jobs[i]->cbdata)) {
                    SXDEBUG("Job %s status query is not finished, but polling is", batch->jobs[i]->job_id);
                    break;
                }
                switch (batch->jobs[i]->status) {
                    case JOBST_UNDEF:/* fall-through */
                    case JOBST_PENDING:
                        pending++;
                        break;
                    case JOBST_ERROR:
                        errors++;
                        break;
                    default:
                        break;
                }
            }
        }
        if (!pending)
            break;
        gettimeofday(&t, NULL);
        if (sxi_timediff(&t, &t0) > PROGRESS_INTERVAL) {
            memcpy(&t0, &t, sizeof(t));
        }
        SXDEBUG("Pending %d jobs, %d errors, %d queries", pending, errors, alive);
        if(wait == JOBS_NO_WAIT)
            break;
        else if(wait == JOBS_WAIT_SLOT && pending < batch->total) {
            SXDEBUG("Waiting for job slot finished, total jobs: %d", batch->total);
            break;
        }

        gettimeofday(&tv1, NULL);
        delay -= (tv1.tv_sec - tv0.tv_sec) * 1000 + (tv1.tv_usec - tv0.tv_usec)/1000;
        if (delay <= 0) delay = 1;
        SXDEBUG("Sleeping %ld ms...", delay);
        usleep(delay * 1000);
    }
    for (i=0;i<batch->length;i++) {
        if (batch->jobs[i] && (wait != JOBS_NO_WAIT && batch->jobs[i]->status != JOBST_PENDING)) {
            rc = job_result(jobs, batch, &batch->jobs[i]);
            if(rc) {
                SXDEBUG("sxi_job_result failed: %s", batch->jobs[i]->message);
                ret = rc;
            }
        }
    }
    if(ret)
        SXDEBUG("job_poll fails with: %d (%s)", ret, sxc_geterrmsg(sx));
    return ret;
}

sxi_job_t* sxi_job_submit(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, const char *name, void *content, size_t content_size, long* http_code, sxi_jobs_t *jobs) {
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct cb_jobget_ctx yget;
    int ret = -1, qret;
    sxi_job_t *yres;
    unsigned j = 0;
    struct jobs_batch *batch = NULL;

    if (http_code)
        *http_code = 0;
    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_job_submit");
        return NULL;
    }

    if(!jobs || sxi_ht_get(jobs->ht, sxi_conns_get_uuid(conns), UUID_LEN, (void**)&batch) || !batch)
        SXDEBUG("Jobs batch for cluster %s is not ready yet", sxi_conns_get_uuid(conns));

    yres = calloc(1, sizeof(*yres));
    if (!yres) {
        sxi_setsyserr(sx, SXE_EMEM, "cannot allocate job");
        return NULL;
    }
    gettimeofday(&yres->last_reached, NULL);
    yres->ctx.yactx = yres;
    yres->cbdata = sxi_cbdata_create_job(conns, jobres_finish, &yres->ctx);
    if (!yres->cbdata) {
        free(yres);
        SXDEBUG("sxi_cbdata_create_job failed");
        return NULL;
    }

    yget.J = NULL;
    yget.job_id = NULL;

    do {
        struct timeval tv;
        qret = sxi_cluster_query(conns, hlist, verb, query, content, content_size, jobget_setup_cb, jobget_cb, &yget);
        gettimeofday(&tv, NULL);
        if (qret == 429) {
            SXDEBUG("throttle 429 received");
            if (batch && batch->jobs && batch->total) {
                if (poll_jobs(conns, jobs, JOBS_WAIT_SLOT)) {
                    SXDEBUG("job_wait failed");
                    ret = -1;
                    goto failure;
                }
                memcpy(&batch->tv, &tv, sizeof(tv));
                SXDEBUG("throttle wait finished");
            }
            sxc_clearerr(sx);
            if (j++ > 0)
                sxi_retry_throttle(sxi_conns_get_client(conns), j);
        }
        if (batch) {
            if (qret != 429 && sxi_timediff(&tv, &batch->tv) > POLL_INTERVAL) {
                if (batch->jobs && batch->total) {
                    /* poll once for progress, don't sleep */
                    if (poll_jobs(conns, jobs, JOBS_NO_WAIT)) {
                        SXDEBUG("job_poll failed");
                        ret = -1;
                        goto failure;
                    }
                }
                memcpy(&batch->tv, &tv, sizeof(tv));
            }
        }
    } while (qret == 429);
    if (http_code)
        *http_code = qret;
    if(qret != 200) {
        SXDEBUG("unexpected json reply, HTTP %d", qret);
	goto failure;
    }
    if(!yget.job_id) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to add job: Invalid job ID");
        goto failure;
    }
    SXDEBUG("Received job id %s with %d-%d secs polling", yget.job_id, yget.poll_min_delay, yget.poll_max_delay);

    yres->poll_min_delay = yget.poll_min_delay;
    yres->poll_max_delay = yget.poll_max_delay;
    yres->verb = verb;
    yres->job_host = strdup(yget.job_host);
    if (!yres->job_host) {
	SXDEBUG("OOM allocating jobhost");
	sxi_seterr(sx, SXE_EMEM, "Cannot allocate jobhost");
	goto failure;
    }
    if (name) {
        yres->name = strdup(name);
        if (!yres->name) {
            SXDEBUG("OOM allocating name");
            sxi_seterr(sx, SXE_EMEM, "Cannot allocate name");
            goto failure;
        }
    }
    yres->job_id = yget.job_id;
    yres->resquery = malloc(lenof(".results/") + strlen(yget.job_id) + 1);
    if(!yres->resquery) {
	SXDEBUG("OOM allocating query");
	sxi_seterr(sx, SXE_EMEM, "Cannot allocate query");
	goto failure;
    }
    sprintf(yres->resquery, ".results/%s", yget.job_id);
    ret = 0;

 failure:
    sxi_jparse_destroy(yget.J);
    if (!ret)
        return yres;
    sxi_job_free(yres);
    return NULL;
}

static int job_result(sxi_jobs_t *jobs, struct jobs_batch *batch, sxi_job_t **yres)
{
    int ret;
    sxc_client_t *sx = jobs->sx;
    switch ((*yres)->status) {
        default:
            return 1;
        case JOBST_OK:
            if ((*yres)->name)
                if((*yres)->verb == REQ_DELETE)
                    sxi_info(sx, "%s: %s", (*yres)->name, "Deleted");
	    if((*yres)->nf_fn) {
		struct filter_handle *fh = (*yres)->nf_fh;
		(*yres)->nf_fn(fh, fh->ctx, sxi_filter_get_cfg(fh, (*yres)->nf_dst_vol), sxi_filter_get_cfg_len(fh, (*yres)->nf_dst_vol), SXF_MODE_UPLOAD, NULL, NULL, (*yres)->nf_src_path, (*yres)->nf_dst_clust, (*yres)->nf_dst_vol, (*yres)->nf_dst_path);
	    }
            /* Make space for a new job only when it succeeds */
            sxi_job_free(*yres);
            *yres = NULL;

            /* Increase success counters */
            batch->successful++;
            jobs->successful++;
            ret = 0;
            break;
        case JOBST_ERROR:
            SXDEBUG("Request failed (%s)", (*yres)->message);
            if ((*yres)->name) 
                sxi_notice(sx, "Failed to complete operation for %s: %s", (*yres)->name, (*yres)->message);
            sxi_seterr(sx, SXE_ECOMM, "Operation failed: %s", (*yres)->message);

            /* Increase error counters */
            batch->errors++;
            jobs->errors++;
            ret = -1;
            break;
    }

    batch->pending--;
    jobs->pending--;

    return ret;
}

static int job_status_ev(sxi_jobs_t *jobs, struct jobs_batch *batch, sxi_job_t **job)
{
    sxc_client_t *sx;
    sxi_job_t *yres;

    if(!jobs)
        return -1;
    sx = jobs->sx;
    if(!batch || !job) {
        sxi_seterr(sx, SXE_EARG, "Null argument to job_status_ev");
        return -1;
    }

    yres = *job;

    if (!yres || !yres->job_host || !yres->job_id) {
        sxi_seterr(sx, SXE_EARG, "Null argument to job_status_ev");
        return -1;
    }
    if (sxi_cbdata_is_finished(yres->cbdata)) {
        int res;
	sxi_cbdata_result(yres->cbdata, NULL, NULL, &yres->http_err);
	if(yres->http_err != 200 || yres->status == JOBST_UNDEF) {
            sxi_seterr(sx, SXE_ECOMM, "Cannot query request result (operation might or might have not succeeded): %s", sxi_cbdata_geterrmsg(yres->cbdata));
            if (yres->fails++ > 0) {
                struct timeval now;
                double last_successful_ms;
                gettimeofday(&now, NULL);
                last_successful_ms = sxi_timediff(&now, &yres->last_reached) * 1000;
                if (last_successful_ms > 3*yres->poll_max_delay) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Job host failed %d times, last successful contact was %.3f s ago", yres->fails, last_successful_ms/1000.0);
                    yres->message = strdup(msg);
                    if (!yres->message)
                        return -1;
                    yres->status = JOBST_ERROR;
                    return job_result(jobs, batch, job);
                }
            }
            return JOB_POLL_MSG;
        } else {
            gettimeofday(&yres->last_reached, NULL);
            res = job_result(jobs, batch, job);
            if (res < 1)
                return res;
        }
        /* loop more */
    }
    return JOB_POLL_MORE;
}

int sxi_job_query_ev(sxi_conns_t *conns, sxi_job_t *yres, unsigned *finished)
{
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if (!yres || !yres->job_host || !yres->job_id) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_job_status_ev");
        return -1;
    }
    sxi_cbdata_reset(yres->cbdata);
    sxi_jparse_destroy(yres->J);
    yres->J = NULL;
    yres->status = JOBST_UNDEF;
    free(yres->message);
    yres->message = NULL;
    yres->ctx.queries_finished = finished;

    return sxi_cluster_query_ev(yres->cbdata, conns, yres->job_host, REQ_GET, yres->resquery, NULL, 0, jobres_setup_cb, jobres_cb);
}

int sxi_jobs_wait(sxi_jobs_t *jobs, sxi_conns_t *conns)
{
    sxc_client_t *sx;
    int ret = 0;

    if(!jobs)
        return 1;
    sx = jobs->sx;

    /* Check if any job was added */
    if(!jobs->total)
        return 0;

    if(!conns) { /* Wait for all jobs */
        const char *uuid = NULL;
        unsigned int uuid_len = 0;
        struct jobs_batch *batch = NULL;

        sxi_ht_enum_reset(jobs->ht);
        while(!sxi_ht_enum_getnext(jobs->ht, (const void**)&uuid, &uuid_len, (const void **)&batch)) {
            if(!uuid || uuid_len != UUID_LEN || !batch) {
                SXDEBUG("Invalid jobs hashtable content");
                sxi_seterr(sx, SXE_EARG, "Failed to obtain jobs batch");
                return 1;
            }

            if(poll_jobs(batch->conns, jobs, JOBS_WAIT_ALL)) {
                SXDEBUG("Failed to wait for jobs for cluster %s", sxi_conns_get_sslname(batch->conns));
                ret = 1;
                /* Do not wait for other jobs when not ignoring errors */
                if(!jobs->ignore_errors)
                    break;
            }
        }
    } else if(poll_jobs(conns, jobs, JOBS_WAIT_ALL))
        ret = 1;

    if(jobs->ignore_errors && jobs->errors > 1) {
        sxc_clearerr(sx);
        sxi_seterr(sx, SXE_SKIP, "Failed to process %d files", jobs->errors);
        ret = 1;
    }
    return ret;
}

int sxi_job_submit_and_poll_err(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size, long *http_err)
{
    int rc;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    sxi_jobs_t *jobs;
    sxi_job_t *job = sxi_job_submit(conns, hlist, verb, query, NULL, content, content_size, http_err, NULL);

    if (!job)
        return 1;
    jobs = sxi_jobs_new(sx, 0);
    if(!jobs) {
        SXDEBUG("Failed to allocate jobs context");
        sxi_job_free(job);
        return 1;
    }

    if(sxi_jobs_add(jobs, job)) {
        SXDEBUG("Failed to add job to jobs context");
        sxi_job_free(job);
        sxi_jobs_free(jobs);
        return 1;
    }

    rc = sxi_jobs_wait(jobs, conns);
    if (http_err)
        *http_err = job->http_err;
    sxi_jobs_free(jobs);
    return rc;
}

int sxi_job_submit_and_poll(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size)
{
    return sxi_job_submit_and_poll_err(conns, hlist, verb, query, content, content_size, NULL);
}

sxi_job_t JOB_NONE;

void sxi_job_set_nf(sxi_job_t *job, struct filter_handle *nf_fh, nf_fn_t nf_fn, const char *nf_src_path, const char *nf_dst_clust, const char *nf_dst_vol, const char *nf_dst_path)
{
    job->nf_fh = nf_fh;
    job->nf_fn = nf_fn;
    job->nf_src_path = strdup(nf_src_path);
    job->nf_dst_clust = strdup(nf_dst_clust);
    job->nf_dst_vol = strdup(nf_dst_vol);
    job->nf_dst_path = strdup(nf_dst_path);
}

const char *sxi_job_get_id(const sxi_job_t *job) {
    return job ? job->job_id : NULL;
}

sxi_job_t *sxi_job_new(sxi_conns_t *conns, const char *id, enum sxi_cluster_verb verb, const char *host) {
    sxi_job_t *job, *ret = NULL;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(!conns)
        return NULL;
    if(!host || !id) {
        sxi_setsyserr(sx, SXE_EARG, "NULL argument");
        return NULL;
    }

    job = calloc(1, sizeof(*job));
    if (!job) {
        sxi_setsyserr(sx, SXE_EMEM, "cannot allocate job");
        return NULL;
    }
    job->ctx.yactx = job;
    job->cbdata = sxi_cbdata_create_job(conns, jobres_finish, &job->ctx);
    if (!job->cbdata) {
        free(job);
        SXDEBUG("sxi_cbdata_create_job failed");
        return NULL;
    }

    gettimeofday(&job->last_reached, NULL);
    job->poll_min_delay = 0;
    job->poll_max_delay = 0;
    job->verb = verb;
    job->job_host = strdup(host);
    if (!job->job_host) {
        SXDEBUG("OOM allocating jobhost");
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate jobhost");
        goto sxi_job_from_id_err;
    }
    job->name = NULL;
    job->job_id = strdup(id);
    if(!job->job_id) {
        SXDEBUG("OOM allocating job_id string");
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate job_id");
        goto sxi_job_from_id_err;
    }
    job->resquery = malloc(lenof(".results/") + strlen(job->job_id) + 1);
    if(!job->resquery) {
        SXDEBUG("OOM allocating query");
        sxi_seterr(sx, SXE_EMEM, "Cannot allocate query");
        goto sxi_job_from_id_err;
    }
    sprintf(job->resquery, ".results/%s", job->job_id);
    ret = job;
sxi_job_from_id_err:
    if(!ret) {
        free(job->resquery);
        free(job->job_id);
        free(job->job_host);
        sxi_cbdata_unref(&job->cbdata);
    }
    return ret;
}

curlev_context_t *sxi_job_cbdata(const sxi_job_t *job) {
    return job ? job->cbdata : NULL;
}

sxi_job_status_t sxi_job_status(const sxi_job_t *job) {
    return job ? job->status : JOBST_UNDEF;
}

static int jobget_ev_setup_cb(curlev_context_t *cbdata, const char *host) {
    struct cb_jobget_ctx *yactx;

    if(!cbdata)
        return -1;

    yactx = (struct cb_jobget_ctx *)sxi_cbdata_get_context(cbdata);
    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(&jobget_acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Failed to retrieve the request details");
	return 1;
    }

    free(yactx->job_id);
    yactx->job_id = NULL;
    yactx->job_host = host;
    yactx->poll_min_delay = 0;
    yactx->poll_max_delay = 0;

    return 0;
}

static int jobget_ev_cb(curlev_context_t *cbdata, const unsigned char *data, size_t size) {
    struct cb_jobget_ctx *yactx;

    if(!cbdata)
        return -1;

    yactx = (struct cb_jobget_ctx *)sxi_cbdata_get_context(cbdata);

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, sxi_jparse_geterr(yactx->J));
	return 1;
    }

    return 0;
}

curlev_context_t *sxi_job_submit_ev(sxi_conns_t *conns, const char *host, enum sxi_cluster_verb verb, const char *query, const char *name, void *content, size_t content_size) {
    sxc_client_t *sx;
    struct cb_jobget_ctx *jobget_ctx;
    curlev_context_t *cbdata;

    if (!conns || !host || !query)
        return NULL;

    sx = sxi_conns_get_client(conns);
    cbdata = sxi_cbdata_create_generic(conns, NULL, NULL);

    jobget_ctx = calloc(1, sizeof(*jobget_ctx));
    if(!jobget_ctx) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory allocating jobget context");
        sxi_cbdata_unref(&cbdata);
        return NULL;
    }

    /* This context is used to parse job submit query json respone */
    sxi_cbdata_set_context(cbdata, jobget_ctx);

    if(sxi_cluster_query_ev(cbdata, conns, host, verb, query, content, content_size, jobget_ev_setup_cb, jobget_ev_cb)) {
        sxi_cbdata_unref(&cbdata);
        return NULL;
    }

    return cbdata;
}

sxi_job_t *sxi_job_submit_ev_wait(curlev_context_t *cbdata, long *http_status) {
    int rc;
    sxi_conns_t *conns = sxi_cbdata_get_conns(cbdata);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct cb_jobget_ctx *jobget_ctx = sxi_cbdata_get_context(cbdata);
    sxi_job_t *ret = NULL;

    if(!cbdata || !sx || !conns)
        return NULL;

    if(!jobget_ctx) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument: Jobget context is not set");
        return NULL;
    }
    rc = sxi_cbdata_wait(cbdata, sxi_conns_get_curlev(conns), http_status);
    if(rc == -2) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to wait for query");
        goto sxi_job_submit_ev_wait_err;
    }

    if(rc == -1 || *http_status != 200) {
        sxi_seterr(sx, SXE_ECOMM, "Query failed with %ld", *http_status);
        goto sxi_job_submit_ev_wait_err;
    }

    ret = sxi_job_new(conns, jobget_ctx->job_id, -1, jobget_ctx->job_host);
sxi_job_submit_ev_wait_err:
    sxi_jparse_destroy(jobget_ctx->J);
    free(jobget_ctx->job_id);
    free(jobget_ctx);
    /* Reset context just in case */
    sxi_cbdata_set_context(cbdata, NULL);

    return ret;
}
