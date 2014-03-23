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
#include "yajlwrap.h"
#include "hostlist.h"
#include "jobpoll.h"
#include "curlevents.h"

#define CBDEBUG(...) do{ sxc_client_t *sx = yactx->sx; SXDEBUG(__VA_ARGS__); } while(0)

struct job_ctx {
    unsigned *queries_finished;
    sxi_job_t *yactx;
};

struct _sxi_job_t {
    sxc_client_t *sx;
    enum sxi_cluster_verb verb;
    struct timeval last_reached;
    int fails;/* failed to get job status, i.e. failed to connect etc. */
    curlev_context_t *cbdata;
    struct job_ctx ctx;
    char *resquery;
    int poll_min_delay, poll_max_delay;
    char *job_host;
    yajl_callbacks yacb;
    yajl_handle yh;
    char *message;
    char *name;
    char *job_id;
    unsigned finished;
    enum _jobstatus_t {
	JOBST_UNDEF,
	JOBST_ERROR,
	JOBST_OK,
	JOBST_PENDING
    } status;
    enum jobres_state { JR_BEGIN, JR_BASE, JR_ID, JR_RES, JR_MSG, JR_COMPLETE } state;
};

static int yacb_jobres_start_map(void *ctx) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state != JR_BEGIN) {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, JR_BEGIN);
	return 0;
    }

    yactx->state = JR_BASE;
    return 1;
}

static int yacb_jobres_map_key(void *ctx, const unsigned char *s, size_t l) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;
    if(!ctx)
	return 0;

    if(l == lenof("requestId") && !memcmp(s, "requestId", lenof("requestId"))) {
	yactx->state = JR_ID;
    } else if(l == lenof("requestStatus") && !memcmp(s, "requestStatus", lenof("requestStatus"))) {
	yactx->state = JR_RES;
    } else if(l == lenof("requestMessage") && !memcmp(s, "requestMessage", lenof("requestMessage"))) {
	yactx->state = JR_MSG;
    } else {
	CBDEBUG("unexpected key '%.*s'", (unsigned)l, s);
	return 0;
    }
    return 1;
}

static int yacb_jobres_string(void *ctx, const unsigned char *s, size_t l) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state == JR_ID) {
	int jl = strlen(yactx->job_id);
	if(jl != l || memcmp(yactx->job_id, s, l)) {
	    CBDEBUG("Request ID mismatch");
	    return 0;
	}
    } else if(yactx->state == JR_MSG) {
	if(yactx->message) {
	    CBDEBUG("Request message already received");
	    return 0;
	}
	yactx->message = malloc(l + 1);
	if(!yactx->message) {
	    CBDEBUG("OOM allocating request message of size %lu", l);
	    return 0;
	}

	memcpy(yactx->message, s, l);
	yactx->message[l] = '\0';
    } else if(yactx->state == JR_RES) {
	if(yactx->status != JOBST_UNDEF) {
	    CBDEBUG("Request status already received");
	    return 0;
	}
	if(l == lenof("OK") && !memcmp(s, "OK", lenof("OK")))
	    yactx->status = JOBST_OK;
	else if(l == lenof("PENDING") && !memcmp(s, "PENDING", lenof("PENDING")))
	    yactx->status = JOBST_PENDING;
	else if(l == lenof("ERROR") && !memcmp(s, "ERROR", lenof("ERROR")))
	    yactx->status = JOBST_ERROR;
	else {
	    CBDEBUG("Invalid request status '%.*s'", (unsigned)l, s);
	    return 0;
	}
    } else {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, JR_ID, JR_MSG);
	return 0;
    }

    yactx->state = JR_BASE;
    return 1;
}

static int yacb_jobres_end_map(void *ctx) {
    sxi_job_t *yactx = (sxi_job_t *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state != JR_BASE) {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, JR_BASE);
	return 0;
    }

    if(!yactx->message) {
	CBDEBUG("No request message received");
	return 0;
    }

    if(yactx->status == JOBST_UNDEF) {
	CBDEBUG("No request status received");
	return 0;
    }

    yactx->state = JR_COMPLETE;
    return 1;
}

static int jobres_setup_cb(curlev_context_t *ctx, const char *host) {
    struct job_ctx *jctx = sxi_cbdata_get_job_ctx(ctx);
    sxi_job_t *yactx = jctx->yactx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(ctx));

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("failed to allocate yajl structure");
	sxi_seterr(sx, SXE_EMEM, "List failed: out of memory");
	return 1;
    }

    yactx->state = JR_BEGIN;
    yactx->sx = sx;
    free(yactx->message);
    yactx->message = NULL;
    yactx->status = JOBST_UNDEF;
    return 0;
}

static int jobres_cb(curlev_context_t *ctx, const unsigned char *data, size_t size) {
    struct job_ctx *jctx = sxi_cbdata_get_job_ctx(ctx);
    sxi_job_t *yctx = jctx->yactx;
    if(yajl_parse(yctx->yh, data, size) != yajl_status_ok) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(ctx));
	SXDEBUG("failed to parse JSON data");
        sxi_seterr(sx, SXE_ECOMM, "communication error");
	return 1;
    }

    return 0;
}

void sxi_job_free(sxi_job_t *yres)
{
    if (!yres)
        return;
    free(yres->resquery);
    free(yres->message);
    free(yres->name);
    free(yres->job_id);
    free(yres->job_host);
    if(yres->yh)
	yajl_free(yres->yh);
    sxi_cbdata_free(&yres->cbdata);
    free(yres);
}

struct cb_jobget_ctx {
    sxc_client_t *sx;
    yajl_callbacks yacb;
    yajl_handle yh;
    char *job_id;
    int poll_min_delay, poll_max_delay;
    const char *job_host;
    enum jobget_state { JG_BEGIN, JG_BASE, JG_ID, JG_POLL_MIN, JG_POLL_MAX, JG_COMPLETE } state;
};

static int yacb_jobget_start_map(void *ctx) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state != JG_BEGIN) {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, JG_BEGIN);
	return 0;
    }

    yactx->state = JG_BASE;
    return 1;
}

static int yacb_jobget_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    if(!ctx)
	return 0;

    if(l == lenof("requestId") && !memcmp(s, "requestId", lenof("requestId"))) {
	yactx->state = JG_ID;
    } else if(l == lenof("minPollInterval") && !memcmp(s, "minPollInterval", lenof("minPollInterval"))) {
	yactx->state = JG_POLL_MIN;
    } else if(l == lenof("maxPollInterval") && !memcmp(s, "maxPollInterval", lenof("maxPollInterval"))) {
	yactx->state = JG_POLL_MAX;
    } else {
	CBDEBUG("unexpected key '%.*s'", (unsigned)l, s);
	return 0;
    }
    return 1;
}

static int yacb_jobget_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state != JG_ID) {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, JG_ID);
	return 0;
    }

    if(yactx->job_id) {
	CBDEBUG("Job Id already received");
	return 0;
    }

    yactx->job_id = malloc(l + 1);
    if(!yactx->job_id) {
	CBDEBUG("OOM allocating job id of size %lu", l);
	return 0;
    }

    memcpy(yactx->job_id, s, l);
    yactx->job_id[l] = '\0';
    yactx->state = JG_BASE;
    return 1;
}

static int yacb_jobget_number(void *ctx, const char *s, size_t l) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    int *n;
    char numb[24], *enumb;

    if(!ctx)
	return 0;

    if(yactx->state == JG_POLL_MIN)
	n = &yactx->poll_min_delay;
    else if(yactx->state == JG_POLL_MAX)
	n = &yactx->poll_max_delay;
    else {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, JG_POLL_MIN, JG_POLL_MAX);
	return 0;
    }

    if(*n) {
	CBDEBUG("Poll delay already received");
	return 0;
    }

    if(l < 1 || l > 10) {
	CBDEBUG("Invalid poll interval '%.*s'", (unsigned)l, s);
	return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    *n = strtol(numb, &enumb, 10);
    if(*enumb || *n <= 0) {
	CBDEBUG("Invalid poll interval '%.*s'", (unsigned)l, s);
	return 0;
    }

    yactx->state = JG_BASE;
    return 1;
}


static int yacb_jobget_end_map(void *ctx) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state != JG_BASE) {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, JG_BASE);
	return 0;
    }

    if(!yactx->job_id) {
	CBDEBUG("No id received");
	return 0;
    }

    if(!yactx->poll_min_delay || !yactx->poll_max_delay) {
	CBDEBUG("No poll interval received");
	return 0;
    }

    yactx->state = JG_COMPLETE;
    return 1;
}

static int jobget_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_jobget_ctx *yactx = (struct cb_jobget_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("failed to allocate yajl structure");
	sxi_seterr(sx, SXE_EMEM, "List failed: out of memory");
	return 1;
    }

    yactx->state = JG_BEGIN;
    yactx->sx = sx;
    free(yactx->job_id);
    yactx->job_id = NULL;
    yactx->job_host = host;
    yactx->poll_min_delay = 0;
    yactx->poll_max_delay = 0;

    return 0;
}

static int jobget_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_jobget_ctx *yctx = (struct cb_jobget_ctx *)ctx;
    if(yajl_parse(yctx->yh, data, size) != yajl_status_ok) {
	sxc_client_t *sx = sxi_conns_get_client(conns);
	SXDEBUG("failed to parse JSON data");
	return 1;
    }

    return 0;
}

static void jobres_finish(curlev_context_t *ctx, const char *url)
{
    struct job_ctx *jctx = sxi_cbdata_get_job_ctx(ctx);
    if (jctx->queries_finished)/* finished, not necesarely successfully */
        (*jctx->queries_finished) ++;
}

sxi_job_t* sxi_job_submit(sxi_conns_t *conns, sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, const char *name, void *content, size_t content_size, int* http_code, sxi_jobs_t *jobs) {
    sxc_client_t *sx = sxi_conns_get_client(conns);
    struct cb_jobget_ctx yget;
    sxi_hostlist_t jobhost;
    yajl_callbacks *yacb;
    int ret = -1, qret;
    sxi_job_t *yres;
    unsigned j = 0;

    if (http_code)
        *http_code = 0;
    if (!query) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_job_submit");
        return NULL;
    }
    yres = calloc(1, sizeof(*yres));
    if (!yres) {
        sxi_setsyserr(sx, SXE_EMEM, "cannot allocate job");
        return NULL;
    }
    yres->ctx.yactx = yres;
    yres->cbdata = sxi_cbdata_create_job(conns, jobres_finish, &yres->ctx);
    if (!yres->cbdata) {
        free(yres);
        return NULL;
    }

    sxi_hostlist_init(&jobhost);
    yacb = &yget.yacb;
    ya_init(yacb);
    yacb->yajl_start_map = yacb_jobget_start_map;
    yacb->yajl_map_key = yacb_jobget_map_key;
    yacb->yajl_string = yacb_jobget_string;
    yacb->yajl_number = yacb_jobget_number;
    yacb->yajl_end_map = yacb_jobget_end_map;
    yget.yh = NULL;
    yget.job_id = NULL;

    do {
        qret = sxi_cluster_query(conns, hlist, verb, query, content, content_size, jobget_setup_cb, jobget_cb, &yget);
        if (qret == 429) {
            SXDEBUG("throttle 429 received");
            if (jobs && jobs->jobs && jobs->n) {
                SXDEBUG("server has throttled us ... polling for jobs");
                if (sxi_job_wait(conns, jobs, NULL)) {
                    SXDEBUG("job_wait failed");
                }
                SXDEBUG("throttle wait finished");
            }
            if (j++ > 0)
                sxi_retry_throttle(sxi_conns_get_client(conns), j);
        }
    } while (qret == 429);
    if (http_code)
        *http_code = qret;
    if(qret != 200 || yget.state != JG_COMPLETE) {
	goto failure;
    }
    SXDEBUG("Received job id %s with %d-%d secs polling\n", yget.job_id, yget.poll_min_delay, yget.poll_max_delay);

    if(sxi_hostlist_add_host(sx, &jobhost, yget.job_host))
	goto failure;

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
    if(yget.yh)
	yajl_free(yget.yh);
    sxi_hostlist_empty(&jobhost);
    if (!ret)
        return yres;
    sxi_job_free(yres);
    return NULL;
}

unsigned sxi_job_min_delay(sxi_job_t *poll)
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

static int sxi_job_result(sxc_client_t *sx, sxi_job_t **yres, unsigned *successful)
{
    int ret;
    switch ((*yres)->status) {
        default:
            return 1;
        case JOBST_OK:
            if ((*yres)->name)
                sxi_info(sx, "%s: %s", (*yres)->name,
                         (*yres)->verb == REQ_DELETE ? "Deleted" : "OK");
            if (successful)
                (*successful)++;
            ret = 0;
            break;
        case JOBST_ERROR:
            SXDEBUG("Request failed (%s)", (*yres)->message);
            if ((*yres)->name)
                sxi_info(sx, "%s: %s", (*yres)->name, (*yres)->message);
            sxi_seterr(sx, SXE_ECOMM, "Operation failed: %s", (*yres)->message);
            ret = -1;
            break;
    }
    sxi_job_free(*yres);
    *yres = NULL;
    return ret;
}

int sxi_job_status_ev(sxi_conns_t *conns, sxi_job_t **job, unsigned *finished, unsigned *successful)
{
    yajl_callbacks *yacb;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    sxi_job_t *yres;

    if (!job) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_job_status_ev");
        return -1;
    }

    yres = *job;

    if (!yres || !finished || !yres->job_host || !yres->job_id) {
        sxi_seterr(sx, SXE_EARG, "Null argument to sxi_job_status_ev");
        return -1;
    }
    if (sxi_cbdata_is_finished(yres->cbdata)) {
        int res;
        if(yres->state != JR_COMPLETE) {
            SXDEBUG("Cannot query request result");
            sxi_seterr(sx, SXE_ECOMM, "Cannot query request result (operation might or might have not succeeded)");
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
                    return sxi_job_result(sx, job, successful);
                }
                sxi_retrymsg(sx, NULL, "job poll", NULL);
            }
        } else {
            gettimeofday(&yres->last_reached, NULL);
            res = sxi_job_result(sx, job, successful);
            if (res < 1)
                return res;
        }
        /* loop more */
    }
    sxi_cbdata_reset(yres->cbdata);
    if (yres->yh)
        yajl_free(yres->yh);

    yres->state = JR_BEGIN;
    yres->status = JOBST_UNDEF;
    yres->yh = NULL;
    yacb = &yres->yacb;
    ya_init(yacb);
    yacb->yajl_start_map = yacb_jobres_start_map;
    yacb->yajl_map_key = yacb_jobres_map_key;
    yacb->yajl_string = yacb_jobres_string;
    yacb->yajl_end_map = yacb_jobres_end_map;
    free(yres->message);
    yres->message = NULL;
    yres->ctx.queries_finished = finished;

    return sxi_cluster_query_ev(yres->cbdata, conns, yres->job_host, REQ_GET, yres->resquery, NULL, 0, jobres_setup_cb, jobres_cb);
}

int sxi_job_wait(sxi_conns_t *conns, sxi_jobs_t *jobs, unsigned *successful)
{
    unsigned finished;
    unsigned alive;
    unsigned pending;
    unsigned errors;
    long delay = 0;
    unsigned i;
    struct timeval tv0, tv1;
    int ret = 0;
    int rc = 0;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if (!jobs) {
        sxi_seterr(sx, SXE_EARG, "null arg to job_wait");
        return -1;
    }
    if (successful)
        *successful = 0;
    while(1) {
        gettimeofday(&tv0, NULL);
        for (i=0;i<jobs->n;i++) {
            if (!jobs->jobs[i])
                continue;
            delay = sxi_job_min_delay(jobs->jobs[i]);
            if (sxi_job_status_ev(conns, &jobs->jobs[i], &finished, successful) == -1) {
                ret = -1;
                continue;
            }
        }
        /* finish callback might be called even if sending the query failed
         * early in some situations, so count the number of still alive queries in
         * a separate loop */
        finished = alive = pending = errors = 0;
        for (i=0;i<jobs->n;i++) {
            if (jobs->jobs[i]) {
                if (!sxi_cbdata_is_finished(jobs->jobs[i]->cbdata))
                    alive++;
                switch (jobs->jobs[i]->status) {
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
        SXDEBUG("Pending %d jobs, %d errors, %d queries", pending, errors, alive);
        if (alive) {
            while (finished != alive && rc != -1) {
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
        gettimeofday(&tv1, NULL);
        delay -= (tv1.tv_sec - tv0.tv_sec) * 1000 + (tv1.tv_usec - tv0.tv_usec)/1000;
        if (delay <= 0) delay = 1;
        SXDEBUG("Sleeping %ld ms...", delay);
        usleep(delay * 1000);
    }
    for (i=0;i<jobs->n;i++) {
        if (jobs->jobs[i])
            sxi_job_result(sx, &jobs->jobs[i], successful);
    }
    return ret;
}

int sxi_job_submit_and_poll(sxi_conns_t *conns, sxi_hostlist_t *hlist, const char *query, void *content, size_t content_size)
{
    int rc;
    sxi_job_t *jtable[1] = {
        sxi_job_submit(conns, hlist, REQ_PUT, query, NULL, content, content_size, NULL, NULL)
    };
    if (!jtable[0])
        return -1;
    sxi_jobs_t jobs = { jtable, 1 };
    rc = sxi_job_wait(conns, &jobs, NULL);
    sxi_job_free(jtable[0]);
    return rc;
}

sxi_job_t JOB_NONE;
