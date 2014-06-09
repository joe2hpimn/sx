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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>
#include <pwd.h>

#include "libsx-int.h"
#include "ltdl.h"
#include "filter.h"
#include "clustcfg.h"
#include "misc.h"
#include "vcrypto.h"

struct _sxc_client_t {
    char errbuf[65536];
    char *tempdir;
    int last_error;
    int verbose;
    struct sxi_logger log;
    int (*confirm)(const char *prompt, int default_answer);
    struct filter_ctx fctx;
    struct tempfile_track temptrack;
    const char *op;
    char *op_host;
    char *op_vol;
    char *op_path;
    char *confdir;
    alias_list_t *alias;
};

static const char *guess_tempdir(void) {
    const char *ret;

    ret = getenv("TMPDIR");
    if(!ret)
	ret = getenv("TEMP");
    if(!ret)
	ret = "/tmp";

    return ret;
}

sxc_client_t *sxc_init(const char *client_version, const sxc_logger_t *func, int (*confirm)(const char *prompt, int def)) {
    sxc_client_t *sx;
    struct sxi_logger l;
    unsigned int config_len;
    const char *home_dir;
    struct passwd *pwd;


    if (!func)
        return NULL;
    memset(&l, 0, sizeof(l));
    l.max_level = SX_LOG_DEBUG;
    l.func = func;

    const char *this_version = sxc_get_version();
    if (!client_version || strcmp(client_version, this_version)) {
        sxi_log_msg(&l, "sxc_init", SX_LOG_CRIT, "Version mismatch: Our version '%s' - library version '%s'",
                    client_version, this_version);
        return NULL;
    }

    /* FIXME THIS IS NOT THREAD SAFE */
    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);
    if (sxi_crypto_check_ver(&l))
        return NULL;
    CURLcode rc = curl_global_init(CURL_GLOBAL_ALL);
    if (rc) {
        sxi_log_msg(&l, "sxc_init", SX_LOG_CRIT, "Failed to initialize libcurl: %s",
                    curl_easy_strerror(rc));
        return NULL;
    }
    sx = calloc(1, sizeof(struct _sxc_client_t));
    if (!sx) {
        sxi_log_syserr(&l, "sxc_init", SX_LOG_CRIT, "Failed to allocate sx structure");
        return NULL;
    }
    if(lt_dlinit()) {
        const char *err = lt_dlerror();
	sx->fctx.filter_cnt = -1;
        sxi_log_syserr(&l, "sxc_init", SX_LOG_CRIT, "Failed to initialize libltdl: %s",
                       err ? err : "");
    }
    sx->log.max_level = SX_LOG_NOTICE;
    sx->log.func = func;
    sx->confirm = confirm;

    /* To set configuration directory use sxc_set_confdir(). Default value is taken from HOME directory. */
    home_dir = getenv("HOME");
    if(!home_dir) {
        pwd = getpwuid(geteuid());
        if(pwd)
            home_dir = pwd->pw_dir;
    }
    if(!home_dir) {
        sx->confdir = NULL;
    } else {
        config_len = strlen(home_dir) + strlen("/.sx");
        sx->confdir = malloc(config_len + 1);
        if(!sx->confdir) {
            sxi_log_syserr(&l, "sxc_init", SX_LOG_ERR, "Could not allocate memory for configuration directory");
            return NULL;
        }
        snprintf(sx->confdir, config_len + 1, "%s/.sx", home_dir);
    }
    sx->alias = NULL;
    if(sxc_set_tempdir(sx, NULL)) {
	sxi_log_syserr(&l, "sxc_init", SX_LOG_CRIT, "Failed to set temporary path");
	sxc_shutdown(sx, 0);
	return NULL;
    }

    return sx;
}

void sxc_shutdown(sxc_client_t *sx, int signal) {
    int i;
    if(!sx)
	return;
    if(!signal)
        sxi_clear_operation(sx);
    if(sx->temptrack.slots) {
	for(i = 0; i < sx->temptrack.slots; i++) {
	    if(sx->temptrack.names[i]) {
		/* TODO: for win32 we may also need to track descriptors */
		unlink(sx->temptrack.names[i]);
		if(!signal)
		    free(sx->temptrack.names[i]);
	    }
	}
	if(!signal)
	    free(sx->temptrack.names);
    }

    if(!signal) {
        /* See sxc_set_confdir */
        free(sx->confdir);
        sxi_free_aliases(sx->alias);
        free(sx->alias);

        if (sx->log.func && sx->log.func->close) {
            sx->log.func->close(sx->log.func->ctx);
        }
	sxi_filter_unloadall(sx);
	free(sx->tempdir);
	free(sx);
	lt_dlexit();
	curl_global_cleanup();
        sxi_vcrypto_cleanup();
    }
}

void sxc_set_verbose(sxc_client_t *sx, int enabled) {
    if (!sx)
        return;
    sx->verbose = enabled;
    if (enabled)
        sxi_log_enable_level(&sx->log, SX_LOG_INFO);
    else
        sxi_log_enable_level(&sx->log, SX_LOG_NOTICE);
}

void sxi_clear_operation(sxc_client_t *sx)
{
    if (!sx)
        return;
    free(sx->op_host);
    free(sx->op_vol);
    free(sx->op_path);
    sx->op_host = NULL;
    sx->op_vol = NULL;
    sx->op_path = NULL;
    sx->op = NULL;
}

const char * sxi_get_operation(sxc_client_t *sx)
{
    return sx ? sx->op : NULL;
}

void sxi_set_operation(sxc_client_t *sx, const char *op, const char *cluster, const char *vol, const char *path)
{
    if (!sx)
        return;
    sxi_clear_operation(sx);
    sx->op = op;
    if (cluster)
        sx->op_host = strdup(cluster);
    if (vol)
        sx->op_vol = strdup(vol);
    if (path)
        sx->op_path = strdup(path);
}

/* FIXME make the output stream settable, default to stderr */
void sxc_set_debug(sxc_client_t *sx, int enabled) {
    if (!sx)
        return;
    if(enabled) {
        sxi_log_enable_level(&sx->log, SX_LOG_DEBUG);
	SXDEBUG("Debug mode is now enabled");
    } else {
        if (sxi_log_is_debug(&sx->log))
	    SXDEBUG("Debug mode is now disabled");
        sxc_set_verbose(sx, sx->verbose);
    }
}

int sxi_is_debug_enabled(sxc_client_t *sx) {
    if(!sx)
	return 0;
    return sxi_log_is_debug(&sx->log);
}

void sxi_debug(sxc_client_t *sx, const char *fn, const char *fmt, ...) {
    va_list ap;
    if (sx && sxi_log_is_debug(&sx->log)) {
        va_start(ap, fmt);
        sxi_vlog_msg(&sx->log, fn, SX_LOG_DEBUG, fmt, ap);
        va_end(ap);
    }
}

void sxi_info(sxc_client_t *sx, const char *fmt, ...) {
    va_list ap;
    if (!sx)
        return;
    va_start(ap, fmt);
    sxi_vlog_msg(&sx->log, NULL, SX_LOG_INFO, fmt, ap);
    va_end(ap);
}

void sxi_notice(sxc_client_t *sx, const char *fmt, ...) {
    va_list ap;
    if (!sx)
        return;
    va_start(ap, fmt);
    sxi_vlog_msg(&sx->log, NULL, SX_LOG_NOTICE, fmt, ap);
    va_end(ap);
}

const char *sxi_get_tempdir(sxc_client_t *sx) {
    if(!sx)
	return guess_tempdir();
    return sx->tempdir;
}

int sxc_set_tempdir(sxc_client_t *sx, const char *tempdir) {
    char *newtmp;

    if(!sx)
	return -1;

    if(!tempdir)
	tempdir = guess_tempdir();

    newtmp = strdup(tempdir);
    if(!newtmp) {
	sxi_seterr(sx, SXE_EMEM, "Failed to set temporary directory: Out of memory");
	return -1;
    }

    free(sx->tempdir);
    sx->tempdir = newtmp;

    return 0;
}

struct filter_ctx *sxi_get_fctx(sxc_client_t *sx) {
    if(!sx)
	return NULL;
    return &sx->fctx;
}

struct tempfile_track *sxi_get_temptrack(sxc_client_t *sx) {
    if(!sx)
	return NULL;
    return &sx->temptrack;
}

const sxf_handle_t *sxc_filter_list(sxc_client_t *sx, int *count)
{
    if(!sx || sx->fctx.filter_cnt < 1)
        return NULL;

    *count = sx->fctx.filter_cnt;
    return sx->fctx.filters;
}

int sxc_geterrnum(sxc_client_t *sx) {
    if(!sx)
	return -1;
    return sx->last_error;
}

const char *sxc_geterrmsg(sxc_client_t *sx) {
    if(!sx)
	return NULL;
    return sx->errbuf;
}

void sxc_clearerr(sxc_client_t *sx) {
    if(!sx)
	return;
    sx->last_error = SXE_NOERROR;
    strcpy(sx->errbuf, "No error");
}

void sxi_seterr(sxc_client_t *sx, enum sxc_error_t err, const char *fmt, ...) {
    va_list ap;

    if(!sx)
	return;
    va_start(ap, fmt);
    if (sx->last_error == SXE_NOERROR) {
        sx->last_error = err;
        vsnprintf(sx->errbuf, sizeof(sx->errbuf) - 1, fmt, ap);
        sx->errbuf[sizeof(sx->errbuf)-1] = '\0';
        sxi_debug(sx, "sxi_seterr", "%s", sx->errbuf);
    } else {
        sxi_vlog_msg(&sx->log, "sxi_seterr_skip", SX_LOG_DEBUG, fmt, ap);
    }
    va_end(ap);
}

void sxi_setclusterr(sxc_client_t *sx, const char *nodeid, const char *reqid, int status,
                     const char *msg, const char *details)
{
    char httpcode[16];
    if (!sx)
        return;
    if (!*msg) {
        snprintf(httpcode, sizeof(httpcode), "HTTP code %d", status);
        msg = httpcode;
    }
    sxi_fmt_start(&sx->log.fmt);
    sxi_fmt_msg(&sx->log.fmt, "Failed to %s: %s (", sx->op ? sx->op : "query cluster", msg);
    if (sx->op_host) {
        sxi_fmt_msg(&sx->log.fmt, "sx://%s", sx->op_host);
        if (sx->op_vol) {
            sxi_fmt_msg(&sx->log.fmt, "/%s", sx->op_vol);
            if (sx->op_path) {
                sxi_fmt_msg(&sx->log.fmt, "/%s", sx->op_path);
            }
        }
    }
    sxi_fmt_msg(&sx->log.fmt," on");
    if (nodeid)
        sxi_fmt_msg(&sx->log.fmt, " node:%s", nodeid);
    if (reqid)
        sxi_fmt_msg(&sx->log.fmt, " reqid:%s", reqid);
    sxi_fmt_msg(&sx->log.fmt, ")");
    if (status < 400 || status >= 500) {
        /* do not print details on 40x */
        if (sx->verbose && details && *details) {
            sxi_fmt_msg(&sx->log.fmt, "\nHTTP %d: %s", status, details);
        }
    }
    sxi_seterr(sx, status == 403 ? SXE_EAUTH : SXE_ECOMM, "%s", sx->log.fmt.buf);
    sxi_clear_operation(sx);
    SXDEBUG("Cluster query failed (HTTP %d): %s", status, sx->errbuf);
    if (details && *details)
        SXDEBUG("Cluster error: %s", details);
}

void sxi_setsyserr(sxc_client_t *sx, enum sxc_error_t err, const char *fmt, ...) {
    va_list ap;

    if(!sx)
	return;
    sxi_fmt_start(&sx->log.fmt);
    va_start(ap, fmt);
    sxi_vfmt_syserr(&sx->log.fmt, fmt, ap);
    va_end(ap);

    sxi_seterr(sx, err, "%s", sx->log.fmt.buf);
}

const sxc_filter_t* sxc_get_filter(const sxf_handle_t *handle)
{
    if(!handle)
	return NULL;
    return handle->f;
}

int sxc_filter_msg(const sxf_handle_t *h, int level, const char *format, ...)
{
    int printed = 0;
    va_list arg;
    if (!h || !h->sx)
        return 0;
    va_start(arg, format);
    const char *fn = h->f && h->f->shortname ? h->f->shortname : "filter";
    sxi_vlog_msg(&h->sx->log, fn, level, format, arg);
    va_end(arg);

    return printed;
}

void sxc_loglasterr(sxc_client_t *sx)
{
    if (!sx)
        return;
    sxi_log_msg(&sx->log, NULL, SX_LOG_ERR, "%s", sxc_geterrmsg(sx));
}

int sxi_confirm(sxc_client_t *sx, const char *prompt, int default_answer)
{
    /* if there's no confirm callback always assume true */
    if(!sx || !sx->confirm)
	return 1;

    return sx->confirm(prompt, default_answer);
}

/* Set configuration directory */
int sxc_set_confdir(sxc_client_t *sx, const char *config_dir) 
{
    char *tmp_confdir = NULL;
    if(!sx || !config_dir)
        return 1;

    /* Try to duplicate string and check it */
    tmp_confdir = strdup(config_dir);
    if(!tmp_confdir) {
        sxi_seterr(sx, SXE_EMEM, "Could not allocate memory for configuration directory name");
        return 1;
    }

    free(sx->confdir);
    sx->confdir = tmp_confdir;
    return 0;
}

/* Get configuration directory full name */
const char *sxc_get_confdir(sxc_client_t *sx) {
    if(!sx)
        return NULL;

    return sx->confdir;
}

alias_list_t *sxi_get_alias_list(sxc_client_t *sx) {
    if(!sx->alias) {
        if(sxi_load_aliases(sx, &sx->alias)) {
            sxi_seterr(sx, SXE_EMEM, "Could not list aliases: %s", sxc_geterrmsg(sx));
        }
    }
    return sx->alias;
}
