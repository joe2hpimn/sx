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
#include "sxlog.h"
#include <string.h>
#include <errno.h>
#include <stdarg.h>

void sxi_fmt_start(struct sxi_fmt *fmt)
{
    if (!fmt)
        return;
    fmt->buf[0] = '\0';
    fmt->pos = 0;
}

static const char truncated[] = "[...]";
static int sxi_fmt_available(const struct sxi_fmt *fmt)
{
    return fmt ? (int) (sizeof(fmt->buf) - sizeof(truncated) - fmt->pos) : -1;
}

void sxi_vfmt_msg(struct sxi_fmt *fmt, const char *format, va_list ap)
{
    int e = errno;
    int size = sxi_fmt_available(fmt);
    int n;
    do {
        if (size <= 0)
            break;/* already truncated */
        n = vsnprintf(fmt->buf + fmt->pos, size, format, ap);
        if (n > size) {
            memcpy(&fmt->buf[sizeof(fmt->buf) - sizeof(truncated)], truncated, sizeof(truncated));
            fmt->pos = sizeof(fmt->buf);
            break;
        }
        fmt->pos += n;
    } while(0);
    errno = e;
}

void sxi_fmt_msg(struct sxi_fmt *fmt, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sxi_vfmt_msg(fmt, format, ap);
    va_end(ap);
}

void sxi_vfmt_syserr(struct sxi_fmt *fmt, const char *format, va_list ap)
{
    int e = errno;
    if (!fmt)
        return;
    sxi_vfmt_msg(fmt, format, ap);
    /* FIXME: make sure this is the XSI version! */
    if (strerror_r(e, fmt->errbuf, sizeof(fmt->errbuf)))
        sxi_fmt_msg(fmt, ": (unable to format system error message)");
    else
        sxi_fmt_msg(fmt, ": %s", fmt->errbuf);
    errno = e;
}

void sxi_fmt_syserr(struct sxi_fmt *fmt, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sxi_vfmt_syserr(fmt, format, ap);
    va_end(ap);
}


void sxi_log_set_level(struct sxi_logger *l, int level)
{
    if (!l)
        return;
    l->max_level = level;
}

void sxi_log_enable_level(struct sxi_logger *l, int level)
{
    l->max_level = l->max_level < level ? level : l->max_level;
}

static void sxi_log_call(struct sxi_logger *l, int level)
{
    if (!l || !l->func)
        return;
    l->func->log(l->func->ctx, l->func->argv0, level, l->fmt.buf);
}

void sxi_vlog_msg(struct sxi_logger *l, const char *fn, int level, const char *format, va_list ap)
{
    if (!l)
        return;
    if (level > l->max_level) /* SX_LOG_EMERG has lowest value, SX_LOG_DEBUG highest */
        return;

    sxi_fmt_start(&l->fmt);
    if (fn)
        sxi_fmt_msg(&l->fmt, "[%s]: ", fn);
    sxi_vfmt_msg(&l->fmt, format, ap);
    sxi_log_call(l, level);
}

void sxi_vlog_syserr(struct sxi_logger *l, const char *fn, int level, const char *format, va_list ap)
{
    if (!l)
        return;

    if (level > l->max_level) /* SX_LOG_ALERT has lowest value, SX_LOG_DEBUG highest */
        return;
    sxi_fmt_start(&l->fmt);
    sxi_vfmt_syserr(&l->fmt, format, ap);
    if (fn)
        sxi_fmt_msg(&l->fmt, " [in %s]", fn);
    sxi_log_call(l, level);
}

void sxi_log_msg(struct sxi_logger *l, const char *fn, int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sxi_vlog_msg(l, fn, level, format, ap);
    va_end(ap);
}

void sxi_log_syserr(struct sxi_logger *l, const char *fn, int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sxi_vlog_syserr(l, fn, level, format, ap);
    va_end(ap);
}

static void sxi_noerr_log(void *ctx, const char *argv0, int level, const char *msg)
{
    FILE *out = (FILE*)ctx;

    if (level != SX_LOG_INFO)
        return;

    if (!out)
        out = stdout;
    fprintf(out, "%s\n", msg);
}


static void sxi_default_log(void *ctx, const char *argv0, int level, const char *msg)
{
    FILE *out = (FILE*)ctx;
    if (!out)
        out = level == SX_LOG_INFO ? stdout : stderr;
    switch(level) {
        case SX_LOG_DEBUG:
            fprintf(out,"%s\n", msg);
            break;
        case SX_LOG_INFO:/* fall-through */
        case SX_LOG_NOTICE:
            fprintf(out,"%s\n", msg);
            break;
        default:
            fprintf(out,"%s: %s\n", argv0, msg);
            break;
    }
}

const char *sxi_log_appname(const char *argv0)
{
    const char *bname;
    if(!argv0)
        return NULL;
    bname = strrchr(argv0, '/');
    if(bname && *bname && bname[1])
        return bname+1;
    return argv0;
}

const sxc_logger_t* sxc_default_logger(sxc_logger_t *logger, const char *argv0)
{
    if (!argv0)
        argv0 = "";
    if (!logger) {
        sxi_default_log(NULL, argv0, SX_LOG_CRIT, "Null argument to logger initializer");
        return NULL;
    }
    logger->log = sxi_default_log;
    logger->ctx = NULL;
    logger->argv0 = sxi_log_appname(argv0);
    logger->close = NULL;
    return logger;
}

static void close_log(void *ctx)
{
    FILE *f = (FILE*)ctx;
    if (!f)
        return;
    fclose(f);
}

const sxc_logger_t* sxc_file_logger(sxc_logger_t *logger, const char *argv0, const char *file, int no_errors)
{
    FILE *f;
    if (!argv0)
        argv0 = "";
    if (!logger) {
        sxi_default_log(NULL, argv0, SX_LOG_CRIT, "Null argument to logger initializer");
        return NULL;
    }
    f = fopen(file,"w");
    if (!f) {
        struct sxi_fmt fmt;
        sxi_fmt_start(&fmt);
        sxi_fmt_syserr(&fmt, "Failed to open logfile '%s'", file);
        sxi_default_log(NULL, argv0, SX_LOG_CRIT, fmt.buf);
        return NULL;
    }
    logger->log = no_errors ? sxi_noerr_log : sxi_default_log;
    logger->ctx = f;
    logger->argv0 = sxi_log_appname(argv0);
    logger->close = close_log;
    return logger;
}
