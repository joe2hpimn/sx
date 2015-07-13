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

#ifndef SXLOG_H
#define SXLOG_H

#include "sx.h"
#include "gnuc.h"
#include <stdarg.h>

/* low-level logging functions, they all preserve errno */

/* log formatting */
struct sxi_fmt {
    char buf[65536];
    char errbuf[65536];
    int pos;
};

void sxi_fmt_start(struct sxi_fmt *fmt);
void sxi_fmt_msg(struct sxi_fmt *fmt, const char *format, ...) FMT_PRINTF(2, 3);
void sxi_fmt_syserr(struct sxi_fmt *fmt, const char *format, ...) FMT_PRINTF(2, 3);
void sxi_vfmt_msg(struct sxi_fmt *fmt, const char *format, va_list ap) FMT_PRINTF(2, 0);
void sxi_vfmt_syserr(struct sxi_fmt *fmt, const char *format, va_list ap) FMT_PRINTF(2, 0);

struct sxi_logger {
    int max_level;
    struct sxi_fmt fmt;
    const sxc_logger_t *func;
};

void sxi_log_set_level(struct sxi_logger *l, int level);
void sxi_log_enable_level(struct sxi_logger *l, int level);
static inline int sxi_log_is_debug(const struct sxi_logger *l)
{
    return l && l->max_level == SX_LOG_DEBUG;
}

void sxi_log_msg(struct sxi_logger *l, const char *fn, int level, const char *fmt, ...) FMT_PRINTF(4, 5);
void sxi_log_syserr(struct sxi_logger *l, const char *fn, int level, const char *fmt, ...) FMT_PRINTF(4, 5);
void sxi_vlog_msg(struct sxi_logger *l, const char *fn, int level, const char *fmt, va_list ap) FMT_PRINTF(4, 0);
void sxi_vlog_syserr(struct sxi_logger *l, const char *fn, int level, const char *fmt, va_list ap) FMT_PRINTF(4, 0);
const char *sxi_log_appname(const char *argv0);

#endif
