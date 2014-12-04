/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *  Special exception for linking this software with OpenSSL:
 *
 *  In addition, as a special exception, Skylable Ltd. gives permission to
 *  link the code of this program with the OpenSSL library and distribute
 *  linked combinations including the two. You must obey the GNU General
 *  Public License in all respects for all of the code used other than
 *  OpenSSL. You may extend this exception to your version of the program,
 *  but you are not obligated to do so. If you do not wish to do so, delete
 *  this exception statement from your version.
 */

#include "default.h"
#include "log.h"
#include "utils.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include "../libsx/src/sxlog.h"
#include "../libsx/src/misc.h"
#include "../libsx/src/cluster.h"
#include "../libsx/src/vcrypto.h"

static struct _sx_logger_ctx {
    pid_t pid;
    const char *file;
    int fd;
    int foreground;
} ctx = { 0, NULL, -1, 0 };

static void log_to_fd(const char *argv0, int fd, int prio, const char *msg)
{
    char buf[65536];
    const char *s;
    switch (prio) {
        case SX_LOG_ALERT:
            s = "ALERT";
            break;
        case SX_LOG_CRIT:
            s = "CRITICAL";
            break;
        case SX_LOG_WARNING:
            s = "Warning";
            break;
        case SX_LOG_NOTICE:
            s = "Notice";
            break;
        case SX_LOG_DEBUG:
            s = "DEBUG";
            break;
        default:
            s = "";
            break;
    }
    struct timeval tv;

    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(buf, sizeof(buf)-1,
             "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s[%d]: %-8s| %s",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (unsigned)tv.tv_usec/1000,
             argv0 ? argv0 : "", ctx.pid, s, msg);
    long len = strlen(buf);
    buf[len++] = '\n';
    buf[len] = '\0';
    const char *b = buf;
    while (len > 0) {
        ssize_t n = write(fd, b, len);
        if (n == -1 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        b += n;
        len -= n;
    }
}

static void dolog(void *_ctx, const char *argv0, int prio, const char *msg)
{
    /* TODO: just do the msg_add_detail here to store the message for the client... */
    switch (prio) {
        case SX_LOG_ALERT:
            syslog(LOG_ALERT, "%s", msg);
            break;
        case SX_LOG_CRIT:
            syslog(LOG_CRIT, "%s", msg);
            break;
        default:
            break;/* only log to syslog very important messages */
    }
    if (ctx.fd == -1) {
        if (prio > SX_LOG_INFO)
            syslog(LOG_ERR,"(no logfile): %s", msg);
        fprintf(stderr, "%s\n", msg);
        return;
    } else if(ctx.foreground)
        fprintf(stderr, "%s\n", msg);

    struct flock lck;

    memset(&lck, 0, sizeof(lck));
    /* lock whole file */
    lck.l_type = F_WRLCK;
    lck.l_whence = SEEK_SET;
    lck.l_start = 0;
    lck.l_len = 0;
    if (fcntl(ctx.fd, F_SETLKW, &lck) == -1) {
        syslog(LOG_CRIT,"Unable to lock logfile: %s", strerror(errno));
    } else {
        log_to_fd(argv0, ctx.fd, prio, msg);
        lck.l_type = F_UNLCK;
        if (fcntl(ctx.fd, F_SETLK, &lck) == -1)
            syslog(LOG_CRIT, "Cannot unlock logfile: %s", strerror(errno));
    }
}

sxc_logger_t server_logger;
struct sxi_logger logger;

void log_init(const sxc_logger_t **custom_logger, const char *argv0, const char *logfile, int foreground)
{
    server_logger.ctx = &ctx;
    server_logger.log = dolog;
    server_logger.close = NULL;
    server_logger.argv0 = sxi_log_appname(argv0);
    if (!*custom_logger)
        *custom_logger = &server_logger;

    logger.max_level = LOG_INFO;
    logger.func = *custom_logger;
    openlog(server_logger.argv0, LOG_PID | LOG_CONS | LOG_NDELAY | LOG_NOWAIT, LOG_USER);
    ctx.pid = getpid();
    ctx.file = logfile;
    ctx.foreground = foreground;
    if (ctx.fd == -1) {
        if (!ctx.file)
            return;
        ctx.fd = open(ctx.file, O_CREAT | O_WRONLY | O_APPEND, 0640);
        if (ctx.fd == -1) {
            int e = errno;
            syslog(LOG_CRIT, "Unable to open logfile '%s': %s", ctx.file, strerror(e));
            fprintf(stderr, "Unable to open logfile '%s': %s\n", ctx.file, strerror(e));
        }
    }
}

void log_done(void)
{
    if (ctx.fd != -1) {
        close(ctx.fd);
        ctx.fd = -1;
    }
    closelog();
}

void log_reopen(void)
{
    if (ctx.fd != -1 && ctx.file) {
        close(ctx.fd);
        ctx.fd = open(ctx.file, O_CREAT | O_WRONLY | O_APPEND, 0640);
        if (ctx.fd == -1)
            syslog(LOG_CRIT, "Failed to (re)open logfile '%s': %s", ctx.file, strerror(errno));
    }
}

void log_setminlevel(sxc_client_t *sx, int prio)
{
    sxi_log_set_level(&logger, prio);
    if (prio == SX_LOG_DEBUG) {
        sxc_set_debug(sx, 1);
    }
    if (prio < SX_LOG_INFO)
        sxc_set_verbose(sx, 0);
}

static int64_t counter;
static struct {
    char reason[65536];
    char details[65536];
    char id[128];
    unsigned n;
    int busy;
} log_record;

static void append(const char *s)
{
    if (!s)
        return;
    unsigned len = strlen(s);
    if (log_record.n + len >= sizeof(log_record.details)) {
        log_record.details[sizeof(log_record.details)-2] = '!';
        log_record.details[sizeof(log_record.details)-1] = '\0';
        return;
    }
    memcpy(log_record.details + log_record.n, s, len);
    log_record.n += len;
}

void msg_add_detail(const char *func, const char *cat, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    append("{");
    append(cat);
    append("}:");
    if (func) {
        append("[");
        append(func);
        append("]: ");
    }
    append(" ");
    log_record.n += vsnprintf(log_record.details + log_record.n,
                              sizeof(log_record.details) - log_record.n,fmt,
                              ap);
    if (log_record.n >= sizeof(log_record.details))
        /* required due to vsnprintf's return value */
        log_record.n = sizeof(log_record.details)-1;
    va_end(ap);
    append("| ");
}

void msg_set_reason(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_record.reason, sizeof(log_record.reason), fmt, ap);
    va_end(ap);
    log_record.reason[sizeof(log_record.reason)-1] = '\0';
    DEBUG("Reason: %s", log_record.reason);
    msg_add_detail(NULL, "Reason", "%s", log_record.reason);
}

void msg_set_errno_reason(const char *fmt, ...)
{
    char errbuf[256];
    int e = errno;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_record.reason, sizeof(log_record.reason), fmt, ap);
    va_end(ap);
    log_record.reason[sizeof(log_record.reason)-1] = '\0';
    if (strerror_r(e, errbuf, sizeof(errbuf)) == -1) {
        msg_add_detail(NULL, "Reason", "%s: errno %d", log_record.reason, e);
    } else {
        errbuf[sizeof(errbuf)-1] = '\0';
        msg_add_detail(NULL, "Reason", "%s: %s", log_record.reason, errbuf);
    }
    errno = e;
}


const char *msg_get_reason(void)
{
    return log_record.reason;
}

const char *msg_log_end(void)
{
    log_record.details[log_record.n] = '\0';
    if (*log_record.details)
        sxi_log_msg(&logger, NULL, SX_LOG_WARNING, "%s", log_record.details);
    return log_record.details;
}

int msg_new_id(void)
{
    unsigned char md[SXI_SHA1_BIN_LEN];
    pid_t p = getpid();
    unsigned len = sizeof(md);

    log_record.n = 0;
    log_record.busy = 0;
    log_record.reason[0] = '\0';
    log_record.id[0] = '\0';

    if (sxi_sha1_calc(&p, sizeof(p), &counter, sizeof(counter), md)) {
        WARN("Digest calculation failed");
        return -1;
    }
    counter++;
    char *id = sxi_b64_enc_core(md, len);
    if (!id) {
        WARN("Out of memory allocating b64 id");
        return -1;
    }
    sxi_strlcpy(log_record.id, id, sizeof(log_record.id));
    msg_add_detail(NULL,"ID","%s", id);
    free(id);
    return 0;
}

const char *msg_get_id(void)
{
    return log_record.id;
}

void msg_set_busy(void)
{
    log_record.busy = 1;
}

int msg_was_busy(void)
{
    return log_record.busy;
}
