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

#ifndef LOG_H
#define LOG_H
#include "types.h"
#include "gnuc.h"
#include "sx.h"
#include <errno.h>
#include "../libsxclient/src/sxlog.h"

extern sxc_logger_t server_logger;
extern struct sxi_logger logger;

void log_init(const sxc_logger_t **custom_logger, const char *argv0, const char *logfile, int foreground);
void log_done(void);
void log_reopen(void);
void log_setminlevel(sxc_client_t *sx, int prio);

/* verbose */
#define INFO(...) sxi_log_msg(&logger, __func__, SX_LOG_INFO,  __VA_ARGS__)

/* warnings meant for nginx's error log */
#define NOTICE(...) sxi_log_msg(&logger, __func__, SX_LOG_NOTICE, __VA_ARGS__)

/* warnings and errors: meant for syslog */
#define WARN(...) sxi_log_msg(&logger, __func__, SX_LOG_WARNING, __VA_ARGS__)

#define CRIT(...) sxi_log_msg(&logger, __func__, SX_LOG_CRIT, __VA_ARGS__)
/* errors that require immediate attention:
 *  running out of disk space
 *  node down
 *  etc.
 *  But not for recoverable errors (like EMEM), or even for
 *  errors that would otherwise quit the process (we'll get respawned anyway) */
#define ALERT(...) sxi_log_msg(&logger, __func__, SX_LOG_ALERT, __VA_ARGS__)

/* Print strerror(errno) after the actual message.
 * errno is preserved by these functions */
#define PINFO(...) sxi_log_syserr(&logger, __func__, SX_LOG_INFO,  __VA_ARGS__)
#define PNOTICE(...) sxi_log_syserr(&logger, __func__, SX_LOG_NOTICE, __VA_ARGS__)
#define PWARN(...) sxi_log_syserr(&logger, __func__, SX_LOG_WARNING, __VA_ARGS__)
#define PCRIT(...) sxi_log_syserr(&logger, __func__, SX_LOG_CRIT, __VA_ARGS__)

#define DEBUG(...) do {\
    if (UNLIKELY(sxi_log_is_debug(&logger))) \
        sxi_log_msg(&logger, __func__, SX_LOG_DEBUG, __VA_ARGS__);\
    } while(0)

void log_sslerrs(const char *func);

int msg_new_id(void);
const char *msg_get_id(void);

/* log user-visible errors for 50x */
void msg_add_sslerr(const char *func);
void msg_add_detail(const char *func, const char *cat, const char *fmt, ...) FMT_PRINTF(3,4);
#define NULLARG() msg_add_detail(__func__,"NULLARG","Called with NULL argument (at %s:%d)", __FILE__, __LINE__)
#define OOM() msg_add_detail(__func__,"OOM","Out of memory (at %s:%d)", __FILE__,__LINE__)
#define BADSTATE(msg) msg_add_detail(__func__,"BADSTATE","%s (at %s:%d)", msg, __FILE__, __LINE__)

#define SQLERR(q, msg)\
    do {\
      WARN("Query \"%s\" failed: (code 0x%x: %s) %s", sqlite3_sql(q),\
           sqlite3_extended_errcode(sqlite3_db_handle(q)),\
           sqlite3_errmsg(sqlite3_db_handle(q)), msg);\
      msg_add_detail(__func__,"SQLite error", "Query failed: %s", msg);\
    } while(0)

#define SQLPARAMERR(q, param)\
    do {\
      const char *err = sqlite3_errmsg(sqlite3_db_handle(q));\
      CRIT("Cannot bind parameter \"%s\" to query \"%s\": %s", param, sqlite3_sql(q), err);\
      msg_add_detail(__func__,"SQLite bind parameter %s: %s", param, err);\
    } while(0)

const char *msg_log_end(void);

void msg_set_reason(const char *fmt, ...) FMT_PRINTF(1,2);
void msg_set_errno_reason(const char *fmt, ...) FMT_PRINTF(1,2);
void msg_set_busy(void);
int msg_was_busy(void);
const char *msg_get_reason(void);

#endif
