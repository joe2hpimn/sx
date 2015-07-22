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

#ifndef FCGI_UTILS_H
#define FCGI_UTILS_H
#include "config.h"

#include <stdio.h>
#include <time.h>

#include "fcgi-server.h"
#include "log.h"
#include "hashfs.h"
#include "job_common.h"

#define CGI_PUTD(data, len)			\
    do {					\
	if(FCGX_PutStr((const char *)(data), len, fcgi_out) < 0)	\
	    DEBUG("FCGX_PutStr() failed: %s", strerror(FCGX_GetError(fcgi_out)));	\
    } while(0)

#define CGI_PUTS(s)				\
    do {					\
	if(FCGX_PutS(s, fcgi_out) < 0)		\
	    DEBUG("FCGX_PutS() failed");		\
    } while(0)

#define CGI_PUTC(c)				\
    do {					\
	if(FCGX_PutChar(c, fcgi_out) < 0)		\
	    DEBUG("FCGX_PutChar() failed");	\
    } while(0)

static inline int FMT_PRINTF(2,3) FCGX_FPrintF_chk(FCGX_Stream *stream, const char *fmt, ...)
{
    int rc;
    va_list ap;
    va_start(ap, fmt);
    rc = FCGX_VFPrintF(stream, fmt, ap);
    va_end(ap);
    return rc;
}

#define CGI_PRINTF(...)				\
    do {					\
	if(FCGX_FPrintF_chk(fcgi_out, __VA_ARGS__) < 0)	\
	    DEBUG("FCGX_FPrintF() failed");	\
    } while(0)

#define CGI_PUTLL(ll)				\
    do {					\
	char __llstr[24];			\
	sprintf(__llstr, "%lld", (long long)(ll));	\
	CGI_PUTS(__llstr);			\
    } while(0)

#define CGI_PUTT(t) CGI_PUTLL((uint64_t)(t))

#define SERVER_NAME "sx"
#define MAX_ARGS 256
#define REPLACEMENT_BATCH_SIZE (64*1024*1024)

extern char *volume, *path, *args[MAX_ARGS];
extern unsigned int nargs;
typedef enum { VERB_UNSUP, VERB_GET, VERB_HEAD, VERB_POST, VERB_PUT, VERB_DELETE, VERB_OPTIONS } verb_t;
extern verb_t verb;
extern uint8_t hashbuf[UPLOAD_CHUNK_SIZE];
extern uint8_t user[AUTH_UID_LEN];
extern sx_uid_t uid, common_id;
extern int64_t user_quota;

void send_server_info(void);
void handle_request(void);
void send_error(int errnum, const char *message);
void send_partial_error(const char *message, rc_ty rc);
int64_t content_len(void);
void send_home(void);
int is_authed(void);
int is_sky(void);
void send_authreq(void);
int get_priv(int volume_priv);
int has_priv(sx_priv_t priv);
int is_reserved(void);
int volume_exists(void);
int arg_num(const char *arg);
#define has_arg(a) (arg_num(a) >= 0)
const char *get_arg(const char *arg);
int get_arg_uint(const char *arg);
int arg_is(const char *arg, const char *ref);
void json_send_qstring(const char *s);
int json_qstring(char *buf, unsigned int buflen, const char *s);
void send_httpdate(time_t t);
void send_qstring_hash(const sx_hash_t *h);
int is_http_10(void);
int is_https(void);
int httpdate_to_time_t(const char *d, time_t *t);
int get_body_chunk(char *buf, int buflen);
void auth_complete(void);
#define MAX_KEEPALIVE_INTERVAL 10
void send_keepalive(void);
void send_nodes(const sx_nodelist_t *nodes);
void send_nodes_randomised(const sx_nodelist_t *nodes);
void send_job_info(job_t job);
#define NO_LAST_MODIFIED 0xffffffff
int is_object_fresh(const sx_hash_t *etag, char type, unsigned int last_modified);

#define quit_errmsg(errnum, message) do { send_error(errnum, message); return; } while(0)
#define quit_errnum(errnum) do { send_error(errnum, NULL); return; } while(0)
#define quit_itererr(message, http) do { send_partial_error(message, http); return; } while(0)
#define quit_home() do { send_home(); return; } while(0)
#define quit_unless_authed() do { if(!is_authed()) { send_authreq(); return; } } while(0)
#define quit_unless_has(priv) do { if(!has_priv(priv)) { quit_errmsg(403, "Permission denied: not enough privileges"); return; } } while(0)
#define quit_unless_volume_exists() do { int __volex = volume_exists(); if(__volex > 0) break; if(__volex == 0) quit_errnum(404); quit_errmsg(500, "Cannot determine if the requested volume is available"); } while(0)

#endif
