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

#ifndef UTILS_H
#define UTILS_H
#include "default.h"

#include <sys/time.h>
#include <sys/types.h>

int bin2hex(const void *src, uint32_t src_len, char *dst, uint32_t dst_len);
int hex2bin(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len);
int hmac_compare(const unsigned char *hmac1, const unsigned char *hmac2, size_t len);
uint64_t MurmurHash64(const void *key, size_t len, unsigned int seed);

int wait_trigger(int pipe, float max_wait_sec, int *forced_awake);

extern const int hexchars[256];
static inline int hexcharval(unsigned char c) {
    return hexchars[c];
}

/* calculate avg, stdev, min/max on the fly */
typedef struct {
    unsigned n;
    double a;
    double q;
} stat_t;

typedef struct {
  double avg;
  double avg_ci;/* 95% confidence interval of the average itself */
  double rounded_avg;
  double rounded_avg_lo;
  double rounded_avg_hi;
} value_t;

static inline void stat_add(stat_t *s, double t)
{
    s->n++;
    double a_prev = s->a;
    s->a += (t - a_prev)/s->n;
    s->q += (t - a_prev) * (t - s->a);
}

void stat_get(const stat_t *s, value_t *v, double unit);


#define UUID_BINARY_SIZE 16
#define UUID_STRING_SIZE 36
typedef struct _sx_uuid_t {
    uint8_t binary[UUID_BINARY_SIZE];
    char string[UUID_STRING_SIZE+1];
} sx_uuid_t;

int uuid_generate(sx_uuid_t *u);
int uuid_from_string(sx_uuid_t *u, const char *s);
void uuid_from_binary(sx_uuid_t *u, const void *b);

int derive_key(const unsigned char *salt, unsigned slen,
               const unsigned char *ikm, unsigned ilen,
               const char *info,
               unsigned char *buf, int blen);

double timediff(struct timeval *time_start, struct timeval *time_end);

int encode_auth(const char *user, const unsigned char *key, unsigned key_size, char *auth, unsigned auth_size);
int encode_auth_bin(const uint8_t *userhash, const unsigned char *key, unsigned key_size, char *auth, unsigned auth_size);
int ssl_version_check(void);
const char *strptimegm(const char *s, const char *format, time_t *t);

int parse_usergroup(const char *usergroup, uid_t *uid, gid_t *gid);
int runas(const char *usergroup);

int cb_fail_null(void *ctx);
int cb_fail_boolean(void *ctx, int boolean);
int cb_fail_start_array(void *ctx);
int cb_fail_end_array(void *ctx);
int cb_fail_string(void *ctx, const unsigned char *s, size_t l);
int cb_fail_number(void *ctx, const char *s, size_t l);
int cb_fail_start_map(void *ctx);
int cb_fail_map_key(void *ctx, const unsigned char *s, size_t l);
int cb_fail_end_map(void *ctx);

const char *src_version(void);

#define WRAP(name, ...) wrap_##name##_impl(__VA_ARGS__, __func__)
#define wrap_malloc(...) WRAP(malloc, __VA_ARGS__)
void* wrap_malloc_impl(uint64_t size, const char *_f);
#define wrap_calloc(...) WRAP(calloc, __VA_ARGS__)
void* wrap_calloc_impl(uint32_t nmemb, uint64_t size, const char *_f);
#define wrap_realloc(...) WRAP(realloc, __VA_ARGS__)
void* wrap_realloc_impl(void *ptr, uint64_t size, const char *_f);
#define wrap_realloc_or_free(...) WRAP(realloc_or_free, __VA_ARGS__)
void* wrap_realloc_or_free_impl(void *ptr, uint64_t size, const char *_f);
#define wrap_strdup(...) WRAP(strdup, __VA_ARGS__)
char *wrap_strdup_impl(const char *src, const char *_f);
#define wrap_waitpid(...) WRAP(waitpid, __VA_ARGS__)
pid_t wrap_waitpid_impl(pid_t pid, int *status, int options, const char *_f);
#endif

/* tweaks */
extern int gc_interval;
extern double gc_max_batch_time;
extern double gc_yield_time;
extern int gc_slow_check;
extern float blockmgr_delay;
extern int db_min_passive_wal_pages;
extern int db_max_passive_wal_pages;
extern int db_max_restart_wal_pages;
extern int db_idle_restart;
extern int db_busy_timeout;
extern int db_max_mmapsize;
extern int db_custom_vfs;
extern int worker_max_wait;
extern int worker_max_requests;
extern int max_pending_user_jobs;
