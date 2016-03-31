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

#include "config.h"
#include "default.h"

#include "log.h"
#include "utils.h"
#include <stdlib.h>
#include <sys/select.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <unistd.h>
#include <ftw.h>
#include "isaac.h"
#include "../libsxclient/src/misc.h"
#include "../libsxclient/src/vcrypto.h"
#include "version.h"

static const char hexchar[16] = "0123456789abcdef";
int bin2hex(const void *src, uint32_t src_len, char *dst, uint32_t dst_len)
{
    const uint8_t *usrc = src;
    if(!src) {
        NULLARG();
        return -1;
    }
    if(dst_len < 2 * src_len + 1) {
        WARN("bad bin2hex input dst_len=%d, src_len=%d", dst_len, src_len);
	return -1;
    }
    for (uint32_t i = 0; i < src_len;i++) {
        uint8_t c = usrc[i];
        dst[0] = hexchar[c >> 4];
        dst[1] = hexchar[c & 0xf];
        dst += 2;
    }
    *dst = '\0';
    return 0;
}

const int hexchars[256] = {
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
     0,  1,  2,  3,   4,  5,  6,  7,     8,  9, -1, -1,  -1, -1, -1, -1,
    -1, 10, 11, 12,  13, 14, 15, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, 10, 11, 12,  13, 14, 15, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,

    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
};

int hex2bin(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len)
{
    if((src_len % 2) || (dst_len < src_len / 2))
	return -1;
    for (uint32_t i = 0; i < src_len; i += 2) {
        int32_t h = (hexcharval(src[i]) << 4) | hexcharval(src[i+1]);
        if (h < 0)
            return -1;
        dst[i >> 1] = h;
    }
    return 0;
}

uint64_t MurmurHash64(const void *key, size_t len, unsigned int seed)
{
	const unsigned int m = 0x5bd1e995;
	const int r = 24;
	unsigned int h1 = seed ^ len;
	unsigned int h2 = 0;
	unsigned int k1, k2;
	uint64_t h;
	const unsigned char * data = (const unsigned char *)key;

    while(len >= 8) {
	k1  = data[0];
	k1 |= (unsigned)data[1] << 8;
	k1 |= (unsigned)data[2] << 16;
	k1 |= (unsigned)data[3] << 24;
	k1 *= m; k1 ^= k1 >> r; 
	k1 *= m; h1 *= m;
	h1 ^= k1;
	data += 4;
	len -= 4;

	k2  = data[0];
	k2 |= (unsigned)data[1] << 8;
	k2 |= (unsigned)data[2] << 16;
	k2 |= (unsigned)data[3] << 24;
	k2 *= m; k2 ^= k2 >> r; 
	k2 *= m; h2 *= m;
	h2 ^= k2;
	data += 4;
	len -= 4;
    }

    if(len >= 4) {
	k1  = data[0];
	k1 |= (unsigned)data[1] << 8;
	k1 |= (unsigned)data[2] << 16;
	k1 |= (unsigned)data[3] << 24;
	k1 *= m; k1 ^= k1 >> r; 
	k1 *= m; h1 *= m;
	h1 ^= k1;
	data += 4;
	len -= 4;
    }

    switch(len) {
        case 3: h2 ^= (unsigned)data[2] << 16;
        case 2: h2 ^= (unsigned)data[1] << 8;
	case 1: h2 ^= data[0];
		h2 *= m;
    };

    h1 ^= h2 >> 18; h1 *= m;
    h2 ^= h1 >> 22; h2 *= m;
    h1 ^= h2 >> 17; h1 *= m;
    h2 ^= h1 >> 19; h2 *= m;

    h = h1;
    h = (h << 32) | h2;
    return h;
}

static double round_digits(double v, long n)
{
    double div = pow(10, n);
    return div * round(v / div);
}

static void round_precision(value_t *v)
{

    /* find number with least number of digits
     * within the interval */
    long n = floor(log10(v->avg));
    if (v->avg < 1e-7) {
        v->rounded_avg = v->rounded_avg_lo = v->rounded_avg_hi = 0.0;
        return;
    }
    double r, lo = v->avg - v->avg_ci, hi = v->avg + v->avg_ci;
    if (lo < 0) lo = 0; /* all our values are positive */
    do {
        r = round_digits(v->avg, n--);
    } while(r < lo || r > hi);
    v->rounded_avg = r;
    v->rounded_avg_lo = round_digits(lo, n);
    v->rounded_avg_hi = round_digits(hi, n);
}

void stat_get(const stat_t *s, value_t *v, double unit)
{
    if (!s->n) {
        memset(v, 0, sizeof(*v));
    } else {
        v->avg = s->a / unit;
        /* sample standard deviation */
        double stdev = sqrt(s->q / (s->n - 1)) / unit;
        double sem = stdev / sqrt(s->n);
/*        v->avg_ci = sem * tinv(0.05, s->n - 1);*/
        v->avg_ci = sem * 2.26;/* assuming n ~ 10 */

        /* we know avg with a precision of +- avg_ci,
         * so round away the digits that are imprecise */
        round_precision(v);
    }
}


int uuid_generate(sx_uuid_t *u) {
    if (sxi_rand_pseudo_bytes(u->binary, sizeof(u->binary))) {
        WARN("Failed to generate UUID");
        return -1;
    }

    /* UUID version 4 */
    u->binary[6] &= 0x0f;
    u->binary[6] |= 0x40;
    u->binary[8] &= 0x3f;
    u->binary[8] |= 0x80;

    sprintf(u->string, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	    u->binary[0], u->binary[1], u->binary[2], u->binary[3],
	    u->binary[4], u->binary[5], u->binary[6], u->binary[7],
	    u->binary[8], u->binary[9], u->binary[10], u->binary[11],
	    u->binary[12], u->binary[13], u->binary[14], u->binary[15]);
    return 0;
}

int uuid_from_string(sx_uuid_t *u, const char *s) {
    if(!u || !s)
	return 1;
    if(strlen(s) != 36 ||
       hex2bin(s, 8, u->binary, 4) ||
       s[8] != '-' ||
       hex2bin(s+9, 4, u->binary+4, 2) ||
       s[13] != '-' ||
       hex2bin(s+14, 4, u->binary+6, 2) ||
       s[18] != '-' ||
       hex2bin(s+19, 4, u->binary+8, 2) ||
       s[23] != '-' ||
       hex2bin(s+24, 12, u->binary+10, 6))
        return 1;

    memcpy(u->string, s, 37);
    return 0;
}

void uuid_from_binary(sx_uuid_t *u, const void *b) {
    memcpy(u->binary, b, sizeof(u->binary));
    sprintf(u->string, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	    u->binary[0], u->binary[1], u->binary[2], u->binary[3],
	    u->binary[4], u->binary[5], u->binary[6], u->binary[7],
	    u->binary[8], u->binary[9], u->binary[10], u->binary[11],
	    u->binary[12], u->binary[13], u->binary[14], u->binary[15]);
}

#define PWARNF(...) sxi_log_msg(&logger, _f, SX_LOG_WARNING, __VA_ARGS__)

int derive_key(const unsigned char *salt, unsigned slen,
               const unsigned char *ikm, unsigned ilen,
               const char *info,
               unsigned char *buf, int blen)
{
    /* RFC5869 */
    uint8_t prk[SXI_SHA1_BIN_LEN], md[SXI_SHA1_BIN_LEN];
    unsigned int mdlen = sizeof(prk);
    sxi_hmac_sha1_ctx *hmac_ctx = sxi_hmac_sha1_init();
    if (!hmac_ctx)
        return -1;

    if (!sxi_hmac_sha1_init_ex(hmac_ctx, salt, slen) ||
        !sxi_hmac_sha1_update(hmac_ctx, ikm, ilen) || /* Input Keying Material */
        !sxi_hmac_sha1_final(hmac_ctx, prk, &mdlen)) {
        /*SSLERR();*/
	sxi_hmac_sha1_cleanup(&hmac_ctx);
        return -1;
    }
    if (!sxi_hmac_sha1_init_ex(hmac_ctx, prk, mdlen) || /* PRK */
        !sxi_hmac_sha1_update(hmac_ctx, (const unsigned char*)info, strlen(info)) || /* T(0) || info */
        !sxi_hmac_sha1_update(hmac_ctx, (const unsigned char*)"\x1", 1) || /* || 0x01 */
        !sxi_hmac_sha1_final(hmac_ctx, md, &mdlen)) {
        /*SSLERR();*/
	sxi_hmac_sha1_cleanup(&hmac_ctx);
        return -1;
    }
    sxi_hmac_sha1_cleanup(&hmac_ctx);
    if (blen != mdlen) {
        WARN("bad hash length");
        return -1;
    }
    memcpy(buf, md, mdlen);
    return 0;
}

void* wrap_malloc_impl(uint64_t size, const char* _f)
{
    if (!size) {
        errno = EINVAL;
        PWARNF("Attempt to allocate 0 bytes");
        return NULL;
    }
    size_t s = size;
    if ((uint64_t)s != size) {
        errno = EOVERFLOW;
    } else {
        void *p = malloc(s);
        if (p)
            return p;
    }
    PWARNF("Failed to allocate %ju bytes", (uintmax_t)size);
    return NULL;
}

void* wrap_calloc_impl(uint32_t nmemb, uint64_t size, const char* _f)
{
    if (!nmemb || !size) {
        errno = EINVAL;
        PWARNF("Attempt to allocate 0 bytes (%u * %ju)", nmemb, (uintmax_t)size);
        return NULL;
    }
    size_t s = size;
    if ((uint64_t)s == size) {
        void *p = calloc(nmemb, size);
        if (p)
            return p;
    } else {
        errno = EOVERFLOW;
    }
    PWARNF("Failed to allocate %u * %ju bytes", nmemb, (uintmax_t)size);
    return NULL;
}

void* wrap_realloc_impl(void *ptr, uint64_t size, const char* _f)
{
    size_t s = size;
    if(!size)
	return NULL;
    if ((uint64_t)s == size) {
        void *p = realloc(ptr, size);
        if (p)
            return p;
    } else {
        errno = EOVERFLOW;
    }
    PWARNF("Failed to reallocate %ju bytes", (uintmax_t)size);
    return NULL;
}

void *wrap_realloc_or_free_impl(void *ptr, uint64_t size, const char* _f) {
    void *r = wrap_realloc(ptr, size);
    if(!r)
	free(ptr);
    return r;
}


char *wrap_strdup_impl(const char *src, const char* _f)
{
    if (!src) {
        PWARNF("Attempt to duplicate null string");
        return NULL;
    }
    char *p = strdup(src);
    if (p)
        return p;
    PWARNF("Failed to duplicate string of length %zu", strlen(src));
    return NULL;
}

pid_t wrap_waitpid_impl(pid_t pid, int *statusp, int options, const char* _f)
{
    int status = 0;
    pid_t p;
    do {
	p = waitpid(pid, &status, options);
    } while (p == -1 && errno == EINTR);
    if (statusp)
	*statusp = status;
    if (p == -1) {
	PWARNF("waitpid failed on pid %d", pid);
	return -1;
    }
    if (!p)
	return 0;
    if (WIFEXITED(status)) {
	int code = WEXITSTATUS(status);
	if (!code)
	    DEBUG("pid %d exited with code 0", p);
	else
	    INFO("pid %d exited with code %d", p, code);
    } else if (WIFSIGNALED(status)) {
	WARN("pid %d killed by signal %d", p, WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
	INFO("pid %d stopped by signal %d", p, WSTOPSIG(status));
    }
    return p;
}

double timediff(struct timeval *time_start, struct timeval *time_end) {
    int ds = 0, du = time_end->tv_usec - time_start->tv_usec;
    if(du < 0) {
	du += 1000000;
	ds--;
    }
    ds += time_end->tv_sec - time_start->tv_sec;
    return (double)ds + (double)du / 1000000.0f;
}

int ssl_version_check(void)
{
    return sxi_crypto_check_ver(&logger);
}

static const struct passwd *getuser(const char *name)
{
    char *end = NULL;
    long uid = strtol(name, &end, 10);
    errno = 0;
    if (end == name + strlen(name))
        return getpwuid(uid);
    return getpwnam(name);
}

static const struct group *getgroup(const char *name)
{
    char *end = NULL;
    long gid = strtol(name, &end, 10);
    errno = 0;
    if (end == name + strlen(name))
        return getgrgid(gid);
    return getgrnam(name);
}

int parse_usergroup(const char *usergroup, uid_t *uid, gid_t *gid)
{
    char *cpy, *group;
    const struct passwd *p;

    if(!usergroup || !uid || !gid) {
        NULLARG();
        return -1;
    }
    cpy = strdup(usergroup);
    if(!cpy) {
	CRIT("OOM");
	return -1;
    }
    group = strchr(cpy,':');
    if(group)
        *group++ = '\0';
    if(!*cpy && (!group || !*group)) {
	CRIT("Can't parse group in '%s'\n", usergroup);
	free(cpy);
	return -1;
    }
    p = getuser(cpy);
    if(!p) {
        CRIT("Unknown user '%s'", cpy);
	free(cpy);
        endpwent();
        return -1;
    }
    *uid = p->pw_uid;
    if(!group || !*group) {
        *gid = p->pw_gid;
    } else {
        const struct group *g = getgroup(group);
        if(!g) {
            CRIT("Unknown group '%s'", group);
	    free(cpy);
            endgrent();
	    endpwent();
            return -1;
        }
        *gid = g->gr_gid;
        endgrent();
    }
    free(cpy);
    endpwent();
    return 0;
}

int runas(const char *usergroup)
{
    uid_t uid;
    gid_t gid;
    const struct passwd *p;

    if(parse_usergroup(usergroup, &uid, &gid))
	return -1;

    if (getuid() == uid && geteuid() == uid &&
        getgid() == gid && getegid() == gid) {
        INFO("Already running as %d:%d, request to change user:group ignored",
             uid, gid);
        return 0;
    }
#ifdef HAVE_SETGROUPS
    if(setgroups(1, &gid) == -1) {
        CRIT("setgroups failed: %s", strerror(errno));
        return -1;
    }
#endif
    if (setgid(gid) == -1) {
        CRIT("Cannot set groupid to %d: %s", gid, strerror(errno));
        return -1;
    }
    if (setuid(uid) == -1) {
        CRIT("Cannot set userid to %d: %s", uid, strerror(errno));
        return -1;
    }

    p = getpwuid(uid);
    const struct group *g = getgrgid(gid);
    DEBUG("Switched to %s:%s (%d:%d)",
         p ? p->pw_name : "N/A",
         g ? g->gr_name : "N/A",
         uid, gid);
    endpwent();
    endgrent();
    return 0;
}

int hmac_compare(const unsigned char *hmac1, const unsigned char *hmac2, size_t len)
{
    int mismatch = 0;

    /* always compare all bytes to eliminate remote timing attacks */
    while(len--)
	if(*hmac1++ != *hmac2++)
	    mismatch = 1;

    return mismatch;
}

int cb_fail_null(void *ctx) {
    return 0;
}

int cb_fail_boolean(void *ctx, int boolean) {
    return 0;
}

int cb_fail_start_array(void *ctx) {
    return 0;
}

int cb_fail_end_array(void *ctx) {
    return 0;
}

int cb_fail_string(void *ctx, const unsigned char *s, size_t l) {
    return 0;
}

int cb_fail_number(void *ctx, const char *s, size_t l) {
    return 0;
}

int cb_fail_start_map(void *ctx) {
    return 0;
}

int cb_fail_map_key(void *ctx, const unsigned char *s, size_t l) {
    return 0;
}

int cb_fail_end_map(void *ctx) {
    return 0;
}

const char *strptimegm(const char *s, const char *format, time_t *t) {
    struct tm tm;
    time_t t1, t2, dt;
    const char *ret;

    memset(&tm, 0, sizeof(tm));
    ret = strptime(s, format, &tm);
    if(!ret)
	return NULL;

    tm.tm_isdst = 0;
    t1 = mktime(&tm);
    gmtime_r(&t1, &tm);
    tm.tm_isdst = 0;
    t2 = mktime(&tm);
    dt = (t1-t2);
    if(t)
	*t = t1+dt;
    return ret;
}

int wait_trigger(int pipe, float max_wait_sec, int *forced_awake)
{
    struct timeval tv;
    fd_set rfds;
    int sl;

    tv.tv_sec = (int)max_wait_sec;
    tv.tv_usec = (max_wait_sec - tv.tv_sec) * 1000000.0;
    FD_ZERO(&rfds);
    FD_SET(pipe, &rfds);
    if (forced_awake)
        *forced_awake = 0;
    while((sl = select(pipe+1, &rfds, NULL, NULL, &tv))) {
        char buf[256];
        if(sl < 0) {
            if(errno != EINTR)
                PCRIT("Failed to wait for triggers");
            break;
        }
        if(read(pipe, buf, sizeof(buf)) < 0) {
            if(errno != EINTR)
                PCRIT("Error reading trigger");
            break;
        }
        tv.tv_sec = 0;
        tv.tv_usec = 0; /* Poll for more */
        FD_ZERO(&rfds);
        FD_SET(pipe, &rfds);
        if (forced_awake)
            *forced_awake = 1;
    }
    if (sl && errno != EINTR)
        return -1;
    return 0;
}

const char *src_version(void)
{
    return SRC_VERSION;
}

int gc_interval;
double gc_max_batch_time;
double gc_yield_time;
int gc_slow_check=1;
float blockmgr_delay;
int max_pending_user_jobs = 128;
/* used outside of fcgi */
int db_min_passive_wal_pages=5000;
int db_max_passive_wal_pages=10000;
int db_max_restart_wal_pages=20000;
int db_idle_restart=600;
int db_busy_timeout=20;
int db_max_mmapsize=2147418112;
int db_custom_vfs=1;
int worker_max_wait;
int worker_max_requests;
