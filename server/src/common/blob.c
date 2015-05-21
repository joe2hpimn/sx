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
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "blob.h"
#include "utils.h"
#include "log.h"

struct _sx_blob_t {
    uint8_t *blob;
    unsigned int pos;
    unsigned int size;
    unsigned int savedpos;
};


enum blob_object {
    BLOB_INT32 = 0,
    BLOB_INT64,
    BLOB_STRING,
    BLOB_BLOB,
    BLOB_DATETIME
};
#define BLOB_MIN_OBJ BLOB_INT32
#define BLOB_MAX_OBJ BLOB_DATETIME

static int64_t blob_htonll(int64_t d) {
#ifndef WORDS_BIGENDIAN
    /* Verified to compile to "bswapq" in gcc and llvm with -O1 or better */
    return
	(((d    ) & 0xff) << (64-8*1)) |
	(((d>> 8) & 0xff) << (64-8*2)) |
	(((d>>16) & 0xff) << (64-8*3)) |
	(((d>>24) & 0xff) << (64-8*4)) |
	(((d>>32) & 0xff) << (64-8*5)) |
	(((d>>40) & 0xff) << (64-8*6)) |
	(((d>>48) & 0xff) << (64-8*7)) |
	(((d>>56) & 0xff));
#else
    return d;
#endif
}

sx_blob_t *sx_blob_new(void) {
    sx_blob_t *s = wrap_calloc(1, sizeof(*s));
    return s;
}

static int pushdata(sx_blob_t *s, enum blob_object itm, const void *d, unsigned int len) {
    uint32_t i;
    if(s->size - s->pos < sizeof(i) + sizeof(i) + len) {
	unsigned int size = s->size + MAX(sizeof(i) + sizeof(i) + len, 1024);
	uint8_t *newblob;
	if(!(newblob = wrap_realloc(s->blob, size)))
	    return -1;
	s->blob = newblob;
	s->size = size;
    }
    i = htonl(itm);
    memcpy(s->blob + s->pos, &i, sizeof(i));
    s->pos += sizeof(i);
    i = htonl(len);
    memcpy(s->blob + s->pos, &i, sizeof(i));
    s->pos += sizeof(i);
    memcpy(s->blob + s->pos, d, len);
    s->pos += len;
    return 0;
}

int sx_blob_add_int32(sx_blob_t *s, int32_t d) {
    d = htonl(d);
    return pushdata(s, BLOB_INT32, &d, sizeof(d));
}

int sx_blob_add_int64(sx_blob_t *s, int64_t d) {
    d = blob_htonll(d);
    return pushdata(s, BLOB_INT64, &d, sizeof(d));
}

int sx_blob_add_string(sx_blob_t *s, const char *d) {
    return pushdata(s, BLOB_STRING, d, strlen(d)+1);
}

int sx_blob_add_blob(sx_blob_t *s, const void *d, unsigned int len) {
    return pushdata(s, BLOB_BLOB, d, len);
}

int sx_blob_add_datetime(sx_blob_t *s, const struct timeval *d) {
    int64_t ts[2];
    ts[0] = blob_htonll(d->tv_sec + d->tv_usec / 1000000);
    ts[1] = blob_htonll(d->tv_usec % 1000000);
    return pushdata(s, BLOB_DATETIME, ts, sizeof(ts));
}

int sx_blob_cat(sx_blob_t *dest, sx_blob_t *src) {
    if(dest->size - dest->pos < src->pos) {
	unsigned int size = dest->size + MAX(src->pos, 1024);
	uint8_t *newblob;
	if(!(newblob = wrap_realloc(dest->blob, size)))
	    return -1;
	dest->blob = newblob;
	dest->size = size;
    }
    memcpy(dest->blob + dest->pos, src->blob, src->pos);
    dest->pos += src->pos;
    return 0;
}

void sx_blob_to_data(const sx_blob_t *s, const void **d, unsigned int *len) {
    *d = s->blob ? s->blob : (const void *)"";
    *len = s->pos;
}

sx_blob_t *sx_blob_from_data(const void *d, unsigned int l) {
    sx_blob_t *s;
    if(!l)
	return NULL;
    if(!(s = sx_blob_new()))
	return NULL;
    if(l)
	s->blob = wrap_malloc(l);
    if(!s->blob) {
	free(s);
	return NULL;
    }
    memcpy(s->blob, d, l);
    s->pos = 0;
    s->size = l;
    return s;
}

static int getdata(sx_blob_t *s, enum blob_object *itm, const void **d, unsigned int *len) {
    uint32_t i;
    DEBUG("in");
    if(s->pos == s->size)
	return 1;
    if(s->pos > s->size || s->size - s->pos < sizeof(i)*2)
	return -1;
    memcpy(&i, s->blob + s->pos, sizeof(i));
    *itm = htonl(i);
    if(*itm < BLOB_MIN_OBJ || *itm > BLOB_MAX_OBJ)
	return -1;
    memcpy(&i, s->blob + s->pos + sizeof(i), sizeof(i));
    i = htonl(i);
    if(s->size - s->pos - sizeof(i)*2 < i)
	return -1;

    *len = i;
    *d = s->blob + s->pos + sizeof(i)*2;
    s->pos += sizeof(i)*2 + i;
    return 0;
}

int sx_blob_get_int32(sx_blob_t *s, int32_t *d) {
    enum blob_object o;
    unsigned int l;
    const void *dt;
    int ret = getdata(s, &o, &dt, &l);

    if(ret)
	return ret;

    if(o != BLOB_INT32 || l != sizeof(*d)) {
	s->pos -= sizeof(l)*2 + l;
	return -1;
    }

    memcpy(d, dt, sizeof(*d));
    *d = htonl(*d);
    return 0;
}

int sx_blob_get_int64(sx_blob_t *s, int64_t *d) {
    enum blob_object o;
    unsigned int l;
    const void *dt;
    int ret = getdata(s, &o, &dt, &l);

    if(ret)
	return ret;

    if(o != BLOB_INT64 || l != sizeof(*d)) {
	s->pos -= sizeof(l)*2 + l;
	return -1;
    }

    memcpy(d, dt, sizeof(*d));
    *d = blob_htonll(*d);
    return 0;
}

int sx_blob_get_string(sx_blob_t *s, const char **d) {
    enum blob_object o;
    unsigned int l;
    int ret = getdata(s, &o, (const void **)d, &l);
    DEBUG("in");

    if(ret)
	return ret;

    if(o != BLOB_STRING || l < 1 || (*d)[l-1] != '\0' || strlen(*d) != l - 1) {
	s->pos -= sizeof(l)*2 + l;
	return -1;
    }
    DEBUG("ok");
    return 0;
}

int sx_blob_get_blob(sx_blob_t *s, const void **d, unsigned int *len) {
    enum blob_object o;
    int ret = getdata(s, &o, d, len);
    DEBUG("in");
    if(ret)
	return ret;

    if(o != BLOB_BLOB) {
	s->pos -= sizeof(unsigned int)*2 + *len;
	return -1;
    }
    DEBUG("ok");
    return 0;
}

int sx_blob_get_datetime(sx_blob_t *s, struct timeval *d) {
    enum blob_object o;
    unsigned int l;
    int64_t ts[2];
    const void *dt;
    int ret = getdata(s, &o, &dt, &l);

    if(ret)
	return ret;

    if(o != BLOB_DATETIME || l != sizeof(ts)) {
	s->pos -= sizeof(l)*2 + l;
	return -1;
    }

    memcpy(ts, dt, sizeof(ts));
    d->tv_sec = (time_t)blob_htonll(ts[0]);
    d->tv_usec = (suseconds_t)blob_htonll(ts[1]);
    return 0;
}


void sx_blob_free(sx_blob_t *s) {
    if(s) {
	free(s->blob);
	free(s);
    }
}

void sx_blob_savepos(sx_blob_t *s) {
    if(s)
	s->savedpos = s->pos;
}

void sx_blob_loadpos(sx_blob_t *s) {
    if(s)
	s->pos = s->savedpos;
}

void sx_blob_reset(sx_blob_t *s) {
    if(s)
	s->pos = 0;
}
