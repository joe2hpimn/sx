/*
 *  Copyright (C) 2015 Skylable Ltd. <info-copyright@skylable.com>
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

#include <yajl/yajl_parse.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "jparse.h"


struct container {
    struct container *up, *down;
    const char *key;
    int pos;
};

struct jparse {
    struct container *first, *last;
    void *ctx; /* Opaque pointer */
    const struct jparse_actions *act;
    yajl_handle yh;
    int newlvl, cancelled, parseerr;
    char errbuf[256];
};


static int jparse_cmp(struct jparse *J, const struct jref **ref) {
    struct container *a = J->first;
    unsigned int i;
    for(i=0; ; i++, a=a->down) {
	const struct jref *b = ref[i];
	int cmp;

	if(!a) /* json ends */
	    return b ? 1 : 0;
	if(!b)/* ref ends */
	    return -1;

	if(a->key) { /* json is a map */
	    if(b->pos == JPWLDKEY) /* ref is a map wildcard */
		continue;
	    if(!b->key) /* ref is an array */
		return -1;
	    /* Both are maps, compare keys */
	    cmp = strcmp(a->key, b->key);
	} else { /* json is an array */
	    if(b->pos == JPWLDITM) /* ref is an array wildcard */
		continue;
	    if(b->key)
		return 1;
	    /* Both are arrays, compare position */
	    cmp = a->pos - b->pos;
	}
	if(cmp)
	    return cmp;
    }
    return 0;
}

#define NONULLJ do {						\
	if(!J)							\
	    return 0;						\
    } while(0)

#define NONULLARGS do {						\
	if(!J || !s)						\
	    return 0;						\
    } while(0)

static __inline__ void bumpar(struct jparse *J) {
    /* If in array bump position */
    if(J && J->last && !J->last->key)
	J->last->pos++;
}

#define FOREACH_MATCH(TYPE, ...)					\
    do{if(J->act && J->act->TYPE) {					\
	unsigned int i = 0;						\
	while(J->act->TYPE[i].ref) {					\
	    if(!jparse_cmp(J, J->act->TYPE[i].ref) && J->act->TYPE[i].cb) \
		J->act->TYPE[i].cb(J, __VA_ARGS__);			\
	    if(J->cancelled)						\
		return 0;						\
	    i++;							\
	}								\
    }} while(0)

static int jpnull(void *ctx) {
    struct jparse *J = (struct jparse *)ctx;

    NONULLJ;

    FOREACH_MATCH(actions_null, J->ctx);
    bumpar(J);
    return 1;
}

static int jpboolean(void *ctx, int boolean) {
    struct jparse *J = (struct jparse *)ctx;

    NONULLJ;

    FOREACH_MATCH(actions_bool, J->ctx, boolean);
    bumpar(J);
    return 1;
}

static int jpnumber(void *ctx, const char *s, size_t l) {
    struct jparse *J = (struct jparse *)ctx;
    char numstr[32];

    NONULLARGS;

    if(J->act && l < sizeof(numstr)) {
	char *eon;
	do {
	    double num;
	    if(!J->act->actions_double)
		break;
	    memcpy(numstr, s, l);
	    numstr[l] = '\0';
	    errno = 0;
	    num = strtod(numstr, &eon);
	    if(errno || eon == numstr || *eon)
		break;
	    FOREACH_MATCH(actions_double, J->ctx, num);
	} while(0);
	do {
	    int64_t num;
	    if(!J->act->actions_int32 && !J->act->actions_int64)
		break;
	    if(!J->act->actions_double) {
		memcpy(numstr, s, l);
		numstr[l] = '\0';
	    }
	    errno = 0;
	    num = strtoll(numstr, &eon, 10);
	    if(errno || eon == numstr || *eon)
		break;
	    FOREACH_MATCH(actions_int64, J->ctx, num);
	    if(num > 0x7fffffff || num < -0x7fffffff)
		break;
	    FOREACH_MATCH(actions_int32, J->ctx, num);
	} while(0);
    }

    bumpar(J);
    return 1;
}

static int jpstring(void * ctx, const unsigned char *s, size_t l) {
    const struct jref **emsgref = JPREF(JPKEY("ErrorMessage"));
    struct jparse *J = (struct jparse *)ctx;

    NONULLARGS;

    if(J->parseerr && !jparse_cmp(J, emsgref)) {
	snprintf(J->errbuf, sizeof(J->errbuf), "Cluster error: %.*s", (unsigned int)l, s);
	J->cancelled = 1;
    }

    FOREACH_MATCH(actions_string, J->ctx, (const char *)s, (unsigned int)l);
    bumpar(J);
    return 1;
}


static int jpstart_map(void *ctx) {
    struct jparse *J = (struct jparse *)ctx;

    NONULLJ;
    if(J->newlvl) {
	/* Not reached */
	snprintf(J->errbuf, sizeof(J->errbuf), "Internal error detected parsing JSON map data");
	J->cancelled = 1;
	return 0;
    }

    FOREACH_MATCH(actions_mapstart, J->ctx);
    J->newlvl = 1;
    return 1;
}

static int jpmap_key(void *ctx, const unsigned char *s, size_t l) {
    struct jparse *J = (struct jparse *)ctx;
    struct container *c, *last;
    char *buf;

    NONULLARGS;
    c = malloc(sizeof(*c) + l + 1);
    if(!c) {
	snprintf(J->errbuf, sizeof(J->errbuf), "Out of memory parsing JSON data");
	J->cancelled = 1;
	return 0;
    }
    buf = (char *)(c+1);
    memcpy(buf, s, l);
    buf[l] = '\0';
    c->key = buf;
    c->pos = 0;
    c->down = NULL;

    last = J->last;
    J->last = c;
    if(J->newlvl) {
	/* Append */
	J->newlvl = 0;
	if(last)
	    last->down = c;
	else
	    J->first = c;
	c->up = last;
    } else {
	/* Replace */
	struct container *parent = last->up;
	if(parent)
	    parent->down = c;
	else
	    J->first = c;
	c->up = parent;
	free(last);
    }

    return 1;
}

static int jpend_obj(void *ctx, int ismap) {
    struct jparse *J = (struct jparse *)ctx;
    struct container *last;

    NONULLJ;

    if(!ismap || !J->newlvl) {
	/* Array or full map */
	last = J->last;
	if(last) {
	    J->last = last->up;
	    if(J->last)
		J->last->down = NULL;
	    else
		J->first = NULL;
	    free(last);
	} else {
	    J->first = NULL;
	    J->last = NULL;
	}
    } else
	J->newlvl = 0; /* empty map */
	
    if(ismap)
	FOREACH_MATCH(actions_mapend, J->ctx);
    else
	FOREACH_MATCH(actions_arrend, J->ctx);

    bumpar(J);
    return 1;
}


static int jpend_map(void *ctx) {
    return jpend_obj(ctx, 1);
}

static int jpend_array(void *ctx) {
    return jpend_obj(ctx, 0);
}

static int jpstart_array(void *ctx) {
    struct jparse *J = (struct jparse *)ctx;
    struct container *c, *last;

    NONULLJ;

    FOREACH_MATCH(actions_arrstart, J->ctx);

    c = malloc(sizeof(*c));
    if(!c) {
	snprintf(J->errbuf, sizeof(J->errbuf), "Out of memory parsing JSON data");
	J->cancelled = 1;
	return 0;
    }
    c->key = NULL;
    c->pos = 0;
    c->down = NULL;

    last = J->last;
    J->last = c;
    if(last)
	last->down = c;
    else
	J->first = c;
    c->up = last;
    return 1;
}

static const yajl_callbacks callbacks = {
    jpnull,
    jpboolean,
    NULL,
    NULL,
    jpnumber,
    jpstring,
    jpstart_map,
    jpmap_key,
    jpend_map,
    jpstart_array,
    jpend_array
};

struct jparse *sxi_jparse_create(const struct jparse_actions *actions, void *ctx, int parseerr) {
    struct jparse *J;
    J = calloc(1, sizeof(*J));
    if(!J)
	return NULL;

    J->yh = yajl_alloc(&callbacks, NULL, J);
    if(!J->yh) {
	free(J);
	return NULL;
    }

    J->act = actions;
    J->ctx = ctx;
    J->parseerr = parseerr;
    return J;
}

void sxi_jparse_destroy(struct jparse *J) {
    if(J) {
	struct container *c1 = J->last, *c2;
	while(c1) {
	    c2 = c1->up;
	    free(c1);
	    c1 = c2;
	}
	if(J->yh)
	    yajl_free(J->yh);
	free(J);
    }
}

static int yajl_res(struct jparse *J, yajl_status res) {
    unsigned char *yreason = NULL;

    switch(res) {
    case yajl_status_ok:
	return 0;
    case yajl_status_client_canceled:
	if(!J->errbuf[0]) /* Not reached */
	    snprintf(J->errbuf, sizeof(J->errbuf), "Operation cancelled by callback");
	return 1;
    case yajl_status_error:
	yreason = yajl_get_error(J->yh, 0, (const unsigned char *)"", 0);
    default:
	if(yreason) {
	    snprintf(J->errbuf, sizeof(J->errbuf), "JSON parser failed: %s", yreason);
	    yajl_free_error(J->yh, yreason);
	} else
	    snprintf(J->errbuf, sizeof(J->errbuf), "JSON parser failed for unspecified reasons");
	return 1;
    }
}

int sxi_jparse_digest(struct jparse *J, const void *data, unsigned int datalen) {
    return yajl_res(J, yajl_parse(J->yh, data, datalen));
}

int sxi_jparse_done(struct jparse *J) {
    return yajl_res(J, yajl_complete_parse(J->yh));
}

const char *sxi_jparse_geterr(struct jparse *J) {
    if(J->errbuf[0])
	return J->errbuf;
    else
	return "No error";
}

void sxi_jparse_cancel(struct jparse *J, const char *reason_fmt, ...) {
    va_list ap;
    if(!J->cancelled) {
	va_start(ap, reason_fmt);
	J->cancelled = 1;
	vsnprintf(J->errbuf, sizeof(J->errbuf), reason_fmt, ap);
	va_end(ap);
    }
}

const struct container *sxi_jparse_whereami(struct jparse *J) {
    return J ? J->first : NULL;
}

int sxi_jpath_ismap(const struct container *jploc) {
    return jploc && jploc->key != NULL;
}

const char *sxi_jpath_mapkey(const struct container *jploc) {
    return sxi_jpath_ismap(jploc) ? jploc->key : NULL;
}

int sxi_jpath_isarray(const struct container *jploc) {
    return jploc && jploc->key == NULL;
}

int sxi_jpath_arraypos(const struct container *jploc) {
    return sxi_jpath_isarray(jploc) ? jploc->pos : -1;
}

const struct container *sxi_jpath_up(const struct container *jploc) {
    return jploc ? jploc->up : NULL;
}

const struct container *sxi_jpath_down(const struct container *jploc) {
    return jploc ? jploc->down : NULL;
}

