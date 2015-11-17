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

#ifndef JPARSE_H
#define JPARSE_H

#include <stdint.h>

/* The function protoes are near the end of this file */

struct jref {
    const char *key;
    int pos;
};

#define JPKEY(k) (&(const struct jref){ k, 0 })
#define JPARR(n) (&(const struct jref){ NULL, n })
#define JPWLDKEY -2
#define JPWLDITM -1
#define JPANYKEY (&(const struct jref){ NULL, JPWLDKEY })
#define JPANYITM (&(const struct jref){ NULL, JPWLDITM })

#define JPREF(...) (const struct jref *[]){ __VA_ARGS__, NULL }


typedef struct jparse jparse_t;

typedef void (*jpmatch_nullfn)(jparse_t *J, void *ctx);
struct jpmatch_null {
    jpmatch_nullfn cb;
    const struct jref **ref;
};
#define JPACTS_NULL(...) .actions_null = (const struct jpmatch_null []) { __VA_ARGS__, { NULL, NULL } }

typedef void (*jpmatch_boolfn)(jparse_t *J, void *ctx, int val);
struct jpmatch_bool {
    jpmatch_boolfn cb;
    const struct jref **ref;
};
#define JPACTS_BOOL(...) .actions_bool = (const struct jpmatch_bool []) { __VA_ARGS__, { NULL, NULL } }

typedef void (*jpmatch_int32fn)(jparse_t *J, void *ctx, int32_t num);
struct jpmatch_int32 {
    jpmatch_int32fn cb;
    const struct jref **ref;
};
#define JPACTS_INT32(...) .actions_int32 = (const struct jpmatch_int32 []) { __VA_ARGS__, { NULL, NULL } }

typedef void (*jpmatch_int64fn)(jparse_t *J, void *ctx, int64_t num);
struct jpmatch_int64 {
    jpmatch_int64fn cb;
    const struct jref **ref;
};
#define JPACTS_INT64(...) .actions_int64 = (const struct jpmatch_int64 []) { __VA_ARGS__, { NULL, NULL } }

typedef void (*jpmatch_double)(jparse_t *J, void *ctx, double num);
struct jpmatch_double {
    jpmatch_double cb;
    const struct jref **ref;
};
#define JPACTS_DOUBLE(...) .actions_double = (const struct jpmatch_double []) { __VA_ARGS__, { NULL, NULL } }

typedef void (*jpmatch_string)(jparse_t *J, void *ctx, const char *string, unsigned int length);
struct jpmatch_string {
    jpmatch_string cb;
    const struct jref **ref;
};
#define JPACTS_STRING(...) .actions_string = (const struct jpmatch_string []) { __VA_ARGS__, { NULL, NULL } }

typedef void (*jpmatch_container)(jparse_t *J, void *ctx);
struct jpmatch_container {
    jpmatch_container cb;
    const struct jref **ref;
};
#define JPACTS_ARRAY_BEGIN(...) .actions_arrstart = (const struct jpmatch_container []) { __VA_ARGS__, { NULL, NULL } }
#define JPACTS_ARRAY_END(...) .actions_arrend = (const struct jpmatch_container []) { __VA_ARGS__, { NULL, NULL } }
#define JPACTS_MAP_BEGIN(...) .actions_mapstart = (const struct jpmatch_container []) { __VA_ARGS__, { NULL, NULL } }
#define JPACTS_MAP_END(...) .actions_mapend = (const struct jpmatch_container []) { __VA_ARGS__, { NULL, NULL } }


struct jparse_actions {
    const struct jpmatch_null *actions_null;
    const struct jpmatch_bool *actions_bool;
    const struct jpmatch_int32 *actions_int32;
    const struct jpmatch_int64 *actions_int64;
    const struct jpmatch_double *actions_double;
    const struct jpmatch_string *actions_string;
    /* Convenience virtual leaves, not real JSON values */
    const struct jpmatch_container *actions_arrstart;
    const struct jpmatch_container *actions_arrend;
    const struct jpmatch_container *actions_mapstart;
    const struct jpmatch_container *actions_mapend;
};
#define JPACT(callback_fn, ...) { callback_fn, JPREF(__VA_ARGS__) }

/* Parser creation and destruction */
jparse_t *sxi_jparse_create(const struct jparse_actions *actions, void *ctx, int parseerr);
void sxi_jparse_destroy(jparse_t *J);

/* JSON data digestion */
int sxi_jparse_digest(jparse_t *J, const void *data, unsigned int datalen);
int sxi_jparse_done(jparse_t *J);
const char *sxi_jparse_geterr(jparse_t *J);

/* In-callback functions */
void sxi_jparse_cancel(jparse_t *J, const char *reason_fmt, ...);
typedef const struct container jploc_t;
jploc_t *sxi_jparse_whereami(jparse_t *J);

/* Path examination and navigation functions */
int sxi_jpath_ismap(jploc_t *jploc);
const char *sxi_jpath_mapkey(jploc_t *jploc);
int sxi_jpath_isarray(jploc_t *jploc);
int sxi_jpath_arraypos(jploc_t *jploc);
jploc_t *sxi_jpath_up(jploc_t *jploc);
jploc_t *sxi_jpath_down(jploc_t *jploc);

#endif
