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
#include <string.h>

#include "yajlwrap.h"
#include "types.h"
#include "libsxclient-int.h"

static int yacb_fail_null(void *ctx) {
    return 0;
}

static int yacb_fail_boolean(void *ctx, int boolean) {
    return 0;
}

static int yacb_fail_number(void *ctx, const char *s, size_t l) {
    return 0;
}

static int yacb_fail_string(void *ctx, const unsigned char *s, size_t l) {
    return 0;
}

static int yacb_fail_start_map(void *ctx) {
    return 0;
}

static int yacb_fail_map_key(void *ctx, const unsigned char *s, size_t l) {
    return 0;
}

static int yacb_fail_end_map(void *ctx) {
    return 0;
}

static int yacb_fail_start_array(void *ctx) {
    return 0;
}

static int yacb_fail_end_array(void *ctx) {
    return 0;
}

static const yajl_callbacks fail_callbacks = {
    yacb_fail_null,
    yacb_fail_boolean,
    NULL,
    NULL,
    yacb_fail_number,
    yacb_fail_string,
    yacb_fail_start_map,
    yacb_fail_map_key,
    yacb_fail_end_map,
    yacb_fail_start_array,
    yacb_fail_end_array
};

void ya_init(yajl_callbacks *c) {
    memcpy(c, &fail_callbacks, sizeof(*c));
}

/* An intantionally very loose error reply parser */
static int yacb_error_null(void *ctx) {
    return 1;
}
static int yacb_error_boolean(void *ctx, int boolean) {
    return 1;
}
static int yacb_error_number(void *ctx, const char *s, size_t l) {
    return 1;
}

int yacb_error_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_error_ctx *yactx = (struct cb_error_ctx *)ctx;
    char *dest;
    if(yactx->state == ER_MSG)
	dest = yactx->msg;
    else if(yactx->state == ER_NODE)
	dest = yactx->node;
    else if(yactx->state == ER_ID)
	dest = yactx->id;
    else if(yactx->state == ER_DETAILS)
        dest = yactx->details;
    else
	return 1;
    l = MIN(l, CB_ERROR_STRSZ - 1);
    memcpy(dest, s, l);
    dest[l] = '\0';
    return 1;
}

static int yacb_error_start_map(void *ctx) {
    struct cb_error_ctx *yactx = (struct cb_error_ctx *)ctx;
    yactx->nmaps++;
    return 1;
}

static int is_err_msg(const unsigned char *s, size_t l)
{
    return (l == lenof("ErrorMessage") && !memcmp(s, "ErrorMessage", lenof("ErrorMessage")));
}

int yacb_error_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_error_ctx *yactx = (struct cb_error_ctx *)ctx;
    if(yactx->nmaps == 1 && yactx->narrays == 0) {
	/* Look for "NodeId" and "ErrorMessage" in the root */
        if(is_err_msg(s,l))
	    yactx->state = ER_MSG;
	else if(l == lenof("NodeId") && !memcmp(s, "NodeId", lenof("NodeId")))
	    yactx->state = ER_NODE;
	else if(l == lenof("ErrorDetails") && !memcmp(s, "ErrorDetails", lenof("ErrorDetails")))
	    yactx->state = ER_DETAILS;
        else if(l == lenof("ErrorId") && !memcmp(s, "ErrorId", lenof("ErrorId")))
            yactx->state = ER_ID;
	else
	    yactx->state = ER_OTHER;
    }
    return 1;
}

int yacb_error_end_map(void *ctx) {
    struct cb_error_ctx *yactx = (struct cb_error_ctx *)ctx;
    yactx->nmaps--;
    sxi_cbdata_setclusterr(yactx->cbdata, yactx->node, yactx->id, yactx->status, yactx->msg, yactx->details);
    return 1;
}
static int yacb_error_start_array(void *ctx) {
    struct cb_error_ctx *yactx = (struct cb_error_ctx *)ctx;
    yactx->narrays++;
    return 1;
}
static int yacb_error_end_array(void *ctx) {
    struct cb_error_ctx *yactx = (struct cb_error_ctx *)ctx;
    yactx->narrays--;
    return 1;
}

static const yajl_callbacks error_callbacks = {
    yacb_error_null,
    yacb_error_boolean,
    NULL,
    NULL,
    yacb_error_number,
    yacb_error_string,
    yacb_error_start_map,
    yacb_error_map_key,
    yacb_error_end_map,
    yacb_error_start_array,
    yacb_error_end_array
};

void ya_error_parser(yajl_callbacks *c) {
    memcpy(c, &error_callbacks, sizeof(*c));
}

int ya_check_error(curlev_context_t *cbdata, struct cb_error_ctx *ctx, const unsigned char *s, size_t l)
{
    if(is_err_msg(s, l)) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->nmaps = 1;
        ctx->cbdata = cbdata;
        ctx->state = ER_MSG;
        return 1;
    }
    return 0;
}
