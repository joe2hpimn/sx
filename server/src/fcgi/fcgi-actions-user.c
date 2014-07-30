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
#include <yajl/yajl_parse.h>

#include "fcgi-utils.h"
#include "hashfs.h"
#include "blob.h"
#include "../../../libsx/src/sxproto.h"
#include "../../../libsx/src/vcrypto.h"

void fcgi_user_onoff(int enable) {
    rc_ty s;

    s = sx_hashfs_user_onoff(hashfs, path, enable);

    if(s != OK)
	quit_errnum(400);

    CGI_PUTS("\r\n");
}

void fcgi_send_user(void) {
    uint8_t user[SXI_SHA1_BIN_LEN];
    sx_uid_t requid;
    uint8_t key[AUTH_KEY_LEN];
    sx_priv_t role;
    sxi_query_t *q;

    if (sxi_sha1_calc(NULL, 0, path, strlen(path), user))
	quit_errmsg(500, "Cannot compute hash: unable to initialize crypto library");

    if(sx_hashfs_get_user_info(hashfs, user, &requid, key, &role) != OK) /* no such user */ {
        quit_errmsg(404, "No such user");
    }
    if (!requid)
        quit_errmsg(403, "Cluster key is not allowed to be retrieved");

    q = sxi_useradd_proto(sx_hashfs_client(hashfs), path, key, role == PRIV_ADMIN);
    if (!q) {
        msg_set_reason("Cannot retrieve user data for '%s': %s", path, sxc_geterrmsg(sx_hashfs_client(hashfs)));
	quit_errmsg(500, msg_get_reason());
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n");
    CGI_PUTS(q->content);
    sxi_query_free(q);
}

struct user_ctx {
    char name[SXLIMIT_MAX_USERNAME_LEN + 1];
    char auth[AUTH_KEY_LEN];
    char type[7];
    int has_auth;
    int has_user;
    int has_type;
    enum user_state { CB_USER_START=0, CB_USER_KEY, CB_USER_NAME, CB_USER_AUTH, CB_USER_TYPE, CB_USER_COMPLETE } state;
};

static int cb_user_string(void *ctx, const unsigned char *s, size_t l) {
    struct user_ctx *uctx = ctx;
    switch (uctx->state) {
	case CB_USER_NAME:
	    if(l >= sizeof(uctx->name)) {
                msg_set_reason("username too long");
		return 0;
	    }
	    memcpy(uctx->name, s, l);
	    uctx->name[l] = 0;
	    uctx->has_user = 1;
	    break;
	case CB_USER_AUTH:
	    {
		char ascii[AUTH_KEY_LEN * 2 + 1];
		if(l != AUTH_KEY_LEN * 2) {
		    INFO("Bad key length %ld", l);
		    return 0;
		}
		memcpy(ascii, s, AUTH_KEY_LEN * 2);
		hex2bin(ascii, AUTH_KEY_LEN * 2, uctx->auth, sizeof(uctx->auth));
		uctx->has_auth = 1;
		break;
	    }
	case CB_USER_TYPE:
	    if(l >= sizeof(uctx->type)) {
		INFO("type too long");
		return 0;
	    }
	    memcpy(uctx->type, s, l);
	    uctx->type[l] = 0;
	    uctx->has_type = 1;
	    break;
	default:
	    return 0;
    }
    uctx->state = CB_USER_KEY;
    return 1;
}

static int cb_user_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct user_ctx *c = ctx;
    if(c->state == CB_USER_KEY) {
	if(l == lenof("userName") && !strncmp("userName", s, l)) {
	    c->state = CB_USER_NAME;
	    return 1;
	}
	if(l == lenof("userType") && !strncmp("userType", s, l)) {
	    c->state = CB_USER_TYPE;
	    return 1;
	}
	if(l == lenof("userKey") && !strncmp("userKey", s, l)) {
	    c->state = CB_USER_AUTH;
	    return 1;
	}
    }
    return 0;
}

static int cb_user_start_map(void *ctx) {
    struct user_ctx *c = ctx;
    if(c->state == CB_USER_START)
	c->state = CB_USER_KEY;
    else
	return 0;
    return 1;
}

static int cb_user_end_map(void *ctx) {
    struct user_ctx *c = ctx;
    if(c->state == CB_USER_KEY)
	c->state = CB_USER_COMPLETE;
    else
	return 0;
    return 1;
}

static const yajl_callbacks user_ops_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_user_string,
    cb_user_start_map,
    cb_user_map_key,
    cb_user_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

void fcgi_create_user(void)
{
    struct user_ctx uctx;
    memset(&uctx, 0, sizeof(uctx));
    rc_ty rc;
    yajl_handle yh = yajl_alloc(&user_ops_parser, NULL, &uctx);
    if (!yh) {
	OOM();
	quit_errmsg(500, "Cannot allocate json parser");
    }

    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0) {
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;
    }

    if(len || yajl_complete_parse(yh) != yajl_status_ok || !uctx.has_auth ||
       !uctx.has_user || !uctx.has_type || uctx.state != CB_USER_COMPLETE
       ) {
        const char *reason = msg_get_reason();
	yajl_free(yh);
	/* TODO: log yajl parse error better... */
	WARN("bad user create request: %d,%d,%d,%d", uctx.has_auth, uctx.has_user, uctx.has_type, uctx.state);
	quit_errmsg(400, *reason ? reason : "Invalid request content");
    }
    yajl_free(yh);
    auth_complete();
    quit_unless_authed();

    if(sx_hashfs_check_username(uctx.name))
	quit_errmsg(400, "Invalid username");

    int role = 0;
    if (!strcmp(uctx.type, "admin"))
	role = ROLE_ADMIN;
    else if (!strcmp(uctx.type, "normal"))
	role = ROLE_USER;
    else
	quit_errmsg(400, "Invalid user type");

    if (has_priv(PRIV_CLUSTER)) {
	INFO("create user from cluster");
	rc = sx_hashfs_create_user(hashfs, uctx.name, NULL, 0, uctx.auth, AUTH_KEY_LEN, role);
	if(rc == EINVAL)
	    quit_errmsg(400, msg_get_reason());
	if (rc == EEXIST)
	    quit_errmsg(409, "User already exists");
	if (rc != OK)
	    quit_errmsg(500, "Unable to add user");
	CGI_PUTS("\r\n");
	INFO("user creation done (from cluster)");
    } else {
	/* user request: create job */
	sx_blob_t *joblb = sx_blob_new();
	const void *job_data;
	unsigned int job_datalen, job_timeout;
	const sx_nodelist_t *allnodes;
	job_t job;
	rc_ty res;

	if (!joblb)
	    quit_errmsg(500, "Cannot allocate job blob");

	if (sx_blob_add_string(joblb, uctx.name) ||
	    sx_blob_add_blob(joblb, uctx.auth, AUTH_KEY_LEN) ||
	    sx_blob_add_int32(joblb, role)) {
	    sx_blob_free(joblb);
	    quit_errmsg(500, "Cannot create job blob");
	}

	sx_blob_to_data(joblb, &job_data, &job_datalen);
	INFO("job_add user");
	/* Users are created globally, in no particluar order (PREVNEXT would be fine too) */
	allnodes = sx_hashfs_nodelist(hashfs, NL_NEXTPREV);
	job_timeout = 12 * sx_nodelist_count(allnodes);
	res = sx_hashfs_job_new(hashfs, uid, &job, JOBTYPE_CREATE_USER, job_timeout, uctx.name, job_data, job_datalen, allnodes);
	sx_blob_free(joblb);
	if(res != OK)
	    quit_errmsg(rc2http(res), msg_get_reason());
	send_job_info(job);
	INFO("user creation done");
    }
}

static int print_user(sx_uid_t user_id, const char *username, const uint8_t *user, const uint8_t *key, int is_admin, void *ctx)
{
    int *first = ctx;
    if (!*first)
        CGI_PUTS(",");
    json_send_qstring(username);
    CGI_PRINTF(":{\"admin\":%s}", is_admin ? "true" : "false");
    *first = 0;
    return 0;
}

void fcgi_list_users(void) {
    int first = 1;
    CGI_PUTS("Content-type: application/json\r\n\r\n{");
    rc_ty rc = sx_hashfs_list_users(hashfs, print_user, &first);
    CGI_PUTS("}");
    if (rc != OK) {
	quit_itererr("Failed to list users", rc);
    }
}

