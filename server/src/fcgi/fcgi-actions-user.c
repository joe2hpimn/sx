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

static const char *user_get_lock(sx_blob_t *b)
{
    const char *name = NULL;
    return !sx_blob_get_string(b, &name) ? name : NULL;
}

static rc_ty user_nodes(sxc_client_t *sx, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    /* Users are created globally, in no particluar order (PREVNEXT would be fine too) */
    *nodes = sx_nodelist_dup(sx_hashfs_nodelist(hashfs, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

struct userdel_ctx {
    const char *name;
    const char *newowner;
};

static int userdel_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct userdel_ctx *uctx = yctx;
    if (!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }

    if (sx_blob_add_string(joblb, uctx->name) ||
        sx_blob_add_string(joblb, uctx->newowner)) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }
    return 0;
}

static unsigned userdel_timeout(sxc_client_t *sx, int nodes)
{
    return 5 * 60 * nodes;
}

static sxi_query_t* userdel_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    const char *name;
    const char *newowner;

    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_string(b, &newowner)) {
        WARN("Corrupt userdel blob");
        return NULL;
    }
    switch (phase) {
        case JOBPHASE_REQUEST:
            return sxi_useronoff_proto(sx, name, 0);
        case JOBPHASE_COMMIT:
            return sxi_userdel_proto(sx, name, newowner);
        case JOBPHASE_ABORT:
            INFO("Delete user '%s': aborting", name);
            return sxi_useronoff_proto(sx, name, 1);
        case JOBPHASE_UNDO:
            INFO("Delete user '%s': undoing", name);
            return sxi_useronoff_proto(sx, name, 0);
        default:
            return NULL;
    }
}

static rc_ty userdel_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
{
    const char *name;
    const char *newowner;
    rc_ty rc = OK;

    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_string(b, &name) ||
        sx_blob_get_string(b, &newowner)) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    if (remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    switch (phase) {
        case JOBPHASE_REQUEST:
            DEBUG("userdel request '%s'", name);
	    return sx_hashfs_user_onoff(hashfs, name, 0);
        case JOBPHASE_COMMIT:
            DEBUG("userdel commit '%s'", name);
            rc = sx_hashfs_delete_user(hashfs, name, newowner);
            if (rc == ENOENT)
                rc = OK;
            if (rc != OK)
                WARN("Failed to delete user %s and replace with %s: %s", name, newowner, msg_get_reason());
            return rc;
        case JOBPHASE_ABORT:
            INFO("Delete user '%s': aborted", name);
            DEBUG("userdel abort '%s'", name);
	    return sx_hashfs_user_onoff(hashfs, name, 1);
        case JOBPHASE_UNDO:
            CRIT("User '%s' may have been left in an inconsistent state after a failed removal attempt", name);
            msg_set_reason("User may have been left in an inconsistent state after a failed removal attempt");
            return FAIL_EINTERNAL;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

const job_2pc_t userdel_spec = {
    NULL,
    JOBTYPE_DELETE_USER,
    NULL,
    user_get_lock,
    userdel_to_blob,
    userdel_execute_blob,
    userdel_proto_from_blob,
    user_nodes,
    userdel_timeout
};

void fcgi_delete_user() {
    struct userdel_ctx uctx;
    char new_owner[SXLIMIT_MAX_USERNAME_LEN+2];
    uctx.name = path;
    if (has_priv(PRIV_CLUSTER))
        uctx.newowner = get_arg("chgto");
    else {
        uint8_t deluser[AUTH_UID_LEN];
        rc_ty s;

        s = sx_hashfs_get_user_by_name(hashfs, path, deluser);
        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());

        s = sx_hashfs_uid_get_name(hashfs, uid, new_owner, sizeof(new_owner));
        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
        if(sx_hashfs_check_username(new_owner))
            quit_errmsg(500, "Internal error (requesting user has an invalid name)");

        if(!memcmp(user, deluser, sizeof(user)))
            quit_errmsg(400, "You may not delete yourself");
        uctx.newowner = new_owner;
    }
    job_2pc_handle_request(sx_hashfs_client(hashfs), &userdel_spec, &uctx);
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
    int role;
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
                ascii[AUTH_KEY_LEN*2] = '\0';
		if (hex2bin(ascii, AUTH_KEY_LEN * 2, uctx->auth, sizeof(uctx->auth))) {
                    INFO("bad hexadecimal string: %s", ascii);
                    return 0;
                }
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

static rc_ty user_parse_complete(void *yctx)
{
    struct user_ctx *uctx = yctx;
    if (!uctx || uctx->state != CB_USER_COMPLETE)
        return EINVAL;
    if(sx_hashfs_check_username(uctx->name)) {
	msg_set_reason("Invalid username");
        return EINVAL;
    }

    uctx->role = 0;
    if (!strcmp(uctx->type, "admin"))
	uctx->role = ROLE_ADMIN;
    else if (!strcmp(uctx->type, "normal"))
	uctx->role = ROLE_USER;
    else {
        msg_set_reason("Invalid user type");
        return EINVAL;
    }
    return OK;
}

static int user_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct user_ctx *uctx = yctx;
    if (!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }

    if (sx_blob_add_string(joblb, uctx->name) ||
        sx_blob_add_blob(joblb, uctx->auth, AUTH_KEY_LEN) ||
        sx_blob_add_int32(joblb, uctx->role)) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }
    return 0;
}

static unsigned user_timeout(sxc_client_t *sx, int nodes)
{
    unsigned timeout = 50 * (nodes - 1);
    if (!timeout)
        timeout = 20;
    return timeout;
}

static sxi_query_t* user_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    const char *name;
    unsigned role;
    const void *auth;
    unsigned auth_len;

    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
	sx_blob_get_int32(b, &role)) {
        WARN("Corrupt user blob");
        return NULL;
    }
    switch (phase) {
        case JOBPHASE_REQUEST:
            return sxi_useradd_proto(sx, name, auth, (role == ROLE_ADMIN));
        case JOBPHASE_COMMIT:
            return sxi_useronoff_proto(sx, name, 1);
        case JOBPHASE_ABORT:/* fall-through */
            INFO("Create user '%s': aborting", name);
            return sxi_userdel_proto(sx, name, "admin");
        case JOBPHASE_UNDO:
            INFO("Create user '%s': undoing", name);
            return sxi_userdel_proto(sx, name, "admin");
        default:
            return NULL;
    }
}

static rc_ty user_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
{
    const char *name;
    const void *auth;
    unsigned auth_len;
    int role;
    rc_ty rc = OK, rc2 = OK;

    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
        auth_len != AUTH_KEY_LEN ||
	sx_blob_get_int32(b, &role)) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    switch (phase) {
        case JOBPHASE_REQUEST:
            DEBUG("useradd request '%s'", name);
            rc = sx_hashfs_create_user(hashfs, name, NULL, 0, auth, AUTH_KEY_LEN, role);
            if(rc == EINVAL)
                return rc;
            if (rc == EEXIST) {
                msg_set_reason("User already exists");
                return rc;
            }
            if (rc != OK) {
                msg_set_reason("Unable to add user");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_COMMIT:
            DEBUG("useradd commit '%s'", name);
	    rc = sx_hashfs_user_onoff(hashfs, name, 1);
            if (rc)
		WARN("Failed to enable user '%s'", name);
            return rc;
        case JOBPHASE_ABORT:
            DEBUG("useradd abort '%s'", name);
            INFO("Create user '%s': aborted", name);
            /* try hard to deactivate / delete */
	    rc = sx_hashfs_user_onoff(hashfs, name, 0);
            rc2 = sx_hashfs_delete_user(hashfs, name, "admin");
            return rc2 == OK ? rc : rc2;
        case JOBPHASE_UNDO:
            DEBUG("useradd undo '%s'", name);
            /* try hard to deactivate / delete */
	    rc = sx_hashfs_user_onoff(hashfs, name, 0);
            rc2 = sx_hashfs_delete_user(hashfs, name, "admin");
            CRIT("User '%s' may have been left in an inconsistent state after a failed removal attempt", name);
            msg_set_reason("User may have been left in an inconsistent state after a failed removal attempt");
            return FAIL_EINTERNAL;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

const job_2pc_t user_spec = {
    &user_ops_parser,
    JOBTYPE_CREATE_USER,
    user_parse_complete,
    user_get_lock,
    user_to_blob,
    user_execute_blob,
    user_proto_from_blob,
    user_nodes,
    user_timeout
};

void fcgi_create_user(void)
{
    struct user_ctx uctx;
    memset(&uctx, 0, sizeof(uctx));

    job_2pc_handle_request(sx_hashfs_client(hashfs), &user_spec, &uctx);
}

struct user_newkey_ctx {
    char auth[AUTH_KEY_LEN];
    enum user_newkey_state { CB_USER_NEWKEY_START=0, CB_USER_NEWKEY_AUTH, CB_USER_NEWKEY_KEY, CB_USER_NEWKEY_COMPLETE } state;
};

static int cb_user_newkey_string(void *ctx, const unsigned char *s, size_t l) {
    struct user_newkey_ctx *uctx = ctx;
    switch (uctx->state) {
	case CB_USER_NEWKEY_AUTH:
	    {
		char ascii[AUTH_KEY_LEN * 2 + 1];
		if(l != AUTH_KEY_LEN * 2) {
		    INFO("Bad key length %ld", l);
		    return 0;
		}
		memcpy(ascii, s, AUTH_KEY_LEN * 2);
                ascii[AUTH_KEY_LEN*2] = '\0';
		if (hex2bin(ascii, AUTH_KEY_LEN * 2, uctx->auth, sizeof(uctx->auth))) {
                    INFO("Bad hexadecimal string: %s", ascii);
                    return 0;
                }
		break;
	    }
	default:
	    return 0;
    }
    uctx->state = CB_USER_NEWKEY_KEY;
    return 1;
}

static int cb_user_newkey_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct user_newkey_ctx *c = ctx;
    if(c->state == CB_USER_NEWKEY_KEY) {
	if(l == lenof("userKey") && !strncmp("userKey", s, l)) {
	    c->state = CB_USER_NEWKEY_AUTH;
	    return 1;
	}
    }
    return 0;
}

static int cb_user_newkey_start_map(void *ctx) {
    struct user_newkey_ctx *c = ctx;
    if(c->state == CB_USER_NEWKEY_START)
	c->state = CB_USER_NEWKEY_KEY;
    else
	return 0;
    return 1;
}

static int cb_user_newkey_end_map(void *ctx) {
    struct user_newkey_ctx *c = ctx;
    if(c->state == CB_USER_NEWKEY_KEY)
	c->state = CB_USER_NEWKEY_COMPLETE;
    else
	return 0;
    return 1;
}

static const yajl_callbacks user_newkey_ops_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_fail_number,
    cb_user_newkey_string,
    cb_user_newkey_start_map,
    cb_user_newkey_map_key,
    cb_user_newkey_end_map,
    cb_fail_start_array,
    cb_fail_end_array
};

static rc_ty user_newkey_parse_complete(void *yctx)
{
    struct user_newkey_ctx *uctx = yctx;
    if (!uctx || uctx->state != CB_USER_NEWKEY_COMPLETE)
        return EINVAL;
    return OK;
}

static int user_newkey_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct user_newkey_ctx *uctx = yctx;
    uint8_t requser[AUTH_UID_LEN];
    uint8_t key[AUTH_KEY_LEN];
    sx_uid_t requid;
    sx_priv_t role;
    rc_ty rc;

    if (!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }
    if(sx_hashfs_check_username(path)) {
        msg_set_reason("Invalid username");
        return -1;
    }
    rc = sx_hashfs_get_user_by_name(hashfs, path, requser);
    if (rc) {
        msg_set_reason("cannot retrieve user: %s", path);
        return -1;
    }
    if(sx_hashfs_get_user_info(hashfs, requser, &requid, key, &role) != OK) /* no such user */ {
        msg_set_reason("No such user");
        return -1;
    }

    if (sx_blob_add_string(joblb, path) ||
        sx_blob_add_blob(joblb, key, AUTH_KEY_LEN) ||
        sx_blob_add_blob(joblb, uctx->auth, AUTH_KEY_LEN)) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }
    return 0;
}

static sxi_query_t* user_newkey_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    const char *name;
    const void *auth, *oldauth;
    unsigned auth_len, oldauth_len;

    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &oldauth, &oldauth_len) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
        auth_len != AUTH_KEY_LEN ||
        oldauth_len != AUTH_KEY_LEN) {
        WARN("Corrupt user blob");
        return NULL;
    }
    switch (phase) {
        case JOBPHASE_COMMIT:
            return sxi_usernewkey_proto(sx, name, auth);
        case JOBPHASE_ABORT:/* fall-through */
            INFO("Newkey for user '%s': aborting", name);
            return sxi_usernewkey_proto(sx, name, oldauth);
        case JOBPHASE_UNDO:
            INFO("Newkey for user '%s': undoing", name);
            return sxi_usernewkey_proto(sx, name, oldauth);
        default:
            return NULL;
    }
}

static rc_ty user_newkey_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
{
    const char *name;
    const void *auth, *oldauth;
    unsigned auth_len, oldauth_len;
    rc_ty rc = OK;

    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &oldauth, &oldauth_len) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
        auth_len != AUTH_KEY_LEN) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    switch (phase) {
        case JOBPHASE_REQUEST:
            /* remote */
            DEBUG("user_newkey request '%s'", name);
            rc = sx_hashfs_user_newkey(hashfs, name, auth, AUTH_KEY_LEN);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to change user key");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_COMMIT:
            DEBUG("user_newkey commit '%s'", name);
            rc = sx_hashfs_user_newkey(hashfs, name, auth, AUTH_KEY_LEN);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to change user key");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_ABORT:
            DEBUG("user_newkey abort '%s'", name);
            rc = sx_hashfs_user_newkey(hashfs, name, oldauth, AUTH_KEY_LEN);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to change user key");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_UNDO:
            DEBUG("user_newkey undo '%s'", name);
            rc = sx_hashfs_user_newkey(hashfs, name, oldauth, AUTH_KEY_LEN);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to change user key");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

const job_2pc_t user_newkey_spec = {
    &user_newkey_ops_parser,
    JOBTYPE_NEWKEY_USER,
    user_newkey_parse_complete,
    user_get_lock,
    user_newkey_to_blob,
    user_newkey_execute_blob,
    user_newkey_proto_from_blob,
    user_nodes,
    user_timeout
};

void fcgi_user_newkey(void)
{
    struct user_newkey_ctx uctx;
    memset(&uctx, 0, sizeof(uctx));

    job_2pc_handle_request(sx_hashfs_client(hashfs), &user_newkey_spec, &uctx);
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

