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

#include "fcgi-utils.h"
#include "fcgi-actions-user.h"
#include "hashfs.h"
#include "blob.h"
#include "../../../libsxclient/src/sxproto.h"
#include "../../../libsxclient/src/vcrypto.h"

void fcgi_user_onoff(int enable, int all_clones) {
    rc_ty s;

    s = sx_hashfs_user_onoff(hashfs, path, enable, all_clones);

    if(s != OK)
	quit_errnum(400);

    CGI_PUTS("\r\n");
}

static const char *user_get_lock(sx_blob_t *b)
{
    const char *name = NULL;
    return !sx_blob_get_string(b, &name) ? name : NULL;
}

static rc_ty user_nodes(sx_hashfs_t *hashfs, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    /* Users are created globally, in no particluar order (PREVNEXT would be fine too) */
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

struct userdel_ctx {
    const char *name;
    const char *newowner;
    int remove_all; /* Set to 1 if we want to remove all clones of the user */
};

static int userdel_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct userdel_ctx *uctx = yctx;
    if (!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }

    if (sx_blob_add_string(joblb, uctx->name) ||
        sx_blob_add_string(joblb, uctx->newowner) ||
        sx_blob_add_int32(joblb, uctx->remove_all)) {
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
    int remove_all;

    if (sx_blob_get_string(b, &name) ||
        sx_blob_get_string(b, &newowner) ||
        sx_blob_get_int32(b, &remove_all)) {
        WARN("Corrupt userdel blob");
        return NULL;
    }

    switch (phase) {
        case JOBPHASE_REQUEST:
            return sxi_useronoff_proto(sx, name, 0, remove_all);
        case JOBPHASE_COMMIT:
            return sxi_userdel_proto(sx, name, newowner, remove_all);
        case JOBPHASE_ABORT:
            INFO("Delete user '%s': aborting", name);
            return sxi_useronoff_proto(sx, name, 1, remove_all);
        case JOBPHASE_UNDO:
            INFO("Delete user '%s': undoing", name);
            return sxi_useronoff_proto(sx, name, 0, remove_all);
        default:
            return NULL;
    }
}

static rc_ty userdel_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
{
    const char *name;
    const char *newowner;
    int remove_all;
    rc_ty rc = OK;

    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_string(b, &name) ||
        sx_blob_get_string(b, &newowner) ||
        sx_blob_get_int32(b, &remove_all)) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    if (remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    switch (phase) {
        case JOBPHASE_REQUEST:
            DEBUG("userdel request '%s'", name);
	    return sx_hashfs_user_onoff(hashfs, name, 0, remove_all);
        case JOBPHASE_COMMIT:
            DEBUG("userdel commit '%s'", name);
            rc = sx_hashfs_delete_user(hashfs, name, newowner, remove_all);
            if (rc == ENOENT)
                rc = OK;
            if (rc != OK)
                WARN("Failed to delete user %s and replace with %s: %s", name, newowner, msg_get_reason());
            return rc;
        case JOBPHASE_ABORT:
            INFO("Delete user '%s': aborted", name);
            DEBUG("userdel abort '%s'", name);
	    return sx_hashfs_user_onoff(hashfs, name, 1, remove_all);
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
    rc_ty s;

    uctx.name = path;
    if(has_arg("all"))
        uctx.remove_all = 1;
    else
        uctx.remove_all = 0;

    uctx.name = path;
    if (has_priv(PRIV_CLUSTER))
        uctx.newowner = get_arg("chgto");
    else {
        uint8_t deluser[AUTH_UID_LEN];

        s = sx_hashfs_get_user_by_name(hashfs, path, deluser, 0);
        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());

        /* Need to check if removed user doesn't have the same CID as me */
        if((uctx.remove_all && !memcmp(user, deluser, AUTH_CID_LEN)) || !memcmp(user, deluser, AUTH_UID_LEN))
            quit_errmsg(400, "You may not delete yourself");

        s = sx_hashfs_uid_get_name(hashfs, uid, new_owner, sizeof(new_owner));
        if(s != OK)
            quit_errmsg(rc2http(s), msg_get_reason());
        if(sx_hashfs_check_username(new_owner, 0))
            quit_errmsg(500, "Internal error (requesting user has an invalid name)");
        uctx.newowner = new_owner;
    }
    job_2pc_handle_request(sx_hashfs_client(hashfs), &userdel_spec, &uctx);
}

void fcgi_send_user(void) {
    uint8_t user_uid[SXI_SHA1_BIN_LEN];
    sx_uid_t requid;
    uint8_t key[AUTH_KEY_LEN];
    char *desc = NULL;
    char **descptr;
    int64_t quota;
    sx_priv_t role;
    sxi_query_t *q;
    rc_ty rc;

    if ((rc = sx_hashfs_get_user_by_name(hashfs, path, user_uid, 0)) != OK) {
        if(rc == ENOENT)
            quit_errmsg(404, "No such user");
        else
            quit_errmsg(rc2http(rc), rc2str(rc));
    }

    descptr = has_arg("desc") ? &desc : NULL;
    if((rc = sx_hashfs_get_user_info(hashfs, user_uid, &requid, key, &role, descptr, &quota)) != OK) /* no such user */ {
        if (rc == ENOENT)
            quit_errmsg(404, "No such user");
        else
            quit_errmsg(rc2http(rc), rc2str(rc));
    }
    if (!requid) {
        free(desc);
        quit_errmsg(403, "Cluster key is not allowed to be retrieved");
    }

    /* note: takes 'quota' param to decide if it should be printed or not. Should be taken into account to not break <1.2 client tools JSON parsers */
    q = sxi_useradd_proto(sx_hashfs_client(hashfs), path, user_uid, key, role == PRIV_ADMIN, desc, has_arg("quota") ? quota : QUOTA_UNDEFINED);
    free(desc);
    if (!q) {
        msg_set_reason("Cannot retrieve user data for '%s': %s", path, sxc_geterrmsg(sx_hashfs_client(hashfs)));
	quit_errmsg(500, msg_get_reason());
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n");
    CGI_PUTS(q->content);
    sxi_query_free(q);
}

struct user_ctx {
    char name[SXLIMIT_MAX_USERNAME_LEN + 1], existing[SXLIMIT_MAX_USERNAME_LEN + 1];
    char desc[SXLIMIT_MAX_USERDESC_LEN+1];
    uint8_t token[AUTHTOK_BIN_LEN];
    int64_t quota;
    int has_key;
    int has_uid;
    int has_name;
    int role;
    int is_clone; /* Set to 1 if existing is filled with existing user name */
};


static void cb_user_name(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_ctx *uctx = ctx;
    if(length >= sizeof(uctx->name)) {
	sxi_jparse_cancel(J, "Username too long");
	return;
    }
    memcpy(uctx->name, string, length);
    uctx->name[length] = 0;
    uctx->has_name = 1;
}

static void cb_user_exname(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_ctx *uctx = ctx;
    if(length >= sizeof(uctx->existing)) {
	sxi_jparse_cancel(J, "Existing username too long");
	return;
    }
    memcpy(uctx->existing, string, length);
    uctx->existing[length] = 0;
    uctx->is_clone = 1;
}

static void cb_user_desc(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_ctx *uctx = ctx;
    if(length >= sizeof(uctx->desc)) {
	sxi_jparse_cancel(J, "User description too long");
	return;
    }
    memcpy(uctx->desc, string, length);
    uctx->desc[length] = 0;
}

static void cb_user_key(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_ctx *uctx = ctx;
    if(length != AUTH_KEY_LEN * 2) {
	sxi_jparse_cancel(J, "Invalid user key length");
	return;
    }
    if (hex2bin(string, AUTH_KEY_LEN * 2, uctx->token + AUTH_UID_LEN, AUTH_KEY_LEN)) {
	sxi_jparse_cancel(J, "Invalid user key");
	return;
    }
    uctx->has_key = 1;
}

static void cb_user_userid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_ctx *uctx = ctx;
    if(length != AUTH_UID_LEN * 2) {
	sxi_jparse_cancel(J, "Invalid userid length");
	return;
    }
    if (hex2bin(string, AUTH_KEY_LEN * 2, uctx->token, AUTH_UID_LEN)) {
	sxi_jparse_cancel(J, "Invalid userid");
	return;
    }
    uctx->has_uid = 1;
}

static void cb_user_type(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_ctx *uctx = ctx;

    /* Note: if this is not a clone, the role is properly overridden in user_parse_complete */
    if(length == lenof("admin") && !memcmp(string, "admin", lenof("admin")))
	uctx->role = ROLE_ADMIN;
    else if(length == lenof("normal") && !memcmp(string, "normal", lenof("normal")))
	uctx->role = ROLE_USER;
    else {
	sxi_jparse_cancel(J, "Invalid user type");
	return;
    }
}

static void cb_user_quota(jparse_t *J, void *ctx, int64_t num) {
    struct user_ctx *uctx = ctx;
    uctx->quota = num;
}


const struct jparse_actions user_acts = {
    JPACTS_STRING(
		  JPACT(cb_user_name, JPKEY("userName")),
		  JPACT(cb_user_exname, JPKEY("existingName")),
		  JPACT(cb_user_desc, JPKEY("userDesc")),
		  JPACT(cb_user_type, JPKEY("userType")),
		  JPACT(cb_user_userid, JPKEY("userID")),
		  JPACT(cb_user_key, JPKEY("userKey"))
		  ),
    JPACTS_INT64(
		 JPACT(cb_user_quota, JPKEY("userQuota"))
		 )
};

static rc_ty user_parse_complete(void *yctx)
{
    struct user_ctx *uctx = yctx;
    rc_ty s;
    if (!uctx)
        return EINVAL;

    /*
     * Check if username is valid.
     *
     * Check if username contains forbidden path elements (such as slash) only for requests coming from user
     * in order to allow cluster to synchronize if users with invalid names already exist.
     */
    if(sx_hashfs_check_username(uctx->name, !has_priv(PRIV_CLUSTER))) {
	msg_set_reason("Invalid username");
        return EINVAL;
    }

    /* Quota can only be either unlimited (0) or as small as the smallest allowed volume size */
    if(uctx->quota != QUOTA_UNLIMITED && uctx->quota < SXLIMIT_MIN_VOLUME_SIZE) {
        msg_set_reason("Quota must be either 0 or at least %lld bytes", (long long)SXLIMIT_MIN_VOLUME_SIZE);
        return EINVAL;
    }

    if(!has_priv(PRIV_CLUSTER)) {
        if(uctx->is_clone) {
	    uint8_t token[AUTH_UID_LEN];

            /* Check if given user exists and take his role */
            if((s = sx_hashfs_get_uid_role(hashfs, uctx->existing, NULL, &uctx->role)) != OK) {
                WARN("Failed to get existing user role");
                return s;
            }

            if((s = sx_hashfs_get_user_by_name(hashfs, uctx->existing, token, 0)) != OK) {
                WARN("Failed to get existing user ID");
                return s;
            }

            if((s = sx_hashfs_get_user_info(hashfs, token, NULL, NULL, NULL, NULL, &uctx->quota)) != OK) {
                WARN("Failed to get existing user quota");
                return s;
            }

	    if(!uctx->has_uid) {
		/* Generate unique user ID for new user or a clone */
		memcpy(uctx->token, token, AUTH_UID_LEN);
		if((s = sx_hashfs_generate_uid(hashfs, uctx->token)) != OK) {
		    msg_set_reason("Cloned user does not exist");
		    WARN("Failed to get existing user ID");
		    return s;
		}
	    } else {
		/* Use the one provided but only if it's an actual clone */
		if(memcmp(token, uctx->token, AUTH_CID_LEN)) {
		    msg_set_reason("Invalid userid provided for use clone");
		    return EINVAL;
		}
	    }
	} else {
	    if(!uctx->has_uid) {
		if(sx_hashfs_hash_buf(NULL, 0, uctx->name, strlen(uctx->name), (sx_hash_t*)uctx->token)) {
		    WARN("Failed to compute user name hash");
		    return FAIL_EINTERNAL;
		}
	    }
	}
	uctx->has_uid = 1;
    }

    if(!uctx->has_uid || !uctx->has_key || !uctx->has_name) {
	msg_set_reason("One or more required fields are missing");
	return EINVAL;
    }

    return OK;
}

static int user_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    char realdesc[SXLIMIT_MAX_USERDESC_LEN+1];
    struct user_ctx *uctx = yctx;
    if (!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }
    if (uctx->existing[0]) {
        snprintf(realdesc, sizeof(realdesc), "%s (clone of '%s')", uctx->desc, uctx->existing);
    } else {
        snprintf(realdesc, sizeof(realdesc), "%s", uctx->desc);
    }
    realdesc[sizeof(realdesc)-1] = '\0';

    if (sx_blob_add_string(joblb, uctx->name) ||
        sx_blob_add_blob(joblb, uctx->token, AUTHTOK_BIN_LEN) ||
        sx_blob_add_int32(joblb, uctx->role) ||
        sx_blob_add_int64(joblb, uctx->quota) ||
        sx_blob_add_string(joblb, realdesc)) {
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
    int role;
    const uint8_t *token;
    const char *desc = NULL;
    unsigned auth_len;
    int64_t quota;

    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, (const void**)&token, &auth_len) ||
        auth_len != AUTHTOK_BIN_LEN ||
	sx_blob_get_int32(b, &role) ||
        sx_blob_get_int64(b, &quota) ||
        sx_blob_get_string(b, &desc)) {
        WARN("Corrupt user blob");
        return NULL;
    }
    switch (phase) {
        case JOBPHASE_REQUEST:
            return sxi_useradd_proto(sx, name, token, &token[AUTH_UID_LEN], (role == ROLE_ADMIN), desc, quota);
        case JOBPHASE_COMMIT:
            return sxi_useronoff_proto(sx, name, 1, 0);
        case JOBPHASE_ABORT:/* fall-through */
            INFO("Create user '%s': aborting", name);
            return sxi_userdel_proto(sx, name, "admin", 0);
        case JOBPHASE_UNDO:
            INFO("Create user '%s': undoing", name);
            return sxi_userdel_proto(sx, name, "admin", 0);
        default:
            return NULL;
    }
}

static rc_ty user_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
{
    const char *name, *desc;
    const uint8_t *token;
    unsigned auth_len;
    int role;
    int64_t quota;
    rc_ty rc = OK, rc2 = OK;

    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, (const void**)&token, &auth_len) ||
        auth_len != AUTHTOK_BIN_LEN ||
	sx_blob_get_int32(b, &role) ||
        sx_blob_get_int64(b, &quota) ||
        sx_blob_get_string(b, &desc)) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    switch (phase) {
        case JOBPHASE_REQUEST:
            DEBUG("useradd request '%s'", name);
            rc = sx_hashfs_create_user(hashfs, name, token, AUTH_UID_LEN, token + AUTH_UID_LEN, AUTH_KEY_LEN, role, desc, quota);
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
	    rc = sx_hashfs_user_onoff(hashfs, name, 1, 0);
            if (rc)
		WARN("Failed to enable user '%s'", name);
            return rc;
        case JOBPHASE_ABORT:
            DEBUG("useradd abort '%s'", name);
            INFO("Create user '%s': aborted", name);
            /* try hard to deactivate / delete */
	    rc = sx_hashfs_user_onoff(hashfs, name, 0, 0);
            rc2 = sx_hashfs_delete_user(hashfs, name, "admin", 0);
            return rc2 == OK ? rc : rc2;
        case JOBPHASE_UNDO:
            DEBUG("useradd undo '%s'", name);
            /* try hard to deactivate / delete */
	    rc = sx_hashfs_user_onoff(hashfs, name, 0, 0);
            rc2 = sx_hashfs_delete_user(hashfs, name, "admin", 0);
            CRIT("User '%s' may have been left in an inconsistent state after a failed removal attempt", name);
            msg_set_reason("User may have been left in an inconsistent state after a failed removal attempt");
            return FAIL_EINTERNAL;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

const job_2pc_t user_spec = {
    &user_acts,
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
    struct user_ctx *uctx = wrap_calloc(1, sizeof(*uctx));
    if(!uctx)
	quit_errmsg(503, "Out of memory");
    job_2pc_handle_request(sx_hashfs_client(hashfs), &user_spec, uctx);
    free(uctx);
}

struct user_modify_ctx {
    uint8_t auth[AUTH_KEY_LEN];
    int key_given, quota_given, desc_given;
    int64_t quota;
    char description[SXLIMIT_MAX_USERDESC_LEN+1];
};

static void cb_user_modify_key(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_modify_ctx *uctx = ctx;
    if(length != AUTH_KEY_LEN * 2) {
	sxi_jparse_cancel(J, "Invalid user key length");
	return;
    }
    if (hex2bin(string, AUTH_KEY_LEN * 2, uctx->auth, sizeof(uctx->auth))) {
	sxi_jparse_cancel(J, "Invalid user key");
	return;
    }
    uctx->key_given = 1;
}

static void cb_user_modify_desc(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct user_modify_ctx *uctx = ctx;
    if(length > SXLIMIT_MAX_USERDESC_LEN) {
	sxi_jparse_cancel(J, "User description too long");
	return;
    }
    memcpy(uctx->description, string, length);
    uctx->description[length] = '\0';
    uctx->desc_given = 1;
}

static void cb_user_modify_quota(jparse_t *J, void *ctx, int64_t num) {
    struct user_modify_ctx *uctx = ctx;
    uctx->quota = num;
    uctx->quota_given = 1;
}

const struct jparse_actions user_modify_acts = {
    JPACTS_STRING(
		  JPACT(cb_user_modify_key, JPKEY("userKey")),
		  JPACT(cb_user_modify_desc, JPKEY("userDesc")),
		  JPACT(cb_user_modify_desc, JPKEY("desc")) /* Legacy */
		  ),
    JPACTS_INT64(
		 JPACT(cb_user_modify_quota, JPKEY("userQuota")),
		 JPACT(cb_user_modify_quota, JPKEY("quota")) /* Legacy */
		 )
};

static rc_ty user_modify_parse_complete(void *yctx)
{
    struct user_modify_ctx *uctx = yctx;
    if (!uctx)
        return EINVAL;

    if(uctx->quota_given || uctx->desc_given) {
        /* Quota and description can only be changed by an admin user */
        if(!has_priv(PRIV_ADMIN)) {
            msg_set_reason("Permission denied: not enough privileges");
            return EPERM;
        }
    }

    if(uctx->quota_given) {
        rc_ty s;
        sx_priv_t role;
        uint8_t requser[AUTH_UID_LEN];

        if((s = sx_hashfs_get_user_by_name(hashfs, path, requser, 0)) != OK) {
            if(s == ENOENT) {
                msg_set_reason("No such user");
                return ENOENT;
            } else {
                msg_set_reason("Failed to retrieve user '%s'", path);
                return FAIL_EINTERNAL;
            }
        }

        if(sx_hashfs_get_user_info(hashfs, requser, NULL, NULL, &role, NULL, NULL) != OK) {
            msg_set_reason("Failed to retrieve user '%s'", path);
            return FAIL_EINTERNAL;
        }

        /* Cannot set quota for admin users */
       if(role & ~(PRIV_READ | PRIV_WRITE | PRIV_MANAGER)) {
            msg_set_reason("Cannot set quota for admin user");
            return EINVAL;
        }

        /* Quota can only be either 0 or as small as the smallest allowed volume size */
        if(uctx->quota != QUOTA_UNLIMITED && uctx->quota < SXLIMIT_MIN_VOLUME_SIZE) {
            msg_set_reason("Quota must be either 0 or at least %lld bytes", (long long)SXLIMIT_MIN_VOLUME_SIZE);
            return EINVAL;
        }
    }
    return OK;
}

static int user_modify_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct user_modify_ctx *uctx = yctx;
    uint8_t requser[AUTH_UID_LEN];
    uint8_t key[AUTH_KEY_LEN];
    sx_uid_t requid;
    sx_priv_t role;
    int64_t oldquota;
    char *olddesc = NULL;
    rc_ty rc;

    if (!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }
    if(sx_hashfs_check_username(path, 1)) {
        msg_set_reason("Invalid username");
        return -1;
    }
    rc = sx_hashfs_get_user_by_name(hashfs, path, requser, 0);
    if (rc) {
        msg_set_reason("cannot retrieve user: %s", path);
        return -1;
    }
    if(sx_hashfs_get_user_info(hashfs, requser, &requid, key, &role, &olddesc, &oldquota) != OK) /* no such user */ {
        msg_set_reason("No such user");
        return -1;
    }

    if (sx_blob_add_string(joblb, path) ||
        sx_blob_add_blob(joblb, key, AUTH_KEY_LEN) ||
        sx_blob_add_blob(joblb, uctx->auth, AUTH_KEY_LEN) ||
        sx_blob_add_int32(joblb, uctx->key_given) ||
        sx_blob_add_int64(joblb, oldquota) ||
        sx_blob_add_int64(joblb, uctx->quota) ||
        sx_blob_add_int32(joblb, uctx->quota_given) ||
        sx_blob_add_string(joblb, olddesc) ||
        sx_blob_add_string(joblb, uctx->description) ||
        sx_blob_add_int32(joblb, uctx->desc_given)) {
        msg_set_reason("Cannot create job blob");
        free(olddesc);
        return -1;
    }
    free(olddesc);
    return 0;
}

static sxi_query_t* user_modify_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    const char *name, *olddesc, *desc;
    const void *auth, *oldauth;
    unsigned auth_len, oldauth_len;
    int64_t quota, oldquota;
    int key_given, quota_given, desc_given;

    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &oldauth, &oldauth_len) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
        sx_blob_get_int32(b, &key_given) ||
        sx_blob_get_int64(b, &oldquota) ||
        sx_blob_get_int64(b, &quota) ||
        sx_blob_get_int32(b, &quota_given) ||
        sx_blob_get_string(b, &olddesc) ||
        sx_blob_get_string(b, &desc) ||
        sx_blob_get_int32(b, &desc_given) ||
        auth_len != AUTH_KEY_LEN ||
        oldauth_len != AUTH_KEY_LEN ||
        (desc_given && (!olddesc || !desc))) {
        WARN("Corrupt user blob");
        return NULL;
    }

    switch (phase) {
        case JOBPHASE_COMMIT:
            return sxi_usermod_proto(sx, name, key_given ? auth : NULL, quota_given ? quota : QUOTA_UNDEFINED, desc_given ? desc : NULL);
        case JOBPHASE_ABORT:/* fall-through */
            INFO("User '%s' modify: aborting", name);
            return sxi_usermod_proto(sx, name, key_given ? oldauth : NULL, quota_given ? oldquota : QUOTA_UNDEFINED, desc_given ? olddesc : NULL);
        case JOBPHASE_UNDO:
            INFO("User '%s' modify: undoing", name);
            return sxi_usermod_proto(sx, name, key_given ? oldauth : NULL, quota_given ? oldquota : QUOTA_UNDEFINED, desc_given ? olddesc : NULL);
        default:
            return NULL;
    }
}

static rc_ty user_modify_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    const char *name, *olddesc, *desc;
    const void *auth, *oldauth;
    unsigned auth_len, oldauth_len;
    int64_t quota, oldquota;
    int key_given, quota_given, desc_given;
    rc_ty rc = OK;

    if (!h || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &oldauth, &oldauth_len) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
        sx_blob_get_int32(b, &key_given) ||
        sx_blob_get_int64(b, &oldquota) ||
        sx_blob_get_int64(b, &quota) ||
        sx_blob_get_int32(b, &quota_given) ||
        sx_blob_get_string(b, &olddesc) ||
        sx_blob_get_string(b, &desc) ||
        sx_blob_get_int32(b, &desc_given) ||
        auth_len != AUTH_KEY_LEN ||
        (desc_given && (!olddesc || !desc))) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    switch (phase) {
        case JOBPHASE_REQUEST:
            /* remote */
            DEBUG("user_modify request '%s'", name);
            rc = sx_hashfs_user_modify(h, name, key_given ? auth : NULL, key_given ? AUTH_KEY_LEN : 0, quota_given ? quota : QUOTA_UNDEFINED, desc_given ? desc : NULL);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to modify user");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_COMMIT:
            DEBUG("user_modify commit '%s'", name);
            rc = sx_hashfs_user_modify(h, name, key_given ? auth : NULL, key_given ? AUTH_KEY_LEN : 0, quota_given ? quota : QUOTA_UNDEFINED, desc_given ? desc : NULL);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to modify user");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_ABORT:
            DEBUG("user_modify abort '%s'", name);
            rc = sx_hashfs_user_modify(h, name, key_given ? oldauth : NULL, key_given ? AUTH_KEY_LEN : 0, quota_given ? oldquota : QUOTA_UNDEFINED, desc_given ? olddesc : NULL);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to modify user");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        case JOBPHASE_UNDO:
            DEBUG("user_modify undo '%s'", name);
            rc = sx_hashfs_user_modify(h, name, key_given ? oldauth : NULL, key_given ? AUTH_KEY_LEN : 0, quota_given ? oldquota : QUOTA_UNDEFINED, desc_given ? olddesc : NULL);
            if(rc == EINVAL)
                return rc;
            if (rc != OK) {
                msg_set_reason("Unable to modify user");
                rc = FAIL_EINTERNAL;
            }
            return rc;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

const job_2pc_t user_modify_spec = {
    &user_modify_acts,
    JOBTYPE_MODIFY_USER,
    user_modify_parse_complete,
    user_get_lock,
    user_modify_to_blob,
    user_modify_execute_blob,
    user_modify_proto_from_blob,
    user_nodes,
    user_timeout
};

void fcgi_user_modify(void)
{
    struct user_modify_ctx uctx;
    memset(&uctx, 0, sizeof(uctx));
    uctx.quota = QUOTA_UNDEFINED;

    if(sx_hashfs_check_username(path, 1))
        quit_errmsg(400, "Invalid username");
    job_2pc_handle_request(sx_hashfs_client(hashfs), &user_modify_spec, &uctx);
}

static int print_user(sx_uid_t user_id, const char *username, const uint8_t *userhash, const uint8_t *key, int is_admin, const char *desc, int64_t quota, int64_t quota_usage, void *ctx)
{
    int *first = ctx;
    if (!*first)
        CGI_PUTS(",");
    json_send_qstring(username);
    CGI_PRINTF(":{\"admin\":%s", is_admin ? "true" : "false");
    if (desc) {
        CGI_PUTS(",\"userDesc\":");
        json_send_qstring(desc);
    }
    if(quota != QUOTA_UNDEFINED) {
        CGI_PUTS(",\"userQuota\":");
        CGI_PUTLL(quota);
        CGI_PRINTF(",\"userQuotaUsed\":");
        CGI_PUTLL(quota_usage);
    }
    CGI_PUTS("}");
    *first = 0;

    return 0;
}

void fcgi_list_users(void) {
    int first = 1;
    const char *clones = NULL;
    uint8_t clones_cid[AUTH_UID_LEN];
    rc_ty rc;
    if(has_arg("clones"))
        clones = get_arg("clones");

    if(clones && (rc = sx_hashfs_get_user_by_name(hashfs, clones, clones_cid, 0)) != OK) {
        if(rc == ENOENT)
            quit_errmsg(404, "No such user");
        else
            quit_errmsg(rc2http(rc), rc2str(rc));
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n{");
    rc = sx_hashfs_list_users(hashfs, clones ? clones_cid : NULL, print_user, has_arg("desc"), has_arg("quota"), &first);
    CGI_PUTS("}");
    if (rc != OK)
        quit_itererr("Failed to list users", rc);
}

void fcgi_self(void) {
    rc_ty s;
    char name[SXLIMIT_MAX_USERNAME_LEN+1];
    int64_t quota_used;
    char *desc = NULL;
    int first = 1, rc;

    s = sx_hashfs_uid_get_name(hashfs, uid, name, sizeof(name));
    if (s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());
    /* Get total usage of volumes owned by the user and its clones */
    if((s = sx_hashfs_get_owner_quota_usage(hashfs, uid, NULL, &quota_used)) != OK)
        quit_errmsg(rc2http(s), rc2str(s));
    s = sx_hashfs_get_user_info(hashfs, user, NULL, NULL, NULL, &desc, NULL);
    if (s != OK) {
        free(desc);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    CGI_PUTS("Content-type: application/json\r\n\r\n{");
    rc = print_user(uid, name, user, NULL, has_priv(PRIV_ADMIN), desc, user_quota, quota_used, &first);
    CGI_PUTS("}");
    free(desc);
    if(rc)
        quit_itererr("Failed to list users", EINTR);
}
