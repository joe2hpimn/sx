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
#include "fcgi-utils.h"
#include "fcgi-actions-volume.h"
#include "../libsxclient/src/misc.h"
#include "../libsxclient/src/clustcfg.h"
#include "blob.h"
#include "utils.h"
#include "job_common.h"
#include "version.h"
#include <fnmatch.h>

#include "libsxclient/src/jparse.h"
#include "libsxclient/src/vcrypto.h"

static rc_ty int64_arg(const char* arg, int64_t *v, int64_t defaultv)
{
    const char *s = get_arg(arg);
    char *eon;
    *v = defaultv;
    if (s) {
        *v = strtoll(s, &eon, 10);
        if (*eon || *v < 0) {
            msg_set_reason("Invalid '%s' parameter: '%s'", arg, s);
            return EINVAL;
        }
    }
    return OK;
}

void fcgi_locate_volume(const sx_hashfs_volume_t *vol) {
    sx_nodelist_t *allnodes, *goodnodes;
    unsigned int blocksize, nnode, nnodes, i, nmeta = 0, comma, growable = 0;
    struct metacontent {
	char key[SXLIMIT_META_MAX_KEY_LEN+1];
	char hexval[SXLIMIT_META_MAX_VALUE_LEN * 2 + 1];
	int custom;
    } *meta = NULL;
    int64_t fsize;
    rc_ty s;
    sx_priv_t priv = 0;
    char owner[SXLIMIT_MAX_USERNAME_LEN+1];
    char volid_hex[SXI_SHA1_TEXT_LEN+1];

    if(has_arg("size") && !strcmp(get_arg("size"), "growable")) {
	growable = 1;
	fsize = sx_hashfs_growable_filesize();
    } else if (int64_arg("size", &fsize, 0))
        quit_errmsg(400, msg_get_reason());

    /* The locate_volume query is shared between different ops.
     * Although most of them (file creation, file deletion, etc) can be
     * safely target to PREV and NEXT volumes, listing files is only 
     * guaranteed to be accurate when performed against a PREV volnode.
     * The same rule is applied for the split replica situation, here we assume it is
     * a write operation, therefore we pass 0 for the write_op flag. */
    s = sx_hashfs_effective_volnodes(hashfs, NL_PREV, vol, fsize, &allnodes, &blocksize, 0);
    switch(s) {
	case OK:
	    break;
	case EINVAL:
	    quit_errmsg(400, msg_get_reason());
	default:
	    quit_errmsg(500, "Cannot locate the requested volume");
    }

    goodnodes = sx_nodelist_new();
    if(!goodnodes) {
	sx_nodelist_delete(allnodes);
	quit_errmsg(503, "Out of memeory");
    }
    nnodes = sx_nodelist_count(allnodes);
    for(nnode=0; nnode<nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(allnodes, nnode);
	if(sx_hashfs_is_node_faulty(hashfs, sx_node_uuid(node)))
	    continue;
	if(sx_nodelist_add(goodnodes, sx_node_dup(node)))
	    break;
    }
    sx_nodelist_delete(allnodes);
    if(nnode < nnodes) {
	sx_nodelist_delete(goodnodes);
	quit_errmsg(503, "Out of memeory");
    }
    if(!sx_nodelist_count(goodnodes)) {
	sx_nodelist_delete(goodnodes);
	quit_errmsg(503, "All nodes for the volume have failed");
    }

    if((s = sx_hashfs_get_access(hashfs, user, vol->name, &priv)) != OK) {
        sx_nodelist_delete(goodnodes);
        quit_errmsg(rc2http(s), "Failed to get volume privs");
    }

    if((s = sx_hashfs_uid_get_name(hashfs, vol->owner, owner, sizeof(owner))) != OK) {
        sx_nodelist_delete(goodnodes);
        quit_errmsg(rc2http(s), "Failed to get volume owner name");
    }

    if(has_priv(PRIV_ADMIN))
        priv = PRIV_READ | PRIV_WRITE;

    if(has_arg("volumeMeta") || has_arg("customVolumeMeta")) {
        const char *metakey;
        const void *metavalue;
        unsigned int metasize;

        if(sx_hashfs_volumemeta_begin(hashfs, vol)) {
            sx_nodelist_delete(goodnodes);
            quit_errmsg(500, "Cannot lookup volume metadata");
        }

	if(!(meta = wrap_malloc(sizeof(*meta) * SXLIMIT_META_MAX_ITEMS))) {
	    sx_nodelist_delete(goodnodes);
	    quit_errmsg(503, "Out of memory");
	}

	for(nmeta = 0; (s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metavalue, &metasize)) == OK && nmeta < SXLIMIT_META_MAX_ITEMS; nmeta++) {
	    if(strncmp(SX_CUSTOM_META_PREFIX, metakey, lenof(SX_CUSTOM_META_PREFIX))) {
		sxi_strlcpy(meta[nmeta].key, metakey, sizeof(meta[nmeta].key));
		meta[nmeta].custom = 0;
	    } else {
		sxi_strlcpy(meta[nmeta].key, metakey + lenof(SX_CUSTOM_META_PREFIX), sizeof(meta[nmeta].key));
		meta[nmeta].custom = 1;
	    }
	    if(bin2hex(metavalue, metasize, meta[nmeta].hexval, sizeof(meta[nmeta].hexval)))
		break;
	}

	if(s != ITER_NO_MORE) {
	    sx_nodelist_delete(goodnodes);
	    free(meta);
	    quit_itererr("Internal error enumerating volume metadata", FAIL_EINTERNAL);
        }
    }
    CGI_PUTS("Content-type: application/json\r\n\r\n{\"nodeList\":");
    send_nodes_randomised(goodnodes);
    sx_nodelist_delete(goodnodes);
    if(has_arg("size")) {
	if(growable) {
	    CGI_PUTS(",\"growableSize\":");
	    CGI_PUTLL(fsize);
	}
	CGI_PRINTF(",\"blockSize\":%u", blocksize);
    }
    CGI_PUTS(",\"owner\":");
    json_send_qstring(owner);
    CGI_PRINTF(",\"replicaCount\":%u,\"effectiveReplicaCount\":%u,\"maxRevisions\":%u,\"privs\":\"%c%c\",\"usedSize\":",
               vol->max_replica, vol->effective_replica, vol->revisions, (priv & PRIV_READ) ? 'r' : '-', (priv & PRIV_WRITE) ? 'w' : '-');
    /*
     * usedSize:         size of the files stored in the volume including file names size and metadata size,
     * filesSize:        size of the files stored in the volume (excluding file names and metadata),
     * filesCount:       number of files stored in the volume (notice: all revisions are included!),
     * sizeBytes:        the volume size
     */
    CGI_PUTLL(vol->usage_total);
    CGI_PRINTF(",\"filesSize\":");
    CGI_PUTLL(vol->usage_files);
    CGI_PRINTF(",\"filesCount\":");
    CGI_PUTLL(vol->nfiles);
    CGI_PRINTF(",\"sizeBytes\":");
    CGI_PUTLL(vol->size);
    bin2hex(vol->global_id.b, sizeof(vol->global_id.b), volid_hex, sizeof(volid_hex));
    CGI_PRINTF(",\"globalID\":\"%s\"", volid_hex);
    if(has_arg("volumeMeta")) {
        CGI_PUTS(",\"volumeMeta\":{");
	comma = 0;
        for(i = 0; i < nmeta; i++) {
	    if(meta[i].custom)
		continue;
            if(comma)
                CGI_PUTC(',');
            json_send_qstring(meta[i].key);
            CGI_PRINTF(":\"%s\"", meta[i].hexval);
	    comma |= 1;
        }
        CGI_PUTC('}');
    }
    if(has_arg("customVolumeMeta")) {
        CGI_PUTS(",\"customVolumeMeta\":{");
	comma = 0;
        for(i = 0; i < nmeta; i++) {
	    if(!meta[i].custom)
		continue;
            if(comma)
                CGI_PUTC(',');
            json_send_qstring(meta[i].key);
            CGI_PRINTF(":\"%s\"", meta[i].hexval);
	    comma |= 1;
        }
        CGI_PUTC('}');
    }
    CGI_PUTC('}');
    free(meta);
}


void fcgi_list_volume(const sx_hashfs_volume_t *vol) {
    const sx_hashfs_file_t *file;
    unsigned int comma = 0;
    sx_hash_t etag;
    rc_ty s;
    const char *pattern;
    int recursive;
    int64_t i, nmax;

    if (int64_arg("limit", &nmax, ~0u))
        quit_errmsg(400, msg_get_reason());

    CGI_PUTS("Content-type: application/json\r\n");

    pattern = get_arg("filter");
    recursive = has_arg("recursive");
    if(!pattern)
        pattern = "/";
    s = sx_hashfs_list_etag(hashfs, vol, pattern, recursive, &etag);
    if (s) {
        const char* reason = msg_get_reason();
        quit_errmsg(rc2http(s), *reason ? reason : "failed to calculate etag");
    }
    if(is_object_fresh(&etag, 'L', NO_LAST_MODIFIED)) {
        return;
    }
    CGI_PUTS("\r\n");
    if (verb == VERB_HEAD)
        return;
    CGI_PUTS("{\"volumeSize\":");
    CGI_PUTLL(vol->size);
    CGI_PUTS(",\"volumeUsedSize\":");
    CGI_PUTLL(vol->usage_total);

    s = sx_hashfs_list_first(hashfs, vol, get_arg("filter"), &file, has_arg("recursive"), get_arg("after"), 0);
    switch(s) {
    case OK:
    case ITER_NO_MORE:
	break;
    case ENOENT: {
	quit_itererr("The list for the volume is not available here", ENOENT);
    }
    case EINVAL: {
	quit_itererr("Invalid argument", EINVAL);
    }
    default: {
	quit_itererr("Internal error", FAIL_EINTERNAL);
    }
    }

    CGI_PUTS(",\"fileList\":{");

    for(i=0; s == OK && i < nmax; i++, s = sx_hashfs_list_next(hashfs)) {
	/* Make room for the comma,
	 * the worst case encoded filename,
	 * the whole file data,
	 * the json closure
	 * and the string terminator */

	/* "filename":{"fileSize":123,"blockSize":4096,"createdAt":456,"fileRev":"REVISON_STRING"} */
	if(comma) {
            CGI_PUTC(',');
	} else
	    comma |= 1;

	json_send_qstring(file->name);
	if(file->revision[0]) {
	    /* A File */
            CGI_PUTS(":{\"fileSize\":");
            CGI_PUTLL(file->file_size);
            CGI_PRINTF(",\"blockSize\":%u,\"createdAt\":", file->block_size);
            CGI_PUTT(file->created_at);
            CGI_PRINTF(",\"fileRevision\":\"%s\"", file->revision);

            if(has_arg("meta")) {
                rc_ty t;
                const char *key;
                const void *value;
                unsigned int value_len;
                unsigned int comma_meta = 0;
                t = sx_hashfs_getfilemeta_begin(hashfs, volume, file->name+1, file->revision, NULL, NULL);
                if(t != OK && t != ITER_NO_MORE)
                    quit_itererr(msg_get_reason(), t);
                CGI_PRINTF(",\"fileMeta\":{");
                while((t = sx_hashfs_getfilemeta_next(hashfs, &key, &value, &value_len)) == OK) {
                    char hex[SXLIMIT_META_MAX_VALUE_LEN*2+1];
                    if(comma_meta)
                        CGI_PUTC(',');
                    json_send_qstring(key);
                    sxi_bin2hex(value, value_len, hex);
                    CGI_PRINTF(":\"%s\"", hex);
                    comma_meta = 1;
                }
                CGI_PUTC('}');
                if(t != ITER_NO_MORE)
                    break;
            }
            CGI_PUTC('}');
	} else {
	    /* A Fakedir */
            CGI_PUTS(":{}");
	}
    }

    CGI_PUTS("}");
    if (i == nmax) {
        DEBUG("listing truncated after %lld filenames", (long long)i);
        s = ITER_NO_MORE;
    }

    if(s != ITER_NO_MORE)  {
	quit_itererr("Failed to list files", s);
        WARN("failed to list: %s", rc2str(s));
    }
    CGI_PUTS("}");
}


struct acl_op {
    char *name;
    int priv;
    int require_owner;
};

struct acl_ctx {
    struct acl_op *ops;
    unsigned n;
    int require_owner;
    const sx_hashfs_volume_t *vol;
};

static void cb_acl(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *aclop = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct acl_ctx *c = ctx;
    int priv;

    if(!strcmp(aclop, "grant-read")) {
	priv = PRIV_READ;
    } else if (!strcmp(aclop, "grant-write")) {
	priv = PRIV_WRITE;
    } else if (!strcmp(aclop, "grant-manager")) {
	priv = PRIV_MANAGER;
	c->require_owner = 1;
    } else if (!strcmp(aclop, "revoke-read")) {
	priv = ~PRIV_READ;
    } else if (!strcmp(aclop, "revoke-write")) {
	priv = ~PRIV_WRITE;
    } else if (!strcmp(aclop, "revoke-manager")) {
	priv = ~PRIV_MANAGER;
	c->require_owner = 1;
    } else {
	/* Not reached */
	sxi_jparse_cancel(J, "Invalid ACL change request %s", aclop);
	return;
    }

    struct acl_op *newops = realloc(c->ops, sizeof(*newops) * (++c->n));
    if (!newops) {
	sxi_jparse_cancel(J, "Out of memory processing ACL change request");
	return;
    }
    c->ops = newops;

    char *name = malloc(length + 1);
    if (!name) {
	sxi_jparse_cancel(J, "Out of memory processing ACL change request");
	return;
    }
    memcpy(name, string, length);
    name[length] = 0;
    c->ops[c->n-1].name = name;
    c->ops[c->n-1].priv = priv;
}

const struct jparse_actions acl_acts = {
    JPACTS_STRING(
		  JPACT(cb_acl, JPKEY("grant-read"), JPANYITM),
		  JPACT(cb_acl, JPKEY("grant-write"), JPANYITM),
		  JPACT(cb_acl, JPKEY("grant-manager"), JPANYITM),
		  JPACT(cb_acl, JPKEY("revoke-read"), JPANYITM),
		  JPACT(cb_acl, JPKEY("revoke-write"), JPANYITM),
		  JPACT(cb_acl, JPKEY("revoke-manager"), JPANYITM)
		  )
};

struct acl_print_ctx {
    int first;
    int is_1_1;
};

static int print_acl(const char *username, int priv, int is_owner, void *ctx)
{
    struct acl_print_ctx *actx = ctx;
    /* FIXME: should set api_version for send_server_info, however send_server_info is called before handle_request */
    if (actx->first)
	CGI_PUTS("Content-type: application/json\r\n\r\n{");
    else
        CGI_PUTS(",");
    json_send_qstring(username);
    CGI_PUTS(":[");
    int comma = 0;
    if (priv & PRIV_READ) {
	CGI_PUTS("\"read\"");
	comma = 1;
    }
    if (priv & PRIV_WRITE) {
	CGI_PRINTF("%s\"write\"", comma ? "," : "");
	comma = 1;
    }
    if (!actx->is_1_1 && (is_owner || (priv & PRIV_MANAGER))) {
	CGI_PRINTF("%s\"manager\"", comma ? "," : "");
	comma = 1;
    }
    if (is_owner) {
	CGI_PRINTF("%s\"owner\"", comma ? ",":"");
	comma = 1;
    }
    CGI_PUTS("]");
    actx->first = 0;
    return 0;
}

void fcgi_list_acl(const sx_hashfs_volume_t *vol) {
    struct acl_print_ctx actx;
    actx.first = 1;
    actx.is_1_1 = !has_arg("manager");
    rc_ty rc = sx_hashfs_list_acl(hashfs, vol, uid, get_priv(1), print_acl, &actx);
    if (rc != OK) {
	if (rc == ENOENT)
	    quit_errmsg(404, "Volume not found");
        if (rc == EPERM)
            quit_errmsg(403, "Not enough privileges to list volume ACL");
	if (actx.first) {
	    msg_set_reason("Failed to list volume acl: %s", rc2str(rc));
	    quit_errmsg(500, msg_get_reason());
	}
	else
	    quit_itererr("Failed to list volume acl", rc);
    }
    CGI_PUTS("}");
}

static rc_ty acl_parse_complete(void *yctx)
{
    struct acl_ctx *actx = yctx;
    rc_ty s;

    if (!actx)
        return EINVAL;
    if (actx->require_owner && !has_priv(PRIV_OWNER)) {
        msg_set_reason("Permission denied: granting/revoking the manager privilege requires owner or admin privilege");
        return EPERM;
    }
    if(!has_priv(PRIV_CLUSTER)) {
        if((s = sx_hashfs_volume_by_name(hashfs, volume, &actx->vol)) != OK) {
            msg_set_reason("Failed to get volume '%s'", volume);
            return s;
        }
    } else {
        sx_hash_t global_vol_id;

        if(strlen(volume) != SXI_SHA1_TEXT_LEN || hex2bin(volume, SXI_SHA1_TEXT_LEN, global_vol_id.b, sizeof(global_vol_id.b))) {
            msg_set_reason("Invalid global volume ID");
            return EINVAL;
        }
        if((s = sx_hashfs_volume_by_global_id(hashfs, &global_vol_id, &actx->vol)) != OK) {
            msg_set_reason("Failed to get volume by global ID");
            return s;
        }
    }
    return OK;
}

static int acl_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *blob)
{
    struct acl_ctx *actx = yctx;
    int i;
    if(!actx || !actx->vol) {
        msg_set_reason("Invalid argument");
        return -1;
    }
    if (sx_blob_add_blob(blob, actx->vol->global_id.b, sizeof(actx->vol->global_id.b)) ||
        sx_blob_add_int32(blob, actx->n))
        return -1;
    for (i=0;i<actx->n;i++) {
        uint8_t user_uid[AUTH_UID_LEN];
        rc_ty rc;
        int undo_priv, new_priv;
        sx_priv_t old_priv;/* TODO: get_access should return int not sx_priv_t, as its a bitmask not an enum */

        int priv  = actx->ops[i].priv;
        const char *name = actx->ops[i].name;
        rc = sx_hashfs_get_user_by_name(hashfs, name, user_uid, 0);
        if (rc) {
            msg_set_reason("Cannot retrieve user id for '%s'", name);
            return -1;
        }
        rc = sx_hashfs_get_access_by_global_id(hashfs, user_uid, &actx->vol->global_id, &old_priv);
        if (rc) {
            msg_set_reason("Cannot retrieve acl for volume '%s' and user '%s'", volume, name);
            return -1;
        }
        if (priv >= 0)
            new_priv = old_priv | priv;
        else
            new_priv = old_priv & priv;
        int undo_revoke = new_priv & ~old_priv;
        int undo_grant = old_priv & ~new_priv;
        if (undo_grant > 0)
            undo_priv = undo_grant;
        else
            undo_priv = ~undo_revoke;
        if (sx_blob_add_string(blob, name) ||
            sx_blob_add_int32(blob, priv) ||
            sx_blob_add_int32(blob, undo_priv))
            return -1;
    }
    return 0;
}

static rc_ty acl_execute_blob(sx_hashfs_t *hashfs, sx_blob_t *b, jobphase_t phase, int remote)
{
    const sx_hash_t *global_vol_id;
    unsigned int global_id_len;
    rc_ty rc = OK;
    int32_t n, i;

    if (!hashfs || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if (phase == JOBPHASE_COMMIT)
        return OK;
    if (sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) || !global_vol_id || global_id_len != sizeof(global_vol_id->b)) {
        msg_set_reason("Corrupt blob: global ID");
        return FAIL_EINTERNAL;
    }
    if (sx_blob_get_int32(b, &n)) {
        msg_set_reason("Corrupt blob: count");
        return FAIL_EINTERNAL;
    }

    for (i=0;i<n && rc == OK;i++) {
        const char *name;
        int priv, undo_priv, role;
        if (sx_blob_get_string(b, &name) ||
            sx_blob_get_int32(b, &priv) ||
            sx_blob_get_int32(b, &undo_priv)) {
            msg_set_reason("Corrupt blob entry %d/%d", i, n);
            return FAIL_EINTERNAL;
        }
        int64_t uid;
        if (phase != JOBPHASE_REQUEST)
            priv = undo_priv;
        rc = sx_hashfs_get_uid_role(hashfs, name, &uid, &role);
        if (rc == OK) {
            if (role > ROLE_USER) {
                msg_set_reason("Cannot grant/revoke privileges for admin user");
                rc = EINVAL;
                break;
            }
            if (priv >= 0) {
                rc = sx_hashfs_grant(hashfs, uid, global_vol_id, priv);
                if (rc != OK)
                    msg_set_reason("Cannot grant privileges: %s", rc2str(rc));
            } else {
                rc = sx_hashfs_revoke(hashfs, uid, global_vol_id, priv);
                if (rc != OK)
                    msg_set_reason("Cannot revoke privileges: %s", rc2str(rc));
            }
        } else {
            msg_set_reason("Cannot get uid for %s: %s", name, rc2str(rc));
        }
    }
    return rc;
}

struct blob_iter {
    sx_blob_t *b;
    int i;
    int n;
    int phase;
};

static const char *blob_iter_cb(void *ctx, int priv_state, int priv_mask)
{
    struct blob_iter *iter = ctx;
    sx_blob_t *b = iter->b;
    DEBUG("blob_iter entered with i=%d, n=%d", iter->i, iter->n);
    while (iter->i++ < iter->n) {
        const char *name;
        int priv, undo_priv;
        if (sx_blob_get_string(b, &name) ||
            sx_blob_get_int32(b, &priv) ||
            sx_blob_get_int32(b, &undo_priv)) {
            sx_blob_loadpos(b);
            iter->i = 0;
            return NULL;
        }
        if (iter->phase != JOBPHASE_REQUEST && iter->phase != JOBPHASE_COMMIT)
            priv = undo_priv;
        DEBUG("blob_iter on %s: %d,%d; %d,%d", name, priv,undo_priv, priv_state,priv_mask);
        if (priv_state > 0) {
            if (priv > 0 && priv & priv_mask)
                return name;
        } else {
            if (priv < 0 && (~priv) & priv_mask)
                return name;
        }
    }
    iter->i = 0;
    sx_blob_loadpos(b);
    return NULL;
}

static const char *grant_read_cb(void *ctx)
{
    return blob_iter_cb(ctx, 1, PRIV_READ);
}

static const char *grant_write_cb(void *ctx)
{
    return blob_iter_cb(ctx, 1, PRIV_WRITE);
}

static const char *grant_manager_cb(void *ctx)
{
    return blob_iter_cb(ctx, 1, PRIV_MANAGER);
}

static const char *revoke_read_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_READ);
}

static const char *revoke_write_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_WRITE);
}

static const char *revoke_manager_cb(void *ctx)
{
    return blob_iter_cb(ctx, -1, PRIV_MANAGER);
}

static sxi_query_t* acl_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    const sx_hash_t *global_vol_id = NULL;
    unsigned int global_id_len = 0;
    char volid_hex[SXI_SHA1_TEXT_LEN+1];
    struct blob_iter iter;
    memset(&iter, 0, sizeof(iter));

    if (sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len) ||
        !global_vol_id || global_id_len != sizeof(global_vol_id->b) ||
        sx_blob_get_int32(b, &iter.n)) {
        WARN("Corrupt acl blob");
        return NULL;
    }
    sx_blob_savepos(b);
    iter.b = b;
    iter.phase = phase;
    bin2hex(global_vol_id->b, sizeof(global_vol_id->b), volid_hex, sizeof(volid_hex));
    return sxi_volumeacl_proto(sx, volid_hex,
                               grant_read_cb, grant_write_cb, grant_manager_cb,
                               revoke_read_cb, revoke_write_cb, revoke_manager_cb,
                               &iter);
}

static const char *acl_get_lock(sx_blob_t *b)
{
    const char *name = NULL;
    return !sx_blob_get_string(b, &name) ? name : NULL;
}

static rc_ty acl_nodes(sx_hashfs_t *hashfs, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

static unsigned acl_timeout(sxc_client_t *sx, int nodes)
{
    return 12 * nodes;
}

const job_2pc_t acl_spec = {
    &acl_acts,
    JOBTYPE_VOLUME_ACL,
    acl_parse_complete,
    acl_get_lock,
    acl_to_blob,
    acl_execute_blob,
    acl_proto_from_blob,
    acl_nodes,
    acl_timeout
};

void fcgi_acl_volume(void) {
    int i;
    if (is_reserved())
	quit_errmsg(403, "Invalid volume name: must not start with a '.'");

    struct acl_ctx actx;
    memset(&actx, 0, sizeof(actx));

    job_2pc_handle_request(sx_hashfs_client(hashfs), &acl_spec, &actx);

    for (i=0;i<actx.n;i++) {
        free(actx.ops[i].name);
    }
    free(actx.ops);
}

/* {"volumeSize":123, "replicaCount":2, "volumeMeta":{"metaKey":"hex(value)"}, "user":"jack", "maxRevisions":5, "global_id":"aabb...1122"} */
struct cb_volnew_ctx {
    sx_blob_t *metablb;
    sx_hash_t global_id;
    int has_global_id;
    int64_t volsize;
    int replica, oom;
    unsigned int nmeta, revisions;
    char owner[SXLIMIT_MAX_USERNAME_LEN+1];
};

static void cb_volnew_volsize(jparse_t *J, void *ctx, int64_t volsize) {
    struct cb_volnew_ctx *c = ctx;
    c->volsize = volsize;
}

static void cb_volnew_replica(jparse_t *J, void *ctx, int32_t replica_count) {
    struct cb_volnew_ctx *c = ctx;
    if(replica_count < 1) {
	sxi_jparse_cancel(J, "Invalid volume replica count");
	return;
    }
    c->replica = replica_count;
}

static void cb_volnew_revisions(jparse_t *J, void *ctx, int32_t revisions) {
    struct cb_volnew_ctx *c = ctx;
    if(revisions < 1) {
	sxi_jparse_cancel(J, "Invalid number of revisions");
	return;
    }
    c->revisions = revisions;
}

static void cb_volnew_owner(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_volnew_ctx *c = ctx;
    if(length >= sizeof(c->owner)) {
	sxi_jparse_cancel(J, "Invalid volume owner");
	return;
    }
    memcpy(c->owner, string, length);
    c->owner[length] = '\0';
}

static void cb_volnew_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *metakey = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    uint8_t metavalue[SXLIMIT_META_MAX_VALUE_LEN];
    struct cb_volnew_ctx *c = ctx;

    if(c->nmeta >= SXLIMIT_META_MAX_ITEMS) {
	sxi_jparse_cancel(J, "Too many volume metadata entries (max: %u)", SXLIMIT_META_MAX_ITEMS);
	return;
    }

    if(hex2bin(string, length, metavalue, sizeof(metavalue))) {
	sxi_jparse_cancel(J, "Invalid volume metadata value for key '%s'", metakey);
	return;
    }

    length /= 2;
    if(sx_hashfs_check_volume_meta(metakey, metavalue, length, !has_priv(PRIV_CLUSTER))) {
	const char *reason = msg_get_reason();
	sxi_jparse_cancel(J, "'%s'", reason ? reason : "Invalid volume metadata");
	return;
    }

    if(sx_blob_add_string(c->metablb, metakey) ||
       sx_blob_add_blob(c->metablb, metavalue, length)) {
	sxi_jparse_cancel(J, "Out of memory processing volume creation request");
	c->oom = 1;
	return;
    }
    c->nmeta++;
}

static void cb_volnew_global_id(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_volnew_ctx *c = ctx;
    if(length != sizeof(c->global_id.b) * 2 || hex2bin(string, length, c->global_id.b, sizeof(c->global_id.b))) {
        sxi_jparse_cancel(J, "Invalid volume owner");
        return;
    }
    c->has_global_id = 1;
}

void fcgi_create_volume(void) {
    const struct jparse_actions acts = {
	JPACTS_INT64(
		     JPACT(cb_volnew_volsize, JPKEY("volumeSize"))
		     ),
	JPACTS_INT32(
		     JPACT(cb_volnew_replica, JPKEY("replicaCount")),
		     JPACT(cb_volnew_revisions, JPKEY("maxRevisions"))
		     ),
	JPACTS_STRING(
		      JPACT(cb_volnew_meta, JPKEY("volumeMeta"), JPANYKEY),
		      JPACT(cb_volnew_owner, JPKEY("owner")),
                      JPACT(cb_volnew_global_id, JPKEY("global_id"))
		      )
    };
    struct cb_volnew_ctx yctx;
    jparse_t *J;
    int len;
    rc_ty s;
    int64_t owner_uid;

    if(sx_hashfs_check_volume_name(volume))
	quit_errmsg(400, "Bad volume name");

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    yctx.volsize = -1LL;
    yctx.replica = 0;
    yctx.revisions = 0;
    yctx.owner[0] = '\0';
    yctx.nmeta = 0;
    yctx.oom = 0;
    yctx.has_global_id = 0;
    yctx.metablb = sx_blob_new();
    if(!yctx.metablb) {
	sxi_jparse_destroy(J);
	quit_errmsg(500, "Cannot allocate meta storage");
    }
    sx_blob_savepos(yctx.metablb);

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
	send_error(yctx.oom ? 500 : 400, sxi_jparse_geterr(J));
	sx_blob_free(yctx.metablb);
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    auth_complete();
    if(!is_authed()) {
	sx_blob_free(yctx.metablb);
	send_authreq();
	return;
    }

    if(yctx.volsize < 0) {
	sx_blob_free(yctx.metablb);
	quit_errmsg(400, "Invalid volume size");
    }

    if(!yctx.owner[0] || sx_hashfs_check_username(yctx.owner, 1)) {
	sx_blob_free(yctx.metablb);
	quit_errmsg(400, "Invalid volume owner: invalid username");
    }

    if(sx_hashfs_get_uid(hashfs, yctx.owner, &owner_uid)) {
	sx_blob_free(yctx.metablb);
	quit_errmsg(400, "Invalid volume owner: user does not exist");
    }

    /* New volume defaults */
    if(yctx.revisions == 0)
	yctx.revisions = 1;
    if(!yctx.replica)
	yctx.replica = 1;

    if(has_priv(PRIV_CLUSTER)) {
	/* Request comes in from the cluster: apply locally */
        if(!yctx.has_global_id) {
            sx_blob_free(yctx.metablb);
            quit_errmsg(400, "Global volume ID has not been provided");
        }

	sx_hashfs_volume_new_begin(hashfs);
	sx_blob_loadpos(yctx.metablb);
	while(yctx.nmeta--) {
	    const char *mkey;
	    const void *mval;
	    unsigned int mval_len;
	    if(sx_blob_get_string(yctx.metablb, &mkey) ||
	       sx_blob_get_blob(yctx.metablb, &mval, &mval_len)) {
		sx_blob_free(yctx.metablb);
		quit_errmsg(500, "Cannot get metadata from blob");
	    }
	    s = sx_hashfs_volume_new_addmeta(hashfs, mkey, mval, mval_len);
	    if(s != OK) {
		sx_blob_free(yctx.metablb);
		if(s == EOVERFLOW)
		    quit_errmsg(400, "Too many metadata items");
		else
		    quit_errmsg(400, "Bad metadata");
	    }
	}

	s = sx_hashfs_volume_new_finish(hashfs, volume, &yctx.global_id, yctx.volsize, yctx.replica, yctx.revisions, owner_uid, 1);
	sx_blob_free(yctx.metablb);

	switch (s) {
	case OK:
	    break;
	case EEXIST:
	    quit_errmsg(409, "Volume already exists");
	case ENAMETOOLONG: /* FIXME: currently not returned */
	    quit_errmsg(414, "Volume name too long");
	case EINVAL:
	    quit_errmsg(400, msg_get_reason());
	default:
	    if (msg_was_busy())
		quit_errmsg(503, "The requested volume could not be created: try again later");
	    else
		quit_errmsg(500, "The requested volume could not be created");
	}
	CGI_PUTS("\r\n");
	return;
    } else {
	/* Request comes in from the user: broadcast to all nodes */
	sx_blob_t *joblb;
	const void *job_data;
	unsigned int job_datalen;
	const sx_nodelist_t *allnodes = sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV);
	int extra_job_timeout = 50 * (sx_nodelist_count(allnodes)-1);
	job_t job;
	rc_ty res;

        if(yctx.has_global_id) {
            sx_blob_free(yctx.metablb);
            quit_errmsg(400, "Global volume ID cannot be provided with a user request");
        }

        /* Generate a volume ID for the new volume */
        if(sxi_rand_bytes(yctx.global_id.b, sizeof(yctx.global_id.b))) {
            sx_blob_free(yctx.metablb);
            quit_errmsg(500, "Failed to generate global volume ID");
        }

        res = sx_hashfs_check_volume_settings(hashfs, volume, yctx.volsize, -1, yctx.replica, yctx.revisions);
        if(res != OK) {
            sx_blob_free(yctx.metablb);
            if(res == EINVAL)
                quit_errmsg(400, msg_get_reason());
            else
                quit_errmsg(500, "The requested volume could not be created");
        }

	if(!(joblb = sx_blob_new())) {
	    sx_blob_free(yctx.metablb);
	    quit_errmsg(500, "Cannot allocate job blob");
	}
	if(sx_blob_add_string(joblb, volume) ||
           sx_blob_add_blob(joblb, yctx.global_id.b, sizeof(yctx.global_id.b)) ||
	   sx_blob_add_string(joblb, yctx.owner) ||
	   sx_blob_add_int64(joblb, yctx.volsize) ||
	   sx_blob_add_int32(joblb, yctx.replica) ||
	   sx_blob_add_int32(joblb, yctx.revisions) ||
	   sx_blob_add_int32(joblb, yctx.nmeta) ||
	   sx_blob_add_int32(joblb, extra_job_timeout) ||
	   sx_blob_cat(joblb, yctx.metablb)) {
	    sx_blob_free(yctx.metablb);
	    sx_blob_free(joblb);
	    quit_errmsg(500, "Cannot create job blob");
	}
	sx_blob_free(yctx.metablb);

	sx_blob_to_data(joblb, &job_data, &job_datalen);
	/* Volumes are created globally, in no particluar order (PREVNEXT would be fine too) */
	res = sx_hashfs_job_new(hashfs, uid, &job, JOBTYPE_CREATE_VOLUME, 20, volume, job_data, job_datalen, allnodes);
	sx_blob_free(joblb);
	if(res != OK)
	    quit_errmsg(rc2http(res), msg_get_reason());

	send_job_info(job);
	return;
    }
}

/*
 * 'volume' contains global volume ID hex (only .s2s query)
 */
void fcgi_volume_onoff(int enable) {
    rc_ty s;
    sx_hash_t global_vol_id;
    unsigned int len;

    if(is_reserved())
	quit_errmsg(403, "Invalid volume name: must not start with a '.'");
    len = strlen(volume);
    if(len != sizeof(global_vol_id.b) * 2 || hex2bin(volume, len, global_vol_id.b, sizeof(global_vol_id.b)))
        quit_errmsg(400, "Invalid volume ID");
    if(enable)
	s = sx_hashfs_volume_enable(hashfs, &global_vol_id);
    else
	s = sx_hashfs_volume_disable(hashfs, &global_vol_id);

    if(s != OK)
	quit_errnum(400);

    CGI_PUTS("\r\n");
}

void fcgi_delete_volume(void) {
    rc_ty s;
    if(is_reserved())
	quit_errmsg(403, "Invalid volume name: must not start with a '.'");

    if(has_priv(PRIV_CLUSTER)) {
        sx_hash_t global_id;

        if(strlen(volume) != SXI_SHA1_TEXT_LEN ||
           hex2bin(volume, SXI_SHA1_TEXT_LEN, global_id.b, sizeof(global_id.b)))
            quit_errmsg(400, "Missing or invalid global ID");

	/* Coming in from cluster */
	s = sx_hashfs_volume_delete(hashfs, &global_id, has_arg("force"));
	if(s != OK)
	    quit_errnum(rc2http(s));

	CGI_PUTS("\r\n");

    } else {
	/* Coming in from (admin) user */
	const sx_hashfs_volume_t *vol;
	const sx_nodelist_t *allnodes;
	unsigned int timeout;
	const void *job_data;
	unsigned int job_datalen;
	sx_blob_t *joblb;
	int emptyvol = 0;
	job_t job;

	if((s = sx_hashfs_volume_by_name(hashfs, volume, &vol)))
	    quit_errmsg(rc2http(s), msg_get_reason());

	if(!sx_hashfs_is_or_was_my_volume(hashfs, vol, 0))
	    quit_errmsg(404, "This volume does not belong here");

	if(!vol->usage_total) {
	    s = sx_hashfs_list_first(hashfs, vol, NULL, NULL, 1, NULL, 0);
	    if(s == ITER_NO_MORE)
		emptyvol = 1;
	    else if(s != OK)
		quit_errmsg(rc2http(s), msg_get_reason());
	}

	if(!emptyvol)
	    quit_errmsg(409, "Cannot delete non-empty volume");

	allnodes = sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV);
	timeout = 5 * 60 * sx_nodelist_count(allnodes);
	joblb = sx_blob_new();
	if(!joblb)
	    quit_errmsg(500, "Cannot allocate job blob");

	if(sx_blob_add_blob(joblb, vol->global_id.b, sizeof(vol->global_id.b))) {
	    sx_blob_free(joblb);
	    quit_errmsg(500, "Cannot create job blob");
	}

	sx_blob_to_data(joblb, &job_data, &job_datalen);
	s = sx_hashfs_job_new(hashfs, 0, &job, JOBTYPE_DELETE_VOLUME, timeout, path, job_data, job_datalen, allnodes);
	sx_blob_free(joblb);

	if(s != OK)
	    quit_errmsg(rc2http(s), msg_get_reason());

	send_job_info(job);

    }
}

void fcgi_trigger_gc(void)
{
    auth_complete();
    quit_unless_authed();
    sx_hashfs_gc_trigger(hashfs);
    CGI_PUTS("\r\n");
}

/* {"vol1":{"usedSize":123,"filesSize":234,"filesCount":345},"vol2":{"usedSize":456,"filesSize":567,"filesCount":678}} */
struct cb_volsizes_ctx {
    struct volsizes_data {
	int64_t id;
	int64_t used_size;
        int64_t files_size;
        int64_t nfiles;
    } *vols;
    unsigned int nvols;

    /* temp */
    int64_t used_size;
    int64_t files_size;
    int64_t nfiles;
};

static void cb_volsizes_used_size(jparse_t *J, void *ctx, int64_t used_size) {
    struct cb_volsizes_ctx *c = ctx;
    c->used_size = used_size;
}

static void cb_volsizes_files_size(jparse_t *J, void *ctx, int64_t files_size) {
    struct cb_volsizes_ctx *c = ctx;
    c->files_size = files_size;
}

static void cb_volsizes_nfiles(jparse_t *J, void *ctx, int64_t nfiles) {
    struct cb_volsizes_ctx *c = ctx;
    c->nfiles = nfiles;
}

static void cb_volsizes_begin(jparse_t *J, void *ctx) {
    struct cb_volsizes_ctx *c = ctx;
    c->used_size = 0;
    c->files_size = 0;
    c->nfiles = 0;
}

static void cb_volsizes_end(jparse_t *J, void *ctx) {
    const char *global_vol_id_hex = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct cb_volsizes_ctx *c = ctx;
    const sx_hashfs_volume_t *vol;
    sx_hash_t global_vol_id;

    if(!global_vol_id_hex || strlen(global_vol_id_hex) != SXI_SHA1_TEXT_LEN ||
       hex2bin(global_vol_id_hex, SXI_SHA1_TEXT_LEN, global_vol_id.b, sizeof(global_vol_id.b))) {
        sxi_jparse_cancel(J, "Invalid global volume ID");
        return;
    }

    if(sx_hashfs_volume_by_global_id(hashfs, &global_vol_id, &vol) != OK)
	return; /* Could be anything, just skip this vol */

    if(sx_hashfs_is_node_volume_owner(hashfs, NL_PREV, sx_hashfs_self(hashfs), vol, 0))
	return; /* Could happen if we are rebalancing */

    if(!(c->nvols & 0xf)) {
	struct volsizes_data *nuvols;
	nuvols = realloc(c->vols, (c->nvols + 16) * sizeof(c->vols[0]));
	if(!nuvols) {
	    sxi_jparse_cancel(J, "Out of memory processing request");
	    return;
	}
	c->vols = nuvols;
    }
    c->vols[c->nvols].id = vol->id;
    c->vols[c->nvols].used_size = c->used_size;
    c->vols[c->nvols].files_size = c->files_size;
    c->vols[c->nvols].nfiles = c->nfiles;
    c->nvols++;
}

void fcgi_volsizes(void) {
    const struct jparse_actions acts = {
	JPACTS_INT64(
                        JPACT(cb_volsizes_used_size, JPANYKEY, JPKEY("usedSize")),
                        JPACT(cb_volsizes_files_size, JPANYKEY, JPKEY("filesSize")),
                        JPACT(cb_volsizes_nfiles, JPANYKEY, JPKEY("filesCount"))
                    ),
        JPACTS_MAP_BEGIN(
                        JPACT(cb_volsizes_begin, JPANYKEY)
                        ),
        JPACTS_MAP_END(
                        JPACT(cb_volsizes_end, JPANYKEY)
                        )
    };
    struct cb_volsizes_ctx yctx;
    jparse_t *J;
    int len;
    unsigned int i;

    /* Assign begin state */
    yctx.nvols = 0;
    yctx.vols = NULL;

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J)
	quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(sxi_jparse_digest(J, hashbuf, len))
	    break;

    if(len || sxi_jparse_done(J)) {
        free(yctx.vols);
	send_error(500, sxi_jparse_geterr(J));
	sxi_jparse_destroy(J);
	return;
    }
    sxi_jparse_destroy(J);

    /* JSON parsing completed */
    auth_complete();
    if(!is_authed()) {
        free(yctx.vols);
        send_authreq();
        return;
    }

    for(i = 0; i < yctx.nvols; i++) {
        rc_ty rc;

        /* Set volume size */
        if((rc = sx_hashfs_reset_volume_cursize(hashfs, yctx.vols[i].id, yctx.vols[i].used_size, yctx.vols[i].files_size, yctx.vols[i].nfiles)) != OK) {
            WARN("Failed to set volume id %llu size to %lld", (long long)yctx.vols[i].id, (long long)yctx.vols[i].used_size);
            free(yctx.vols);
            quit_errmsg(rc2http(rc), rc2str(rc));
        }
    }

    CGI_PUTS("\r\n");
    free(yctx.vols);
}

/* {"owner":"alice","size":1000000000,"maxRevisions":10,"customVolumeMeta":{"customMeta1":"aabbcc"},"name":"newvolumename"} */
struct volmod_ctx {
    sx_hash_t global_vol_id;
    const sx_hashfs_volume_t *vol;
    char oldname[SXLIMIT_MAX_VOLNAME_LEN+1];
    char newname[SXLIMIT_MAX_VOLNAME_LEN+1];
    char oldowner[SXLIMIT_MAX_USERNAME_LEN+1];
    char newowner[SXLIMIT_MAX_USERNAME_LEN+1];
    int64_t oldsize;
    int64_t newsize;
    int oldrevs;
    int newrevs;
    int nmeta;
    sx_blob_t *meta;
    int noldmeta;
    sx_blob_t *oldmeta;
};

static void volmod_ctx_init(struct volmod_ctx *ctx) {
    ctx->oldname[0] = '\0';
    ctx->newname[0] = '\0';
    ctx->oldowner[0] = '\0';
    ctx->newowner[0] = '\0';
    ctx->newsize = -1;
    ctx->oldsize = -1;
    ctx->newrevs = -1;
    ctx->oldrevs = -1;
    ctx->meta = NULL;
    ctx->nmeta = -1;
    ctx->oldmeta = NULL;
    ctx->noldmeta = -1;
    ctx->vol = NULL;
}

static const char *volmod_get_lock(sx_blob_t *b)
{
    const char *vol = NULL;
    return !sx_blob_get_string(b, &vol) ? vol : NULL;
}

static rc_ty volmod_nodes(sx_hashfs_t *h, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if (!nodes)
        return FAIL_EINTERNAL;
    /* All nodes have to receive modification request since owners and sizes are set globally */
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(h, NL_NEXTPREV));
    if (!*nodes)
        return FAIL_EINTERNAL;

    return OK;
}

static int blob_to_volmod(sxc_client_t *sx, sx_blob_t *b, struct volmod_ctx *ctx) {
    const char *oldname = NULL, *newname = NULL;
    const char *oldowner = NULL, *newowner = NULL;
    const sx_hash_t *global_vol_id = NULL;
    unsigned int global_id_len = 0;

    if(!b || !ctx)
        return 1;
    volmod_ctx_init(ctx);

    if(sx_blob_get_blob(b, (const void**)&global_vol_id, &global_id_len)
       || !global_vol_id || global_id_len != sizeof(global_vol_id->b)
       || sx_blob_get_string(b, &oldname) || sx_blob_get_string(b, &newname)
       || sx_blob_get_string(b, &oldowner) || sx_blob_get_string(b, &newowner)
       || sx_blob_get_int64(b, &ctx->oldsize) || sx_blob_get_int64(b, &ctx->newsize)
       || sx_blob_get_int32(b, &ctx->oldrevs) || sx_blob_get_int32(b, &ctx->newrevs)) {
        WARN("Corrupted volume mod blob");
        return 1;
    }
    memcpy(ctx->global_vol_id.b, global_vol_id->b, sizeof(ctx->global_vol_id.b));

    if(oldname && *oldname)
        snprintf(ctx->oldname, SXLIMIT_MAX_VOLNAME_LEN+1, "%s", oldname);
    else
        ctx->oldname[0] = '\0';

    if(newname && *newname)
        snprintf(ctx->newname, SXLIMIT_MAX_VOLNAME_LEN+1, "%s", newname);
    else
        ctx->newname[0] = '\0';

    if(oldowner && *oldowner)
        snprintf(ctx->oldowner, SXLIMIT_MAX_USERNAME_LEN+1, "%s", oldowner);
    else
        ctx->oldowner[0] = '\0';

    if(newowner && *newowner)
        snprintf(ctx->newowner, SXLIMIT_MAX_USERNAME_LEN+1, "%s", newowner);
    else
        ctx->newowner[0] = '\0';

    return 0;
}

static int volmod_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct volmod_ctx *ctx = yctx;

    if (!joblb) {
        msg_set_reason("Cannot allocate job storage");
        return -1;
    }

    if(sx_blob_add_blob(joblb, ctx->global_vol_id.b, sizeof(ctx->global_vol_id.b)) || sx_blob_add_string(joblb, ctx->oldname)
        || sx_blob_add_string(joblb, ctx->newname) || sx_blob_add_string(joblb, ctx->oldowner)
        || sx_blob_add_string(joblb, ctx->newowner) || sx_blob_add_int64(joblb, ctx->oldsize)
        || sx_blob_add_int64(joblb, ctx->newsize) || sx_blob_add_int32(joblb, ctx->oldrevs)
        || sx_blob_add_int32(joblb, ctx->newrevs) || sx_blob_add_int32(joblb, ctx->nmeta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    if(ctx->nmeta != -1 && sx_blob_cat(joblb, ctx->meta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    /* Backup also old meta */
    if(sx_blob_add_int32(joblb, ctx->noldmeta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    if(ctx->noldmeta != -1 && sx_blob_cat(joblb, ctx->oldmeta)) {
        msg_set_reason("Cannot create job storage");
        return -1;
    }

    return 0;
}

static unsigned volmod_timeout(sxc_client_t *sx, int nodes)
{
    return 20 * nodes;
}

static sxi_query_t* volmod_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    struct volmod_ctx ctx;
    sxi_query_t *ret;
    sxc_meta_t *meta = NULL;
    char volid_hex[SXI_SHA1_TEXT_LEN+1];

    if(blob_to_volmod(sx, b, &ctx)) {
        WARN("Failed to read job blob");
        return NULL;
    }
    bin2hex(ctx.global_vol_id.b, sizeof(ctx.global_vol_id.b), volid_hex, sizeof(volid_hex));

    /* If job is in abort phase, then skip setting metadata */
    if(sx_hashfs_blob_to_sxc_meta(sx, b, &meta, phase != JOBPHASE_COMMIT)) {
        WARN("Failed to read job blob");
        return NULL;
    }

    /* Pick up old metadata */
    if(phase != JOBPHASE_COMMIT && sx_hashfs_blob_to_sxc_meta(sx, b, &meta, 0)) {
        WARN("Failed to read job blob");
        return NULL;
    }

    /* In COMMIT phase meta contains new metadata, in ABORT or UNDO it contains old, backed up metadata */
    switch (phase) {
        case JOBPHASE_COMMIT:
            ret = sxi_volume_mod_proto_internal(sx, volid_hex, *ctx.newname ? ctx.newname : NULL, *ctx.newowner ? ctx.newowner : NULL, ctx.newsize, ctx.newrevs, meta);
            break;
        case JOBPHASE_ABORT:
        case JOBPHASE_UNDO:
            ret = sxi_volume_mod_proto_internal(sx, volid_hex, *ctx.oldname ? ctx.oldname : NULL, *ctx.oldowner ? ctx.oldowner : NULL, ctx.oldsize, ctx.oldrevs, meta);
            break;
        default:
            ret = NULL;
    }

    sxc_meta_free(meta);
    return ret;
}

static rc_ty volmod_create_revsclean_job(sx_hashfs_t *h, const sx_hashfs_volume_t *vol) {
    rc_ty s;
    job_t job;
    sx_nodelist_t *curnode_list = NULL;
    sx_blob_t *joblb;
    const void *job_data;
    unsigned int job_datalen;
    int job_timeout = 20;
    const sx_node_t *me;

    me = sx_hashfs_self(h);
    if(!me) {
        WARN("Failed to get self node reference");
        return FAIL_EINTERNAL;
    }

    /* Schedule to PREVNEXT. On old volnodes all files will eventually be dropped,
     * but we should avoid listing old revs and it is done on PREV */
    if(!sx_hashfs_is_node_volume_owner(h, NL_PREVNEXT, me, vol, 0)) {
        /* Do not schedule this job if local node is not a volnode */
        DEBUG("Skipped scheduling revsclean job: not a volnode");
        return OK;
    }

    curnode_list = sx_nodelist_new();
    if(!curnode_list) {
        WARN("Failed to allocate nodeslist");
        return FAIL_EINTERNAL;
    }
    if(sx_nodelist_add(curnode_list, sx_node_dup(me))) {
        WARN("Failed to add myself to nodelist");
        sx_nodelist_delete(curnode_list);
        return FAIL_EINTERNAL;
    }

    if(!(joblb = sx_blob_new())) {
        WARN("Cannot allocate job blob");
        sx_nodelist_delete(curnode_list);
        return FAIL_EINTERNAL;
    }

    if(sx_blob_add_blob(joblb, vol->global_id.b, sizeof(vol->global_id.b)) || sx_blob_add_string(joblb, "")) {
        sx_blob_free(joblb);
        sx_nodelist_delete(curnode_list);
        WARN("Cannot create job blob");
        return FAIL_EINTERNAL;
    }

    sx_blob_to_data(joblb, &job_data, &job_datalen);
    s = sx_hashfs_job_new(h, 0, &job, JOBTYPE_REVSCLEAN, job_timeout, vol->name, job_data, job_datalen, curnode_list);
    sx_blob_free(joblb);
    sx_nodelist_delete(curnode_list);
    return s;
}

static rc_ty volmod_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    struct volmod_ctx ctx;
    rc_ty rc = OK, s;
    int i, nmeta, change_meta = 0;

    if (!h || !b) {
        WARN("NULL arguments");
        return FAIL_EINTERNAL;
    }

    if(blob_to_volmod(sx_hashfs_client(h), b, &ctx)) {
        WARN("Corrupted volume mod blob");
        return FAIL_EINTERNAL;
    }

    if((s = sx_hashfs_volume_by_global_id(h, &ctx.global_vol_id, &ctx.vol)) != OK) {
        msg_set_reason("Failed to get volume instance");
        return s;
    }

    if (remote && phase == JOBPHASE_REQUEST)
        phase = JOBPHASE_COMMIT;

    if(sx_blob_get_int32(b, &nmeta)) {
        WARN("Corrupted volume mod blob");
        return 1;
    }

    if(nmeta != -1) {
        if(sx_hashfs_volume_mod_begin(h, ctx.vol))
            return 1;
        change_meta = 1;
    }

    for(i = 0; i < nmeta; i++) {
        const char *metakey;
        const void *metaval;
        unsigned int l;

        if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &l)) {
            WARN("Failed to get meta key-value pair from blob");
            return FAIL_EINTERNAL;
        }

        if(phase == JOBPHASE_COMMIT && (s = sx_hashfs_volume_mod_addmeta(h, metakey, metaval, l)) != OK) {
            WARN("Failed to add meta key-value pair to context blob");
            return s;
        }
    }

    /* When meta change is intended and job phase is abort or undo, then pick backed up meta from blob */
    if(phase != JOBPHASE_COMMIT && change_meta) {
        if(sx_blob_get_int32(b, &nmeta)) {
            WARN("Corrupted volume mod blob");
            return 1;
        }

        for(i = 0; i < nmeta; i++) {
            const char *metakey;
            const void *metaval;
            unsigned int l;

            if(sx_blob_get_string(b, &metakey) || sx_blob_get_blob(b, &metaval, &l)) {
                WARN("Failed to get meta key-value pair from blob");
                return FAIL_EINTERNAL;
            }

            if(sx_hashfs_volume_mod_addmeta(h, metakey, metaval, l)) {
                WARN("Failed to add meta key-value pair to context blob");
                return FAIL_EINTERNAL;
            }
        }
    }

    switch (phase) {
        case JOBPHASE_COMMIT:
            rc = sx_hashfs_volume_mod(h, ctx.vol, ctx.newname, ctx.newowner, ctx.newsize, ctx.newrevs, change_meta);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.vol->name, msg_get_reason());
            if(rc == OK && ctx.newrevs < ctx.oldrevs) {
                rc = volmod_create_revsclean_job(h, ctx.vol);
                if(rc != OK)
                    WARN("Failed to create revsclean job");
                /* Do not fail here, its background job */
                return OK;
            }
            return rc;
        case JOBPHASE_ABORT:
            rc = sx_hashfs_volume_mod(h, ctx.vol, ctx.oldname, ctx.oldowner, ctx.oldsize, ctx.oldrevs, change_meta);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.vol->name, msg_get_reason());
            return rc;
        case JOBPHASE_UNDO:
            CRIT("volume '%s' may have been left in an inconsistent state after a failed modification attempt", ctx.vol->name);
            rc = sx_hashfs_volume_mod(h, ctx.vol, ctx.oldname, ctx.oldowner, ctx.oldsize, ctx.oldrevs, change_meta);
            if (rc != OK)
                WARN("Failed to change volume %s: %s", ctx.vol->name, msg_get_reason());
            return rc;
        default:
            WARN("Impossible job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

static rc_ty volmod_parse_complete(void *yctx)
{
    rc_ty s;
    struct volmod_ctx *ctx = yctx;

    if (!ctx)
        return EINVAL;

    if((*ctx->newname || *ctx->newowner || ctx->newsize != -1) && !has_priv(PRIV_ADMIN)) {
        msg_set_reason("Permission denied: Not enough privileges");
        return EPERM;
    } else if(ctx->newrevs != -1 && !has_priv(PRIV_OWNER)) {
        msg_set_reason("Permission denied: Not enough privileges");
        return EPERM;
    } else if(!has_priv(PRIV_MANAGER)) {
        msg_set_reason("Permission denied: Not enough privileges");
        return EPERM;
    }

    /* Check if the volume exists */
    if(has_priv(PRIV_CLUSTER)) {
        if(strlen(volume) != SXI_SHA1_TEXT_LEN || hex2bin(volume, SXI_SHA1_TEXT_LEN, ctx->global_vol_id.b, sizeof(ctx->global_vol_id.b))) {
            msg_set_reason("Invalid global volume ID");
            return EINVAL;
        }
        s = sx_hashfs_volume_by_global_id(hashfs, &ctx->global_vol_id, &ctx->vol);
        if(s != OK)
            return s;
    } else {
        s = sx_hashfs_volume_by_name(hashfs, volume, &ctx->vol);
        if(s != OK)
            return s;
        memcpy(ctx->global_vol_id.b, ctx->vol->global_id.b, sizeof(ctx->global_vol_id.b));
    }

    /* Preliminary checks for a volume rename
     *
     * Check if there won't be a name collision after renaming volume to
     * a new name. This check has to be run first because the static storage in sx_hashfs_volume_t
     * will be overwritten by sx_hashfs_volume_by_name. */
    if(*ctx->newname) {
        /* Avoid modifications for the same name provided */
        if(!strcmp(ctx->vol->name, ctx->newname)) {
            *ctx->oldname = '\0';
            *ctx->newname = '\0';
        } else {
            sxi_strlcpy(ctx->oldname, ctx->vol->name, sizeof(ctx->oldname));
            s = sx_hashfs_check_volume_existence(hashfs, ctx->newname);
            if(s != ENOENT && s != EEXIST) {
                msg_set_reason("Failed to check volume existence");
                return s;
            } else if(s == EEXIST) {
                msg_set_reason("Volume already exists");
                return EEXIST;
            }

            /* Rebalance and faulty node replacement jobs require files synchronization which could
             * encounter unexpected 'Not found' issues if the volume was renamed in the middle of the process. */
            if(sx_hashfs_is_rebalancing(hashfs)) {
                msg_set_reason("The cluster is being rebalanced");
                return EINVAL;
            }

            if(sx_nodelist_count(sx_hashfs_faulty_nodes(hashfs))) {
                msg_set_reason("The cluster contains faulty nodes which are still being replaced");
                return EINVAL;
            }

            if(sx_hashfs_is_upgrading(hashfs)) {
                msg_set_reason("The cluster is being upgraded");
                return EINVAL;
            }
        }
    }

    /* Reject renaming volume while changing its replica */
    if(*ctx->newname && ctx->vol->prev_max_replica != ctx->vol->max_replica) {
        msg_set_reason("The volume is undergoing replica change");
        return EINVAL;
    }

    /* Preliminary checks for ownership change */
    if(*ctx->newowner) {
        /* Do that check only for local node */
        if(sx_hashfs_uid_get_name(hashfs, ctx->vol->owner, ctx->oldowner, SXLIMIT_MAX_USERNAME_LEN) != OK) {
            WARN("Could not get current volume owner");
            msg_set_reason("Volume owner does not exist");
            return ENOENT;
        }

        if(sx_hashfs_check_username(ctx->newowner, 1)) {
            msg_set_reason("Invalid username");
            return EINVAL;
        }

        /* Check if new volume owner exists */
        if((s = sx_hashfs_get_user_by_name(hashfs, ctx->newowner, NULL, 0)) != OK) {
            msg_set_reason("User not found");
            return s;
        }

        /* Avoid modifications for the same owner provided */
        if(!strcmp(ctx->oldowner, ctx->newowner)) {
            *ctx->oldowner = '\0';
            *ctx->newowner = '\0';
        }
    }

    if(ctx->newsize != -1) {
        if(ctx->newsize != ctx->vol->size)
            ctx->oldsize = ctx->vol->size;
        else {
            ctx->newsize = -1;
            ctx->oldsize = -1;
        }
    }

    if(ctx->newrevs != -1) {
        if(ctx->newrevs != (int)ctx->vol->revisions)
            ctx->oldrevs = ctx->vol->revisions;
        else {
            ctx->newrevs = -1;
            ctx->oldrevs = -1;
        }
    }

    if(ctx->newrevs != -1 || ctx->newsize != -1) {
        /* Check if new volume configuration is ok */
        if((s = sx_hashfs_check_volume_settings(hashfs, volume, ctx->newsize != -1 ? ctx->newsize : ctx->vol->size, ctx->vol->size, ctx->vol->max_replica, ctx->newrevs != -1 ? ctx->newrevs : ctx->vol->revisions)) != OK)
            return s; /* Message is set by sx_hashfs_check_volume_settings() */
    }

    if(ctx->nmeta != -1) {
        const char *metakey;
        const void *metaval;
        unsigned int l;

        if(!ctx->meta) {
            WARN("Corrupt volume modification context");
            return FAIL_EINTERNAL;
        }

        /* New meta has been given, we need to backup old meta in order to properly handle abort/undo phases */
        if((s = sx_hashfs_volumemeta_begin(hashfs, ctx->vol)) != OK)
            return s;
        ctx->oldmeta = sx_blob_new();
        if(!ctx->oldmeta) {
            msg_set_reason("Out of memory");
            return FAIL_EINTERNAL;
        }
        ctx->noldmeta = 0;

        s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metaval, &l);
        while(s == OK) {
            if(!strncmp(SX_CUSTOM_META_PREFIX, metakey, lenof(SX_CUSTOM_META_PREFIX))) {
                if(sx_blob_add_string(ctx->oldmeta, metakey + lenof(SX_CUSTOM_META_PREFIX)) || sx_blob_add_blob(ctx->oldmeta, metaval, l)) {
                    msg_set_reason("Out of memory");
                    sx_blob_free(ctx->oldmeta);
                    ctx->oldmeta = NULL;
                    ctx->noldmeta = -1;
                    return FAIL_EINTERNAL;
                }
                ctx->noldmeta++;
            }
            s = sx_hashfs_volumemeta_next(hashfs, &metakey, &metaval, &l);
        }

        if(s != ITER_NO_MORE) {
            WARN("Failed to iterate through volume meta");
            sx_blob_free(ctx->oldmeta);
            ctx->oldmeta = NULL;
            ctx->noldmeta = -1;
            return s;
        }
    }

    return OK;
}

static void cb_volmod_name(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(length < SXLIMIT_MIN_VOLNAME_LEN || length > SXLIMIT_MAX_VOLNAME_LEN) {
        sxi_jparse_cancel(J, "Invalid volume name");
        return;
    }
    memcpy(c->newname, string, length);
    c->newname[length] = '\0';
}

static void cb_volmod_owner(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(length > SXLIMIT_MAX_USERNAME_LEN) {
	sxi_jparse_cancel(J, "Username is too long");
	return;
    }
    memcpy(c->newowner, string, length);
    c->newowner[length] = '\0';
}

static void cb_volmod_meta_begin(jparse_t *J, void *ctx) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;

    if(c->meta) {
        sxi_jparse_cancel(J, "Multiple custom volume meta maps provided");
        return;
    }
    c->meta = sx_blob_new();
    if(!c->meta) {
        sxi_jparse_cancel(J, "Out of memory processing custom metadata");
        return;
    }
    c->nmeta = 0;
}

static void cb_volmod_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    uint8_t metaval[SXLIMIT_META_MAX_VALUE_LEN];

    if(sxi_hex2bin(string, length, metaval, sizeof(metaval))) {
	sxi_jparse_cancel(J, "Invalid meta value on '%.*s'", length, string);
	return;
    }

    length /= 2;
    if(sx_hashfs_check_meta(key, metaval, length)) {
	sxi_jparse_cancel(J, "Invalid custom volume metadata pair %s", key);
	return;
    }
    if(sx_blob_add_string(c->meta, key) || sx_blob_add_blob(c->meta, metaval, length)) {
	sxi_jparse_cancel(J, "Out of memory processing custom metadata pair");
	return;
    }
    c->nmeta++;
}

static void cb_volmod_size(jparse_t *J, void *ctx, int64_t num) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->newsize >= 0) {
	sxi_jparse_cancel(J, "Volume size already received");
	return;
    }
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid new volume size");
	return;
    }
    c->newsize = num;
}

static void cb_volmod_revs(jparse_t *J, void *ctx, int32_t num) {
    struct volmod_ctx *c = (struct volmod_ctx *)ctx;
    if(c->newrevs >= 0) {
	sxi_jparse_cancel(J, "Number of file revisions already received");
	return;
    }
    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid number of file revisions");
	return;
    }
    c->newrevs = num;
}

const struct jparse_actions volmod_acts = {
    JPACTS_STRING(
                  JPACT(cb_volmod_name, JPKEY("name")),
		  JPACT(cb_volmod_owner, JPKEY("owner")),
		  JPACT(cb_volmod_meta, JPKEY("customVolumeMeta"), JPANYKEY)
		  ),
    JPACTS_INT64(
		 JPACT(cb_volmod_size, JPKEY("size"))
		 ),
    JPACTS_INT32(
		 JPACT(cb_volmod_revs, JPKEY("maxRevisions"))
		 ),
    JPACTS_MAP_BEGIN(
                 JPACT(cb_volmod_meta_begin, JPKEY("customVolumeMeta"))
                 )
};

const job_2pc_t volmod_spec = {
    &volmod_acts,
    JOBTYPE_MODIFY_VOLUME,
    volmod_parse_complete,
    volmod_get_lock,
    volmod_to_blob,
    volmod_execute_blob,
    volmod_proto_from_blob,
    volmod_nodes,
    volmod_timeout
};

void fcgi_volume_mod(void) {
    struct volmod_ctx ctx;
    volmod_ctx_init(&ctx);
    job_2pc_handle_request(sx_hashfs_client(hashfs), &volmod_spec, &ctx);
    sx_blob_free(ctx.meta);
    sx_blob_free(ctx.oldmeta);
}


/* JSON: {"mode":"ro|rw"} */

struct cluster_mode_ctx {
    enum cluster_mode_t { CM_UNSET, CM_READONLY, CM_READWRITE } mode;
};

static void cb_clustermode(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cluster_mode_ctx *c = ctx;

    if(length == 2) {
	if(!memcmp(string, "ro", 2)) {
	    c->mode = CM_READONLY;
	    return;
	} else if(!memcmp(string, "rw", 2)) {
	    c->mode = CM_READWRITE;
	    return;
	}
    }
    sxi_jparse_cancel(J, "Invalid cluster mode %.*s", length, string);
}

const struct jparse_actions cluster_mode_acts = {
    JPACTS_STRING(JPACT(cb_clustermode, JPKEY("mode")))
};

static rc_ty cluster_mode_parse_complete(void *yctx)
{
    struct cluster_mode_ctx *c = yctx;
    if(c->mode != CM_READONLY && c->mode != CM_READWRITE) {
        msg_set_reason("Cluster mode missing");
        return EINVAL;
    }
    return OK;
}

static int cluster_mode_to_blob(sxc_client_t *sx, int nodes, void *yctx, sx_blob_t *joblb)
{
    struct cluster_mode_ctx *c = yctx;
    if(!joblb) {
        msg_set_reason("Cannot allocate job blob");
        return -1;
    }

    if(sx_blob_add_int32(joblb, (c->mode == CM_READONLY))) {
        msg_set_reason("Cannot create job blob");
        return -1;
    }
    return 0;
}

static unsigned cluster_mode_timeout(sxc_client_t *sx, int nodes)
{
    return nodes > 1 ? 50 * (nodes - 1) : 20;
}

static sxi_query_t* cluster_mode_proto_from_blob(sxc_client_t *sx, sx_blob_t *b, jobphase_t phase)
{
    int32_t mode = 0;

    if(sx_blob_get_int32(b, &mode)) {
        WARN("Corrupt user blob");
        return NULL;
    }

    switch(phase) {
        case JOBPHASE_REQUEST:
            return sxi_cluster_mode_proto(sx, mode);
        case JOBPHASE_ABORT:/* fall-through */
            INFO("Aborting cluster mode switch operation: '%s'", mode ? "read-only" : "read-write");
            return sxi_cluster_mode_proto(sx, !mode);
        default:
            WARN("Invalid job phase");
            return NULL;
    }
}

static rc_ty cluster_mode_execute_blob(sx_hashfs_t *h, sx_blob_t *b, jobphase_t phase, int remote)
{
    rc_ty rc = FAIL_EINTERNAL;
    int32_t mode = 0;
    int cluster_readonly = 0;

    if(!h || !b) {
        msg_set_reason("NULL arguments");
        return FAIL_EINTERNAL;
    }
    if(sx_blob_get_int32(b, &mode)) {
        msg_set_reason("Corrupted blob");
        return FAIL_EINTERNAL;
    }

    if(sx_hashfs_cluster_get_mode(h, &cluster_readonly)) {
        WARN("Failed to get cluster oparting mode");
        msg_set_reason("Failed to check cluster operating mode");
        return FAIL_EINTERNAL;
    }

    if(!remote && phase == JOBPHASE_REQUEST && cluster_readonly == mode) {
        msg_set_reason("Cluster is already in '%s' mode", cluster_readonly ? "read-only" : "read-write");
        return EINVAL;
    }

    switch(phase) {
        case JOBPHASE_REQUEST:
            DEBUG("Cluster mode switch request: '%s'", mode ? "read-only" : "read-write");
            rc = sx_hashfs_cluster_set_mode(h, mode);
            if(rc != OK)
                msg_set_reason("Unable to switch cluster to '%s' mode", mode ? "read-only" : "read-write");
            return rc;
        case JOBPHASE_ABORT:
            DEBUG("Cluster mode switch abort: '%s'", mode ? "read-only" : "read-write");
            rc = sx_hashfs_cluster_set_mode(h, !mode);
            if(rc != OK)
                msg_set_reason("Unable to switch cluster to '%s' mode", mode ? "read-write" : "read-only");
            return rc;
        default:
            WARN("Invalid job phase: %d", phase);
            return FAIL_EINTERNAL;
    }
}

static const char *cluster_mode_get_lock(sx_blob_t *b)
{
    return "CLUSTER_MODE";
}

static rc_ty cluster_mode_nodes(sx_hashfs_t *h, sx_blob_t *blob, sx_nodelist_t **nodes)
{
    if(!nodes)
        return FAIL_EINTERNAL;
    /* Spawn cluster mode job to all nodes */
    *nodes = sx_nodelist_dup(sx_hashfs_effective_nodes(hashfs, NL_NEXTPREV));
    if(!*nodes)
        return FAIL_EINTERNAL;
    return OK;
}

const job_2pc_t cluster_mode_spec = {
    &cluster_mode_acts,
    JOBTYPE_CLUSTER_MODE,
    cluster_mode_parse_complete,
    cluster_mode_get_lock,
    cluster_mode_to_blob,
    cluster_mode_execute_blob,
    cluster_mode_proto_from_blob,
    cluster_mode_nodes,
    cluster_mode_timeout
};

void fcgi_cluster_mode(void) {
    struct cluster_mode_ctx c = { CM_UNSET };

    job_2pc_handle_request(sx_hashfs_client(hashfs), &cluster_mode_spec, &c);
}

static void blob_send(const sx_blob_t *b)
{
    const void *data;
    uint32_t len, len_net;
    sx_blob_to_data(b, &data, &len);
    len_net = htonl(len);
    CGI_PUTD(&len_net, sizeof(len_net));
    CGI_PUTD(data, len);
}

static void blob_send_eof(void)
{
    sx_blob_t *b = sx_blob_new();
    if (!b)
        quit_errmsg(500, "OOM");
    if (sx_blob_add_string(b, "EOF$")) {
        sx_blob_free(b);
        quit_errmsg(500, "blob_add failed");
    }
    blob_send(b);
    sx_blob_free(b);
}

static int list_rev_cb(const sx_hashfs_volume_t *vol, const sx_uuid_t *target, const sx_hash_t *revision_id, const sx_hash_t *contents, int64_t nblocks, unsigned block_size)
{
    int64_t i=-1;
    sx_blob_t *b = sx_blob_new();
    if (!b)
        return -1;
    DEBUG("IN");
    do {
        if (sx_blob_add_string(b, "[REV]") ||
            sx_blob_add_blob(b, revision_id->b, sizeof(revision_id->b)) ||
            sx_blob_add_int32(b, block_size))
            break;
        for (i=0;i<nblocks;i++) {
            const sx_hash_t *hash = &contents[i];
            sx_nodelist_t *nl = sx_hashfs_all_hashnodes(hashfs, NL_NEXT, hash, vol->max_replica);
            if (!nl)
                break;
            const sx_node_t *found = sx_nodelist_lookup(nl, target);
            sx_nodelist_delete(nl);
            if (found && sx_blob_add_blob(b, hash->b, sizeof(hash->b)))
                break;
        }
        if (sx_blob_add_blob(b, "", 0)) {
            i = -1;
            break;
        }
        blob_send(b);
    } while(0);
    sx_blob_free(b);
    return i == nblocks ? 0 : -1;
}

static int list_count_cb(int64_t count)
{
    sx_blob_t *b = sx_blob_new();
    if (!b)
        return -1;
    DEBUG("IN");
    do {
        if (sx_blob_add_string(b,"[COUNT]") ||
            sx_blob_add_int64(b, count))
            break;
        blob_send(b);
    } while(0);
    sx_blob_free(b);
    return 0;
}

void fcgi_list_revision_blocks(const sx_hashfs_volume_t *vol) {
    int max_age = get_arg_uint("max-age");
    const char *min_rev  = get_arg("min-rev");
    const char *node_uuid = get_arg("for-node-uuid");
    int metadb = get_arg_uint("metadb");
    sx_hash_t min_revision;
    sx_uuid_t uuid;
    if (max_age < 0)
        quit_errmsg(400, "Invalid max-age: cannot be negative");
    if (!node_uuid || uuid_from_string(&uuid, node_uuid))
        quit_errmsg(400, "target node uuid missing or invalid");
    if (min_rev && *min_rev &&
        hex2bin(min_rev, strlen(min_rev), min_revision.b, sizeof(min_revision.b)))
        quit_errmsg(400, "failed to convert revision from hex");
    rc_ty rc;
    CGI_PUTS("\r\n");
    DEBUG("max-age: %d", max_age);
    if ((rc = sx_hashfs_list_revision_blocks(hashfs, vol, &uuid, (min_rev && *min_rev) ? &min_revision : NULL, max_age, metadb, list_rev_cb, list_count_cb)))
        quit_errmsg(rc2http(rc), msg_get_reason());
    blob_send_eof();
}

void fcgi_mass_delete(void) {
    const sx_hashfs_volume_t *vol;
    rc_ty s;
    const char *input_pattern = get_arg("filter");
    sx_blob_t *b;
    struct timeval timestamp;
    job_t job_id;
    const void *job_data = NULL;
    unsigned int job_data_len = 0;
    sx_nodelist_t *volnodes;

    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol, 0))
        quit_errnum(404);

    if(!input_pattern)
        input_pattern = "*";

    /* Determine timestamp */
    gettimeofday(&timestamp, NULL);

    b = sx_blob_new();
    if(!b)
        quit_errmsg(500, "Failed to allocate blob");

    if(sx_blob_add_blob(b, vol->global_id.b, sizeof(vol->global_id.b)) || sx_blob_add_int32(b, has_arg("recursive")) ||
       sx_blob_add_string(b, input_pattern) || sx_blob_add_datetime(b, &timestamp)) {
        sx_blob_free(b);
        quit_errmsg(500, "Failed to add data to blob");
    }

    /* Request comes in from the user: create jobs on each volnode */
    if((s = sx_hashfs_effective_volnodes(hashfs, NL_NEXTPREV, vol, 0, &volnodes, NULL, 1)) != OK) {
        sx_blob_free(b);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    sx_blob_to_data(b, &job_data, &job_data_len);
    s = sx_hashfs_mass_job_new(hashfs, uid, &job_id, JOBTYPE_MASSDELETE, MASS_JOB_DELAY_TIMEOUT, volume, job_data, job_data_len, volnodes);
    sx_blob_free(b);
    sx_nodelist_delete(volnodes);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());
    send_job_info(job_id);
}

void fcgi_mass_rename(void) {
    const sx_hashfs_volume_t *vol;
    rc_ty s;
    char source[SXLIMIT_MAX_FILENAME_LEN+1], dest[SXLIMIT_MAX_FILENAME_LEN+1];
    const char *dst = get_arg("dest");
    const char *src = get_arg("source");
    unsigned int slen, dlen, sslashes;
    const sx_hashfs_file_t *file = NULL;
    sx_blob_t *b;
    const void *job_data = NULL;
    unsigned int job_data_len = 0;
    struct timeval timestamp;
    job_t job_id;
    int recursive = has_arg("recursive");
    sx_nodelist_t *volnodes = NULL;
    unsigned int nfiles = 0;


    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!sx_hashfs_is_or_was_my_volume(hashfs, vol, 0))
        quit_errnum(404);

    if(!src)
        src = "";
    if(!dst)
        dst = "";
    while(*src == '/')
        src++;
    while(*dst == '/')
        dst++;

    if(strlen(src) > SXLIMIT_MAX_FILENAME_LEN)
        quit_errmsg(400, "Invalid source path");
    if(strlen(dst) > SXLIMIT_MAX_FILENAME_LEN)
        quit_errmsg(400, "Invalid destination path");
    sxi_strlcpy(source, src, sizeof(source));
    sxi_strlcpy(dest, dst, sizeof(dest));

    /* Duplicate slashes are only sanitized for 'volume' and 'path', query args are not, so sanitize them now. */
    sxi_inplace_dedup_slashes(source);
    sxi_inplace_dedup_slashes(dest);

    slen = strlen(source);
    dlen = strlen(dest);
    sslashes = sxi_count_slashes(source);

    /* Check if dest is a directory when source is a directory too */
    if(((!slen || source[slen-1] == '/') && (dlen && dest[dlen-1] != '/')))
        quit_errmsg(400, "Not a directory");

    /* Determine timestamp */
    gettimeofday(&timestamp, NULL);

    b = sx_blob_new();
    if(!b)
        quit_errmsg(500, "Failed to allocate blob");

    if(sx_blob_add_blob(b, vol->global_id.b, sizeof(vol->global_id.b)) || sx_blob_add_int32(b, has_arg("recursive")) ||
       sx_blob_add_string(b, source) || sx_blob_add_datetime(b, &timestamp) ||
       sx_blob_add_string(b, dest)) {
        sx_blob_free(b);
        quit_errmsg(500, "Failed to add data to blob");
    }

    /* Check number of source file matches */
    for(s = sx_hashfs_list_first(hashfs, vol, source, &file, recursive, NULL, 0); s == OK; s = sx_hashfs_list_next(hashfs)) {
        unsigned int nslashes = sxi_count_slashes(file->name + 1);

        if(!recursive && nslashes > sslashes) {
            DEBUG("Listed file has more slashes, skipping due to non-recursive rename required");
            continue;
        }
        nfiles++;
        /* We need an information if source pattern points to more than one file */
        if(nfiles == 2)
            break;
    }
    if(s != OK && s != ITER_NO_MORE) {
        sx_blob_free(b);
        quit_errmsg(rc2http(s), rc2str(s));
    } else if(nfiles == 0 && s == ITER_NO_MORE) {
        /* No such file, skip creating mass rename job */
        sx_blob_free(b);
        quit_errmsg(404, "Not Found");
    } else if(nfiles == 2 && (dlen && dest[dlen-1] != '/') && !recursive) {
        /* Source pattern points to more than one file, directory is required as target */
        sx_blob_free(b);
        quit_errmsg(400, "Not a directory");
    }

    if((s = sx_hashfs_effective_volnodes(hashfs, NL_NEXTPREV, vol, 0, &volnodes, NULL, 1)) != OK) {
        sx_blob_free(b);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    sx_blob_to_data(b, &job_data, &job_data_len);
    s = sx_hashfs_mass_job_new(hashfs, uid, &job_id, JOBTYPE_MASSRENAME, MASS_JOB_DELAY_TIMEOUT, volume, job_data, job_data_len, volnodes);
    sx_blob_free(b);
    sx_nodelist_delete(volnodes);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());
    send_job_info(job_id);
}

/* Mass jobs scheduling and committing
 *
 * {
 *     "job_data":"aabbccddeeff1100",
 *     "job_type":9,
 *     "job_timeout":123672,
 *     "job_lockname":"somelockname"
 * }
 */
struct mass_job_schedule_ctx {
    /* Contains the slave job data */
    void *slave_job_data;
    unsigned int slave_job_data_len;

    /* Slave job type */
    jobtype_t slave_job_type;
    /* Slave job timeout */
    time_t slave_job_timeout;
    /* Slave job lock name */
    char slave_job_lockname[128];
};


static void cb_mass_job_sched_data(jparse_t *J, void *ctx, const char *str, unsigned int len) {
    struct mass_job_schedule_ctx *c = (struct mass_job_schedule_ctx *)ctx;

    if(!len || len & 1) {
        sxi_jparse_cancel(J, "Invalid slave job data");
        return;
    }

    if(c->slave_job_data) {
        sxi_jparse_cancel(J, "job_data has already been received");
        return;
    }

    c->slave_job_data = malloc(len/2);
    if(!c->slave_job_data) {
        sxi_jparse_cancel(J, "Out of memory");
        return;
    }

    if(hex2bin(str, len, c->slave_job_data, len/2)) {
        sxi_jparse_cancel(J, "Invalid slave job data");
        free(c->slave_job_data);
        c->slave_job_data = NULL;
        return;
    }

    c->slave_job_data_len = len/2;
}

static void cb_mass_job_sched_type(jparse_t *J, void *ctx, int type) {
    struct mass_job_schedule_ctx *c = (struct mass_job_schedule_ctx *)ctx;

    if(type < 0) {
        sxi_jparse_cancel(J, "Invalid job type");
        return;
    }

    c->slave_job_type = (jobtype_t)type;
}

static void cb_mass_job_sched_timeout(jparse_t *J, void *ctx, int64_t timeout) {
    struct mass_job_schedule_ctx *c = (struct mass_job_schedule_ctx *)ctx;

    c->slave_job_timeout = (time_t)timeout;
}

static void cb_mass_job_sched_lockname(jparse_t *J, void *ctx, const char *str, unsigned int len) {
    struct mass_job_schedule_ctx *c = (struct mass_job_schedule_ctx *)ctx;

    if(len >= sizeof(c->slave_job_lockname)) {
        sxi_jparse_cancel(J, "Lockname is too long");
        return;
    }

    memset(c->slave_job_lockname, 0, sizeof(c->slave_job_lockname));
    if(len) {
        memcpy(c->slave_job_lockname, str, len);
        c->slave_job_lockname[len] = '\0';
    }
}

void fcgi_mass_job_schedule(void) {
    const struct jparse_actions acts = {
        JPACTS_STRING(
                     JPACT(cb_mass_job_sched_data, JPKEY("job_data")),
                     JPACT(cb_mass_job_sched_lockname, JPKEY("job_lockname"))
                     ),
        JPACTS_INT32(
                     JPACT(cb_mass_job_sched_type, JPKEY("job_type"))
                    ),
        JPACTS_INT64(
                     JPACT(cb_mass_job_sched_timeout, JPKEY("job_timeout"))
                    )
    };
    struct mass_job_schedule_ctx yctx = { NULL, 0, 0, 0, { 0 } };
    rc_ty s;
    job_t slave_job_id;
    jparse_t *J;
    unsigned int len;

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J)
        quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
        if(sxi_jparse_digest(J, hashbuf, len))
            break;

    if(len || sxi_jparse_done(J)) {
        send_error(400, sxi_jparse_geterr(J));
        sxi_jparse_destroy(J);
        return;
    }
    sxi_jparse_destroy(J);
    auth_complete();
    quit_unless_authed();

    if(!yctx.slave_job_timeout || !yctx.slave_job_type)
        quit_errmsg(400, "Request is missing required fields");

    s = sx_hashfs_create_local_mass_job(hashfs, uid, &slave_job_id, yctx.slave_job_type, yctx.slave_job_timeout, yctx.slave_job_lockname, yctx.slave_job_data, yctx.slave_job_data_len);
    free(yctx.slave_job_data);
    if(s != OK)
        quit_errmsg(rc2http(s), rc2str(s));
    send_job_info(slave_job_id);
}

void fcgi_mass_job_commit(void) {
    const char *slave_job_id_str = path;
    job_t slave_job_id;
    rc_ty s;
    const char *q;
    const char *uuid_str = sx_node_uuid_str(sx_hashfs_self(hashfs));
    char *enumb = NULL;

    if(!slave_job_id_str)
        quit_errmsg(400, "Invalid job ID");

    q = strchr(slave_job_id_str, ':');
    if(!q || q - slave_job_id_str != UUID_STRING_SIZE)
        quit_errmsg(400, "Invalid job ID");

    if(!uuid_str)
        quit_errmsg(400, "Invalid node UUID");
    if(strncmp(slave_job_id_str, uuid_str, q - slave_job_id_str))
        quit_errmsg(400, "UUID mismatch");

    q++;
    slave_job_id = strtoll(q, &enumb, 10);
    if(enumb && *enumb)
        quit_errmsg(400, "Invalid job ID");

    if((s = sx_hashfs_commit_local_mass_job(hashfs, slave_job_id, 1)) != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    CGI_PUTS("\r\n");
}

/* {"prev_replica":1,"next_replica":2} */
struct cb_mod_rep_ctx {
    unsigned int prev;
    unsigned int next;
};

static void cb_mod_rep_next(jparse_t *J, void *ctx, int next_replica) {
    struct cb_mod_rep_ctx *c = (struct cb_mod_rep_ctx *)ctx;

    if(next_replica <= 0 || (unsigned)next_replica > sx_nodelist_count(sx_hashfs_all_nodes(hashfs, NL_NEXTPREV))) {
        sxi_jparse_cancel(J, "Invalid replica value: must be between 1 and %d", sx_nodelist_count(sx_hashfs_all_nodes(hashfs, NL_NEXTPREV)));
        return;
    }

    c->next = next_replica;
}

static void cb_mod_rep_prev(jparse_t *J, void *ctx, int prev_replica) {
    struct cb_mod_rep_ctx *c = (struct cb_mod_rep_ctx *)ctx;

    if(prev_replica <= 0 || (unsigned)prev_replica > sx_nodelist_count(sx_hashfs_all_nodes(hashfs, NL_NEXTPREV))) {
        sxi_jparse_cancel(J, "Invalid replica value: must be between 1 and %d", sx_nodelist_count(sx_hashfs_all_nodes(hashfs, NL_NEXTPREV)));
        return;
    }

    c->prev = prev_replica;
}

void fcgi_modify_volume_replica(void) {
    const struct jparse_actions acts = {
        JPACTS_INT32(
                     JPACT(cb_mod_rep_next, JPKEY("next_replica")),
                     JPACT(cb_mod_rep_prev, JPKEY("prev_replica"))
                     )
    };
    jparse_t *J;
    job_t job, ret_job;
    int len;
    rc_ty s;
    const sx_hashfs_volume_t *vol = NULL;
    struct cb_mod_rep_ctx yctx = { 0, 0 };
    const sx_nodelist_t *allnodes;
    sx_nodelist_t *new_volnodes = NULL;
    unsigned int nallnodes;
    sx_blob_t *b;
    const void *job_data;
    unsigned int job_data_len;

    J = sxi_jparse_create(&acts, &yctx, 0);
    if(!J)
        quit_errmsg(503, "Cannot create JSON parser");

    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
        if(sxi_jparse_digest(J, hashbuf, len))
            break;

    if(len || sxi_jparse_done(J)) {
        send_error(400, sxi_jparse_geterr(J));
        sxi_jparse_destroy(J);
        return;
    }
    sxi_jparse_destroy(J);
    auth_complete();
    quit_unless_authed();

    s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(!yctx.next || !yctx.prev)
        quit_errmsg(400, "Previous or next replica has not been provided");

    if(sx_hashfs_is_rebalancing(hashfs))
        quit_errmsg(rc2http(FAIL_LOCKED), "The cluster is still being rebalanced");

    if(sx_hashfs_is_upgrading(hashfs))
        quit_errmsg(rc2http(FAIL_LOCKED), "The cluster is still being upgraded");

    if(sx_nodelist_count(sx_hashfs_ignored_nodes(hashfs)))
        quit_errmsg(400, "The cluster contains faulty nodes which must be replaced");

    if(sx_nodelist_count(sx_hashfs_faulty_nodes(hashfs)))
        quit_errmsg(400, "The cluster contains faulty nodes which are still being replaced");

    if(has_priv(PRIV_CLUSTER)) {
        /* When performing job on the remote node, simply update the replica values */
        s = sx_hashfs_modify_volume_replica(hashfs, vol, yctx.prev, yctx.next);
        if(s != OK) {
            WARN("Failed to modify volume replica");
            quit_errmsg(rc2http(s), msg_get_reason());
        }
        CGI_PUTS("\r\n");
        return;
    }

    /* Check volume settings after checking for PRIV_CLUSTER, i.e. when the request comes from the user.
     * It therefore supports undoing changes. */
    s = sx_hashfs_check_volume_settings(hashfs, volume, vol->size, vol->size, yctx.next, vol->revisions);
    if(s != OK)
        quit_errmsg(rc2http(s), msg_get_reason());

    if(sx_hashfs_is_changing_volume_replica(hashfs) == 1)
        quit_errmsg(400, "The cluster is already performing volume replica changes");

    /* In case prev_replica == vol->max_replica we can skip the whole operation and return a dummy job for the 
     * client tool to be able to poll its status which is going to always be a success. Scheduling the whole 
     * chain when we know that the replica is not gonna change is going to be a waste of time. */
    if(yctx.prev == yctx.next) {
        sx_nodelist_t *singlenode = sx_nodelist_new();
        if(!singlenode)
            quit_errmsg(503, "Not enough memory to perform requested action");

        if(sx_nodelist_add(singlenode, sx_node_dup(sx_hashfs_self(hashfs)))) {
            sx_nodelist_delete(singlenode);
            quit_errmsg(503, "Not enough memory to perform requested action");
        }

        DEBUG("Scheduling dummy volume replica change job");
        s = sx_hashfs_job_new(hashfs, uid, &job, JOBTYPE_DUMMY, 20, NULL, NULL, 0, singlenode);
        if(s != OK) {
            sx_nodelist_delete(singlenode);
            quit_errmsg(rc2http(s), msg_get_reason());
        }

        sx_nodelist_delete(singlenode);
        send_job_info(job);
        return;
    }

    allnodes = sx_hashfs_all_nodes(hashfs, NL_NEXTPREV);
    if(!allnodes)
        quit_errmsg(500, "Failed to obtain nodelist");
    nallnodes = sx_nodelist_count(allnodes);

    b = sx_blob_new();
    if(!b)
        quit_errmsg(500, "Out of memory");

    if(sx_blob_add_string(b, vol->name) || sx_blob_add_int32(b, yctx.prev) || sx_blob_add_int32(b, yctx.next) || sx_blob_add_int32(b, 0)) {
        sx_blob_free(b);
        quit_errmsg(500, "Out of memory");
    }

    if((s = sx_hashfs_over_replica_volnodes(hashfs, vol, yctx.prev, yctx.next, allnodes, &new_volnodes)) != OK) {
        sx_blob_free(b);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    if((s = sx_hashfs_job_new_begin(hashfs))) {
        sx_blob_free(b);
        sx_nodelist_delete(new_volnodes);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    sx_blob_to_data(b, &job_data, &job_data_len);
    s = sx_hashfs_job_new_notrigger(hashfs, JOB_NOPARENT, uid, &job, JOBTYPE_VOLREP_CHANGE, 20 * nallnodes, NULL, job_data, job_data_len, allnodes);
    if(s != OK) {
        sx_blob_free(b);
        sx_nodelist_delete(new_volnodes);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    /* That job ID will be returned to the client so that the polling is done as soon as the volume goes into the split replica state. */
    ret_job = job;

    /* The VOLREP_BLOCKS job is responsible for synchronization of blocks to the new volnodes */
    s = sx_hashfs_mass_job_new_notrigger(hashfs, job, uid, &job, JOBTYPE_VOLREP_BLOCKS, JOB_NO_EXPIRY, "VOLREP_BLOCKS", job_data, job_data_len, allnodes);
    if(s != OK) {
        sx_blob_free(b);
        sx_nodelist_delete(new_volnodes);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    /* The VOLREP_FILES job is responsible for synchronization of files to the new volnodes */
    s = sx_hashfs_mass_job_new_notrigger(hashfs, job, uid, &job, JOBTYPE_VOLREP_FILES, JOB_NO_EXPIRY, "VOLREP_FILES", job_data, job_data_len, new_volnodes);
    if(s != OK) {
        sx_blob_free(b);
        sx_nodelist_delete(new_volnodes);
        quit_errmsg(rc2http(s), msg_get_reason());
    }
    sx_nodelist_delete(new_volnodes);

    sx_blob_reset(b);
    /* New volume replica is the same as the old volume replica */
    if(sx_blob_add_string(b, vol->name) || sx_blob_add_int32(b, yctx.next) || sx_blob_add_int32(b, yctx.next) || sx_blob_add_int32(b, 0)) {
        sx_blob_free(b);
        quit_errmsg(500, "Out of memory");
    }

    sx_blob_to_data(b, &job_data, &job_data_len);
    s = sx_hashfs_job_new_notrigger(hashfs, job, uid, &job, JOBTYPE_VOLREP_CHANGE, 20 * nallnodes, NULL, job_data, job_data_len, allnodes);
    if(s != OK) {
        sx_blob_free(b);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    sx_blob_free(b);
    s = sx_hashfs_job_new_end(hashfs);
    if(s != OK) {
        sx_hashfs_job_new_abort(hashfs);
        quit_errmsg(rc2http(s), msg_get_reason());
    }

    send_job_info(ret_job);
}
