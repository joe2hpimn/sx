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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "libsxclient-int.h"
#include "misc.h"
#include "hostlist.h"
#include "clustcfg.h"
#include "cluster.h"
#include "yajlwrap.h"
#include "filter.h"
#include "sxproto.h"
#include "jobpoll.h"
#include "volops.h"
#include "vcrypto.h"

int sxc_volume_add(sxc_cluster_t *cluster, const char *name, int64_t size, unsigned int replica, unsigned int revisions, sxc_meta_t *metadata, const char *owner)
{
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_query_t *proto;
    int qret;

    sxc_clearerr(sx);
    if(!replica) {
	SXDEBUG("Invalid replica for volume");
	sxi_seterr(sx, SXE_EARG, "Invalid replica for volume");
	return 1;
    }

    proto = sxi_volumeadd_proto(sx, name, owner, size, replica, revisions, metadata);
    if(!proto) {
	SXDEBUG("Cannot allocate request");
	return 1;
    }
    sxi_set_operation(sx, "add volume", sxi_cluster_get_name(cluster), name, NULL);
    qret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, proto->verb, proto->path, proto->content, proto->content_len);
    sxi_query_free(proto);
    return qret;
}

int sxc_volume_remove(sxc_cluster_t *cluster, const char *name) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_hostlist_t volhosts;
    char *enc_vol;
    int ret;

    sxc_clearerr(sx);

    sxi_hostlist_init(&volhosts);
    if(sxi_locate_volume(sxi_cluster_get_conns(cluster), name, &volhosts, NULL, NULL, NULL)) {
	sxi_hostlist_empty(&volhosts);
	return 1;
    }

    enc_vol = sxi_urlencode(sx, name, 0);
    if(!enc_vol) {
	SXDEBUG("Cannot encode volume name");
	sxi_hostlist_empty(&volhosts);
	return 1;
    }

    sxi_set_operation(sx, "remove volume", sxi_cluster_get_name(cluster), name, NULL);
    ret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), &volhosts, REQ_DELETE, enc_vol, NULL, 0);

    sxi_hostlist_empty(&volhosts);
    free(enc_vol);
    return ret;
}

int sxc_volume_modify(sxc_cluster_t *cluster, const char *volume, const char *newowner, int64_t newsize, int max_revs, sxc_meta_t *custom_meta) {
    sxc_client_t *sx;
    sxi_hostlist_t volhosts;
    sxi_query_t *query = NULL;
    int ret = -1;

    if(!cluster)
        return -1;
    sx = sxi_cluster_get_client(cluster);

    if(!volume) {
        sxi_seterr(sx, SXE_EARG, "Failed to change volume size: invalid argument");
        return -1;
    }

    sxc_clearerr(sx);
    sxi_hostlist_init(&volhosts);
    if(sxi_locate_volume(sxi_cluster_get_conns(cluster), volume, &volhosts, NULL, NULL, NULL))
        goto sxc_volume_modify_err;

    query = sxi_volume_mod_proto(sx, volume, newowner, newsize, max_revs, custom_meta);
    if(!query) {
        sxi_seterr(sx, SXE_EMEM, "Failed to prepare volume modify query");
        goto sxc_volume_modify_err;
    }

    sxi_set_operation(sx, "modify volume", sxi_cluster_get_name(cluster), volume, NULL);
    ret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), &volhosts, REQ_PUT, query->path, query->content, query->content_len);

sxc_volume_modify_err:
    sxi_hostlist_empty(&volhosts);
    sxi_query_free(query);
    return ret;
}

int sxi_volume_cfg_store(sxc_client_t *sx, sxc_cluster_t *cluster, const char *vname, const char *filter_uuid, const unsigned char *filter_cfg, unsigned int filter_cfglen)
{
    const char *confdir;
    char *path;
    int fd;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    if(!sx || !cluster)
	return 1;

    confdir = sxi_cluster_get_confdir(cluster);
    if(!confdir) {
	sxi_seterr(sx, SXE_ECFG, "Cannot obtain configuration directory");
	return 1;
    }

    if(!filter_uuid) {
	path = malloc(strlen(confdir) + strlen(vname) + 32);
	if(!path) {
	    sxi_seterr(sx, SXE_EMEM, "Can't allocate memory for volume config directory");
	    return 1;
	}
	sprintf(path, "%s/volumes/%s", confdir, vname);
	if(access(path, F_OK) && mkdir(path, 0700) == -1) {
	    sxi_seterr(sx, SXE_ECFG, "Can't create volume configuration directory %s", path);
	    free(path);
	    return 1;
	}
	free(path);
	return 0;
    }

    path = malloc(strlen(confdir) + strlen(filter_uuid) + strlen(vname) + 32);
    if(!path) {
	sxi_seterr(sx, SXE_EMEM, "Can't allocate memory for volume config directory");
	return 1;
    }
    sprintf(path, "%s/volumes/%s", confdir, vname);
    if(access(path, F_OK) && mkdir(path, 0700) == -1) {
	sxi_seterr(sx, SXE_EWRITE, "Can't create volume configuration directory %s", path);
	free(path);
	return 1;
    }

    sprintf(path, "%s/volumes/%s/filter", confdir, vname);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(fd == -1) {
	sxi_seterr(sx, SXE_EWRITE, "Can't open %s for writing", path);
	free(path);
	return 1;
    }
    if(write(fd, filter_uuid, strlen(filter_uuid)) != (ssize_t) strlen(filter_uuid)) {
	sxi_seterr(sx, SXE_EWRITE, "Can't write to %s", path);
	free(path);
	close(fd);
	return 1;
    }
    if(close(fd)) {
	sxi_seterr(sx, SXE_EWRITE, "Can't close file %s", path);
	free(path);
	return 1;
    }

    sprintf(path, "%s/volumes/%s/%s", confdir, vname, filter_uuid);
    if(access(path, F_OK)) {
	if(mkdir(path, 0700) == -1) {
	    sxi_seterr(sx, SXE_EFILTER, "Can't create filter directory %s", path);
	    free(path);
	    return 1;
	}
    }

    if(filter_cfg) {
	sxi_sha256(filter_cfg, filter_cfglen, digest);
	sprintf(path, "%s/volumes/%s/%s/.sx-chksum", confdir, vname, filter_uuid);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if(fd == -1) {
	    sxi_seterr(sx, SXE_EWRITE, "Can't open %s for writing", path);
	    free(path);
	    return 1;
	}
	if(write(fd, digest, sizeof(digest)) != sizeof(digest)) {
	    sxi_seterr(sx, SXE_EWRITE, "Can't write to %s", path);
	    free(path);
	    close(fd);
	    return 1;
	}
	if(close(fd)) {
	    sxi_seterr(sx, SXE_EWRITE, "Can't close file %s", path);
	    free(path);
	    return 1;
	}

    }

    free(path);
    return 0;
}

/*
static int confirm_volume(sxc_client_t *sx, const char *vname, sxc_filter_t *filter)
{
    char prompt[512];
    int cnt;

    cnt = snprintf(prompt, sizeof(prompt), "*** You're about to access the volume '%s' for the first time.\n", vname);
    if(filter)
	cnt += snprintf(prompt + cnt, sizeof(prompt) - cnt, "*** The volume uses filter '%s'\n", filter->shortname);
    cnt += snprintf(prompt + cnt, sizeof(prompt) - cnt, "Continue?");

    return sxi_confirm(sx, prompt, 1) ? 0 : -1;
}
*/

static void volume_info(sxc_client_t *sx, const char *vname, sxc_filter_t *filter, int fp)
{
    fprintf(stderr, "*** Accessing data on the volume '%s' for the first time\n", vname);
    if(filter)
	fprintf(stderr, "*** The volume uses filter '%s'\n", filter->shortname);
    if(fp)
	fprintf(stderr, "*** The fingerprint of the volume has been stored.\n");
}

static void bigerr(sxc_cluster_t *cluster, const char *vname)
{
    const char *clustname = sxc_cluster_get_sslname(cluster);
    int i, len = 6 + strlen(clustname) + strlen(vname);

    fprintf(stderr,
	"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"	\
	"!!! ERROR: REMOTE VOLUME CONFIGURATION HAS CHANGED FOR !!!\n"	\
	"!!! ");
    if(len < 51) {
	int cnt = 0;
	for(i = 0; i < (51 - len) / 2; i++)
	    cnt += fprintf(stderr, " ");
	cnt += fprintf(stderr, "sx://%s/%s", clustname, vname);
	for(i = 0; cnt < 51 && i < 80; i++, cnt++)
	    fprintf(stderr, " ");
    } else 
	fprintf(stderr, "sx://%s/%s", clustname, vname);
    fprintf(stderr,
	"!!!\n"								\
	"!!!       PLEASE CONTACT YOUR CLUSTER ADMINISTRATOR    !!!\n"	\
	"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
}

int sxi_volume_cfg_check(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_meta_t *vmeta, const char *vname)
{
    char local_filter_uuid[37], remote_filter_uuid[37], cfgkey[37 + 5];
    const char *confdir;
    const void *cfgval = NULL;
    unsigned int cfgval_len = 0;
    const void *mval;
    unsigned int mval_len;
    char *path;
    int nocluster = 0, nofilter = 0, nochksum = 0, ret;
    int fd;
    unsigned char local_digest[SHA256_DIGEST_LENGTH], remote_digest[SHA256_DIGEST_LENGTH];
    struct filter_handle *fh;

    if(!sx || !cluster || !vname)
	return 1;

    confdir = sxi_cluster_get_confdir(cluster);
    if(!confdir) {
	sxi_seterr(sx, SXE_ECFG, "Cannot obtain configuration directory");
	return 1;
    }

    path = malloc(strlen(confdir) + sizeof(local_filter_uuid) + strlen(vname) + 32);
    if(!path) {
	sxi_seterr(sx, SXE_EMEM, "Can't allocate memory for volume config directory");
	return 1;
    }
    sprintf(path, "%s/volumes/%s", confdir, vname);
    if(access(path, F_OK)) {
	nocluster = 1;
    } else {
	sprintf(path, "%s/volumes/%s/filter", confdir, vname);
	if(access(path, F_OK)) {
	    nofilter = 1;
    	} else {
	    fd = open(path, O_RDONLY);
	    if(fd == -1) {
		sxi_seterr(sx, SXE_EREAD, "Can't open %s for reading", path);
		free(path);
		return 1;
	    }
	    if(read(fd, local_filter_uuid, 36) != 36) {
		sxi_seterr(sx, SXE_EREAD, "Can't read %s", path);
		free(path);
		close(fd);
		return 1;
	    }
	    local_filter_uuid[36] = 0;
	    close(fd);

	    sprintf(path, "%s/volumes/%s/%s/.sx-chksum", confdir, vname, local_filter_uuid);
	    if(access(path, F_OK)) {
		nochksum = 1;
	    } else {
		fd = open(path, O_RDONLY);
		if(fd == -1) {
		    sxi_seterr(sx, SXE_EREAD, "Can't open %s for reading", path);
		    free(path);
		    return 1;
		}
		if(read(fd, local_digest, sizeof(local_digest)) != sizeof(local_digest)) {
		    sxi_seterr(sx, SXE_EREAD, "Can't read %s", path);
		    free(path);
		    close(fd);
		    return 1;
		}
		close(fd);
	    }
	}
    }
    free(path);

    if(vmeta && !sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
	if(mval_len != 16) {
	    sxi_seterr(sx, SXE_EFILTER, "Filter(s) enabled but can't handle metadata");
	    return 1;
	}
	sxi_uuid_unparse(mval, remote_filter_uuid);

	if(!nocluster && !nofilter && strcmp(local_filter_uuid, remote_filter_uuid)) {
	    bigerr(cluster, vname);
	    sxi_seterr(sx, SXE_EFILTER, "Remote volume reports filter ID %s, local settings report filter ID %s", remote_filter_uuid, local_filter_uuid);
	    return 1;
	}

	fh = sxi_filter_gethandle(sx, mval);
	if(!fh) {
	    sxi_seterr(sx, SXE_EFILTER, "Filter ID %s required by remote volume not found", remote_filter_uuid);
	    return 1;
	}

	snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", remote_filter_uuid);
	sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);

	if(nochksum && cfgval) {
	    bigerr(cluster, vname);
	    sxi_seterr(sx, SXE_EFILTER, "Remote volume reports filter config, local settings report no filter config");
	    return 1;
	} else if(!nocluster && !nochksum && !cfgval) {
	    bigerr(cluster, vname);
	    sxi_seterr(sx, SXE_EFILTER, "Remote volume reports no filter config, local settings report filter config");
	    return 1;
	} else if(!nocluster && cfgval) {
	    sxi_sha256(cfgval, cfgval_len, remote_digest);
	    if(memcmp(local_digest, remote_digest, sizeof(local_digest))) {
		bigerr(cluster, vname);
		sxi_seterr(sx, SXE_EFILTER, "Remote volume reports different filter config than local settings");
		return 1;
	    }
	}

	if(nocluster) {
	    /*
	    if(confirm_volume(sx, vname, fh->f) < 0) {
		sxi_seterr(sx, SXE_EFILTER, "Remote volume configuration rejected");
		return 1;
	    }
	    */
	    if((ret = sxi_volume_cfg_store(sx, cluster, vname, remote_filter_uuid, cfgval, cfgval_len)))
		fprintf(stderr, "WARNING: Failed to store volume configuration but the process will continue anyway\n");

	    volume_info(sx, vname, fh->f, !ret);
	    return 0;
	}

    } else if(!nocluster && !nofilter) {
	bigerr(cluster, vname);
	sxi_seterr(sx, SXE_EFILTER, "Remote volume reports no filter, local volume configuration reports filter ID %s", local_filter_uuid);
	return 1;
    }

    if(nocluster) {
	/*
	if(confirm_volume(sx, vname, NULL) < 0) {
	    sxi_seterr(sx, SXE_EFILTER, "Remote volume configuration rejected");
	    return 1;
	}
	*/
	if((ret = sxi_volume_cfg_store(sx, cluster, vname, NULL, NULL, 0)))
	    fprintf(stderr, "WARNING: Failed to store local configuration but the process will continue anyway\n");
	volume_info(sx, vname, NULL, !ret);
    }

    return 0;
}

#define cluster_err(...) sxi_seterr(sxi_cluster_get_client(cluster), __VA_ARGS__)
#define cluster_syserr(...) sxi_setsyserr(sxi_cluster_get_client(cluster), __VA_ARGS__)

struct priv_iter {
    const char *read_users;
    const char *write_users;
    const char *manager_users;
};

struct user_iter {
    sxc_client_t *sx;
    const char *user;
    int grant_acls;
    int revoke_acls;
};

static const char *get_grant_acl(void *ctx, sx_acl_t priv)
{
    struct user_iter *iter = ctx;
    if (iter->grant_acls & priv) {
        iter->grant_acls &= ~priv;
        return iter->user;
    }
    return NULL;
}

static const char *get_revoke_acl(void *ctx, sx_acl_t priv)
{
    struct user_iter *iter = ctx;
    if (iter->revoke_acls & priv) {
        iter->revoke_acls &= ~priv;
        return iter->user;
    }
    return NULL;
}

static const char *grant_read(void *ctx)
{
    return get_grant_acl(ctx, SX_ACL_READ);
}

static const char *grant_write(void *ctx)
{
    return get_grant_acl(ctx, SX_ACL_WRITE);
}

static const char *grant_manager(void *ctx)
{
    return get_grant_acl(ctx, SX_ACL_MANAGER);
}

static const char *revoke_read(void *ctx)
{
    return get_revoke_acl(ctx, SX_ACL_READ);
}

static const char *revoke_write(void *ctx)
{
    return get_revoke_acl(ctx, SX_ACL_WRITE);
}

static const char *revoke_manager(void *ctx)
{
    return get_revoke_acl(ctx, SX_ACL_MANAGER);
}

int sxc_volume_acl(sxc_cluster_t *cluster, const char *url, const char *user, int grant_acls, int revoke_acls)
{
    struct user_iter user_iter;
    sxc_client_t *sx;
    sxi_query_t *proto;
    int rc;

    memset(&user_iter, 0, sizeof(user_iter));
    if (!cluster) {
	cluster_err(SXE_EARG, "Null args");
        return 1;
    }
    if (!grant_acls && !revoke_acls) {
        cluster_err(SXE_EARG, "You must specify at least one grant/revoke operation to perform");
        return 1;
    }
    if (grant_acls & revoke_acls) {
        cluster_err(SXE_EARG, "Conflicting operation: cannot both grant and revoke same privilege");
        return 1;
    }
    if ((grant_acls & SX_ACL_OWNER) ||
        (revoke_acls & SX_ACL_OWNER)) {
        cluster_err(SXE_EARG, "Cannot grant or revoke owner privilege");
        return 1;
    }
    sx = sxi_cluster_get_client(cluster);
    user_iter.sx = sx;
    user_iter.grant_acls = grant_acls;
    user_iter.revoke_acls = revoke_acls;
    user_iter.user = user;
    proto = sxi_volumeacl_proto(sx, url, grant_read, grant_write, grant_manager,
                                revoke_read, revoke_write, revoke_manager, &user_iter);

    sxi_set_operation(sxi_cluster_get_client(cluster), "modify volume acl", sxi_cluster_get_name(cluster), url, NULL);
    rc = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, proto->verb, proto->path, proto->content, proto->content_len);
    sxi_query_free(proto);
    return rc;
}

// {"volumeList":{"vol":{"replicaCount":1,"revisions":4,"privs":"rw","sizeBytes":10737418240,"volumeMeta":{"key1":"val1","key2":"val2"}},"volxxx":{"replicaCount":1,"revisions":2,"privs":"r-","sizeBytes":10737418240,"volumeMeta":{"key1":"val1","key2":"val2"}}}
struct cb_listvolumes_ctx {
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    FILE *f;
    char *volname;
    struct cbl_volume_t {
	int64_t size;
        int64_t used_size;
	unsigned int replica_count;
        unsigned int revisions;
	unsigned int namelen;
        unsigned int owner_len;
        char privs[3];
    } voldata;
    char *owner;
    sxc_meta_t *meta;
    unsigned int meta_count;
    char *curkey;
    enum listvolumes_state { LV_ERROR, LV_BEGIN, LV_BASE, LV_VOLUMES, LV_NAME, LV_VALUES, LV_VALNAME, LV_OWNER,
			     LV_REPLICA, LV_REVISIONS, LV_PRIVS, LV_USEDSIZE, LV_SIZE, LV_META, LV_META_KEY, LV_META_VALUE, LV_DONE, LV_COMPLETE } state;
};
#define expect_state(expst) do { if(yactx->state != (expst)) { CBDEBUG("bad state (in %d, expected %d)", yactx->state, expst); return 0; } } while(0)

static int yacb_listvolumes_start_map(void *ctx) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state == LV_BEGIN)
	yactx->state = LV_BASE;
    else if(yactx->state == LV_VOLUMES)
	yactx->state = LV_NAME;
    else if(yactx->state == LV_VALUES)
	yactx->state = LV_VALNAME;
    else if(yactx->state == LV_META)
        yactx->state = LV_META_KEY;
    else {
	CBDEBUG("bad state (in %d, expected %d, %d, %d or %d)", yactx->state, LV_BEGIN, LV_VOLUMES, LV_VALUES, LV_META);
	return 0;
    }
    return 1;
}

static int yacb_listvolumes_end_map(void *ctx) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == LV_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == LV_DONE)
	yactx->state = LV_COMPLETE;
    else if(yactx->state == LV_NAME)
	yactx->state = LV_DONE;
    else if(yactx->state == LV_META_KEY)
        yactx->state = LV_VALNAME;
    else if(yactx->state == LV_VALNAME) {
        unsigned int i;

	if(yactx->voldata.replica_count < 1 || yactx->voldata.used_size < 0 || yactx->voldata.size < 0 || !yactx->volname || !yactx->voldata.namelen) {
	    CBDEBUG("incomplete entry");
	    return 0;
	}
	if(!fwrite(&yactx->voldata, sizeof(yactx->voldata), 1, yactx->f) || !fwrite(yactx->volname, yactx->voldata.namelen, 1, yactx->f)) {
	    CBDEBUG("failed to save file attributes to temporary file");
	    sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
	    return 0;
	}

        if(yactx->owner && !fwrite(yactx->owner, yactx->voldata.owner_len, 1, yactx->f)) {
            CBDEBUG("failed to save volume owner to temporary file");
            sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
            return 0;
        }

	free(yactx->volname);
	yactx->volname = NULL;
	yactx->voldata.namelen = 0;
        free(yactx->owner);
        yactx->owner = NULL;
        yactx->voldata.owner_len = 0;
	yactx->state = LV_NAME;

        /* Handle meta */
        if(!fwrite(&yactx->meta_count, sizeof(yactx->meta_count), 1, yactx->f)) {
            CBDEBUG("Failed to save meta count to temporary file");
            sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to save meta count to temporary file");
            return 0;
        }

        /* Iterate over all metas and write them to temp file */
        for(i = 0; i < sxc_meta_count(yactx->meta); i++) {
            const char *key = NULL;
            unsigned int key_len = 0;
            const void *value = NULL;
            unsigned int value_len = 0;
            if(sxc_meta_getkeyval(yactx->meta, i, &key, &value, &value_len)) {
                sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
                CBDEBUG("Could not get meta key-value pair: %s", sxc_geterrmsg(sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata))));
                /* FIXME: Do not store errors in global buffer (bb#751) */
                sxi_cbdata_restore_global_error(sx, yactx->cbdata);
                return 0;
            }

            key_len = strlen(key);
            if(!fwrite(&key_len, sizeof(key_len), 1, yactx->f) || !fwrite(key, key_len, 1, yactx->f)) {
                CBDEBUG("Failed to save meta key to temporary file");
                sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to save meta key to temporary file");
                return 0;
            }
            if(!fwrite(&value_len, sizeof(value_len), 1, yactx->f) || !fwrite(value, value_len, 1, yactx->f)) {
                CBDEBUG("Failed to save meta value to temporary file");
		sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to save meta value to temporary file");
                return 0;
            }
        }
        sxc_meta_free(yactx->meta);
        yactx->meta = NULL;
        yactx->meta_count = 0;
    } else {
	CBDEBUG("bad state (in %d, expected %d, %d, %d or %d)", yactx->state, LV_DONE, LV_NAME, LV_META_KEY, LV_VALNAME);
	return 0;
    }
    return 1;
}

static int yacb_listvolumes_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if (yactx->state == LV_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    if(yactx->state == LV_META_VALUE) {
        if(sxc_meta_setval_fromhex(yactx->meta, yactx->curkey, (const char *)s, l)) {
            sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
            CBDEBUG("failed to add meta value: %s", sxc_geterrmsg(sx));
            /* FIXME: Do not store errors in global buffer (bb#751) */
            sxi_cbdata_restore_global_error(sx, yactx->cbdata);
            return 0;
        }
        free(yactx->curkey);
        yactx->curkey = NULL;
        yactx->state = LV_META_KEY;
        yactx->meta_count++;
        return 1;
    }
    if(yactx->state == LV_PRIVS) {
        if(l != 2 || (s[0] != 'r' && s[0] != '-') || (s[1] != 'w' && s[1] != '-')) {
            CBDEBUG("Bad privs string");
            return 0;
        }

        memcpy(yactx->voldata.privs, s, l);
        yactx->state = LV_VALNAME;
        return 1;
    }
    if(yactx->state == LV_OWNER) {
        if(yactx->owner || yactx->voldata.owner_len) {
            CBDEBUG("Inconsistent state");
            return 0;
        }
        yactx->voldata.owner_len = l;
        yactx->owner = malloc(yactx->voldata.owner_len);
        if(!yactx->owner) {
            CBDEBUG("OOM duplicating username '%.*s'", (unsigned)l, s);
            sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
            return 0;
        }
        memcpy(yactx->owner, s, yactx->voldata.owner_len);
        yactx->state = LV_VALNAME;
        return 1;
    }

    return 0;
}

static int yacb_listvolumes_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == LV_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == LV_DONE || yactx->state == LV_BASE) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = LV_ERROR;
            return 1;
        }
    }

    if(yactx->state == LV_BASE) {
	if(l == lenof("volumeList") && !memcmp(s, "volumeList", lenof("volumeList"))) {
	    yactx->state = LV_VOLUMES;
	    return 1;
	}
	CBDEBUG("unexpected base key '%.*s'", (unsigned)l, s);
        return 0;
    }

    if(yactx->state == LV_NAME) {
	if(yactx->volname) {
	    CBDEBUG("Inconsistent state");
	    return 0;
	}
	yactx->voldata.namelen = l;
	yactx->volname = malloc(yactx->voldata.namelen);
	if(!yactx->volname) {
	    CBDEBUG("OOM duplicating volume name '%.*s'", (unsigned)l, s);
	    sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->volname, s, yactx->voldata.namelen);
	yactx->voldata.replica_count = 0;
        yactx->voldata.revisions = 0;
        yactx->voldata.used_size = -1;
	yactx->voldata.size = -1;
        yactx->voldata.privs[0] = '\0';
	yactx->state = LV_VALUES;
	return 1;
    }

    if(yactx->state == LV_VALNAME) {
        if(l == lenof("owner") && !memcmp(s, "owner", lenof("owner"))) {
            yactx->state = LV_OWNER;
            return 1;
        }
	if(l == lenof("replicaCount") && !memcmp(s, "replicaCount", lenof("replicaCount"))) {
	    yactx->state = LV_REPLICA;
	    return 1;
	}
        if(l == lenof("maxRevisions") && !memcmp(s, "maxRevisions", lenof("maxRevisions"))) {
            yactx->state = LV_REVISIONS;
            return 1;
        }
        if(l == lenof("privs") && !memcmp(s, "privs", lenof("privs"))) {
            yactx->state = LV_PRIVS;
            return 1;
        }
        if(l == lenof("usedSize") && !memcmp(s, "usedSize", lenof("usedSize"))) {
            yactx->state = LV_USEDSIZE;
            return 1;
        }
	if(l == lenof("sizeBytes") && !memcmp(s, "sizeBytes", lenof("sizeBytes"))) {
	    yactx->state = LV_SIZE;
	    return 1;
	}
        if(l == lenof("volumeMeta") && !memcmp(s, "volumeMeta", lenof("volumeMeta"))) {
            sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
            yactx->state = LV_META;
            yactx->meta = sxc_meta_new(sx);
	    if(!yactx->meta) {
		CBDEBUG("OOM Allocating meta");
                /* FIXME: Do not store errors in global buffer (bb#751) */
                sxi_cbdata_restore_global_error(sx, yactx->cbdata);
		return 0;
	    }
            return 1;
        }
	CBDEBUG("unexpected voldata key '%.*s'", (unsigned)l, s);
	return 0;
    }

    if(yactx->state == LV_META_KEY) {
        yactx->curkey = malloc(l + 1);
        if(!yactx->curkey) {
            CBDEBUG("OOM Allocating temporary meta key '%.*s'", (unsigned)l, s);
            sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
            return 0;
        }
        memcpy(yactx->curkey, s, l);
        yactx->curkey[l] = '\0';
        yactx->state = LV_META_VALUE;
        return 1;
    }

    CBDEBUG("bad state (in %d, expected %d, %d, %d or %d)", yactx->state, LV_BASE, LV_NAME, LV_VALNAME, LV_META_KEY);
    return 0;
}

static int yacb_listvolumes_number(void *ctx, const char *s, size_t l) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    char numb[24], *enumb;
    if(!ctx)
	return 0;

    if(yactx->state == LV_REPLICA) {
	if(yactx->voldata.replica_count) {
	    CBDEBUG("Replica count already received");
	    return 0;
	}
	if(l < 1 || l > 10) {
	    CBDEBUG("Invalid replica count '%.*s'", (unsigned)l, s);
	    return 0;
	}
	memcpy(numb, s, l);
	numb[l] = '\0';
	yactx->voldata.replica_count = strtol(numb, &enumb, 10);
	if(*enumb || yactx->voldata.replica_count < 1) {
	    CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
	    return 0;
	}
    } else if(yactx->state == LV_REVISIONS) {
        if(yactx->voldata.revisions) {
            CBDEBUG("Revisions limit already received: %d", yactx->voldata.revisions);
            return 0;
        }
        if(l < 1 || l > 10) {
            CBDEBUG("Invalid revisions limit '%.*s'", (unsigned)l, s);
            return 0;
        }
        memcpy(numb, s, l);
        numb[l] = '\0';
        yactx->voldata.revisions = strtol(numb, &enumb, 10);
        if(*enumb || yactx->voldata.revisions < 1) {
            CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
            return 0;
        }
    } else if(yactx->state == LV_USEDSIZE){
        if(yactx->voldata.used_size > 0) {
            CBDEBUG("Volume used size already received: %lld", (long long)yactx->voldata.used_size);
            return 0;
        }
        if(l < 1 || l > 20) {
            CBDEBUG("Invalid volume used size '%.*s'", (unsigned)l, s);
            return 0;
        }
        memcpy(numb, s, l);
        numb[l] = '\0';
        yactx->voldata.used_size = strtoll(numb, &enumb, 10);
        if(*enumb) {
            CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
            return 0;
        }
        if(yactx->voldata.used_size < 0) {
            CBDEBUG("Current volume size is less than 0: %lld, falling back to 0", (long long)yactx->voldata.used_size);
            yactx->voldata.used_size = 0;
        }
    } else if(yactx->state == LV_SIZE){
	if(yactx->voldata.size > 0) {
	    CBDEBUG("Volume size already received");
	    return 0;
	}
	if(l < 1 || l > 20) {
	    CBDEBUG("Invalid volume size '%.*s'", (unsigned)l, s);
	    return 0;
	}
	memcpy(numb, s, l);
	numb[l] = '\0';
	yactx->voldata.size = strtoll(numb, &enumb, 10);
	if(*enumb || yactx->voldata.size < 0) {
	    CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
	    return 0;
	}
    } else {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, LV_REPLICA, LV_SIZE);
	return 0;
    }

    yactx->state = LV_VALNAME;
    return 1;
}

static int listvolumes_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("failed to allocate yajl structure");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "List volumes failed: Out of memory");
	return 1;
    }

    free(yactx->volname);
    yactx->volname = NULL;
    free(yactx->owner);
    yactx->owner = NULL;
    yactx->voldata.owner_len = 0;
    rewind(yactx->f);
    yactx->state = LV_BEGIN;

    /* Meta handling */
    sxc_meta_free(yactx->meta);
    free(yactx->curkey);
    yactx->meta = NULL;
    yactx->curkey = NULL;
    yactx->meta_count = 0;

    return 0;
}

static int listvolumes_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != LV_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
	return 1;
    }
    return 0;
}

struct _sxc_cluster_lv_t {
    sxc_client_t *sx;
    sxc_cluster_t *cluster;
    FILE *f;
    char *fname;
    int has_meta;
};

sxc_cluster_lv_t *sxc_cluster_listvolumes(sxc_cluster_t *cluster, int get_meta) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    struct cb_listvolumes_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_cluster_lv_t *ret;
    char *fname;
    int qret;

    sxc_clearerr(sx);
    memset(&yctx, 0, sizeof(yctx));
    ya_init(yacb);
    yacb->yajl_start_map = yacb_listvolumes_start_map;
    yacb->yajl_map_key = yacb_listvolumes_map_key;
    yacb->yajl_string = yacb_listvolumes_string;
    yacb->yajl_number = yacb_listvolumes_number;
    yacb->yajl_end_map = yacb_listvolumes_end_map;

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
	CFGDEBUG("failed to create temporary storage for volume list");
	return NULL;
    }

    sxi_set_operation(sx, "list volumes", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, get_meta ? "?volumeList&volumeMeta":"?volumeList", NULL, 0, listvolumes_setup_cb, listvolumes_cb, &yctx);
    if(qret != 200) {
	CFGDEBUG("query returned %d", qret);
	free(yctx.volname);
	sxc_meta_free(yctx.meta);
	free(yctx.curkey);
	if(yctx.yh)
	    yajl_free(yctx.yh);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != LV_COMPLETE) {
        if (yctx.state != LV_ERROR) {
            CFGDEBUG("JSON parsing failed");
            cluster_err(SXE_ECOMM, "List volumes failed: Communication error");
        }
	free(yctx.volname);
	sxc_meta_free(yctx.meta);
	free(yctx.curkey);
	if(yctx.yh)
	    yajl_free(yctx.yh);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    free(yctx.volname);
    sxc_meta_free(yctx.meta);
    free(yctx.curkey);
    if(yctx.yh)
	yajl_free(yctx.yh);

    ret = malloc(sizeof(*ret));
    if(!ret) {
	CFGDEBUG("OOM allocating results");
	cluster_err(SXE_EMEM, "Volume list failed: Out of memory");
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    rewind(yctx.f);
    ret->sx = sx;
    ret->f = yctx.f;
    ret->fname = fname;
    ret->cluster = cluster;
    ret->has_meta = get_meta ? 1 : 0;
    return ret;
}

int sxc_cluster_listvolumes_next(sxc_cluster_lv_t *lv, char **volume_name, char **volume_owner, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *revisions, char privs[3], sxc_meta_t **meta) {
    struct cbl_volume_t volume;
    sxc_client_t *sx = lv->sx;
    unsigned int meta_count = 0;
    unsigned int i = 0;
    char *key = NULL;
    void *value = NULL;

    if(!lv->has_meta && meta) {
        SXDEBUG("set get_meta to 1 to obtain volume meta");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return -1;
    }

    if(!fread(&volume, sizeof(volume), 1, lv->f)) {
	if(ferror(lv->f)) {
	    SXDEBUG("error reading attributes from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next volume: Read item from cache failed");
	    return -1;
	}
	return 0;
    }

    if(volume.namelen & 0x80000000) {
	SXDEBUG("Invalid volume name length");
	sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next volume: Bad data from cache file");
	return -1;
    }

    if(volume_name) {
	*volume_name = malloc(volume.namelen + 1);
	if(!*volume_name) {
	    SXDEBUG("OOM allocating result file name (%u bytes)", volume.namelen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next volume: Out of memory");
	    return -1;
	}
	if(!fread(*volume_name, volume.namelen, 1, lv->f)) {
	    SXDEBUG("error reading name from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next volume: Read item from cache failed");
	    return -1;
	}
        (*volume_name)[volume.namelen] = '\0';
        if(sxi_is_debug_enabled(sx)) {
            sxi_hostlist_t nodes;
            sxi_hostlist_init(&nodes);
            if (!sxi_locate_volume(sxi_cluster_get_conns(lv->cluster), *volume_name, &nodes, NULL, NULL, NULL)) {
                unsigned n = sxi_hostlist_get_count(&nodes);
                SXDEBUG("Volume %s master nodes:", *volume_name);
                for (i=0;i<n;i++)
                    SXDEBUG("\t%s", sxi_hostlist_get_host(&nodes,
                                                          i));
            }
            sxi_hostlist_empty(&nodes);
        }
    } else
	fseek(lv->f, volume.namelen, SEEK_CUR);

    if(volume.owner_len & 0x80000000) {
        SXDEBUG("Invalid volume owner name length");
        sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next volume: Bad data from cache file");
        return -1;
    }

    if(volume_owner && volume.owner_len) {
        *volume_owner = malloc(volume.owner_len + 1);
        if(!*volume_owner) {
            SXDEBUG("OOM allocating volume owner name (%u bytes)", volume.owner_len);
            sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next volume: Out of memory");
            return -1;
        }
        if(!fread(*volume_owner, volume.owner_len, 1, lv->f)) {
            SXDEBUG("error reading volume owner name from results file");
            sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next volume: Read item from cache failed");
            return -1;
        }
        (*volume_owner)[volume.owner_len] = '\0';
    } else
        fseek(lv->f, volume.owner_len, SEEK_CUR);

    /* For compatibility reasons owner can be not assigned therefore return NULL here */
    if(volume_owner && !volume.owner_len)
        *volume_owner = NULL;

    if(volume_used_size)
        *volume_used_size = volume.used_size;

    if(volume_size)
	*volume_size = volume.size;

    if(replica_count)
	*replica_count = volume.replica_count;

    if(revisions)
        *revisions = volume.revisions;

    if(privs)
        memcpy(privs, volume.privs, 2);

    if(!fread(&meta_count, sizeof(meta_count), 1, lv->f)) {
        SXDEBUG("error reading meta count from results file");
        sxi_setsyserr(sx, SXE_EREAD, "error reading meta count from results file");
        return -1;
    }

    if(meta) {
        *meta = sxc_meta_new(sx);
        if(!*meta) {
            SXDEBUG("OOM could not allocate meta");
            sxi_setsyserr(sx, SXE_EMEM, "OOM could not allocate meta");
            return -1;
        }
    }

    for(i = 0; i < meta_count; i++) {
	unsigned int key_len, value_len;
	key = value = NULL;

        if(!fread(&key_len, sizeof(key_len), 1, lv->f)) {
            SXDEBUG("error reading meta key length from results file");
            sxi_setsyserr(sx, SXE_EREAD, "error reading meta key length from results file");
            break;
        }
	if(key_len & 0x80000000) {
            SXDEBUG("invalid meta key length from results file");
            sxi_setsyserr(sx, SXE_EREAD, "invalid meta key length from results file");
            break;
        }

	if(meta) {
	    key = calloc(key_len + 1, sizeof(char));
	    if(!key) {
		SXDEBUG("OOM could not allocate memory for meta key");
		sxi_setsyserr(sx, SXE_EMEM, "OOM could not allocate memory for meta key");
		break;
	    }

	    if(!fread(key, key_len, 1, lv->f)) {
		SXDEBUG("error reading meta key length from results file");
		sxi_setsyserr(sx, SXE_EREAD, "error reading meta key length from results file");
		break;
	    }
	} else
	    fseek(lv->f, key_len, SEEK_CUR);

        if(!fread(&value_len, sizeof(value_len), 1, lv->f)) {
            SXDEBUG("error reading meta key length from results file");
            sxi_setsyserr(sx, SXE_EREAD, "error reading meta key length from results file");
            break;
        }
	if(value_len & 0x80000000) {
            SXDEBUG("invalid meta value length from results file");
            sxi_setsyserr(sx, SXE_EREAD, "invalid meta value length from results file");
            break;
        }

	if(meta) {
	    value = calloc(value_len + 1, sizeof(char));
	    if(!value) {
		SXDEBUG("OOM could not allocate memory for meta value");
		sxi_setsyserr(sx, SXE_EMEM, "OOM could not allocate memory for meta value");
		break;
	    }

	    if(!fread(value, value_len, 1, lv->f)) {
		SXDEBUG("error reading meta value length from results file");
		sxi_setsyserr(sx, SXE_EREAD, "error reading meta value length from results file");
		break;
	    }

	    /* Value and key are read, add them to meta if needed */
	    if(sxc_meta_setval(*meta, key, value, value_len)) {
		SXDEBUG("Could not add meta key-value pair: %s", sxc_geterrmsg(sx));
		break;
	    }

	    free(key);
	    free(value);
            key = NULL;
            value = NULL;
	} else
	    fseek(lv->f, value_len, SEEK_CUR);
    }

    if(i != meta_count) {
	if(meta) {
	    free(key);
	    free(value);
	    sxc_meta_free(*meta);
	    *meta = NULL;
	}
	return -1;
    }

    return 1;
}

void sxc_cluster_listvolumes_reset(sxc_cluster_lv_t *lv) {
    if(lv)
        rewind(lv->f);
}

void sxc_cluster_listvolumes_free(sxc_cluster_lv_t *lv) {
    fclose(lv->f);
    unlink(lv->fname);
    free(lv->fname);
    free(lv);
}
#define expect_state(expst) do { if(yactx->state != (expst)) { CBDEBUG("bad state (in %d, expected %d)", yactx->state, expst); return 0; } } while(0)

struct cb_listusers_ctx {
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    FILE *f;
    char *usrname;
    char *desc;
    struct cbl_user_t {
        int is_admin;
        unsigned int namelen;
        unsigned int desclen;
        int64_t quota;
        int64_t quota_used;
    } usrdata;

    enum listusers_state { LU_ERROR, LU_BEGIN, LU_NAME, LU_VALUES, LU_VALNAME, LU_ISADMIN, LU_DESC, LU_QUOTA, LU_QUOTA_USED, LU_DONE, LU_COMPLETE } state;
};

static int yacb_listusers_start_map(void *ctx) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state == LU_BEGIN)
	yactx->state = LU_NAME;
    else if(yactx->state == LU_VALUES)
	yactx->state = LU_VALNAME;
    else {
	CBDEBUG("bad state (in %d, expected %d, or %d)", yactx->state, LU_BEGIN, LU_VALUES);
	return 0;
    }
    return 1;
}

static int yacb_listusers_end_map(void *ctx) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->state == LU_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == LU_DONE)
	yactx->state = LU_COMPLETE;
    else if(yactx->state == LU_NAME)
	yactx->state = LU_COMPLETE;
    else if(yactx->state == LU_VALNAME) {
	if(!fwrite(&yactx->usrdata, sizeof(yactx->usrdata), 1, yactx->f) ||
           !fwrite(yactx->usrname, yactx->usrdata.namelen, 1, yactx->f) ||
           (yactx->usrdata.desclen && !fwrite(yactx->desc, yactx->usrdata.desclen, 1, yactx->f))) {
	    CBDEBUG("Failed to save user attributes to temporary file");
	    sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
	    return 0;
	}
	free(yactx->usrname);
	yactx->usrname = NULL;
	yactx->usrdata.namelen = 0;
        free(yactx->desc);
        yactx->desc = NULL;
        yactx->usrdata.desclen = 0;
	yactx->state = LU_NAME;
    } else {
	CBDEBUG("bad state (in %d, expected %d, %d or %d)", yactx->state, LU_DONE, LU_NAME, LU_VALNAME);
	return 0;
    }
    return 1;
}

static int yacb_listusers_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->state == LU_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == LU_NAME) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = LU_ERROR;
            return 1;
        }
    }
    if(yactx->state == LU_NAME) {
	if(yactx->usrname) {
	    CBDEBUG("Inconsistent state");
	    return 0;
	}
	yactx->usrdata.namelen = l;
	yactx->usrname = malloc(yactx->usrdata.namelen);
	if(!yactx->usrname) {
	    CBDEBUG("OOM duplicating username '%.*s'", (unsigned)l, s);
	    sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->usrname, s, yactx->usrdata.namelen);
	yactx->usrdata.is_admin = 0;
	yactx->state = LU_VALUES;
	return 1;
    }

    if(yactx->state == LU_VALNAME) {
	if(l == lenof("admin") && !memcmp(s, "admin", lenof("admin"))) {
	    yactx->state = LU_ISADMIN;
	    return 1;
	}
        if(l == lenof("userDesc") && !memcmp(s, "userDesc", lenof("userDesc"))) {
            yactx->state = LU_DESC;
            return 1;
        }
        if(l == lenof("userQuota") && !memcmp(s, "userQuota", lenof("userQuota"))) {
            yactx->state = LU_QUOTA;
            return 1;
        }
        if(l == lenof("userQuotaUsed") && !memcmp(s, "userQuotaUsed", lenof("userQuotaUsed"))) {
            yactx->state = LU_QUOTA_USED;
            return 1;
        }
	CBDEBUG("unexpected usrdata key '%.*s'", (unsigned)l, s);
	return 0;
    }

    CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, LU_NAME, LU_VALNAME);
    return 0;
}

static int yacb_listusers_bool(void *ctx, int boolean) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state == LU_ISADMIN) {
	yactx->usrdata.is_admin = boolean;
    } else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, LU_ISADMIN);
	return 0;
    }

    yactx->state = LU_VALNAME;
    return 1;
}

static int yacb_listusers_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if (yactx->state == LU_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    if (yactx->state == LU_DESC) {
        yactx->usrdata.desclen = l;
        yactx->desc = malloc(yactx->usrdata.desclen);
        if (!yactx->desc) {
            CBDEBUG("OOM duplicating user desc '%.*s'", (unsigned)l, s);
            sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
            return 0;
        }
        memcpy(yactx->desc, s, yactx->usrdata.desclen);
        yactx->state = LU_VALNAME;
        return 1;
    }
    return 0;
}

static int yacb_listusers_number(void *ctx, const char *s, size_t l) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    char number[21], *enumb = NULL;
    int64_t n;
    if (yactx->state == LU_ERROR)
        return 1;

    if(l > 20) {
        CBDEBUG("Quota too long");
        sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "Failed to parse quota");
        return 0;
    }

    memcpy(number, s, l);
    number[l] = '\0';
    n = strtoll(number, &enumb, 10);
    if(enumb && *enumb) {
        CBDEBUG("Failed to parse quota");
        sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "Failed to parse quota");
        return 0;
    }
    if (yactx->state == LU_QUOTA) {
        yactx->usrdata.quota = n;
        yactx->state = LU_VALNAME;
        return 1;
    } else if(yactx->state == LU_QUOTA_USED) {
        yactx->usrdata.quota_used = n;
        yactx->state = LU_VALNAME;
        return 1;
    }
    return 0;
}

static int listusers_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("failed to allocate yajl structure");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "List users failed: Out of memory");
	return 1;
    }

    free(yactx->usrname);
    yactx->usrname = NULL;
    rewind(yactx->f);
    yactx->state = LU_BEGIN;

    return 0;
}

static int listusers_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != LU_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
	return 1;
    }
    return 0;
}

struct _sxc_cluster_lu_t {
    sxc_client_t *sx;
    FILE *f;
    char *fname;
};

static sxc_cluster_lu_t *cluster_listusers_common(sxc_cluster_t *cluster, const char *url) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    struct cb_listusers_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_cluster_lu_t *ret;
    char *fname;
    int qret;

    sxc_clearerr(sx);

    ya_init(yacb);
    memset(&yctx, 0, sizeof(yctx));
    yacb->yajl_start_map = yacb_listusers_start_map;
    yacb->yajl_map_key = yacb_listusers_map_key;
    yacb->yajl_boolean = yacb_listusers_bool;
    yacb->yajl_string  = yacb_listusers_string;
    yacb->yajl_end_map = yacb_listusers_end_map;
    yacb->yajl_number = yacb_listusers_number;
    yctx.yh = NULL;
    yctx.usrname = NULL;
    yctx.desc = NULL;

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
        CFGDEBUG("failed to create temporary storage for user list");
        return NULL;
    }

    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, url, NULL, 0, listusers_setup_cb, listusers_cb, &yctx);
    if(qret != 200) {
        CFGDEBUG("query returned %d", qret);
        free(yctx.usrname);
        if(yctx.yh)
            yajl_free(yctx.yh);
        fclose(yctx.f);
        unlink(fname);
        free(fname);
        return NULL;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != LU_COMPLETE) {
        if (yctx.state != LU_ERROR) {
            CFGDEBUG("JSON parsing failed: %d", yctx.state);
            cluster_err(SXE_ECOMM, "List users failed: Communication error");
        }
        free(yctx.usrname);
        if(yctx.yh)
            yajl_free(yctx.yh);
        fclose(yctx.f);
        unlink(fname);
        free(fname);
        return NULL;
    }

    free(yctx.usrname);
    if(yctx.yh)
        yajl_free(yctx.yh);

    ret = malloc(sizeof(*ret));
    if(!ret) {
        CFGDEBUG("OOM allocating results");
        cluster_err(SXE_EMEM, "Volume list failed: Out of memory");
        fclose(yctx.f);
        unlink(fname);
        free(fname);
        return NULL;
    }

    rewind(yctx.f);
    ret->sx = sx;
    ret->f = yctx.f;
    ret->fname = fname;
    return ret;
}

static sxc_cluster_lu_t *cluster_listusers(sxc_cluster_t *cluster, const char *list_clones) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxc_cluster_lu_t *ret;
    unsigned int len;
    char *query;

    len = lenof(".users?desc&quota") + 1;
    if(list_clones)
        len += lenof("&clones=") + strlen(list_clones);
    query = malloc(len);
    if(!query) {
        CFGDEBUG("Failed to allocate memory for query");
        return NULL;
    }
    snprintf(query, len, ".users?desc&quota%s%s", (list_clones ? "&clones=" : ""), (list_clones ? list_clones : ""));
    sxi_set_operation(sx, "list users", sxi_cluster_get_name(cluster), NULL, NULL);
    ret = cluster_listusers_common(cluster, query);
    free(query);
    return ret;
}

sxc_cluster_lu_t *sxc_cluster_listclones(sxc_cluster_t *cluster, const char *username) {
    return cluster_listusers(cluster, username);
}

sxc_cluster_lu_t *sxc_cluster_listusers(sxc_cluster_t *cluster) {
    return sxc_cluster_listclones(cluster, NULL);
}

int sxc_cluster_listusers_next(sxc_cluster_lu_t *lu, char **user_name, int *is_admin, char **desc, int64_t *quota, int64_t *quota_used) {
    struct cbl_user_t user;
    sxc_client_t *sx;
    char *user_desc;
    if (!lu || !user_name)
        return -1;
    if(desc)
        *desc = NULL;
    sx = lu->sx;

    if(!fread(&user, sizeof(user), 1, lu->f)) {
	if(ferror(lu->f)) {
	    SXDEBUG("error reading attributes from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next user: Read item from cache failed");
	    return -1;
	}
	return 0;
    }
    if(user.namelen & 0x80000000 || user.desclen & 0x80000000) {
        SXDEBUG("Invalid username length");
        sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next user: Bad data from cache file");
        return -1;
    }

    *user_name = malloc(user.namelen + 1);
    if(!*user_name) {
        SXDEBUG("OOM allocating result file name (%u bytes)", user.namelen);
        sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next user: Out of memory");
        return -1;
    }
    if(!fread(*user_name, user.namelen, 1, lu->f)) {
        SXDEBUG("error reading name from results file");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next user: Read item from cache failed");
        free(*user_name);
        *user_name = NULL;
        return -1;
    }
    (*user_name)[user.namelen] = '\0';

    user_desc = malloc(user.desclen + 1);
    if(!user_desc) {
        SXDEBUG("OOM allocating result file name (%u bytes)", user.desclen);
        sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next user: Out of memory");
        free(*user_name);
        *user_name = NULL;
        return -1;
    }

    if(user.desclen && !fread(user_desc, user.desclen, 1, lu->f)) {
        SXDEBUG("error reading name from results file");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next user: Read item from cache failed");
        free(user_desc);
        free(*user_name);
        *user_name = NULL;
        return -1;
    }
    user_desc[user.desclen] = '\0';

    if(desc)
        *desc = user_desc;
    else
        free(user_desc);
    if(quota)
        *quota = user.quota;
    if(quota_used)
        *quota_used = user.quota_used;
    if(is_admin)
        *is_admin = user.is_admin;

    return 1;
}

int sxc_cluster_whoami(sxc_cluster_t *cluster, char **user, char **role, char **desc, int64_t *quota, int64_t *quota_used) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxc_cluster_lu_t *lu;
    int rc, ret = 1, is_admin = 0;

    if(!user) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    *user = NULL;
    if(role)
        *role = NULL;
    if(desc)
        *desc = NULL;
    if(quota)
        *quota = -1;
    if(quota_used)
        *quota_used = -1;

    sxi_set_operation(sx, "get user details", sxi_cluster_get_name(cluster), NULL, NULL);
    lu = cluster_listusers_common(cluster, ".self");
    if(!lu)
        goto sxc_cluster_whoami_err;
    rc = sxc_cluster_listusers_next(lu, user, &is_admin, desc, quota, quota_used);
    sxc_cluster_listusers_free(lu);
    /* successful sxc_cluster_listusers_next() returns 1 */
    if(rc != 1)
        goto sxc_cluster_whoami_err;

    if(role) {
        if(is_admin)
            *role = strdup("admin");
        else
            *role = strdup("normal");
        if(!*role)
            goto sxc_cluster_whoami_err;
    }

    ret = 0;
sxc_cluster_whoami_err:
    if(ret) {
        free(*user);
        *user = NULL;
        if(desc) {
            free(*desc);
            *desc = NULL;
        }
        if(role) {
            free(*role);
            *role = NULL;
        }
        if(quota)
            *quota = -1;
        if(quota_used)
            *quota_used = -1;
    }

    return ret;
}

void sxc_cluster_listusers_free(sxc_cluster_lu_t *lu) {
    if (!lu)
        return;
    fclose(lu->f);
    unlink(lu->fname);
    free(lu->fname);
    free(lu);
}

struct cbl_acluser_t {
    int acls;
    unsigned int namelen;
};

struct cb_listaclusers_ctx {
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    FILE *f;
    uint64_t volume_size;
    char *fname;
    struct cbl_acluser_t acluser;
    unsigned int replica;
    unsigned int naclusers;
    enum list_aclusers_state { LA_ERROR, LA_BEGIN, LA_ACLUSER, LA_PRIVS, LA_CAN_READ, LA_CAN_WRITE, LA_IS_OWNER, LA_COMPLETE } state;
};


static int yacb_listaclusers_start_map(void *ctx) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if(!ctx)
	return 0;

    switch(yactx->state) {
    case LA_BEGIN:
	yactx->state = LA_ACLUSER;
        return 1;
    default:
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
}

static int yacb_listaclusers_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if(!ctx || !l)
	return 0;

    if (yactx->state == LA_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == LA_ACLUSER) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = LA_ERROR;
            return 1;
        }
    }
    if(yactx->state == LA_ACLUSER) {
	yactx->state = LA_PRIVS;
        memset(&yactx->acluser, 0, sizeof(yactx->acluser));
	yactx->acluser.namelen = l;
	yactx->fname = malloc(yactx->acluser.namelen);
	if(!yactx->fname) {
	    CBDEBUG("OOM duplicating acluser name '%.*s'", (unsigned)l, s);
	    sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->fname, s, yactx->acluser.namelen);
	yactx->naclusers++;
	return 1;
    }
    return 0;
}

static int yacb_listaclusers_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if (yactx->state == LA_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if(yactx->state == LA_PRIVS) {
	if(l == lenof("read") && !memcmp(s, "read", lenof("read")))
            yactx->acluser.acls |= SX_ACL_READ;
	else if(l == lenof("write") && !memcmp(s, "write", lenof("write")))
            yactx->acluser.acls |= SX_ACL_WRITE;
	else if(l == lenof("manager") && !memcmp(s, "manager", lenof("manager")))
            yactx->acluser.acls |= SX_ACL_MANAGER;
	else if(l == lenof("owner") && !memcmp(s, "owner", lenof("owner")))
            yactx->acluser.acls |= SX_ACL_OWNER;
	else {
	    CBDEBUG("unexpected attribute '%.*s' in LA_PRIVS", (unsigned)l, s);
	    return 0;
	}
	return 1;
    }
    return 0;
}

static int yacb_listaclusers_start_array(void *ctx) {
    return 1;
}
static int yacb_listaclusers_end_array(void *ctx) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state == LA_PRIVS) {
	if(!fwrite(&yactx->acluser, sizeof(yactx->acluser), 1, yactx->f) || !fwrite(yactx->fname, yactx->acluser.namelen, 1, yactx->f)) {
	    CBDEBUG("failed to save acluser attributes to temporary acluser");
	    sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write temporary file");
	    return 0;
	}
	free(yactx->fname);
	yactx->fname = NULL;
	yactx->state = LA_ACLUSER;
	return 1;
    }
    return 0;
}

static int yacb_listaclusers_end_map(void *ctx) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == LA_ERROR)
        return yacb_error_end_map(&yactx->errctx);

    if(yactx->state == LA_ACLUSER) {
	/* We land here on an empty list */
	yactx->state = LA_COMPLETE;
	return 1;
    }

    CBDEBUG("bad state %d", yactx->state);
    return 0;
}


static int listaclusers_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("failed to allocate yajl structure");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "List failed: Out of memory");
	return 1;
    }

    yactx->state = LA_BEGIN;
    rewind(yactx->f);
    yactx->volume_size = 0;
    yactx->replica = 0;
    free(yactx->fname);
    yactx->fname = NULL;
    memset(&yactx->acluser, 0, sizeof(yactx->acluser));
    yactx->naclusers = 0;

    return 0;
}

static int listaclusers_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != LA_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
	return 1;
    }

    return 0;
}


struct _sxc_cluster_la_t {
    sxc_client_t *sx;
    char *fname;
    FILE *f;
};

sxc_cluster_la_t *sxc_cluster_listaclusers(sxc_cluster_t *cluster, const char *volume) {
    char *enc_vol, *url, *fname;
    struct cb_listaclusers_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxi_hostlist_t volhosts;
    sxc_cluster_la_t *ret;
    unsigned int len;
    int qret;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);

    sxc_clearerr(sx);

    sxi_hostlist_init(&volhosts);
    if(sxi_locate_volume(sxi_cluster_get_conns(cluster), volume, &volhosts, NULL, NULL, NULL)) {
	sxi_hostlist_empty(&volhosts);
	return NULL;
    }

    if(!(enc_vol = sxi_urlencode(sx, volume, 0))) {
	CFGDEBUG("failed to encode volume %s", volume);
	sxi_hostlist_empty(&volhosts);
	return NULL;
    }

    len = strlen(enc_vol) + 1 + sizeof("?o=acl&manager");

    if(!(url = malloc(len))) {
	CFGDEBUG("OOM allocating url (%u bytes)", len);
	cluster_err(SXE_EMEM, "List failed: Out of memory");
	sxi_hostlist_empty(&volhosts);
	free(enc_vol);
	return NULL;
    }
    snprintf(url, len, "%s?o=acl&manager", enc_vol);
    free(enc_vol);

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
	CFGDEBUG("failed to create temporary storage for acluser list");
	sxi_hostlist_empty(&volhosts);
	free(url);
	return NULL;
    }

    ya_init(yacb);
    yacb->yajl_start_map = yacb_listaclusers_start_map;
    yacb->yajl_map_key = yacb_listaclusers_map_key;
    yacb->yajl_string = yacb_listaclusers_string;
    yacb->yajl_end_map = yacb_listaclusers_end_map;
    yacb->yajl_start_array = yacb_listaclusers_start_array;
    yacb->yajl_end_array = yacb_listaclusers_end_array;

    yctx.yh = NULL;
    yctx.fname = NULL;

    sxi_set_operation(sx, "list volume acl", sxi_cluster_get_name(cluster), volume, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), &volhosts, REQ_GET, url, NULL, 0, listaclusers_setup_cb, listaclusers_cb, &yctx);
    sxi_hostlist_empty(&volhosts);
    free(url);
    free(yctx.fname);
    if(qret != 200) {
	CFGDEBUG("query returned %d", qret);
	if(yctx.yh)
	    yajl_free(yctx.yh);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != LA_COMPLETE) {
        if (yctx.state != LA_ERROR) {
            CFGDEBUG("JSON parsing failed");
            cluster_err(SXE_ECOMM, "List failed: Communication error");
        }
	if(yctx.yh)
	    yajl_free(yctx.yh);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(yctx.yh)
	yajl_free(yctx.yh);

    if(fflush(yctx.f) ||
       ftruncate(fileno(yctx.f), ftell(yctx.f)) ||
       fseek(yctx.f, 0L, SEEK_SET)) {
	cluster_err(SXE_EWRITE, "List failed: Failed to write temporary data");
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    ret = malloc(sizeof(*ret));
    if(!ret) {
	CFGDEBUG("OOM allocating results");
	cluster_err(SXE_EMEM, "List failed: Out of memory");
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    ret->sx = sx;
    ret->f = yctx.f;
    ret->fname = fname;
    return ret;
}

int sxc_cluster_listaclusers_next(sxc_cluster_la_t *la, char **acluser_name, int *acls) {
    struct cbl_acluser_t acluser;
    sxc_client_t *sx;

    if (!la || !acluser_name || !acls)
        return -1;
    sx = la->sx;
    if(!fread(&acluser, sizeof(acluser), 1, la->f)) {
	if(ferror(la->f)) {
	    SXDEBUG("error reading attributes from results acluser");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next acluser: Read item from cache failed");
	    return -1;
	}
	return 0;
    }
    if(acluser.namelen & 0x80000000) {
        SXDEBUG("Invalid acluser name length");
        sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next acluser: Bad data from cache file");
        return -1;
    }

    *acluser_name = malloc(acluser.namelen + 1);
    if(!*acluser_name) {
        SXDEBUG("OOM allocating result acluser name (%u bytes)", acluser.namelen);
        sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next acluser: Out of memory");
        return -1;
    }
    if(!fread(*acluser_name, acluser.namelen, 1, la->f)) {
        SXDEBUG("error reading name from results acluser");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next acluser: Read item from cache failed");
        return -1;
    }
    (*acluser_name)[acluser.namelen] = '\0';

    *acls = acluser.acls;

    return 1;
}

void sxc_cluster_listaclusers_free(sxc_cluster_la_t *la) {
    if (!la)
        return;
    if(la->f)
	fclose(la->f);
    if(la->fname) {
	unlink(la->fname);
	free(la->fname);
    }
    free(la);
}

