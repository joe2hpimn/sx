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
#include "curlevents.h"
#include "filter.h"
#include "sxproto.h"
#include "jobpoll.h"
#include "volops.h"
#include "vcrypto.h"
#include "jparse.h"

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

    proto = sxi_volumeadd_proto(sx, name, owner, size, replica, revisions, metadata, NULL, 0);
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

int sxc_volume_modify(sxc_cluster_t *cluster, const char *volume, const char *newname, const char *newowner, int64_t newsize, int max_revs, sxc_meta_t *custom_meta) {
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

    query = sxi_volume_mod_proto(sx, volume, newname, newowner, newsize, max_revs, custom_meta);
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

int sxc_volume_modify_replica(sxc_cluster_t *cluster, const char *volume, unsigned int replica) {
    sxc_client_t *sx;
    sxi_hostlist_t volhosts;
    sxi_query_t *query = NULL;
    int ret = -1;
    unsigned int prev_replica;

    if(!cluster)
        return -1;
    sx = sxi_cluster_get_client(cluster);

    if(!volume) {
        sxi_seterr(sx, SXE_EARG, "Failed to change volume size: invalid argument");
        return -1;
    }

    sxc_clearerr(sx);
    sxi_hostlist_init(&volhosts);
    if(sxi_volume_info(sxi_cluster_get_conns(cluster), volume, &volhosts, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &prev_replica, NULL, NULL, NULL, NULL))
        goto sxc_volume_modify_err;

    query = sxi_replica_change_proto(sx, volume, prev_replica, replica);
    if(!query) {
        sxi_seterr(sx, SXE_EMEM, "Failed to prepare volume replica modify query");
        goto sxc_volume_modify_err;
    }

    sxi_set_operation(sx, "modify volume replica", sxi_cluster_get_name(cluster), volume, NULL);
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
	if(access(path, F_OK) && mkdir(path, 0700) == -1 && errno != EEXIST) {
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
    if(access(path, F_OK) && mkdir(path, 0700) == -1 && errno != EEXIST) {
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
	if(mkdir(path, 0700) == -1 && errno != EEXIST) {
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

// {"volumeList":{"vol":{"replicaCount":2,"effectiveReplicaCount":1,"revisions":4,"privs":"rw","sizeBytes":10737418240,"volumeMeta":{"key1":"val1","key2":"val2"}},"volxxx":{"replicaCount":1,"revisions":2,"privs":"r-","sizeBytes":10737418240,"volumeMeta":{"key1":"val1","key2":"val2"}}}
struct cb_listvolumes_ctx {
    curlev_context_t *cbdata;
    const struct jparse_actions *acts;
    jparse_t *J;
    FILE *f;
    struct cbl_volume_t {
	int64_t size;
        int64_t used_size;
        int64_t fsize;
        int64_t nfiles;
	unsigned int replica_count;
	unsigned int effective_replica_count;
        unsigned int revisions;
	unsigned int namelen;
        unsigned int owner_len;
        char privs[2];
    } voldata;
    char *owner;
    sxc_meta_t *meta;
    unsigned int meta_count;
    enum sxc_error_t err;
};

static void cb_listvolumes_owner(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(yactx->owner) {
	sxi_jparse_cancel(J, "Multiple volume owners received");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->owner = malloc(length);
    if(!yactx->owner) {
	sxi_jparse_cancel(J, "Out of memory processing volume owner");
	yactx->err = SXE_EMEM;
	return;
    }
    memcpy(yactx->owner, string, length);
    yactx->voldata.owner_len = length;
}

static void cb_listvolumes_privs(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(length != 2 || (string[0] != 'r' && string[0] != '-') || (string[1] != 'w' && string[1] != '-')) {
	sxi_jparse_cancel(J, "Invalid privilege '%.*s' received for volume '%s'", length, string, volume);
	yactx->err = SXE_ECOMM;
	return;
    }
    memcpy(yactx->voldata.privs, string, 2);
}

static void cb_listvolumes_rpl(jparse_t *J, void *ctx, int32_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num < 1) {
	sxi_jparse_cancel(J, "Invalid replica count '%d' received for volume '%s'", num, volume);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->voldata.replica_count = num;
}

static void cb_listvolumes_effrpl(jparse_t *J, void *ctx, int32_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num < 1) {
	sxi_jparse_cancel(J, "Invalid effective replica count '%d' received for volume '%s'", num, volume);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->voldata.effective_replica_count = num;
}

static void cb_listvolumes_revs(jparse_t *J, void *ctx, int32_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num < 1) {
	sxi_jparse_cancel(J, "Invalid number of revisions '%d' received for volume '%s'", num, volume);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->voldata.revisions = num;
}

static void cb_listvolumes_size(jparse_t *J, void *ctx, int64_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid size %lld received for volume '%s'", (long long)num, volume);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->voldata.size = num;
}

static void cb_listvolumes_usedsize(jparse_t *J, void *ctx, int64_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num < 0) {
        sxi_jparse_cancel(J, "Invalid size %lld received for volume '%s'", (long long)num, volume);
        yactx->err = SXE_ECOMM;
        return;
    }

    yactx->voldata.used_size = num;
}

static void cb_listvolumes_fsize(jparse_t *J, void *ctx, int64_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid files size %lld received for volume '%s'", (long long)num, volume);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->voldata.fsize = num;
}

static void cb_listvolumes_nfiles(jparse_t *J, void *ctx, int64_t num) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(num < 0) {
        sxi_jparse_cancel(J, "Invalid files number %lld received for volume '%s'", (long long)num, volume);
        yactx->err = SXE_ECOMM;
        return;
    }

    yactx->voldata.nfiles = num;
}

static void cb_listvolumes_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));

    if(!yactx->meta)
	yactx->meta = sxc_meta_new(sx);
    if(!yactx->meta) {
	sxi_jparse_cancel(J, "Out of memory processing volume metadata");
	yactx->err = SXE_EMEM;
	return;
    }

    if(sxc_meta_setval_fromhex(yactx->meta, key, string, length)) {
	if(sxc_geterrnum(sx) == SXE_EARG) {
	    sxi_jparse_cancel(J, "Invalid volume metadata received");
	    yactx->err = SXE_ECOMM;
	} else {
	    sxi_jparse_cancel(J, "Out of memory processing metadata");
	    yactx->err = SXE_EMEM;
	}
	sxc_clearerr(sx);
	return;
    }

    yactx->meta_count++;
}

static void cb_listvolumes_init(jparse_t *J, void *ctx) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    yactx->voldata.replica_count = 0;
    yactx->voldata.effective_replica_count = 0;
    yactx->voldata.revisions = 0;
    yactx->voldata.used_size = -1;
    yactx->voldata.fsize = -1;
    yactx->voldata.nfiles = -1;
    yactx->voldata.size = -1;
    yactx->voldata.privs[0] = '\0';
    yactx->voldata.privs[1] = '\0';
}

static void cb_listvolumes_complete(jparse_t *J, void *ctx) {
    const char *volume = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
    unsigned int i;

    yactx->voldata.namelen = strlen(volume);
    if(yactx->voldata.replica_count < 1 || yactx->voldata.used_size < 0 || yactx->voldata.size < 0 ||  !yactx->voldata.namelen) {
	sxi_jparse_cancel(J, "Missing attributes for volume '%s'", volume);
	yactx->err = SXE_ECOMM;
    }

    if(yactx->voldata.effective_replica_count < 1)
	yactx->voldata.effective_replica_count = yactx->voldata.replica_count;

    if(!fwrite(&yactx->voldata, sizeof(yactx->voldata), 1, yactx->f) ||
       !fwrite(volume, yactx->voldata.namelen, 1, yactx->f) ||
       (yactx->owner && !fwrite(yactx->owner, yactx->voldata.owner_len, 1, yactx->f)) ||
       !fwrite(&yactx->meta_count, sizeof(yactx->meta_count), 1, yactx->f)) {
	sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	yactx->err = SXE_EWRITE;
	sxc_clearerr(sx);
	return;
    }

    /* Iterate over all metas and write them to temp file */
    for(i = 0; i < sxc_meta_count(yactx->meta); i++) {
	const char *key = NULL;
	unsigned int key_len = 0;
	const void *value = NULL;
	unsigned int value_len = 0;
	if(sxc_meta_getkeyval(yactx->meta, i, &key, &value, &value_len)) {
	    sxi_jparse_cancel(J, "Failed to enumerate volume metadata");
	    yactx->err = SXE_ECOMM;
	    return;
	}

	key_len = strlen(key);
	if(!fwrite(&key_len, sizeof(key_len), 1, yactx->f) || !fwrite(key, key_len, 1, yactx->f) ||
	   !fwrite(&value_len, sizeof(value_len), 1, yactx->f) || (value_len && !fwrite(value, value_len, 1, yactx->f))) {
	    sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	    sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	    yactx->err = SXE_EWRITE;
	    sxc_clearerr(sx);
	    return;
	}
    }

    sxc_meta_free(yactx->meta);
    yactx->meta = NULL;
    yactx->meta_count = 0;
    free(yactx->owner);
    yactx->owner = NULL;
    yactx->voldata.owner_len = 0;
}

static int listvolumes_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    free(yactx->owner);
    yactx->owner = NULL;
    yactx->voldata.owner_len = 0;
    rewind(yactx->f);

    /* Meta handling */
    sxc_meta_free(yactx->meta);
    yactx->meta = NULL;
    yactx->meta_count = 0;

    return 0;
}

static int listvolumes_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
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
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_listvolumes_owner, JPKEY("volumeList"), JPANYKEY, JPKEY("owner")),
		      JPACT(cb_listvolumes_privs, JPKEY("volumeList"), JPANYKEY, JPKEY("privs")),
		      JPACT(cb_listvolumes_meta, JPKEY("volumeList"), JPANYKEY, JPKEY("volumeMeta"), JPANYKEY)
		      ),
	JPACTS_INT32(
		     JPACT(cb_listvolumes_rpl, JPKEY("volumeList"), JPANYKEY, JPKEY("replicaCount")),
		     JPACT(cb_listvolumes_effrpl, JPKEY("volumeList"), JPANYKEY, JPKEY("effectiveReplicaCount")),
		     JPACT(cb_listvolumes_revs, JPKEY("volumeList"), JPANYKEY, JPKEY("maxRevisions"))
		     ),
	JPACTS_INT64(
		     JPACT(cb_listvolumes_size, JPKEY("volumeList"), JPANYKEY, JPKEY("sizeBytes")),
		     JPACT(cb_listvolumes_usedsize, JPKEY("volumeList"), JPANYKEY, JPKEY("usedSize")),
                     JPACT(cb_listvolumes_fsize, JPKEY("volumeList"), JPANYKEY, JPKEY("filesSize")),
                     JPACT(cb_listvolumes_nfiles, JPKEY("volumeList"), JPANYKEY, JPKEY("nFiles"))
		     ),
	JPACTS_MAP_BEGIN(
			 JPACT(cb_listvolumes_init, JPKEY("volumeList"), JPANYKEY)
			 ),
	JPACTS_MAP_END(
		       JPACT(cb_listvolumes_complete, JPKEY("volumeList"), JPANYKEY)
		       )
    };
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    struct cb_listvolumes_ctx yctx;
    sxc_cluster_lv_t *ret;
    char *fname;
    int qret;

    sxc_clearerr(sx);
    memset(&yctx, 0, sizeof(yctx));
    yctx.acts = &acts;

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
	CFGDEBUG("failed to create temporary storage for volume list");
	return NULL;
    }

    sxi_set_operation(sx, "list volumes", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, get_meta ? "?volumeList&volumeMeta":"?volumeList", NULL, 0, listvolumes_setup_cb, listvolumes_cb, &yctx);
    if(qret != 200) {
	CFGDEBUG("query returned %d", qret);
	sxc_meta_free(yctx.meta);
	free(yctx.owner);
	sxi_jparse_destroy(yctx.J);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	sxc_meta_free(yctx.meta);
	free(yctx.owner);
	sxi_jparse_destroy(yctx.J);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    sxi_jparse_destroy(yctx.J);
    sxc_meta_free(yctx.meta);
    free(yctx.owner);

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

int sxc_cluster_listvolumes_next(sxc_cluster_lv_t *lv, char **volume_name, char **volume_owner, int64_t *volume_used_size, int64_t *volume_files_size, int64_t *volume_nfiles, int64_t *volume_size, unsigned int *replica_count, unsigned int *effective_replica_count, unsigned int *revisions, char privs[3], sxc_meta_t **meta) {
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

    if(volume_files_size)
        *volume_files_size = volume.fsize;

    if(volume_nfiles)
        *volume_nfiles = volume.nfiles;

    if(volume_size)
	*volume_size = volume.size;

    if(replica_count)
	*replica_count = volume.replica_count;

    if(effective_replica_count)
	*effective_replica_count = volume.effective_replica_count;

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

	    if(value_len && !fread(value, value_len, 1, lv->f)) {
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
    if(!lv)
        return;
    fclose(lv->f);
    unlink(lv->fname);
    free(lv->fname);
    free(lv);
}

struct cb_listusers_ctx {
    curlev_context_t *cbdata;
    const struct jparse_actions *acts;
    jparse_t *J;
    FILE *f;
    char *desc;
    struct cbl_user_t {
        int is_admin;
        unsigned int namelen;
        unsigned int desclen;
        int64_t quota;
        int64_t quota_used;
    } usrdata;
    enum sxc_error_t err;
};

/* 
   {
   "user1":{"admin":true, "userDesc":"this is a cluster user", "userQuota":1234, "userQuotaUsed":567},
   "otheruser":{...
   }
 */

static void cb_listusers_admin(jparse_t *J, void *ctx, int is_admin) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    yactx->usrdata.is_admin = is_admin;
}

static void cb_listusers_desc(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *user = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    if(yactx->desc) {
	sxi_jparse_cancel(J, "Multiple user descriptions received for user '%s'", user);
	yactx->err = SXE_ECOMM;
	return;
    }
    
    yactx->desc = malloc(length);
    if(!yactx->desc) {
	sxi_jparse_cancel(J, "Out of memory processing users");
	yactx->err = SXE_EMEM;
	return;
    }

    yactx->usrdata.desclen = length;
    memcpy(yactx->desc, string, length);
}

static void cb_listusers_quota(jparse_t *J, void *ctx, int64_t num) {
    const char *user = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid quota received for user '%s'", user);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->usrdata.quota = num;
}

static void cb_listusers_usedquota(jparse_t *J, void *ctx, int64_t num) {
    const char *user = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid used quota received for user '%s'", user);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->usrdata.quota_used = num;
}

static void cb_listusers_init(jparse_t *J, void *ctx) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    yactx->usrdata.is_admin = 0;
    yactx->usrdata.quota = -1;
    yactx->usrdata.quota_used = -1;
}

static void cb_listusers_complete(jparse_t *J, void *ctx) {
    const char *user = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    if(yactx->usrdata.quota < 0 || yactx->usrdata.quota_used < 0) {
	sxi_jparse_cancel(J, "Invalid quota values received for user '%s'", user);
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->usrdata.namelen = strlen(user);
    if(!fwrite(&yactx->usrdata, sizeof(yactx->usrdata), 1, yactx->f) ||
       !fwrite(user, yactx->usrdata.namelen, 1, yactx->f) ||
       (yactx->usrdata.desclen && !fwrite(yactx->desc, yactx->usrdata.desclen, 1, yactx->f))) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
	sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	yactx->err = SXE_EWRITE;
	sxc_clearerr(sx);
	return;
    }

    free(yactx->desc);
    yactx->desc = NULL;
    yactx->usrdata.desclen = 0;
}

static int listusers_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    free(yactx->desc);
    yactx->desc = NULL;
    yactx->usrdata.desclen = 0;
    rewind(yactx->f);

    return 0;
}

static int listusers_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
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
    const struct jparse_actions acts = {
	JPACTS_BOOL(JPACT(cb_listusers_admin, JPANYKEY, JPKEY("admin"))),
	JPACTS_STRING(JPACT(cb_listusers_desc, JPANYKEY, JPKEY("userDesc"))),
	JPACTS_INT64(
		     JPACT(cb_listusers_quota, JPANYKEY, JPKEY("userQuota")),
		     JPACT(cb_listusers_usedquota, JPANYKEY, JPKEY("userQuotaUsed"))
		     ),
	JPACTS_MAP_BEGIN(JPACT(cb_listusers_init, JPANYKEY)),
	JPACTS_MAP_END(JPACT(cb_listusers_complete, JPANYKEY))
    };
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    struct cb_listusers_ctx yctx;
    sxc_cluster_lu_t *ret;
    char *fname;
    int qret;

    sxc_clearerr(sx);

    memset(&yctx, 0, sizeof(yctx));
    yctx.acts = &acts;

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
        CFGDEBUG("failed to create temporary storage for user list");
        return NULL;
    }

    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, url, NULL, 0, listusers_setup_cb, listusers_cb, &yctx);
    if(qret != 200) {
        CFGDEBUG("query returned %d", qret);
	sxi_jparse_destroy(yctx.J);
        free(yctx.desc);
        fclose(yctx.f);
        unlink(fname);
        free(fname);
        return NULL;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	sxi_jparse_destroy(yctx.J);
        free(yctx.desc);
        fclose(yctx.f);
        unlink(fname);
        free(fname);
        return NULL;
    }
    sxi_jparse_destroy(yctx.J);

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
    const struct jparse_actions *acts;
    jparse_t *J;
    FILE *f;
    struct cbl_acluser_t acluser;
    unsigned int naclusers;
    enum sxc_error_t err;
};

/*
  {
  "user1":[ "read", "write", "manager","owner" ],
  "admin":[ "read", "write", "manager" ]
  }
*/

static void cb_listaclusers_init(jparse_t *J, void *ctx) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    memset(&yactx->acluser, 0, sizeof(yactx->acluser));
}

static void cb_listaclusers_priv(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;

    if(length == lenof("read") && !memcmp(string, "read", lenof("read")))
	yactx->acluser.acls |= SX_ACL_READ;
    else if(length == lenof("write") && !memcmp(string, "write", lenof("write")))
	yactx->acluser.acls |= SX_ACL_WRITE;
    else if(length == lenof("manager") && !memcmp(string, "manager", lenof("manager")))
	yactx->acluser.acls |= SX_ACL_MANAGER;
    else if(length == lenof("owner") && !memcmp(string, "owner", lenof("owner")))
	yactx->acluser.acls |= SX_ACL_OWNER;
    /* NOTE: unknown privileges are just ignored */
}

static void cb_listaclusers_complete(jparse_t *J, void *ctx) {
    const char *user = sxi_jpath_mapkey(sxi_jparse_whereami(J));
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;

    yactx->acluser.namelen = strlen(user);
    if(!fwrite(&yactx->acluser, sizeof(yactx->acluser), 1, yactx->f) || !fwrite(user, yactx->acluser.namelen, 1, yactx->f)) {
	sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
	sxi_setsyserr(sx, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxc_geterrmsg(sx));
	yactx->err = SXE_EWRITE;
	sxc_clearerr(sx);
	return;
    }
    yactx->naclusers++;
}

static int listaclusers_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;

    yactx->cbdata = cbdata;

    sxi_jparse_destroy(yactx->J);
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    rewind(yactx->f);
    memset(&yactx->acluser, 0, sizeof(yactx->acluser));
    yactx->naclusers = 0;

    return 0;
}

static int listaclusers_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
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
    const struct jparse_actions acts = {
	JPACTS_ARRAY_BEGIN(JPACT(cb_listaclusers_init, JPANYKEY)),
	JPACTS_STRING(JPACT(cb_listaclusers_priv, JPANYKEY, JPANYITM)),
	JPACTS_ARRAY_END(JPACT(cb_listaclusers_complete, JPANYKEY))
    };
    char *enc_vol, *url, *fname;
    struct cb_listaclusers_ctx yctx;
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

    yctx.acts = &acts;
    yctx.J = NULL;

    sxi_set_operation(sx, "list volume acl", sxi_cluster_get_name(cluster), volume, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), &volhosts, REQ_GET, url, NULL, 0, listaclusers_setup_cb, listaclusers_cb, &yctx);
    sxi_hostlist_empty(&volhosts);
    free(url);
    if(qret != 200) {
	CFGDEBUG("query returned %d", qret);
	sxi_jparse_destroy(yctx.J);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	sxi_jparse_destroy(yctx.J);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }
    sxi_jparse_destroy(yctx.J);

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

