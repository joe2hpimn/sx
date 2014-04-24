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

#include "libsx-int.h"
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

int sxc_volume_add(sxc_cluster_t *cluster, const char *name, int64_t size, unsigned int replica, sxc_meta_t *metadata, const char *owner)
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

    proto = sxi_volumeadd_proto(sx, name, owner, size, replica, metadata);
    if(!proto) {
	SXDEBUG("Cannot allocate request");
	return 1;
    }
    sxi_set_operation(sx, "add volume", sxi_cluster_get_name(cluster), name, NULL);
    qret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, proto->path, proto->content, proto->content_len);
    sxi_query_free(proto);
    return qret;
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
    if(write(fd, filter_uuid, strlen(filter_uuid)) != strlen(filter_uuid)) {
	sxi_seterr(sx, SXE_EWRITE, "Can't write to %s", path);
	free(path);
	close(fd);
	return 1;
    }
    close(fd);

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
	close(fd);
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

struct user_iter {
    sxc_client_t *sx;
    char *user;
    const char *grant_read_users;
    const char *grant_write_users;
    const char *revoke_read_users;
    const char *revoke_write_users;
};

static const char *acl_loop(struct user_iter *iter, const char **ptr)
{
    const char *q = *ptr;
    const char *qend;
    unsigned int n;

    if (!q)
        return NULL;
    qend = strchr(q, ',');
    if (!qend) {
        qend = q + strlen(q);
        *ptr = NULL;
    } else
        *ptr = qend+1;
    n = qend - q;
    free(iter->user);
    iter->user = malloc(n + 1);
    if (!iter->user) {
        sxi_setsyserr(iter->sx, SXE_EMEM, "OOM on allocating username");
        return NULL;
    }
    strncpy(iter->user, q, n);
    iter->user[n] = '\0';
    return iter->user;
}

static const char *grant_read(void *ctx)
{
    struct user_iter *iter = ctx;
    return acl_loop(iter, &iter->grant_read_users);
}

static const char *grant_write(void *ctx)
{
    struct user_iter *iter = ctx;
    return acl_loop(iter, &iter->grant_write_users);
}

static const char *revoke_read(void *ctx)
{
    struct user_iter *iter = ctx;
    return acl_loop(iter, &iter->revoke_read_users);
}

static const char *revoke_write(void *ctx)
{
    struct user_iter *iter = ctx;
    return acl_loop(iter, &iter->revoke_write_users);
}

int sxc_volume_acl(sxc_cluster_t *cluster, const char *url,
                  const char *user, const char *grant, const char *revoke)
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
    if (!grant && !revoke) {
        cluster_err(SXE_EARG, "You must specify at least one grant/revoke operation to perform");
        return 1;
    }
    sx = sxi_cluster_get_client(cluster);
    user_iter.sx = sx;
    if (grant) {
        if (!strcmp(grant,"read"))
            user_iter.grant_read_users = user;
        else if (!strcmp(grant,"write"))
            user_iter.grant_write_users = user;
        else if (!strcmp(grant,"read,write") || !strcmp(grant, "write,read")) {
            user_iter.grant_read_users = user;
            user_iter.grant_write_users = user;
        } else {
            cluster_err(SXE_EARG, "Unknown permissions for grant: %s", grant);
        }
    }
    if (revoke) {
        if (!strcmp(revoke,"read"))
            user_iter.revoke_read_users = user;
        else if (!strcmp(revoke,"write"))
            user_iter.revoke_write_users = user;
        else if (!strcmp(revoke,"read,write") || !strcmp(revoke, "write,read")) {
            user_iter.revoke_read_users = user;
            user_iter.revoke_write_users = user;
        } else
            cluster_err(SXE_EARG, "Unknown permissions for revoke: %s", revoke);
    }
    proto = sxi_volumeacl_proto(sx, url, grant_read, grant_write,
                                revoke_read, revoke_write, &user_iter);
    free(user_iter.user);

    sxi_set_operation(sxi_cluster_get_client(cluster), "modify volume acl", sxi_cluster_get_name(cluster), url, NULL);
    rc = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, proto->path, proto->content, proto->content_len);
    sxi_query_free(proto);
    return rc;
}

// {"volumeList":{"vol":{"replicaCount":1,"sizeBytes":10737418240},"volxxx":{"replicaCount":1,"sizeBytes":10737418240}}
struct cb_listvolumes_ctx {
    sxc_client_t *sx;
    yajl_callbacks yacb;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    FILE *f;
    char *volname;
    struct cbl_volume_t {
	int64_t size;
	unsigned int replica_count;
	unsigned int namelen;
    } voldata;

    enum listvolumes_state { LV_ERROR, LV_BEGIN, LV_BASE, LV_VOLUMES, LV_NAME, LV_VALUES, LV_VALNAME, LV_REPLICA, LV_SIZE, LV_DONE, LV_COMPLETE } state;
};
#define CBDEBUG(...) do{ sxc_client_t *sx = yactx->sx; SXDEBUG(__VA_ARGS__); } while(0)
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
    else {
	CBDEBUG("bad state (in %d, expected %d, %d or %d)", yactx->state, LV_BEGIN, LV_VOLUMES, LV_VALUES);
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
    else if(yactx->state == LV_VALNAME) {
	if(yactx->voldata.replica_count < 1 || yactx->voldata.size < 0 || !yactx->volname || !yactx->voldata.namelen) {
	    CBDEBUG("incomplete entry");
	    return 0;
	}
	if(!fwrite(&yactx->voldata, sizeof(yactx->voldata), 1, yactx->f) || !fwrite(yactx->volname, yactx->voldata.namelen, 1, yactx->f)) {
	    CBDEBUG("failed to save file attributes to temporary file");
	    sxi_setsyserr(yactx->sx, SXE_EWRITE, "Failed to write to temporary file");
	    return 0;
	}
	free(yactx->volname);
	yactx->volname = NULL;
	yactx->voldata.namelen = 0;
	yactx->state = LV_NAME;
    } else {
	CBDEBUG("bad state (in %d, expected %d, %d or %d)", yactx->state, LV_DONE, LV_NAME, LV_VALNAME);
	return 0;
    }
    return 1;
}

static int yacb_listvolumes_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if (yactx->state == LV_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    return 0;
}

static int yacb_listvolumes_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == LV_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == LV_DONE || yactx->state == LV_BASE) {
        if (ya_check_error(yactx->sx, &yactx->errctx, s, l)) {
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
	yactx->volname = malloc(l);
	if(!yactx->volname) {
	    CBDEBUG("OOM duplicating volume name '%.*s'", (unsigned)l, s);
	    sxi_seterr(yactx->sx, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->volname, s, l);
	yactx->voldata.replica_count = 0;
	yactx->voldata.size = -1;
	yactx->voldata.namelen = l;

	yactx->state = LV_VALUES;
	return 1;
    }

    if(yactx->state == LV_VALNAME) {
	if(l == lenof("replicaCount") && !memcmp(s, "replicaCount", lenof("replicaCount"))) {
	    yactx->state = LV_REPLICA;
	    return 1;
	}
	if(l == lenof("sizeBytes") && !memcmp(s, "sizeBytes", lenof("sizeBytes"))) {
	    yactx->state = LV_SIZE;
	    return 1;
	}
	CBDEBUG("unexpected voldata key '%.*s'", (unsigned)l, s);
	return 0;
    }

    CBDEBUG("bad state (in %d, expected %d, %d or %d)", yactx->state, LV_BASE, LV_NAME, LV_VALNAME);
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

static int listvolumes_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("failed to allocate yajl structure");
	sxi_seterr(sx, SXE_EMEM, "List volumes failed: out of memory");
	return 1;
    }

    free(yactx->volname);
    yactx->volname = NULL;
    rewind(yactx->f);
    yactx->state = LV_BEGIN;
    yactx->sx = sx;

    return 0;
}

static int listvolumes_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_listvolumes_ctx *yactx = (struct cb_listvolumes_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != LV_ERROR) {
            CBDEBUG("failed to parse JSON data");
            sxi_seterr(sxi_conns_get_client(conns), SXE_ECOMM, "communication error");
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
};

sxc_cluster_lv_t *sxc_cluster_listvolumes(sxc_cluster_t *cluster) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    struct cb_listvolumes_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_cluster_lv_t *ret;
    char *fname;
    int qret;

    sxc_clearerr(sx);

    ya_init(yacb);
    yacb->yajl_start_map = yacb_listvolumes_start_map;
    yacb->yajl_map_key = yacb_listvolumes_map_key;
    yacb->yajl_string = yacb_listvolumes_string;
    yacb->yajl_number = yacb_listvolumes_number;
    yacb->yajl_end_map = yacb_listvolumes_end_map;

    yctx.yh = NULL;
    yctx.volname = NULL;

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
	CFGDEBUG("failed to create temporary storage for volume list");
	return NULL;
    }

    sxi_set_operation(sx, "list volumes", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, "?volumeList", NULL, 0, listvolumes_setup_cb, listvolumes_cb, &yctx);
    if(qret != 200) {
	CFGDEBUG("query returned %d", qret);
	free(yctx.volname);
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
            cluster_err(SXE_ECOMM, "List volumes failed: communication error");
        }
	free(yctx.volname);
	if(yctx.yh)
	    yajl_free(yctx.yh);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    free(yctx.volname);
    if(yctx.yh)
	yajl_free(yctx.yh);

    ret = malloc(sizeof(*ret));
    if(!ret) {
	CFGDEBUG("OOM allocating results");
	cluster_err(SXE_EMEM, "Volume list failed: out of memory");
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
    return ret;
}

int sxc_cluster_listvolumes_next(sxc_cluster_lv_t *lv, char **volume_name, int64_t *volume_size, unsigned int *replica_count) {
    struct cbl_volume_t volume;
    sxc_client_t *sx = lv->sx;

    if(!fread(&volume, sizeof(volume), 1, lv->f)) {
	if(ferror(lv->f)) {
	    SXDEBUG("error reading attributes from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next volume: read item from cache failed");
	    return -1;
	}
	return 0;
    }

    if(volume_name) {
	*volume_name = malloc(volume.namelen + 1);
	if(!*volume_name) {
	    SXDEBUG("OOM allocating result file name (%u bytes)", (unsigned)volume.namelen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next volume: out of memory");
	    return -1;
	}
	if(!fread(*volume_name, volume.namelen, 1, lv->f)) {
	    SXDEBUG("error reading name from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next volume: read item from cache failed");
	    return -1;
	}
        (*volume_name)[volume.namelen] = '\0';
        if(sxi_is_debug_enabled(sx)) {
            sxi_hostlist_t nodes;
            sxi_hostlist_init(&nodes);
            if (!sxi_locate_volume(lv->cluster, *volume_name, &nodes,NULL)) {
                unsigned n = sxi_hostlist_get_count(&nodes);
                unsigned i;
                SXDEBUG("Volume %s master nodes:", *volume_name);
                for (i=0;i<n;i++)
                    SXDEBUG("\t%s", sxi_hostlist_get_host(&nodes,
                                                          i));
            }
            sxi_hostlist_empty(&nodes);
        }
    } else
	fseek(lv->f, volume.namelen, SEEK_CUR);

    if(volume_size)
	*volume_size = volume.size;

    if(replica_count)
	*replica_count = volume.replica_count;

    return 1;
}

void sxc_cluster_listvolumes_free(sxc_cluster_lv_t *lv) {
    fclose(lv->f);
    unlink(lv->fname);
    free(lv->fname);
    free(lv);
}
#define CBDEBUG(...) do{ sxc_client_t *sx = yactx->sx; SXDEBUG(__VA_ARGS__); } while(0)
#define expect_state(expst) do { if(yactx->state != (expst)) { CBDEBUG("bad state (in %d, expected %d)", yactx->state, expst); return 0; } } while(0)

struct cb_listusers_ctx {
    sxc_client_t *sx;
    yajl_callbacks yacb;
    yajl_handle yh;
    struct cb_error_ctx errctx;
    FILE *f;
    char *usrname;
    struct cbl_user_t {
        int is_admin;
	unsigned int namelen;
    } usrdata;

    enum listusers_state { LU_ERROR, LU_BEGIN, LU_NAME, LU_VALUES, LU_VALNAME, LU_ISADMIN, LU_DONE, LU_COMPLETE } state;
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
	if(!fwrite(&yactx->usrdata, sizeof(yactx->usrdata), 1, yactx->f) || !fwrite(yactx->usrname, yactx->usrdata.namelen, 1, yactx->f)) {
	    CBDEBUG("failed to save file attributes to temporary file");
	    sxi_setsyserr(yactx->sx, SXE_EWRITE, "Failed to write to temporary file");
	    return 0;
	}
	free(yactx->usrname);
	yactx->usrname = NULL;
	yactx->usrdata.namelen = 0;
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
        if (ya_check_error(yactx->sx, &yactx->errctx, s, l)) {
            yactx->state = LU_ERROR;
            return 1;
        }
    }
    if(yactx->state == LU_NAME) {
	if(yactx->usrname) {
	    CBDEBUG("Inconsistent state");
	    return 0;
	}
	yactx->usrname = malloc(l);
	if(!yactx->usrname) {
	    CBDEBUG("OOM duplicating user name '%.*s'", (unsigned)l, s);
	    sxi_seterr(yactx->sx, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->usrname, s, l);
	yactx->usrdata.is_admin = 0;
	yactx->usrdata.namelen = l;

	yactx->state = LU_VALUES;
	return 1;
    }

    if(yactx->state == LU_VALNAME) {
	if(l == lenof("admin") && !memcmp(s, "admin", lenof("admin"))) {
	    yactx->state = LU_ISADMIN;
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
    return 0;
}


static int listusers_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("failed to allocate yajl structure");
	sxi_seterr(sx, SXE_EMEM, "List users failed: out of memory");
	return 1;
    }

    free(yactx->usrname);
    yactx->usrname = NULL;
    rewind(yactx->f);
    yactx->state = LU_BEGIN;
    yactx->sx = sx;

    return 0;
}

static int listusers_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_listusers_ctx *yactx = (struct cb_listusers_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != LU_ERROR) {
            CBDEBUG("failed to parse JSON data");
            sxi_seterr(sxi_conns_get_client(conns), SXE_ECOMM, "communication error");
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

sxc_cluster_lu_t *sxc_cluster_listusers(sxc_cluster_t *cluster) {
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    struct cb_listusers_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_cluster_lu_t *ret;
    char *fname;
    int qret;

    sxc_clearerr(sx);

    ya_init(yacb);
    yacb->yajl_start_map = yacb_listusers_start_map;
    yacb->yajl_map_key = yacb_listusers_map_key;
    yacb->yajl_boolean = yacb_listusers_bool;
    yacb->yajl_string  = yacb_listusers_string;
    yacb->yajl_end_map = yacb_listusers_end_map;

    yctx.yh = NULL;
    yctx.usrname = NULL;

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
	CFGDEBUG("failed to create temporary storage for user list");
	return NULL;
    }

    sxi_set_operation(sx, "list users", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, ".users", NULL, 0, listusers_setup_cb, listusers_cb, &yctx);
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
            cluster_err(SXE_ECOMM, "List users failed: communication error");
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
	cluster_err(SXE_EMEM, "Volume list failed: out of memory");
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

int sxc_cluster_listusers_next(sxc_cluster_lu_t *lu, char **user_name, int *is_admin) {
    struct cbl_user_t user;
    sxc_client_t *sx;
    if (!lu || !user_name || !is_admin)
        return -1;
    sx = lu->sx;

    if(!fread(&user, sizeof(user), 1, lu->f)) {
	if(ferror(lu->f)) {
	    SXDEBUG("error reading attributes from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next user: read item from cache failed");
	    return -1;
	}
	return 0;
    }

    if(user_name) {
	*user_name = malloc(user.namelen + 1);
	if(!*user_name) {
	    SXDEBUG("OOM allocating result file name (%u bytes)", (unsigned)user.namelen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next user: out of memory");
	    return -1;
	}
	if(!fread(*user_name, user.namelen, 1, lu->f)) {
	    SXDEBUG("error reading name from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next user: read item from cache failed");
	    return -1;
	}
	(*user_name)[user.namelen] = '\0';
    } else
	fseek(lu->f, user.namelen, SEEK_CUR);

    *is_admin = user.is_admin;
    return 1;
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
    int can_read;
    int can_write;
    int is_owner;
    int is_admin;
    unsigned int namelen;
};

struct cb_listaclusers_ctx {
    sxc_client_t *sx;
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
        if (ya_check_error(yactx->sx, &yactx->errctx, s, l)) {
            yactx->state = LA_ERROR;
            return 1;
        }
    }
    if(yactx->state == LA_ACLUSER) {
	yactx->state = LA_PRIVS;
	yactx->fname = malloc(l+1);
	if(!yactx->fname) {
	    CBDEBUG("OOM duplicating acluser name '%.*s'", (unsigned)l, s);
	    sxi_seterr(yactx->sx, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->fname, s, l);
        memset(&yactx->acluser, 0, sizeof(yactx->acluser));
	yactx->acluser.namelen = l;
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
            yactx->acluser.can_read = 1;
	else if(l == lenof("write") && !memcmp(s, "write", lenof("write")))
            yactx->acluser.can_write = 1;
	else if(l == lenof("owner") && !memcmp(s, "owner", lenof("owner")))
	    yactx->acluser.is_owner = 1;
        else if (l == lenof("admin") && !memcmp(s, "admin", lenof("admin")))
            yactx->acluser.is_admin = 1;
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
	    sxi_setsyserr(yactx->sx, SXE_EWRITE, "Failed to write temporary file");
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


static int listaclusers_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_listaclusers_ctx *yactx = (struct cb_listaclusers_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	SXDEBUG("failed to allocate yajl structure");
	sxi_seterr(sx, SXE_EMEM, "List failed: out of memory");
	return 1;
    }

    yactx->state = LA_BEGIN;
    yactx->sx = sx;
    rewind(yactx->f);
    yactx->volume_size = 0;
    yactx->replica = 0;
    free(yactx->fname);
    yactx->fname = NULL;
    memset(&yactx->acluser, 0, sizeof(yactx->acluser));
    yactx->naclusers = 0;

    return 0;
}

static int listaclusers_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_listaclusers_ctx *yctx = (struct cb_listaclusers_ctx *)ctx;
    if(yajl_parse(yctx->yh, data, size) != yajl_status_ok) {
        if (yctx->state != LA_ERROR) {
            sxc_client_t *sx = sxi_conns_get_client(conns);
            SXDEBUG("failed to parse JSON data");
            sxi_seterr(sxi_conns_get_client(conns), SXE_ECOMM, "communication error");
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
    if(sxi_locate_volume(cluster, volume, &volhosts, NULL)) {
	sxi_hostlist_empty(&volhosts);
	return NULL;
    }

    if(!(enc_vol = sxi_urlencode(sx, volume, 0))) {
	CFGDEBUG("failed to encode volume %s", volume);
	sxi_hostlist_empty(&volhosts);
	return NULL;
    }

    len = strlen(enc_vol) + 1 + sizeof("?o=acl");

    if(!(url = malloc(len))) {
	CFGDEBUG("OOM allocating url (%u bytes)", len);
	cluster_err(SXE_EMEM, "List failed: out of memory");
	sxi_hostlist_empty(&volhosts);
	free(enc_vol);
	return NULL;
    }
    snprintf(url, len, "%s?o=acl", enc_vol);
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
            cluster_err(SXE_ECOMM, "List failed: communication error");
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
	cluster_err(SXE_EWRITE, "List failed: failed to write temporary data");
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    ret = malloc(sizeof(*ret));
    if(!ret) {
	CFGDEBUG("OOM allocating results");
	cluster_err(SXE_EMEM, "List failed: out of memory");
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

int sxc_cluster_listaclusers_next(sxc_cluster_la_t *la, char **acluser_name, int *can_read, int *can_write, int *is_owner, int *is_admin) {
    struct cbl_acluser_t acluser;
    sxc_client_t *sx;

    if (!la || !acluser_name || !can_read || !can_write || !is_owner)
        return -1;
    sx = la->sx;
    if(!fread(&acluser, sizeof(acluser), 1, la->f)) {
	if(ferror(la->f)) {
	    SXDEBUG("error reading attributes from results acluser");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next acluser: read item from cache failed");
	    return -1;
	}
	return 0;
    }

    if(acluser_name) {
	*acluser_name = malloc(acluser.namelen + 1);
	if(!*acluser_name) {
	    SXDEBUG("OOM allocating result acluser name (%u bytes)", (unsigned)acluser.namelen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next acluser: out of memory");
	    return -1;
	}
	if(!fread(*acluser_name, acluser.namelen, 1, la->f)) {
	    SXDEBUG("error reading name from results acluser");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next acluser: read item from cache failed");
	    return -1;
	}
	(*acluser_name)[acluser.namelen] = '\0';
    } else
	fseek(la->f, acluser.namelen, SEEK_CUR);

    *can_read = acluser.can_read;
    *can_write = acluser.can_write;
    *is_owner = acluser.is_owner;
    *is_admin = acluser.is_admin;

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

