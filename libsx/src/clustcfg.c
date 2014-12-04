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
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>

#include "libsx-int.h"
#include "cluster.h"
#include "yajlwrap.h"
#include "clustcfg.h"
#include "sxreport.h"
#include "sxproto.h"
#include "jobpoll.h"
#include "curlevents.h"
#include "vcrypto.h"
#include "misc.h"

struct _sxc_cluster_t {
    sxc_client_t *sx;
    char *config_dir;
    sxi_conns_t *conns;
    struct sxi_access *useprof;
    struct sxi_access *access;
    char *cafile;
};


struct sxi_access {
    char *profile;
    char *auth;
    struct sxi_access *next;
};

#define cluster_err(...) sxi_seterr(cluster->sx, __VA_ARGS__)
#define cluster_syserr(...) sxi_setsyserr(cluster->sx, __VA_ARGS__)

sxc_client_t *sxi_cluster_get_client(const sxc_cluster_t *cluster) {
    return cluster ? cluster->sx : NULL;
}

sxi_conns_t *sxi_cluster_get_conns(sxc_cluster_t *cluster) {
    return cluster ? cluster->conns : NULL;
}

sxc_cluster_t *sxc_cluster_new(sxc_client_t *sx) {
    sxc_cluster_t *cluster;
    if(!sx)
	return NULL;

    sxc_clearerr(sx);
    cluster = calloc(1, sizeof(*cluster));
    if(!cluster) {
	SXDEBUG("OOM allocating config");
	sxi_seterr(sx, SXE_EMEM, "Failed to create config: Out of memory");
	return NULL;
    }
    cluster->sx = sx;
    cluster->conns = sxi_conns_new(sx);
    if(!cluster->conns) {
	free(cluster);
	return NULL;
    }

    return cluster;
}

void sxc_cluster_reset_hosts(sxc_cluster_t *cluster) {
    if(cluster)
	sxi_hostlist_empty(sxi_conns_get_hostlist(cluster->conns));
}

void sxc_cluster_free(sxc_cluster_t *cluster) {
    struct sxi_access *access;

    if(cluster) {
	free(cluster->config_dir);
	sxc_cluster_reset_hosts(cluster);
	sxi_conns_free(cluster->conns);
	access = cluster->access;
	while(access) {
	    struct sxi_access *delme = access;
	    access = access->next;
	    free(delme);
	}
	free(cluster->cafile);
	free(cluster);
    }
}

int sxc_cluster_set_dnsname(sxc_cluster_t *cluster, const char *dnsname) {
    struct addrinfo *res, *ungai;
    sxc_client_t *sx;
    sxi_hostlist_t dns_nodes;
    int rc;

    if (!cluster || sxi_conns_set_dnsname(cluster->conns, dnsname))
        return 1;
    if (!dnsname)
        return 0;
    sx = sxi_cluster_get_client(cluster);
    if((rc = getaddrinfo(dnsname, NULL, NULL, &res)))
	return 0;

    sxi_hostlist_init(&dns_nodes);
    ungai = res;
    for(; res; res = res->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        void *addr;

        if(res->ai_family == AF_INET)
            addr = &((struct sockaddr_in *)(res->ai_addr))->sin_addr;
        else if(res->ai_family == AF_INET6)
            addr = &((struct sockaddr_in6 *)(res->ai_addr))->sin6_addr;
        else
            continue;
        if(!inet_ntop(res->ai_family, addr, buf, sizeof(buf)))
            continue;
        if(sxi_hostlist_add_host(sx, &dns_nodes, buf))
            continue; /* FIXME: !? */
    }
    freeaddrinfo(ungai);
    rc = sxi_hostlist_add_list(sx, sxi_conns_get_hostlist(cluster->conns), &dns_nodes);
    sxi_hostlist_empty(&dns_nodes);
    return rc;
}

int sxc_cluster_set_sslname(sxc_cluster_t *cluster, const char *sslname) {
    return cluster ? sxi_conns_set_sslname(cluster->conns, sslname) : 1;
}

const char *sxc_cluster_get_dnsname(const sxc_cluster_t *cluster) {
    return cluster ? sxi_conns_get_dnsname(cluster->conns) : NULL;
}

const char *sxc_cluster_get_sslname(const sxc_cluster_t *cluster) {
    return cluster ? sxi_conns_get_sslname(cluster->conns) : NULL;
}

int sxc_cluster_set_uuid(sxc_cluster_t *cluster, const char *uuid) {
    return cluster ? sxi_conns_set_uuid(cluster->conns, uuid) : 1;
}

void sxc_cluster_remove_uuid(sxc_cluster_t *cluster) {
   sxi_conns_remove_uuid(cluster->conns);
}

const char *sxc_cluster_get_uuid(const sxc_cluster_t *cluster) {
    return cluster ? sxi_conns_get_uuid(cluster->conns) : NULL;
}

int sxc_cluster_add_host(sxc_cluster_t *cluster, const char *host) {
    return cluster ? sxi_hostlist_add_host(cluster->sx, sxi_conns_get_hostlist(cluster->conns), host) : 1;
}

int sxc_cluster_set_cafile(sxc_cluster_t *cluster, const char *cafile) {
    char *newca;
    if(!cluster)
	return 1;

    if(cafile) {
	newca = strdup(cafile);
	if(!newca) {
	    sxi_seterr(cluster->sx, SXE_EMEM, "Cannot allocate certificate path");
	    return 1;
	}
    } else
	newca = NULL;

    free(cluster->cafile);
    cluster->cafile = newca;
    sxi_conns_set_cafile(cluster->conns, cluster->cafile);
    return 0;
}

static struct sxi_access *sxc_cluster_get_access(sxc_cluster_t *cluster, const char *profile_name) {
    struct sxi_access *auth;
    if(!cluster)
	return NULL;
    if(!profile_name || !*profile_name)
	profile_name = "default";
    auth = cluster->access;
    while(auth) {
	if(!strcmp(auth->profile, profile_name))
	    return auth;
	auth = auth->next;
    }

    CFGDEBUG("cannot locate profile %s", profile_name);
    return NULL;
}

int sxc_cluster_add_access(sxc_cluster_t *cluster, const char *profile_name, const char *access_token) {
    struct sxi_access *access;

    if(!cluster)
	return 1;
    if(!sxi_is_valid_authtoken(sxi_cluster_get_client(cluster), access_token)) {
	CFGDEBUG("refusing to add invalid auth token to config");
	cluster_err(SXE_EARG, "Cannot add access credentials to config: Invalid authentication token");
	return 1;
    }
    if(!profile_name || !*profile_name)
	profile_name = "default";

    access = sxc_cluster_get_access(cluster, profile_name);
    if(access)
	memcpy(access->auth, access_token, AUTHTOK_ASCII_LEN);
    else {
	unsigned int prolen = strlen(profile_name) + 1;
	unsigned int toklen = AUTHTOK_ASCII_LEN + 1;
	unsigned int authlen = sizeof(*access) + prolen + toklen;
	access = malloc(authlen);
	if(!access) {
	    CFGDEBUG("OOM allocating access container");
	    cluster_err(SXE_EMEM, "Cannot add access credentials to config: Out of memory");
	    return 1;
	}
	access->profile = (char *)(access+1);
	access->auth = access->profile + prolen;
	access->next = cluster->access;
	memcpy(access->profile, profile_name, prolen);
	memcpy(access->auth, access_token, toklen);
	cluster->access = access;
    }

    CFGDEBUG("Granted access for %s", profile_name);
    return 0;
}

int sxc_cluster_set_access(sxc_cluster_t *cluster, const char *profile_name) {
    struct sxi_access *access = sxc_cluster_get_access(cluster, profile_name);
    sxc_client_t *sx = cluster->sx;

    sxc_clearerr(sx);
    if(!access) {
	SXDEBUG("cannot set access to profile %s", profile_name ? profile_name : "default");
	sxi_seterr(sx, SXE_EARG, "Cannot set config access credentials: Invalid profile");
	return 1;
    }
    if(sxi_conns_set_auth(cluster->conns, access->auth)) {
	SXDEBUG("cannot set access to profile %s, token %s", profile_name, access->auth);
	return 1;
    }
    return 0;
}


static char *get_confdir(sxc_client_t *sx, const char *config_dir, const char *cluster_name) {
    unsigned int name_len, config_len;
    const char *home_dir;
    char *confdir;

    if(!cluster_name || !*cluster_name) {
	SXDEBUG("called with NULL or empty name");
	sxi_seterr(sx, SXE_EARG, "Cannot locate config directory: Invalid argument");
	return NULL;
    }

    name_len = strlen(cluster_name);
    if(memchr(cluster_name, '/', name_len)) {
	SXDEBUG("invalid cluster name %s", cluster_name);
	sxi_seterr(sx, SXE_EARG, "Cannot locate config directory: Invalid argument");
	return NULL;
    }

    if(!config_dir) {
	home_dir = sxi_getenv("HOME");
	if(!home_dir) {
	    struct passwd *pwd = getpwuid(geteuid());
	    if(pwd)
		home_dir = pwd->pw_dir;
	}
	if(!home_dir) {
	    sxi_seterr(sx, SXE_EARG, "Cannot locate config directory: Cannot determine home directory");
	    return NULL;
	}
	config_len = strlen(home_dir) + 1 + lenof(".sx");
    } else
	config_len = strlen(config_dir);

    confdir = malloc(config_len + name_len + 2);
    if(!confdir) {
	SXDEBUG("OOM allocating config directory");
	sxi_seterr(sx, SXE_EMEM, "Cannot locate config directory: Out of memory");
	return NULL;
    }

    if(config_dir)
	sprintf(confdir, "%s/%s", config_dir, cluster_name);
    else
	sprintf(confdir, "%s/.sx/%s", home_dir, cluster_name);

    return confdir;
}

sxc_cluster_t *sxc_cluster_load(sxc_client_t *sx, const char *config_dir, const char *cluster_name) {
    char *fname = NULL, *line;
    unsigned int confdir_len, err = 0;
    sxc_cluster_t *cluster = NULL;
    struct dirent *dent;
    int secure = 0;
    FILE *f;
    DIR *d;

    sxc_clearerr(sx);
    do {
	struct stat st;
	int ids;

	cluster = sxc_cluster_new(sx);
	if(!cluster)
	    break;

	cluster->config_dir = get_confdir(sx, config_dir, cluster_name);
	if(!cluster->config_dir)
	    break;

	if(stat(cluster->config_dir, &st)) {
	    SXDEBUG("Cannot stat config directory %s", cluster->config_dir);
	    sxi_setsyserr(sx, SXE_ECFG, "Cannot stat configuration directory %s", cluster->config_dir);
            break;
        }

        if(sxc_cluster_set_sslname(cluster, cluster_name))
            break;

	if(st.st_mode & 077) {
	    SXDEBUG("Bad permissions on config dir %s", cluster->config_dir);
	    sxi_seterr(sx, SXE_ECFG, "Configuration directory has got too broad permissions. Please run 'chmod 0700 \"%s\"'", cluster->config_dir);
	    break;
	}
	confdir_len = strlen(cluster->config_dir);

	fname = malloc(confdir_len + 1 + sizeof("config")); /* Fits /nodes, /config, /auth and /ca.pem */
	if(!fname) {
	    SXDEBUG("OOM allocating config path");
	    sxi_seterr(sx, SXE_EMEM, "Cannot load cluster config: Out of memory");
	    break;
	}
	sprintf(fname, "%s/%s", cluster->config_dir, "config");

	if(!(f = fopen(fname, "r"))) {
	    SXDEBUG("failed to open config file %s", fname);
	    sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Failed to open file %s", fname);
	    break;
	}

	while(!sxc_fgetline(sx, f, &line) && line) {
	    int res = 0;
	    if(!strncmp(line, "ClusterUUID=", lenof("ClusterUUID=")))
		res = sxc_cluster_set_uuid(cluster, line + lenof("ClusterUUID="));
	    else if(!strncmp(line, "Hostname=", lenof("Hostname=")))
		res = sxc_cluster_set_dnsname(cluster, line + lenof("Hostname="));
	    else if(!strncmp(line, "HttpPort=", lenof("HttpPort="))) {
		char *eop;
		int port = strtol(line + lenof("HttpPort="), &eop, 10);
		if(port <= 0 ||
		   *eop ||
		   sxc_cluster_set_httpport(cluster, port))
		    res = 1;
	    } else if(!strncmp(line, "UseSSL=", lenof("UseSSL="))) {
		const char *p = line + lenof("UseSSL=");
		if(!strncasecmp(p, "yes", 3))
		    secure = 1;
		else if(!strncasecmp(p, "no", 2))
		    secure = -1;
		else {
		    SXDEBUG("Invalid config value for UseSSL: %s", p);
		    res = 1;
		}
	    } else if(strlen(line))
		SXDEBUG("Ignoring unrecognized entry '%s'", line);

	    free(line);
	    if(res)
		break;
	}
	fclose(f);
	if(line) {
	    SXDEBUG("bad config file %s", fname);
	    sxi_seterr(sx, SXE_ECFG, "Cannot load cluster config: Bad config file %s", fname);
	    break;
	}
	if(!sxc_cluster_get_uuid(cluster)) {
	    SXDEBUG("config file is missing the 'ClusterUUID' directive");
	    sxi_seterr(sx, SXE_ECFG, "Cannot load cluster config: Bad config file %s", fname);
	    break;
	}

	memcpy(fname + confdir_len, "/nodes", sizeof("/nodes"));
	d = opendir(fname);
	if(!d) {
	    SXDEBUG("failed to open nodes directory %s", fname);
	    sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Cannot open nodes directory %s", fname);
	    break;
	}
	while((dent = readdir(d))) {
	    if(dent->d_name[0] == '.' && (dent->d_name[1] == '\0' || (dent->d_name[1] == '.' && dent->d_name[2] == '\0')))
		continue;
	    if(sxc_cluster_add_host(cluster, dent->d_name)) {
		SXDEBUG("failed to add node %s", dent->d_name);
		err = 1;
		break;
	    }
	}
	closedir(d);
	if(err)
	    break;

	memcpy(fname + confdir_len, "/auth", sizeof("/auth"));
	d = opendir(fname);
	if(!d) {
	    SXDEBUG("failed to open auth directory %s", fname);
	    sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Cannot open auth directory %s", fname);
	    break;
	}

	errno = 0;
	ids = 0;
	while((dent = readdir(d))) {
	    char *auth_file;
	    int auth_len;
	    if(dent->d_name[0] == '.') /* skip dot dirs and tempfiles */
		continue;
	    auth_len = strlen(dent->d_name);
	    auth_file = malloc(confdir_len + lenof("/auth") + 1 + auth_len + 1);
	    if(!auth_file) {
		SXDEBUG("OOM allocating full path to auth file %s", dent->d_name);
		sxi_seterr(sx, SXE_EMEM, "Cannot load cluster config: Out of memory");
		err = 1;
		break;
	    }
	    sprintf(auth_file, "%s/%s", fname, dent->d_name);
	    f = fopen(auth_file, "r");
	    free(auth_file);
	    if(!f) {
		SXDEBUG("failed to open auth file %s", dent->d_name);
		if(errno == EACCES) {
		    errno = 0;
		    continue;
		}
		sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Cannot open auth file %s", dent->d_name);
		err = 1;
		break;
	    }
	    if(sxc_fgetline(sx, f, &line)) {
		fclose(f);
		SXDEBUG("failed to retrieve auth token for file %s", dent->d_name);
		sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Cannot load auth token from file %s", dent->d_name);
		err = 1;
		break;
	    }
	    fclose(f);
	    if(!line) {
		SXDEBUG("found empty auth file %s", dent->d_name);
		sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Cannot load empty auth file %s", dent->d_name);
		err = 1;
		break;
	    }

	    if(sxc_cluster_add_access(cluster, dent->d_name, line)) {
		free(line);
		err = 1;
		break;
	    }
	    if(!strcmp(dent->d_name, "default"))
		cluster->useprof = cluster->access;
	    free(line);
	    ids ++;
	}
	if(errno) {
	    SXDEBUG("Readdir failed with %d", errno);
	    sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Failed to list auth files");
	    err = 1;
	} else if(!ids) {
	    SXDEBUG("No auth ids were loaded");
	    sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: No auth files could be loaded");
	    err = 1;
	}
	closedir(d);
        if (err)
            break;

	memcpy(fname + confdir_len, "/ca.pem", sizeof("/ca.pem"));
	if(secure >= 0) {
	    struct stat buf;
	    if(stat(fname, &buf) == -1) {
		if(errno != ENOENT || secure) {
		    sxi_setsyserr(sx, SXE_ECFG, "Cannot access CA certificate file %s", fname);
                    break;
		} else if(!secure)
		    secure = -1;
	    } else
		secure = 1;
	}
        if(secure > 0)
            err = sxc_cluster_set_cafile(cluster, fname);
        else
            err = sxc_cluster_set_cafile(cluster, NULL);

	free(fname);
	fname = NULL;

	if(err)
	    break;
	if(!cluster->useprof)
	    cluster->useprof = cluster->access;

	SXDEBUG("Successfully loaded with %d ids", ids);
	return cluster;
    } while(0);

    SXDEBUG("failed");
    free(fname);
    sxc_cluster_free(cluster);
    return NULL;
}

int64_t sxc_cluster_get_bandwidth_limit(sxc_client_t *sx, const sxc_cluster_t *cluster) {
    if(!cluster || !sx) {
        SXDEBUG("Could not get bandwidth limit: NULL argument.");
        return -1;
    }

    return sxi_conns_get_bandwidth_limit(cluster->conns);
}

int sxc_cluster_set_bandwidth_limit(sxc_client_t *sx, sxc_cluster_t *cluster, int64_t bandwidth_limit) {
    if(!sx || !cluster || !cluster->conns) {
        SXDEBUG("Could not set bandwidth limit: NULL argument");
        return 1;
    }
        
    return sxi_conns_set_bandwidth_limit(cluster->conns, bandwidth_limit);
}

struct cb_fetchnodes_ctx {
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    struct cb_error_ctx errctx;
    sxi_hostlist_t hlist;
    yajl_handle yh;
    enum fetchnodes_state { FN_ERROR, FN_BEGIN, FN_CLUSTER, FN_NODES, FN_NODE, FN_COMPLETE } state;
};
#define expect_state(expst) do { if(yactx->state != (expst)) { CBDEBUG("bad state (in %d, expected %d)", yactx->state, expst); return 0; } } while(0)

static int yacb_fetchnodes_start_map(void *ctx) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state == FN_BEGIN)
	yactx->state = FN_CLUSTER;
    else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, FN_BEGIN);
	return 0;
    }
    return 1;
}

static int yacb_fetchnodes_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->state == FN_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == FN_CLUSTER) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = FN_ERROR;
            return 1;
        }
    }
    if(yactx->state == FN_CLUSTER) {
	if(l == lenof("nodeList") && !memcmp(s, "nodeList", lenof("nodeList"))) {
	    yactx->state = FN_NODES;
	    return 1;
	}
	CBDEBUG("unexpected cluster key '%.*s'", (unsigned)l, s);
	return 0;
    }

    CBDEBUG("bad state (in %d, expected %d)", yactx->state, FN_CLUSTER);
    return 0;
}

static int yacb_fetchnodes_start_array(void *ctx) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    if(!ctx)
	return 0;

    expect_state(FN_NODES);

    yactx->state = FN_NODE;
    return 1;
}

static int yacb_fetchnodes_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    char *host;
    sxc_client_t *sx;
    if(!ctx)
	return 0;
    if (yactx->state == FN_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);

    sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
    expect_state(FN_NODE);
    if(l<=0)
	return 0;

    if(!(host = malloc(l+1))) {
	CBDEBUG("OOM duplicating hostname '%.*s'", (unsigned)l, s);
	sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
	return 0;
    }

    memcpy(host, s, l);
    host[l] = '\0';
    if(sxi_hostlist_add_host(sx, &yactx->hlist, host)) {
	CBDEBUG("failed to add host %s", host);
	free(host);
        /* FIXME: Do not store errors in global buffer (bb#751) */
        sxi_cbdata_restore_global_error(sx, yactx->cbdata);
	return 0;
    }

    free(host);
    return 1;
}

static int yacb_fetchnodes_end_array(void *ctx) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    if(!ctx)
	return 0;

    expect_state(FN_NODE);

    yactx->state = FN_CLUSTER;
    return 1;
}

static int yacb_fetchnodes_end_map(void *ctx) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == FN_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == FN_CLUSTER)
	yactx->state = FN_COMPLETE;
    else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, FN_CLUSTER);
	return 0;
    }
    return 1;
}

static int fetchnodes_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("OOM allocating yajl context");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    yactx->state = FN_BEGIN;
    yactx->cbdata = cbdata;
    sxi_hostlist_empty(&yactx->hlist);

    return 0;
}

static int fetchnodes_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != FN_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
	return 1;
    }
    return 0;
}

int sxc_cluster_fetchnodes(sxc_cluster_t *cluster) {
    struct cb_fetchnodes_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_client_t *sx = cluster->sx;
    sxi_hostlist_t *orighlist;
    int ret = 1;

    sxi_hostlist_init(&yctx.hlist);
    ya_init(yacb);
    yacb->yajl_start_map = yacb_fetchnodes_start_map;
    yacb->yajl_map_key = yacb_fetchnodes_map_key;
    yacb->yajl_start_array = yacb_fetchnodes_start_array;
    yacb->yajl_string = yacb_fetchnodes_string;
    yacb->yajl_end_array = yacb_fetchnodes_end_array;
    yacb->yajl_end_map = yacb_fetchnodes_end_map;
    yctx.yh = NULL;

    orighlist = sxi_conns_get_hostlist(cluster->conns);
    if(!sxi_hostlist_get_count(orighlist)) {
        cluster_err(SXE_ECOMM, "Cannot update list of nodes: No node found%s in local cache", sxc_cluster_get_dnsname(cluster) ? " via dns resolution nor" : "");
	goto config_fetchnodes_error;
    }

    sxi_hostlist_shuffle(orighlist);

    sxi_set_operation(sxi_cluster_get_client(cluster), "fetch nodes", sxi_cluster_get_name(cluster), NULL, NULL);
    if(sxi_cluster_query(cluster->conns, NULL, REQ_GET, "?nodeList", NULL, 0, fetchnodes_setup_cb, fetchnodes_cb, &yctx) != 200) {
	SXDEBUG("query failed");
	goto config_fetchnodes_error;
    }

    if(!sxi_conns_get_uuid(cluster->conns)) {
	SXDEBUG("no uuid was set by query");
	sxi_seterr(sx, SXE_ECOMM, "Cannot update list of nodes: Cluster uuid missing");
	goto config_fetchnodes_error;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != FN_COMPLETE) {
        if (yctx.state != FN_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Cannot update list of nodes: Communication error");
        }
	goto config_fetchnodes_error;
    }

    if(!sxi_hostlist_get_count(&yctx.hlist)) {
	SXDEBUG("no host retrieved");
	sxi_seterr(sx, SXE_ECOMM, "Cannot update list of nodes: No nodes found");
	goto config_fetchnodes_error;
    }

    if(sxi_getenv("SX_DEBUG_SINGLEHOST")) {
	sxi_hostlist_empty(&yctx.hlist);
	if(sxi_hostlist_add_host(sx, &yctx.hlist, sxi_getenv("SX_DEBUG_SINGLEHOST"))) {
	    if(sxc_geterrnum(sx) == SXE_EARG) {
		sxc_clearerr(sx);
		sxi_seterr(sx, SXE_EARG, "Invalid value of SX_DEBUG_SINGLEHOST");
	    }
	    goto config_fetchnodes_error;
	}
    }

    if(sxi_conns_set_hostlist(cluster->conns, &yctx.hlist)) {
	SXDEBUG("failed to update cluster hostlist");
	goto config_fetchnodes_error;
    }

    ret = 0;
    /* FIXME warn if the NS records are not in sync */


 config_fetchnodes_error:
    if(yctx.yh)
	yajl_free(yctx.yh);

    sxi_hostlist_empty(&yctx.hlist);

    return ret;
}

struct cb_whoami_ctx {
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    struct cb_error_ctx errctx;
    char *whoami;
    yajl_handle yh;
    enum whoami_state { FW_ERROR, FW_BEGIN, FW_CLUSTER, FW_WHOAMI, FW_COMPLETE } state;
};
#define expect_state(expst) do { if(yactx->state != (expst)) { CBDEBUG("bad state (in %d, expected %d)", yactx->state, expst); return 0; } } while(0)

static int yacb_whoami_start_map(void *ctx) {
    struct cb_whoami_ctx *yactx = (struct cb_whoami_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state == FW_BEGIN)
	yactx->state = FW_CLUSTER;
    else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, FW_BEGIN);
	return 0;
    }
    return 1;
}

static int yacb_whoami_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_whoami_ctx *yactx = (struct cb_whoami_ctx *)ctx;
    if(!ctx)
	return 0;

    if (yactx->state == FW_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == FW_CLUSTER) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = FW_ERROR;
            return 1;
        }
    }
    if(yactx->state == FW_CLUSTER) {
	if(l == lenof("whoami") && !memcmp(s, "whoami", lenof("whoami"))) {
	    yactx->state = FW_WHOAMI;
	    return 1;
	}
	CBDEBUG("unexpected cluster key '%.*s'", (unsigned)l, s);
	return 0;
    }

    CBDEBUG("bad state (in %d, expected %d)", yactx->state, FW_CLUSTER);
    return 0;
}

static int yacb_whoami_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_whoami_ctx *yactx = (struct cb_whoami_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == FW_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);

    expect_state(FW_WHOAMI);
    if(l<=0)
	return 0;

    if(!(yactx->whoami = malloc(l+1))) {
	CBDEBUG("OOM duplicating username '%.*s'", (unsigned)l, s);
	sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
	return 0;
    }

    memcpy(yactx->whoami, s, l);
    yactx->whoami[l] = '\0';
    yactx->state = FW_CLUSTER;
    return 1;
}

static int yacb_whoami_end_map(void *ctx) {
    struct cb_whoami_ctx *yactx = (struct cb_whoami_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == FW_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == FW_CLUSTER)
	yactx->state = FW_COMPLETE;
    else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, FW_CLUSTER);
	return 0;
    }
    return 1;
}

static int whoami_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_whoami_ctx *yactx = (struct cb_whoami_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("OOM allocating yajl context");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot run whoami: Out of memory");
	return 1;
    }

    yactx->state = FW_BEGIN;
    yactx->cbdata = cbdata;
    yactx->whoami = NULL;

    return 0;
}

static int whoami_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_whoami_ctx *yactx = (struct cb_whoami_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != FW_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
	return 1;
    }
    return 0;
}

char* sxc_cluster_whoami(sxc_cluster_t *cluster) {
    struct cb_whoami_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_client_t *sx = cluster->sx;
    char *ret = NULL;

    ya_init(yacb);
    yacb->yajl_start_map = yacb_whoami_start_map;
    yacb->yajl_map_key = yacb_whoami_map_key;
    yacb->yajl_string = yacb_whoami_string;
    yacb->yajl_end_map = yacb_whoami_end_map;
    yctx.yh = NULL;

    sxi_set_operation(sxi_cluster_get_client(cluster), "whoami", sxi_cluster_get_name(cluster), NULL, NULL);
    if(sxi_cluster_query(cluster->conns, NULL, REQ_GET, "?whoami", NULL, 0, whoami_setup_cb, whoami_cb, &yctx) != 200) {
	SXDEBUG("query failed");
	goto config_whoami_error;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != FW_COMPLETE) {
        if (yctx.state != FW_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Cannot run whoami: Communication error");
        }
	goto config_whoami_error;
    }
    ret = yctx.whoami;
    SXDEBUG("whoami: %s", ret);

 config_whoami_error:
    if(yctx.yh) {
        if (!ret)
            free(yctx.whoami);
	yajl_free(yctx.yh);
    }

    return ret;
}

struct cb_locate_ctx {
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    sxi_hostlist_t *hlist;
    struct cb_error_ctx errctx;
    int64_t blocksize;
    yajl_handle yh;
    sxc_meta_t *meta;
    char *curkey;
    enum locate_state { LC_ERROR, LC_BEGIN, LC_KEYS, LC_SIZE, LC_NODES, LC_NODE, LC_META, LC_METAKEY, LC_METAVALUE, LC_COMPLETE } state;
};

static int yacb_locate_start_map(void *ctx) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(!ctx)
	return 0;

    if(yactx->state != LC_BEGIN && yactx->state != LC_META) {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, LC_BEGIN, LC_META);
	return 0;
    }

    yactx->state++;
    return 1;
}

static int yacb_locate_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == LC_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == LC_KEYS) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = LC_ERROR;
            return 1;
        }
    }

    if(yactx->state == LC_KEYS) {
	if(l == lenof("nodeList") && !memcmp(s, "nodeList", lenof("nodeList"))) {
	    yactx->state = LC_NODES;
	    return 1;
	} else if(l == lenof("blockSize") && !memcmp(s, "blockSize", lenof("blockSize"))) {
	    yactx->state = LC_SIZE;
	    return 1;
	} else if(l == lenof("volumeMeta") && !memcmp(s, "volumeMeta", lenof("volumeMeta"))) {
	    yactx->state = LC_META;
	    return 1;
	}
    } else if(yactx->state == LC_METAKEY) {
	if(yactx->meta) {
	    yactx->curkey = malloc(l+1);
	    if(!yactx->curkey) {
		CBDEBUG("OOM duplicating meta key '%.*s'", (unsigned)l, s);
		sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
		return 0;
	    }
	    memcpy(yactx->curkey, s, l);
	    yactx->curkey[l] = '\0';
	}
	yactx->state = LC_METAVALUE;
	return 1;
    } else {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, LC_KEYS, LC_METAKEY);
	return 0;
    }


    CBDEBUG("unexpected key '%.*s'", (unsigned)l, s);
    return 0;
}

static int yacb_locate_number(void *ctx, const char *s, size_t l) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    char numb[24], *enumb;
    int64_t nnumb;

    if(!ctx)
	return 0;

    expect_state(LC_SIZE);

    if(l > 20) {
	CBDEBUG("number too long (%u bytes)", (unsigned)l);
	return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    nnumb = strtoll(numb, &enumb, 10);
    if(*enumb || nnumb < 0) {
	CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
	return 0;
    }

    yactx->blocksize = nnumb;
    yactx->state = LC_KEYS;
    return 1;
}

static int yacb_locate_start_array(void *ctx) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(!ctx)
	return 0;

    expect_state(LC_NODES);

    yactx->state++;
    return 1;
}

static int yacb_locate_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    sxc_client_t *sx;
    if(!ctx)
	return 0;
    sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));

    if (yactx->state == LC_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    if(yactx->state == LC_NODE) {
	char *host;
	if(l<=0)
	    return 0;

	if(!(host = malloc(l+1))) {
	    CBDEBUG("OOM duplicating hostname '%.*s'", (unsigned)l, s);
	    sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
	    return 0;
	}

	memcpy(host, s, l);
	host[l] = '\0';
	if(sxi_hostlist_add_host(sx, yactx->hlist, host)) {
	    CBDEBUG("failed to add host %s", host);
	    free(host);

            /* FIXME: Do not store errors in global buffer (bb#751) */
            sxi_cbdata_restore_global_error(sx, yactx->cbdata);
	    return 0;
	}

	free(host);
	return 1;
    } else if(yactx->state == LC_METAVALUE) {
	if(yactx->meta) {
	    if(sxc_meta_setval_fromhex(yactx->meta, yactx->curkey, (const char *)s, l)) {
		CBDEBUG("failed to add value");
                sxi_cbdata_restore_global_error(sx, yactx->cbdata);
		return 0;
	    }
	    free(yactx->curkey);
	    yactx->curkey = NULL;
	}
	yactx->state = LC_METAKEY;
	return 1;
    } else {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, LC_NODE, LC_METAVALUE);
	return 0;
    }
}

static int yacb_locate_end_array(void *ctx) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(!ctx)
	return 0;

    expect_state(LC_NODE);

    yactx->state = LC_KEYS;
    return 1;
}

static int yacb_locate_end_map(void *ctx) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(!ctx)
	return 0;
    if (yactx->state == LC_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == LC_KEYS)
	yactx->state = LC_COMPLETE;
    else if(yactx->state == LC_METAKEY)
	yactx->state = LC_KEYS;
    else {
	CBDEBUG("bad state (in %d, expected %d or %d)", yactx->state, LC_KEYS, LC_METAKEY);
	return 0;
    }
    return 1;
}


static int locate_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("failed to allocate yajl structure");
	sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Locate failed: Out of memory");
	return 1;
    }

    free(yactx->curkey);
    yactx->curkey = NULL;
    sxc_meta_empty(yactx->meta);

    yactx->state = LC_BEGIN;
    yactx->blocksize = -1;
    sxi_hostlist_empty(yactx->hlist);

    return 0;
}

static int locate_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != LC_ERROR) {
            CBDEBUG("failed to parse JSON data");
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
	return 1;
    }
    return 0;
}

int sxi_volume_info(sxi_conns_t *conns, const char *volume, sxi_hostlist_t *nodes, int64_t *size, sxc_meta_t *metadata) {
    struct cb_locate_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    char *enc_vol, *url;
    int qret;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    sxc_clearerr(sx);
    if(!(enc_vol = sxi_urlencode(sx, volume, 0))) {
	SXDEBUG("failed to encode volume %s", volume);
	return 1;
    }

    if(!(url = malloc(strlen(enc_vol) + lenof("?o=locate&volumeMeta&size=") + 64))) {
	SXDEBUG("OOM allocating url (%lu bytes)", strlen(enc_vol) + lenof("?o=locate&volumeMeta&size=") + 64);
	sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
	free(enc_vol);
	return 1;
    }
    if(size)
	sprintf(url, "%s?o=locate&size=%lld", enc_vol, (long long int)*size);
    else
	sprintf(url, "%s?o=locate", enc_vol);
    if(metadata)
	strcat(url, "&volumeMeta");
    free(enc_vol);

    ya_init(yacb);
    yacb->yajl_start_map = yacb_locate_start_map;
    yacb->yajl_map_key = yacb_locate_map_key;
    yacb->yajl_start_array = yacb_locate_start_array;
    yacb->yajl_string = yacb_locate_string;
    yacb->yajl_end_array = yacb_locate_end_array;
    yacb->yajl_number = yacb_locate_number;
    yacb->yajl_end_map = yacb_locate_end_map;

    yctx.yh = NULL;
    yctx.hlist = nodes;
    yctx.meta = metadata;
    yctx.curkey = NULL;

    sxi_set_operation(sx, "locate volume", sxi_conns_get_sslname(conns), volume, NULL);
    qret = sxi_cluster_query(conns, NULL, REQ_GET, url, NULL, 0, locate_setup_cb, locate_cb, &yctx);
    free(url);
    if(qret != 200) {
	SXDEBUG("query returned %d", qret);
	if(yctx.yh)
	    yajl_free(yctx.yh);
	sxc_meta_empty(metadata);
        sxi_seterr(sx, SXE_ECOMM, "failed to query volume location");
        /* we must return an error code */
	return qret ? qret : -1;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != LC_COMPLETE) {
        if (yctx.state != LC_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Locate failed: Communication error");
        }
	if(yctx.yh)
	    yajl_free(yctx.yh);
	sxi_ht_empty(metadata);
	return -SXE_ECOMM;
    }
    if(size)
	*size = yctx.blocksize;
    if(yctx.yh)
	yajl_free(yctx.yh);

    if(sxi_getenv("SX_DEBUG_SINGLEHOST")) {
	sxi_hostlist_empty(nodes);
	sxi_hostlist_add_host(sx, nodes, sxi_getenv("SX_DEBUG_SINGLEHOST"));
    }
    if(sxi_getenv("SX_DEBUG_SINGLE_VOLUMEHOST")) {
        sxi_hostlist_empty(nodes);
        sxi_hostlist_add_host(sx, nodes, sxi_getenv("SX_DEBUG_SINGLE_VOLUMEHOST"));
    }
    return 0;
}

int sxi_locate_volume(sxi_conns_t *conns, const char *volume, sxi_hostlist_t *nodes, int64_t *size, sxc_meta_t *metadata) {
    sxi_set_operation(sxi_conns_get_client(conns), "locate volume", volume, NULL, NULL);
    return sxi_volume_info(conns, volume, nodes, size, metadata);
}

int sxi_is_valid_cluster(const sxc_cluster_t *cluster) {
    const sxi_hostlist_t *hlist;
    if(!cluster ||
       !cluster->sx ||
       !sxc_cluster_get_uuid(cluster) ||
       !sxc_cluster_get_sslname(cluster) ||
       !(hlist = sxi_conns_get_hostlist(cluster->conns)) ||
       !sxi_hostlist_get_count(hlist) || !cluster->access) {
	return 0;
    }
    return 1;
}

int sxc_cluster_save(sxc_cluster_t *cluster, const char *config_dir) {
    const sxi_hostlist_t *hlist;
    char *clusterd, *fname, *confdir;
    unsigned int clusterd_len, hlist_len, port;
    struct sxi_access *access;
    const char *s;
    FILE *f;
    struct dirent *dent;
    DIR *d;
    int i, ret = 0;

    if(!sxi_is_valid_cluster(cluster)) {
	CFGDEBUG("invalid config");
	if(cluster)
	    cluster_err(SXE_EARG, "Cannot save config: Config is invalid");
	return 1;
    }
    hlist = sxi_conns_get_hostlist(cluster->conns);
    hlist_len = sxi_hostlist_get_count(hlist);
    access = cluster->access;

    confdir = get_confdir(cluster->sx, config_dir, sxc_cluster_get_sslname(cluster));
    if(!confdir) {
	CFGDEBUG("cannot retrieve config directory");
	return 1;
    }
    clusterd_len = strlen(confdir);
    clusterd = malloc(clusterd_len + sizeof("/config") + 1); /* fits /volumes too */
    if(!clusterd) {
	CFGDEBUG("OOM allocating config file path");
	cluster_err(SXE_EMEM, "Cannot save config: Out of memory");
	free(confdir);
	return 1;
    }
    memcpy(clusterd, confdir, clusterd_len + 1);
    free(confdir);

    if(sxi_mkdir_hier(cluster->sx, clusterd, 0700)) {
	CFGDEBUG("failed to create config directory %s", clusterd);
	free(clusterd);
	return 1;
    }

    if(!(fname = sxi_tempfile_track(cluster->sx, clusterd, &f))) {
	CFGDEBUG("failed to create tempfile in %s", clusterd);
	free(clusterd);
	return 1;
    }

    clearerr(f);
    fprintf(f, "ClusterUUID=%s\nUseSSL=%s\n",
	    sxc_cluster_get_uuid(cluster),
	    sxi_conns_is_secure(cluster->conns) ? "Yes" : "No");
    s = sxc_cluster_get_dnsname(cluster);
    if(s)
	fprintf(f, "Hostname=%s\n", s);

    port = sxc_cluster_get_httpport(cluster);
    if(port)
	fprintf(f, "HttpPort=%u\n", port);

    i = ferror(f);
    i |= fclose(f);
    if(i) {
	CFGDEBUG("failed to write to config file %s", fname);
	cluster_syserr(SXE_EWRITE, "Cannot save config: Write to %s failed", fname);
	free(clusterd);
	sxi_tempfile_unlink_untrack(cluster->sx, fname);
	return 1;
    }

    memcpy(&clusterd[clusterd_len], "/config", sizeof("/config"));
    if(rename(fname, clusterd)) {
	CFGDEBUG("failed to rename %s to %s", fname, clusterd);
	cluster_syserr(SXE_EWRITE, "Cannot save config: Failed to rename %s to %s failed", fname, clusterd);
	free(clusterd);
	sxi_tempfile_unlink_untrack(cluster->sx, fname);
	return 1;
    }
    sxi_tempfile_untrack(cluster->sx, fname);

    memcpy(&clusterd[clusterd_len], "/volumes", sizeof("/volumes"));
    if(sxi_mkdir_hier(cluster->sx, clusterd, 0700)) {
	CFGDEBUG("failed to create volumes directory %s", clusterd);
	free(clusterd);
	return 1;
    }

    memcpy(&clusterd[clusterd_len], "/nodes", sizeof("/nodes"));
    if(sxi_mkdir_hier(cluster->sx, clusterd, 0700)) {
	CFGDEBUG("failed to create nodes directory %s", clusterd);
	free(clusterd);
	return 1;
    }

    for(i=0; i<(int)hlist_len; i++) {
	const char *host = sxi_hostlist_get_host(hlist, i);
	unsigned int len = clusterd_len + lenof("/nodes/") + strlen(host) + 1;
	char *touchme = malloc(len);

	if(!touchme) {
	    CFGDEBUG("OOM allocating host file for %s", host);
	    cluster_err(SXE_EMEM, "Cannot save config: Out of memory");
	    free(clusterd);
	    return 1;
	}
	sprintf(touchme, "%s/%s", clusterd, host);
	f = fopen(touchme, "w");
	if(!f || fclose(f)) {
	    CFGDEBUG("failed to touch host file %s", touchme);
	    cluster_syserr(SXE_EWRITE, "Cannot save config: Failed to touch file %s", touchme);
	    free(clusterd);
	    free(touchme);
	    return 1;
	}
	free(touchme);
    }

    d = opendir(clusterd);
    if(!d) {
	CFGDEBUG("failed to open nodes directory %s", clusterd);
	cluster_syserr(SXE_ECFG, "Cannot save config: Failed to open nodes directory %s", clusterd);
	free(clusterd);
	return 1;
    }

    while((dent = readdir(d))) {
	if(dent->d_name[0] == '.' && (dent->d_name[1] == '\0' || (dent->d_name[1] == '.' && dent->d_name[2] == '\0')))
	    continue;

	if(!sxi_hostlist_contains(hlist, dent->d_name)) {
	    unsigned int len = clusterd_len + lenof("/nodes/") + strlen(dent->d_name) + 1;
	    char *rmme = malloc(len);

	    if(!rmme) {
		CFGDEBUG("OOM allocating file name for node %s", dent->d_name);
		cluster_err(SXE_EMEM, "Cannot save config: Out of memory");
		closedir(d);
		free(clusterd);
		return 1;
	    }
	    sprintf(rmme, "%s/%s", clusterd, dent->d_name);
	    if(unlink(rmme))
		CFGDEBUG("failed to remove stale node file %s", rmme); /* FIXME warn here */
	    free(rmme);
	}
    }
    closedir(d);

    memcpy(&clusterd[clusterd_len], "/auth", sizeof("/auth"));
    if(sxi_mkdir_hier(cluster->sx, clusterd, 0700)) {
	CFGDEBUG("failed to create auth directory %s", clusterd);
	free(clusterd);
	return 1;
    }

    for( ; access ; access = access->next) {
	unsigned int len = clusterd_len + lenof("/auth/") + strlen(access->profile) + 1;
	char *writeme = malloc(len);
	if(!writeme) {
	    CFGDEBUG("OOM allocating name for profile %s", access->profile);
	    cluster_err(SXE_EMEM, "Cannot save config: Out of memory");
	    free(clusterd);
	    return 1;
	}
	sprintf(writeme, "%s/%s", clusterd, access->profile);

	if(!(fname = sxi_tempfile_track(cluster->sx, clusterd, &f))) {
	    CFGDEBUG("failed to create auth tempfile in %s", clusterd);
	    free(writeme);
	    free(clusterd);
	    return 1;
	}

	fprintf(f, "%s", access->auth);
	i = ferror(f);
	i |= fclose(f);
	if(i) {
	    CFGDEBUG("failed to write auth file for profile %s to tempfile %s", access->profile, fname);
	    cluster_syserr(SXE_EWRITE, "Cannot save config: Failed to write profile %s to tempfile", access->profile);
	    sxi_tempfile_unlink_untrack(cluster->sx, fname);
	    free(writeme);
	    free(clusterd);
	    return 1;
	}

	if(rename(fname, writeme)) {
	    CFGDEBUG("failed to rename %s to %s", fname, clusterd);
	    cluster_syserr(SXE_EWRITE, "Cannot save config: Failed to rename %s to %s", fname, clusterd);
	    sxi_tempfile_unlink_untrack(cluster->sx, fname);
	    free(writeme);
	    free(clusterd);
	    return 1;
	}
	sxi_tempfile_untrack(cluster->sx, fname);
	free(writeme);
    }
    memcpy(&clusterd[clusterd_len], "/ca.pem", sizeof("/ca.pem"));
    if (cluster->cafile && strcmp(clusterd,cluster->cafile)) {
        f = fopen(cluster->cafile,"r");
        ret = 1;
        if (f) {
            FILE *fo = fopen(clusterd,"w");
            if (fo) {
                char buf[1024];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), f))) {
                    if (fwrite(buf, 1, n, fo) < n)
                        break;
                }
                if (ferror(f))
                    cluster_syserr(SXE_EREAD, "Cannot read tempfile (ca.pem)");
                else if (ferror(fo))
                    cluster_syserr(SXE_EWRITE, "Cannot write to '%s'", clusterd);
                else
                    ret = 0;
                if (fclose(fo))
                    cluster_syserr(SXE_EWRITE, "Cannot close file '%s'", clusterd);
            } else {
                cluster_syserr(SXE_EWRITE, "Cannot open file '%s' for writing", clusterd);
            }
            fclose(f);
        } else
            cluster_err(SXE_ECOMM,"Could not retrieve ca.pem");
	if(sxi_tempfile_istracked(cluster->sx, cluster->cafile))
	    sxi_tempfile_unlink_untrack(cluster->sx, cluster->cafile);
        ret |= sxc_cluster_set_cafile(cluster, clusterd);
    } else
        ret = 0;

    clusterd[clusterd_len] = '\0';
    free(cluster->config_dir);
    cluster->config_dir = clusterd;
    return ret;
}

int sxc_cluster_remove(sxc_cluster_t *cluster, const char *config_dir) {
    char *confdir;

    if(!sxi_is_valid_cluster(cluster)) {
	CFGDEBUG("invalid config");
	if(cluster)
	    cluster_err(SXE_EARG, "config is invalid");
	return 1;
    }

    confdir = get_confdir(cluster->sx, config_dir, sxc_cluster_get_sslname(cluster));
    if(!confdir) {
	CFGDEBUG("cannot retrieve config directory");
	return 1;
    }

    if(sxi_rmdirs(confdir)) {
	cluster_err(SXE_EWRITE, "rmdir failed");
	free(confdir);
	return 1;
    }
    free(confdir);
    return 0;
}

struct cbl_file_t {
    int64_t filesize;
    time_t created_at;
    unsigned int namelen;
    unsigned int revlen;
    unsigned int blocksize;
    unsigned int fuck_off_valgrind;
};

struct cb_listfiles_ctx {
    struct cb_error_ctx errctx;
    curlev_context_t *cbdata;
    yajl_callbacks yacb;
    yajl_handle yh;
    FILE *f;
    uint64_t volume_size;
    int64_t volume_used_size;
    char *fname;
    char *frev;
    struct cbl_file_t file;
    unsigned int replica;
    unsigned int nfiles;
    enum list_files_state { LF_ERROR, LF_BEGIN, LF_MAIN, LF_REPLICACNT, LF_VOLUMEUSEDSIZE, LF_VOLUMESIZE, LF_FILES, LF_FILE, LF_FILECONTENT, LF_FILEATTRS, LF_FILESIZE, LF_BLOCKSIZE, LF_FILETIME, LF_FILEREV, LF_COMPLETE } state;
};


static int yacb_listfiles_start_map(void *ctx) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    if(!ctx)
	return 0;

    switch(yactx->state) {
    case LF_BEGIN:
	/* yactx->state = LF_MAIN; */
    case LF_FILES:
	/* yactx->state = LF_FILE; */
    case LF_FILECONTENT:
	/* yactx->state = LF_FILEATTRS; */
	yactx->state++;
	return 1;
    default:
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }
}

static int yacb_listfiles_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    if(!ctx || !l)
	return 0;

    if(yactx->state == LF_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if(yactx->state == LF_MAIN) {
        if(ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = LF_ERROR;
            return 1;
        }
	if(l == lenof("volumeSize") && !memcmp(s, "volumeSize", lenof("volumeSize")))
	    yactx->state = LF_VOLUMESIZE;
        else if(l == lenof("volumeUsedSize") && !memcmp(s, "volumeUsedSize", lenof("volumeUsedSize")))
            yactx->state = LF_VOLUMEUSEDSIZE;
	else if(l == lenof("replicaCount") && !memcmp(s, "replicaCount", lenof("replicaCount")))
	    yactx->state = LF_REPLICACNT;
	else if(l == lenof("fileList") && !memcmp(s, "fileList", lenof("fileList")))
	    yactx->state = LF_FILES;
	else {
	    CBDEBUG("unexpected attribute '%.*s' in LF_MAIN", (unsigned)l, s);
	    return 0;
	}
	return 1;
    }

    if(yactx->state == LF_FILE) {
	yactx->state = LF_FILECONTENT;
	yactx->file.namelen = l;
	yactx->fname = malloc(yactx->file.namelen);
	if(!yactx->fname) {
	    CBDEBUG("OOM duplicating file name '%.*s'", (unsigned)l, s);
	    sxi_cbdata_setsyserr(yactx->cbdata, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->fname, s, yactx->file.namelen);
	yactx->file.revlen = 0;
	yactx->file.created_at = -1;
	yactx->file.filesize = -1;
	yactx->file.blocksize = 0;
	yactx->nfiles++;
	return 1;
    }

    if(yactx->state == LF_FILEATTRS) {
	if(l == lenof("fileSize") && !memcmp(s, "fileSize", lenof("fileSize")))
	    yactx->state = LF_FILESIZE;
	else if(l == lenof("blockSize") && !memcmp(s, "blockSize", lenof("blockSize")))
	    yactx->state = LF_BLOCKSIZE;
	else if(l == lenof("createdAt") && !memcmp(s, "createdAt", lenof("createdAt")))
	    yactx->state = LF_FILETIME;
	else if(l == lenof("fileRevision") && !memcmp(s, "fileRevision", lenof("fileRevision")))
	    yactx->state = LF_FILEREV;
	else {
	    CBDEBUG("unexpected attribute '%.*s' in LF_FILEATTRS", (unsigned)l, s);
	    return 0;
	}
	return 1;
    }

    return 0;
}


static int yacb_listfiles_number(void *ctx, const char *s, size_t l) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    char numb[24], *enumb;
    int64_t nnumb;

    if(!ctx)
	return 0;

    if(l > 20) {
	CBDEBUG("number too long (%u bytes)", (unsigned)l);
	return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    nnumb = strtoll(numb, &enumb, 10);
    if(*enumb || (yactx->state != LF_VOLUMEUSEDSIZE && nnumb < 0)) {
	CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
	return 0;
    }

    switch(yactx->state) {
    case LF_VOLUMESIZE:
	if(yactx->volume_size) {
	    CBDEBUG("volumeSize already received");
	    return 0;
	}
	yactx->volume_size = nnumb;
	yactx->state = LF_MAIN;
	return 1;
    case LF_VOLUMEUSEDSIZE:
        if(yactx->volume_used_size) {
            CBDEBUG("volumeUsedSize already received");
            return 0;
        }
        yactx->volume_used_size = nnumb;
        if(nnumb < 0) {
            CBDEBUG("Current volume size is less than 0: %lld, falling back to 0", (long long)nnumb);
            yactx->volume_used_size = 0;
        }
        yactx->state = LF_MAIN;
        return 1;
    case LF_REPLICACNT:
	if(yactx->replica) {
	    CBDEBUG("replicaCount already received");
	    return 0;
	}
	yactx->replica = nnumb;
	yactx->state = LF_MAIN;
	return 1;
    case LF_FILESIZE:
	if(yactx->file.filesize != -1) {
	    CBDEBUG("size already received");
	    return 0;
	}
	yactx->file.filesize = nnumb;
	break;
    case LF_BLOCKSIZE:
	if(yactx->file.blocksize) {
	    CBDEBUG("blocksize already received");
	    return 0;
	}
	yactx->file.blocksize = nnumb;
	break;
    case LF_FILETIME:
	if(yactx->file.created_at >= 0) {
	    CBDEBUG("createdAt already received");
	    return 0;
	}
	yactx->file.created_at = nnumb;
	break;
    default:
	CBDEBUG("bad state %d", yactx->state);
	return 0;
    }

    yactx->state = LF_FILEATTRS;
    return 1;
}

static int yacb_listfiles_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state == LF_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    if(yactx->state == LF_FILEREV) {
	if(!l)
	    return 0;
	yactx->file.revlen = l;
	yactx->frev = malloc(yactx->file.revlen);
	if(!yactx->frev) {
	    CBDEBUG("OOM duplicating file rev '%.*s'", (unsigned)l, s);
	    sxi_cbdata_setsyserr(yactx->cbdata, SXE_EMEM, "Out of memory");
	    return 0;
	}
	memcpy(yactx->frev, s, yactx->file.revlen);
	yactx->state = LF_FILEATTRS;
	return 1;
    }

    return 0;
}

static int yacb_listfiles_end_map(void *ctx) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    if(!ctx)
	return 0;
    if(yactx->state == LF_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == LF_FILEATTRS) {
	if(!yactx->fname) {
	    CBDEBUG("missing file name");
	    return 0;
	}
	if(!yactx->file.revlen) {
	    if(yactx->fname[yactx->file.namelen-1] != '/') {
		CBDEBUG("bad directory name");
		return 0;
	    }
	    if(yactx->file.filesize >= 0 || yactx->file.blocksize || yactx->file.created_at >= 0) {
		CBDEBUG("bad directory attributes");
		return 0;
	    }
	    yactx->file.filesize = 0;
	    yactx->file.blocksize = 0;
	    yactx->file.created_at = 0;
	} else {
	    if(yactx->file.filesize < 0 || !yactx->file.blocksize || yactx->file.created_at < 0) {
		CBDEBUG("missing file attributes");
		return 0;
	    }
	}
	if(!fwrite(&yactx->file, sizeof(yactx->file), 1, yactx->f) ||
	   !fwrite(yactx->fname, yactx->file.namelen, 1, yactx->f) ||
	   (yactx->file.revlen && !fwrite(yactx->frev, yactx->file.revlen, 1, yactx->f)) ||
	   !fwrite(&yactx->file, sizeof(yactx->file), 1, yactx->f)) {
	    CBDEBUG("failed to save file attributes to temporary file");
	    sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
	    return 0;
	}
	free(yactx->fname);
	yactx->fname = NULL;
	free(yactx->frev);
	yactx->frev = NULL;
	yactx->state = LF_FILE;
	return 1;
    }

    if(yactx->state == LF_FILES) {
	yactx->state = LF_MAIN;
	return 1;
    }

    if(yactx->state == LF_FILE) {
	/* We land here on an empty list */
	yactx->state = LF_MAIN;
	return 1;
    }

    if(yactx->state == LF_MAIN) {
	yactx->state = LF_COMPLETE;
	return 1;
    }

    CBDEBUG("bad state %d", yactx->state);
    return 0;
}


static int listfiles_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("failed to allocate yajl structure");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "List failed: Out of memory");
	return 1;
    }

    yactx->state = LF_BEGIN;
    rewind(yactx->f);
    yactx->volume_size = 0;
    yactx->volume_used_size = 0;
    yactx->replica = 0;
    free(yactx->fname);
    yactx->fname = NULL;
    free(yactx->frev);
    yactx->frev = NULL;
    yactx->file.filesize = -1;
    yactx->file.created_at = -1;
    yactx->file.namelen = 0;
    yactx->file.revlen = 0;
    yactx->file.fuck_off_valgrind = 0;
    yactx->nfiles = 0;

    return 0;
}

static int listfiles_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
	CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
	sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
	return 1;
    }

    return 0;
}


struct _sxc_cluster_lf_t {
    sxc_client_t *sx;
    char *fname;
    FILE *f;
    int want_relative;
    int reverse;
    unsigned pattern_slashes;
    unsigned prefix_len;
};

unsigned sxi_count_slashes(const char *str)
{
    unsigned n = 0;
    char c;
    if (!str)
        return 0;
    do {
        c = *str++;
        if (c == '/')
            n++;
    } while (c);
    return n;
}

/* TODO: share with server? */
char *sxi_ith_slash(char *s, unsigned int i) {
    unsigned found = 0;
    if (!i)
        return s;
    while ((s = strchr(s, '/'))) {
        found++;
        if (found == i)
            return s;
        s++;
    }
    return NULL;
}

sxc_cluster_lf_t *sxi_conns_listfiles(sxi_conns_t *conns, const char *volume, sxi_hostlist_t *volhosts, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *nfiles, int reverse, int sizeOnly) {
    char *enc_vol, *enc_glob = NULL, *url, *fname;
    struct cb_listfiles_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_cluster_lf_t *ret;
    unsigned int len;
    int qret;
    char *cur;
    sxc_client_t *sx = sxi_conns_get_client(conns);
    int qm = 1; /* state if we want to add quotation mark or ampersand */

    sxc_clearerr(sx);

    if(!volume || !volhosts) {
        SXDEBUG("NULL argument");
        return NULL;
    }

    sxi_set_operation(sx, "list files", sxi_conns_get_sslname(conns), volume, NULL);

    if(!(enc_vol = sxi_urlencode(sx, volume, 0))) {
        SXDEBUG("failed to encode volume %s", volume);
        return NULL;
    }

    len = strlen(enc_vol) + 1;
    if(glob_pattern) {
        if(!(enc_glob = sxi_urlencode(sx, glob_pattern, 1))) {
            SXDEBUG("failed to encode pattern %s", glob_pattern);
	    free(enc_vol);
	    return NULL;
	}
	len += lenof("?filter=") + strlen(enc_glob);
    }

    if(recursive)
	len += lenof("&recursive");

    if(sizeOnly)
        len += lenof("&sizeOnly");

    if(!(url = malloc(len))) {
        SXDEBUG("OOM allocating url (%u bytes)", len);
        sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
	free(enc_vol);
	free(enc_glob);
	return NULL;
    }

    sprintf(url, "%s", enc_vol);
    cur = url + strlen(enc_vol);
    if(enc_glob) {
        sprintf(cur, "?filter=%s", enc_glob);
        qm = 0;
        cur += strlen(cur);
    }
    if(recursive) {
        sprintf(cur, "%s", qm ? "?recursive" : "&recursive");
        qm = 0;
        cur += strlen(cur);
    }
    if(sizeOnly) {
        sprintf(cur, "%s", qm ? "?sizeOnly" : "&sizeOnly");
        qm = 0;
        cur += strlen(cur);
    }
    free(enc_vol);
    free(enc_glob);

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
        SXDEBUG("failed to create temporary storage for file list");
	free(url);
	return NULL;
    }

    ya_init(yacb);
    yacb->yajl_start_map = yacb_listfiles_start_map;
    yacb->yajl_map_key = yacb_listfiles_map_key;
    yacb->yajl_number = yacb_listfiles_number;
    yacb->yajl_string = yacb_listfiles_string;
    yacb->yajl_end_map = yacb_listfiles_end_map;

    yctx.yh = NULL;
    yctx.fname = NULL;
    yctx.frev = NULL;

    sxi_set_operation(sx, "list volume files", sxi_conns_get_sslname(conns), volume, NULL);
    qret = sxi_cluster_query(conns, volhosts, REQ_GET, url, NULL, 0, listfiles_setup_cb, listfiles_cb, &yctx);
    free(url);
    free(yctx.fname);
    free(yctx.frev);
    if(qret != 200) {
        SXDEBUG("query returned %d", qret);
	if(yctx.yh)
	    yajl_free(yctx.yh);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != LF_COMPLETE) {
        if (yctx.state != LF_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "List failed: Communication error");
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
       fseek(yctx.f, 0, reverse ? SEEK_END : SEEK_SET)) {
        sxi_seterr(sx, SXE_EWRITE, "List failed: Failed to write temporary data");
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    ret = malloc(sizeof(*ret));
    if(!ret) {
        SXDEBUG("OOM allocating results");
        sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    if(volume_used_size)
        *volume_used_size = yctx.volume_used_size;

    if(volume_size)
	*volume_size = yctx.volume_size;

    if(replica_count)
	*replica_count = yctx.replica;

    if(nfiles)
	*nfiles = yctx.nfiles;

    ret->sx = sx;
    ret->f = yctx.f;
    ret->fname = fname;
    ret->want_relative = glob_pattern && *glob_pattern && glob_pattern[strlen(glob_pattern)-1] == '/';
    ret->pattern_slashes = sxi_count_slashes(glob_pattern);
    ret->reverse = reverse;
    return ret;
}

sxc_cluster_lf_t *sxc_cluster_listfiles(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *nfiles, int reverse) {
    sxi_hostlist_t volhosts;
    sxc_cluster_lf_t *ret;

    sxi_hostlist_init(&volhosts);
    if(sxi_locate_volume(sxi_cluster_get_conns(cluster), volume, &volhosts, NULL, NULL)) {
        CFGDEBUG("Failed to locate volume %s", volume);
        sxi_hostlist_empty(&volhosts);
        return NULL;
    }

    ret = sxi_conns_listfiles(sxi_cluster_get_conns(cluster), volume, &volhosts, glob_pattern, recursive, volume_used_size, volume_size, replica_count, nfiles, reverse, 0);
    sxi_hostlist_empty(&volhosts);
    return ret;
}

int sxc_cluster_listfiles_prev(sxc_cluster_lf_t *lf, char **file_name, int64_t *file_size, time_t *file_created_at, char **file_revision) {
    struct cbl_file_t file;
    long pos;
    sxc_client_t *sx = lf->sx;

    pos = ftell(lf->f);
    if(pos < 0) {
	SXDEBUG("error getting the current position in the result file");
	sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
	return -1;
    }
    if((size_t) pos < sizeof(file) * 2)
	return 0;
    fseek(lf->f, pos-sizeof(file), SEEK_SET);

    if(!fread(&file, sizeof(file), 1, lf->f)) {
	SXDEBUG("error reading attributes from results file");
	sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
	return -1;
    }
    if((file.namelen | file.revlen) & 0x80000000) {
	SXDEBUG("Invalid data length from cache file");
	sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Bad data from cache file");
	return -1;
    }
    if((size_t) pos < sizeof(file) * 2 + file.namelen + file.revlen)
	return 0;

    if(file_name) {
	fseek(lf->f, pos - file.namelen - file.revlen - sizeof(file), SEEK_SET);
	*file_name = malloc(file.namelen + 1);
	if(!*file_name) {
	    SXDEBUG("OOM allocating result file name (%u bytes)", file.namelen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
	    return -1;
	}
	if(!fread(*file_name, file.namelen, 1, lf->f)) {
	    SXDEBUG("error reading name from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
	    return -1;
	}
	(*file_name)[file.namelen] = '\0';
    }

    if(file_revision) {
	fseek(lf->f, pos - file.revlen - sizeof(file), SEEK_SET);
	*file_revision = malloc(file.revlen + 1);
	if(!*file_revision) {
	    SXDEBUG("OOM allocating result file rev (%u bytes)", file.revlen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
	    return -1;
	}
	if(!fread(*file_revision, file.revlen, 1, lf->f)) {
	    SXDEBUG("error reading revision name from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
	    return -1;
	}
	(*file_revision)[file.revlen] = '\0';
    }

    fseek(lf->f, pos - file.namelen - file.revlen - sizeof(file)*2, SEEK_SET);

    if(file_size)
	*file_size = file.filesize;

    if(file_created_at)
	*file_created_at = file.created_at;

    return 1;
}

int sxc_cluster_listfiles_next(sxc_cluster_lf_t *lf, char **file_name, int64_t *file_size, time_t *file_created_at, char **file_revision) {
    struct cbl_file_t file;
    sxc_client_t *sx = lf->sx;
    int ret = -1;

    if(file_name)
	*file_name = NULL;
    if(file_revision)
	*file_revision = NULL;

    if(lf->reverse) {
	ret = sxc_cluster_listfiles_prev(lf, file_name, file_size, file_created_at, file_revision);
	goto lfnext_out;
    }

    if(!fread(&file, sizeof(file), 1, lf->f)) {
	if(ferror(lf->f)) {
	    SXDEBUG("error reading attributes from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
	} else
	    ret = 0;
	goto lfnext_out;
    }
    if((file.namelen | file.revlen) & 0x80000000) {
	SXDEBUG("Invalid data length from cache file");
	sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Bad data from cache file");
	goto lfnext_out;
    }

    if(file_name) {
	*file_name = malloc(file.namelen + 1);
	if(!*file_name) {
	    SXDEBUG("OOM allocating result file name (%u bytes)", file.namelen);
	    sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
	    goto lfnext_out;
	}
	if(!fread(*file_name, file.namelen, 1, lf->f)) {
	    SXDEBUG("error reading name from results file");
	    sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
	    goto lfnext_out;
	}
	(*file_name)[file.namelen] = '\0';
	file.namelen = 0;
    }

    if(file_revision) {
	if(file.revlen) {
	    fseek(lf->f, file.namelen, SEEK_CUR);
	    *file_revision = malloc(file.revlen + 1);
	    if(!*file_revision) {
		SXDEBUG("OOM allocating result file revision (%u bytes)", file.revlen);
		sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
		goto lfnext_out;
	    }
	    if(!fread(*file_revision, file.revlen, 1, lf->f)) {
		SXDEBUG("error reading revision from results file");
		sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
		goto lfnext_out;
	    }
	    (*file_revision)[file.revlen] = '\0';
	    file.revlen = 0;
	}
    }

    fseek(lf->f, file.namelen + file.revlen + sizeof(file), SEEK_CUR);

    if(file_size)
	*file_size = file.filesize;

    if(file_created_at)
	*file_created_at = file.created_at;

    ret = 1;

 lfnext_out:
    if(ret != 1) {
	if(file_name) {
	    free(*file_name);
	    *file_name = NULL;
	}
	if(file_revision) {
	    free(*file_revision);
	    *file_revision = NULL;
	}
    }

    return ret;
}

void sxc_cluster_listfiles_free(sxc_cluster_lf_t *lf) {
    if (!lf)
        return;
    if(lf->f)
	fclose(lf->f);
    if(lf->fname) {
	unlink(lf->fname);
	free(lf->fname);
    }
    free(lf);
}

int sxi_cluster_hashcalc(const sxc_cluster_t *cluster, const void *buffer, unsigned int len, char *hash) {
    return sxi_conns_hashcalc(cluster->conns, buffer, len, hash);
}

sxc_cluster_t *sxc_cluster_load_and_update(sxc_client_t *sx, const char *cluster_name, const char *profile_name) {
    sxi_hostlist_t oldlist;
    int need_save = 0, n1, n2;
    sxc_cluster_t *ret = sxc_cluster_load(sx, sxc_get_confdir(sx), cluster_name);
    if(!ret)
	return NULL;

    sxi_hostlist_init(&oldlist);
    if(sxc_cluster_set_access(ret, profile_name))
	goto load_and_update_err;

    sxi_hostlist_add_list(sx, &oldlist, sxi_conns_get_hostlist(ret->conns));
    if(sxc_cluster_fetchnodes(ret))
        goto load_and_update_err;
    n1 = sxi_hostlist_get_count(&oldlist);
    n2 = sxi_hostlist_get_count(sxi_conns_get_hostlist(ret->conns));

    if (n1 == n2) {
        int i;
        sxi_hostlist_t *newlist = sxi_conns_get_hostlist(ret->conns);
        for (i=0;i<n1;i++)
            if (!sxi_hostlist_contains(&oldlist,
                                       sxi_hostlist_get_host(newlist, i))) {
                need_save = 1;
                break;
            }
    } else
        need_save = 1;
    sxi_hostlist_empty(&oldlist);

    if (!need_save)
	    SXDEBUG("Skipping cluster save, nodelist wasn't changed");
    if(need_save && sxc_cluster_save(ret, sxc_get_confdir(sx)))
	goto load_and_update_err;

    return ret;

 load_and_update_err:
    sxi_hostlist_empty(&oldlist);
    sxc_cluster_free(ret);
    return NULL;
}

const char *sxi_cluster_get_confdir(const sxc_cluster_t *cluster) {
    return cluster ? cluster->config_dir : NULL;
}

char *sxc_user_add(sxc_cluster_t *cluster, const char *username, int admin, const char *oldtoken)
{
    uint8_t buf[AUTH_UID_LEN + AUTH_KEY_LEN + 2], *uid = buf, *key = &buf[AUTH_UID_LEN];
    char *tok, *retkey = NULL;
    sxc_client_t *sx;
    sxi_query_t *proto;
    sxi_md_ctx *ch_ctx;
    int l, qret;

    if(!cluster)
	return NULL;
    if(!username) {
        cluster_err(SXE_EARG, "Null args");
        return NULL;
    }
    sx = sxi_cluster_get_client(cluster);

    /* UID part - unsalted username hash */
    l = strlen(username);
    ch_ctx = sxi_md_init();
    if (!ch_ctx)
        return NULL;
    if(!sxi_sha1_init(ch_ctx)) {
	cluster_err(SXE_ECRYPT, "Cannot compute hash: Unable to initialize crypto library");
	return NULL;
    }
    if(!sxi_sha1_update(ch_ctx, username, l) || !sxi_sha1_final(ch_ctx, uid, NULL)) {
	cluster_err(SXE_ECRYPT, "Cannot compute hash: Crypto library failure");
        sxi_md_cleanup(&ch_ctx);
	return NULL;
    }
    sxi_md_cleanup(&ch_ctx);

    if (oldtoken) {
        char old[AUTHTOK_BIN_LEN];
        unsigned l = sizeof(old);
        if (sxi_b64_dec(sx, oldtoken, old, &l))
            return NULL;
        if (l != sizeof(old)) {
            cluster_err(SXE_EARG, "Bad length for old authentication token");
            return NULL;
        }
        memcpy(key, &old[AUTH_UID_LEN], AUTH_KEY_LEN);
    } else {
        /* KEY part - really random bytes */
        if (sxi_rand_bytes(key, AUTH_KEY_LEN) != 1) {
            cluster_err(SXE_ECRYPT, "Unable to produce a random key");
            return NULL;
        }
    }

    /* Encode token */
    buf[sizeof(buf) - 2] = 0; /* First reserved byte */
    buf[sizeof(buf) - 1] = 0; /* Second reserved byte */
    tok = sxi_b64_enc(sx, buf, sizeof(buf));
    if(!tok)
	return NULL;
    if(strlen(tok) != AUTHTOK_ASCII_LEN) {
	/* Always false but it doensn't hurt to be extra careful */
	free(tok);
	cluster_err(SXE_ECOMM, "The generated auth token has invalid size");
	return NULL;
    }

    if (oldtoken && strcmp(tok, oldtoken)) {
        free(tok);
        cluster_err(SXE_EARG, "The provided old authentication token and username don't match");
        return NULL;
    }

    /* Query */
    proto = sxi_useradd_proto(sx, username, key, admin);
    if(!proto) {
	cluster_err(SXE_EMEM, "Unable to allocate space for request data");
	free(tok);
	return NULL;
    }
    sxi_set_operation(sxi_cluster_get_client(cluster), "create user", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, proto->verb, proto->path, proto->content, proto->content_len);
    if(!qret) {
	retkey = malloc(AUTHTOK_ASCII_LEN + 1);
	if(!retkey) {
	    cluster_err(SXE_EMEM, "Unable to allocate memory for user key");
	} else {
	    sxi_strlcpy(retkey, tok, AUTHTOK_ASCII_LEN+1);
        }
    }
    sxi_query_free(proto);
    free(tok);
    return retkey;
}

char *sxc_user_newkey(sxc_cluster_t *cluster, const char *username, const char *oldtoken)
{
    uint8_t buf[AUTH_UID_LEN + AUTH_KEY_LEN + 2], *uid = buf, *key = &buf[AUTH_UID_LEN];
    char *tok, *retkey = NULL;
    sxc_client_t *sx;
    sxi_query_t *proto;
    sxi_md_ctx *ch_ctx;
    int l, qret;
    long http_err;

    if(!cluster)
	return NULL;
    if(!username) {
        cluster_err(SXE_EARG, "Null args");
        return NULL;
    }
    sx = sxi_cluster_get_client(cluster);

    /* UID part - unsalted username hash */
    l = strlen(username);
    ch_ctx = sxi_md_init();
    if (!ch_ctx)
        return NULL;
    if(!sxi_sha1_init(ch_ctx)) {
	cluster_err(SXE_ECRYPT, "Cannot compute hash: Unable to initialize crypto library");
	return NULL;
    }
    if(!sxi_sha1_update(ch_ctx, username, l) || !sxi_sha1_final(ch_ctx, uid, NULL)) {
	cluster_err(SXE_ECRYPT, "Cannot compute hash: Crypto library failure");
        sxi_md_cleanup(&ch_ctx);
	return NULL;
    }
    sxi_md_cleanup(&ch_ctx);

    if (oldtoken) {
        char old[AUTHTOK_BIN_LEN];
        unsigned l = sizeof(old);
        if (sxi_b64_dec(sx, oldtoken, old, &l))
            return NULL;
        if (l != sizeof(old)) {
            cluster_err(SXE_EARG, "Bad length for old authentication token");
            return NULL;
        }
        memcpy(key, &old[AUTH_UID_LEN], AUTH_KEY_LEN);
    } else {
        /* KEY part - really random bytes */
        if (sxi_rand_bytes(key, AUTH_KEY_LEN) != 1) {
            cluster_err(SXE_ECRYPT, "Unable to produce a random key");
            return NULL;
        }
    }

    /* Encode token */
    buf[sizeof(buf) - 2] = 0; /* First reserved byte */
    buf[sizeof(buf) - 1] = 0; /* Second reserved byte */
    tok = sxi_b64_enc(sx, buf, sizeof(buf));
    if(!tok)
	return NULL;
    if(strlen(tok) != AUTHTOK_ASCII_LEN) {
	/* Always false but it doensn't hurt to be extra careful */
	free(tok);
	cluster_err(SXE_ECOMM, "The generated auth token has invalid size");
	return NULL;
    }

    if (oldtoken && strcmp(tok, oldtoken)) {
        free(tok);
        cluster_err(SXE_EARG, "The provided old authentication token and username don't match");
        return NULL;
    }

    /* Query */
    proto = sxi_usernewkey_proto(sx, username, key);
    if(!proto) {
	cluster_err(SXE_EMEM, "Unable to allocate space for request data");
	free(tok);
	return NULL;
    }
    sxi_set_operation(sxi_cluster_get_client(cluster), "change user key", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_job_submit_and_poll_err(sxi_cluster_get_conns(cluster), NULL, proto->verb, proto->path, proto->content, proto->content_len, &http_err);
    if(!qret || http_err == 401) {
	retkey = malloc(AUTHTOK_ASCII_LEN + 1);
	if(!retkey) {
	    cluster_err(SXE_EMEM, "Unable to allocate memory for user key");
	} else {
	    sxi_strlcpy(retkey, tok, AUTHTOK_ASCII_LEN + 1);
        }
    }
    sxi_query_free(proto);
    free(tok);
    return retkey;
}

int sxc_user_remove(sxc_cluster_t *cluster, const char *username) {
    char *enc_name, *query;
    sxc_client_t *sx;
    int ret;

    if(!cluster)
	return 1;
    if(!username || !*username) {
        cluster_err(SXE_EARG, "Null args");
        return 1;
    }
    sx = sxi_cluster_get_client(cluster);

    enc_name = sxi_urlencode(sx, username, 0);
    if(!enc_name) {
	cluster_err(SXE_EMEM, "Failed to encode username");
	return 1;
    }

    query = malloc(lenof(".users/") + strlen(enc_name) + 1);
    if(!query) {
	free(enc_name);
	cluster_err(SXE_EMEM, "Unable to allocate space for request data");
	return 1;
    }
    sprintf(query, ".users/%s", enc_name);
    free(enc_name);

    sxi_set_operation(sx, "remove user", sxi_cluster_get_name(cluster), NULL, NULL);
    ret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, REQ_DELETE, query, NULL, 0);

    free(query);
    return ret;
}

struct cb_userkey_ctx {
    enum userkey_state { USERKEY_ERROR, USERKEY_BEGIN, USERKEY_MAP, USERKEY_KEY, USERKEY_COMPLETE } state;
    struct cb_error_ctx errctx;
    yajl_callbacks yacb;
    curlev_context_t *cbdata;
    yajl_handle yh;
    const char *username;
    FILE *f;
};

static int userkey_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host)
{
    struct cb_userkey_ctx *yactx = ctx;
    if (yactx->yh)
        yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh = yajl_alloc(&yactx->yacb, NULL, yactx))) {
        CBDEBUG("OOM allocating yajl context");
        sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot get user key: Out of memory");
        return 1;
    }

    yactx->state = USERKEY_BEGIN;
    return 0;
}

static int userkey_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_userkey_ctx *yactx = ctx;
    if (yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != USERKEY_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
        return 1;
    }
    return 0;
}

static int yacb_userkey_start_map(void *ctx) {
    struct cb_userkey_ctx *yactx = ctx;
    if(!ctx)
	return 0;

    if(yactx->state == USERKEY_BEGIN) {
	yactx->state = USERKEY_MAP;
    } else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, USERKEY_BEGIN);
	return 0;
    }
    return 1;
}

static int yacb_userkey_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_userkey_ctx *yactx = ctx;
    if(!ctx)
	return 0;

    if (yactx->state == USERKEY_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == USERKEY_MAP) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = USERKEY_ERROR;
            return 1;
        }
    }
    if(yactx->state == USERKEY_MAP) {
	if(l == lenof("userKey") && !memcmp(s, "userKey", lenof("userKey"))) {
	    yactx->state = USERKEY_KEY;
	    return 1;
	}
	return 1;
    }

    CBDEBUG("bad state (in %d, expected %d)", yactx->state, USERKEY_KEY);
    return 0;
}

static int yacb_userkey_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_userkey_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if (yactx->state == USERKEY_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);

    if(l<=0)
	return 0;
    if (yactx->state == USERKEY_MAP)
        return 1;
    if (yactx->state == USERKEY_KEY) {
        unsigned char token[AUTHTOK_BIN_LEN];
        sxi_md_ctx *ch_ctx;
        sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));

        memset(token, 0, sizeof(token));
	if(sxi_hex2bin((const char *)s, l, token + AUTH_UID_LEN, AUTH_KEY_LEN)) {
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "Failed to convert user key from hex");
            return 0;
        }

        ch_ctx = sxi_md_init();
        if(!sxi_sha1_init(ch_ctx)) {
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECRYPT, "Cannot compute hash: Unable to initialize crypto library");
            sxi_md_cleanup(&ch_ctx);
            return 1;
        }
        if(!sxi_sha1_update(ch_ctx, yactx->username, strlen(yactx->username)) ||
           !sxi_sha1_final(ch_ctx, token, NULL)) {
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECRYPT, "Cannot compute hash: Crypto library failure");
            sxi_md_cleanup(&ch_ctx);
            return 1;
        }
        sxi_md_cleanup(&ch_ctx);
        char *tok = sxi_b64_enc(sx, token, sizeof(token));

        /* FIXME: Do not store errors in global buffer (bb#751) */
        sxi_cbdata_restore_global_error(sx, yactx->cbdata);

        fprintf(yactx->f, "%s\n", tok);
        free(tok);
        yactx->state = USERKEY_MAP;
        return 1;
    }
    return 0;
}

static int yacb_userkey_end_map(void *ctx) {
    struct cb_userkey_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if (yactx->state == USERKEY_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == USERKEY_MAP)
	yactx->state = USERKEY_COMPLETE;
    else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, FN_CLUSTER);
	return 0;
    }
    return 1;
}

int sxc_user_getkey(sxc_cluster_t *cluster, const char *username, FILE *storeauth)
{
    sxc_client_t *sx;
    struct cb_userkey_ctx yctx;
    yajl_callbacks *yacb;
    int ret = 1;
    unsigned n;
    char *url = NULL;

    if(!cluster)
	return 1;
    if(!username || !storeauth) {
        cluster_err(SXE_EARG, "Null args");
        return 1;
    }
    memset(&yctx, 0, sizeof(yctx));
    yacb = &yctx.yacb;
    ya_init(yacb);
    yacb->yajl_start_map = yacb_userkey_start_map;
    yacb->yajl_map_key = yacb_userkey_map_key;
    yacb->yajl_string = yacb_userkey_string;
    yacb->yajl_end_map = yacb_userkey_end_map;
    yctx.yh = NULL;
    yctx.f = storeauth;
    yctx.username = username;

    sx = sxi_cluster_get_client(cluster);

    /* Query */
    n = strlen(username) + sizeof(".users/");
    url = malloc(n);
    if (!url) {
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto done;
    }
    snprintf(url, n, ".users/%s", username);

    sxi_set_operation(sxi_cluster_get_client(cluster), "get user's key", sxi_cluster_get_name(cluster), NULL, NULL);
    if (sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, url, NULL, 0,
                          userkey_setup_cb, userkey_cb, &yctx) != 200)
        goto done;
    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != USERKEY_COMPLETE) {
        if (yctx.state != USERKEY_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Cannot get user key: Communication error");
        }
        goto done;
    }
    ret = 0;

done:
    free(url);
    if(yctx.yh)
	yajl_free(yctx.yh);
    return ret;
}

void sxi_report_configuration(sxc_client_t *sx, const char *configdir)
{
    DIR *d;
    struct dirent *dentry;
    char *dir;
    sxi_report_section(sx, "Client configuration");

    if (configdir) {
        dir = get_confdir(sx, NULL, ".");
        if (dir) {
            sxi_info(sx, "Default configuration directory: %s", dir);
            free(dir);
        }
    }

    dir = get_confdir(sx, configdir, ".");
    if (!dir) {
        sxi_seterr(sx, SXE_ECFG, "Cannot determine configuration directory");
        return;
    }
    sxi_info(sx, "Current configuration directory: %s", dir);
    d = opendir(dir);
    if (!d) {
        sxi_setsyserr(sx, SXE_ECFG, "Cannot open configuration directory '%s'", dir);
        free(dir);
        return;
    }
    while ((dentry = readdir(d))) {
        sxc_cluster_t *cluster;
        const sxi_hostlist_t *hlist;
        if (!strcmp(dentry->d_name, ".") || !strcmp(dentry->d_name, ".."))
            continue;
        sxi_info(sx, "Client configuration");
        cluster = sxc_cluster_load(sx, dir, dentry->d_name);
        if (cluster) {
            sxi_info(sx, "\tValid: %s", sxi_is_valid_cluster(cluster) ? "Yes" : "No");
            sxi_info(sx, "\tServer UUID: %s", sxc_cluster_get_uuid(cluster));
            hlist = sxi_conns_get_hostlist(cluster->conns);
            sxi_info(sx, "\tHost count: %d", hlist ? sxi_hostlist_get_count(hlist) : 0);
            if (cluster->cafile) {
                sxi_vcrypt_print_cert_info(sx, cluster->cafile, 0);
            }
            sxc_cluster_free(cluster);
        }
        sxi_list(sx, dir, dentry->d_name, 0);
    }
    closedir(d);
    free(dir);
}

/* FIXME: interactive stuff doesn't belong in a lib! */
int sxc_cluster_fetch_ca(sxc_cluster_t *cluster, int quiet)
{
    const char *tmpcafile = NULL;
    FILE *f;
    tmpcafile = sxi_tempfile_track(cluster->sx, NULL, &f);
    if(!tmpcafile)
	return 1;
    fclose(f);
    /* ask the SSL cert question only once,
     * for consistency we do the request on non-SSL too. */
    sxi_set_operation(sxi_cluster_get_client(cluster), "fetch certificate", sxi_cluster_get_name(cluster), NULL, NULL);
    if (sxi_conns_root_noauth(sxi_cluster_get_conns(cluster), tmpcafile, quiet))
        return 1;
    /* TODO: also check whether the root CA changed ..., and whether server cert
     * changed especially if we're not trusted */
    if (tmpcafile && sxc_cluster_set_cafile(cluster, tmpcafile))
        return 1;
    return 0;
}

int sxc_cluster_trigger_gc(sxc_cluster_t *cluster, int delete_reservations)
{
    const sxi_hostlist_t *all;
    unsigned i, failed = 0;
    sxc_client_t *sx;

    if (!cluster)
        return 1;
    sx = sxi_cluster_get_client(cluster);
    all = sxi_conns_get_hostlist(cluster->conns);
    for (i=0;i<sxi_hostlist_get_count(all);i++) {
        const char *host = sxi_hostlist_get_host(all, i);
        sxi_hostlist_t hlist;
        sxi_hostlist_init(&hlist);
        if (sxi_hostlist_add_host(sx, &hlist, host)) {
            sxi_hostlist_empty(&hlist);
            return 1;
        }
        sxc_clearerr(sx);
        if (sxi_cluster_query(cluster->conns, &hlist, delete_reservations ? REQ_DELETE : REQ_PUT, ".gc", "", 0, NULL, NULL, NULL) != 200) {
            sxi_notice(sx, "Failed to trigger GC on %s: %s", host, sxc_geterrmsg(sx));
            failed++;
        }
        sxi_hostlist_empty(&hlist);
    }
    return failed;
}

int sxc_cluster_disable_proxy(sxc_cluster_t *cluster)
{
    if (!cluster)
        return -1;
    return sxi_conns_disable_proxy(cluster->conns);
}

int sxc_cluster_set_httpport(sxc_cluster_t *cluster, unsigned int port) {
    if(!cluster)
	return -1;
    return sxi_conns_set_port(cluster->conns, port);
}

unsigned int sxc_cluster_get_httpport(const sxc_cluster_t *cluster) {
    if(!cluster)
	return -1;
    return sxi_conns_get_port(cluster->conns);
}

int sxc_cluster_set_progress_cb(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_xfer_callback cb, void *ctx) {
    sxi_conns_t *conns;

    if(!cluster || !cb) {
        SXDEBUG("NULL argument");        
        sxi_seterr(sx, SXE_EARG, "NULL argument: %s", cluster != NULL ? "cb" : "cluster");
        return 1;
    }

    conns = sxi_cluster_get_conns(cluster);
    if(!conns) {
        SXDEBUG("Could not get cluster conns reference");
        sxi_seterr(sx, SXE_EARG, "Could not get cluster conns reference");
        return 1;
    }

    /* Initialize new transfer stats if not initialized yet */
    if(!sxi_conns_get_xfer_stat(conns)) {
        sxc_xfer_stat_t *xfer_stat = sxi_xfer_new(sx, cb, ctx);
        if(!xfer_stat) {
            SXDEBUG("Could not allocate memory");
            sxi_seterr(sx, SXE_EMEM, "Could not allocate memory");
            return 1;
        }

        return sxi_conns_set_xfer_stat(conns, xfer_stat);
    }

    return 0;
}

sxc_xfer_stat_t *sxi_cluster_get_xfer_stat(sxc_cluster_t* cluster) {
    return sxi_conns_get_xfer_stat(sxi_cluster_get_conns(cluster));
}

int sxc_cluster_set_conns_limit(sxc_cluster_t *cluster, unsigned int max_active, unsigned int max_active_per_host) {
    if(!cluster)
        return 1;

    return sxi_conns_set_connections_limit(cluster->conns, max_active, max_active_per_host);
}
