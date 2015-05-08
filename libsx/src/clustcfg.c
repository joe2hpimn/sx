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
#include <fcntl.h>

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
#include <sys/mman.h>

#define BCRYPT_TOKEN_ITERATIONS_LOG2 12

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

int sxi_conns_resolve_hostlist(sxi_conns_t *conns) {
    struct addrinfo *res, *ungai;
    sxc_client_t *sx;
    sxi_hostlist_t dns_nodes;
    int rc;
    const char *dnsname;

    if(!conns)
        return 1;
    sx = sxi_conns_get_client(conns);
    dnsname = sxi_conns_get_dnsname(conns);
    if((rc = getaddrinfo(dnsname, NULL, NULL, &res)))
        return 0;

    SXDEBUG("Resolving host name: %s", dnsname);
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
        SXDEBUG("Adding DNS-resolved host '%s'", buf);
        if(sxi_hostlist_add_host(sx, &dns_nodes, buf))
            continue; /* FIXME: !? */
    }
    freeaddrinfo(ungai);
    rc = sxi_hostlist_add_list(sx, sxi_conns_get_hostlist(conns), &dns_nodes);
    sxi_hostlist_empty(&dns_nodes);
    return rc;
}

int sxc_cluster_set_dnsname(sxc_cluster_t *cluster, const char *dnsname) {
    if (!cluster || sxi_conns_set_dnsname(cluster->conns, dnsname))
        return 1;
    if (!dnsname)
        return 0;
    return sxi_conns_resolve_hostlist(cluster->conns);
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
            double ul_speed = 0.0, dl_speed = 0.0;
            FILE *nodef;
            char *node_fname;
            unsigned int node_fname_len;

	    if(dent->d_name[0] == '.' && (dent->d_name[1] == '\0' || (dent->d_name[1] == '.' && dent->d_name[2] == '\0')))
		continue;
            if(sxc_cluster_add_host(cluster, dent->d_name)) {
                SXDEBUG("failed to add node %s", dent->d_name);
                err = 1;
                break;
            }
            node_fname_len = confdir_len + strlen("/nodes") + strlen(dent->d_name) + 2;
            node_fname = malloc(node_fname_len);
            if(!node_fname) {
                SXDEBUG("OOM allocating node file path");
                sxi_seterr(sx, SXE_EMEM, "Cannot load cluster config: Out of memory");
                err = 1;
                break;
            }
            snprintf(node_fname, node_fname_len, "%s/%s", fname, dent->d_name);
            if(!(nodef = fopen(node_fname, "r"))) {
                SXDEBUG("Failed to open node file %s for reading", node_fname);
                sxi_setsyserr(sx, SXE_ECFG, "Cannot load cluster config: Cannot open node file %s", dent->d_name);
                err = 1;
                free(node_fname);
                break;
            }
            if(fscanf(nodef, "UploadSpeed=%lf\nDownloadSpeed=%lf\n", &ul_speed, &dl_speed) != 2)
                SXDEBUG("Nodes speeds are not present, use 0.0");
            else {
                if(sxi_set_host_speed_stats(cluster->conns, dent->d_name, ul_speed, dl_speed)) {
                    SXDEBUG("Failed to set host %s speed", dent->d_name);
                    err = 1;
                    if(fclose(nodef))
                        SXDEBUG("Failed to close node file %s", node_fname);
                    free(node_fname);
                    break;
                }
            }
            if(fclose(nodef)) {
                SXDEBUG("Failed to close node file %s", node_fname);
                err = 1;
                free(node_fname);
                break;
            }
            free(node_fname);
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

/* Print basic cluster information */
int sxc_cluster_info(sxc_cluster_t *cluster, const char *profile, const char *host) {
    sxc_client_t *sx;
    const char *dnsname;
    int port, secure;
    sxi_hostlist_t *hlist;
    struct sxi_access *access;
    char *config_link;

    if(!cluster)
        return 1;
    sx = sxi_cluster_get_client(cluster);
    if(!host) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    access = sxc_cluster_get_access(cluster, profile);
    if(!access || !access->auth) {
        sxi_seterr(sx, SXE_ECFG, "Failed to get user access");
        return 1;
    }

    dnsname = sxc_cluster_get_dnsname(cluster);
    port = sxc_cluster_get_httpport(cluster);
    secure = sxi_conns_is_secure(sxi_cluster_get_conns(cluster));
    if(!port) {
        /* Handle default ports */
        if(secure)
           port = 443;
        else
           port = 80;
    }

    printf("Cluster name: %s\n", sxc_cluster_get_sslname(cluster));
    if(dnsname && strcmp(dnsname, host))
        printf("Cluster DNS name: %s\n", dnsname);
    printf("Cluster UUID: %s\n", sxc_cluster_get_uuid(cluster));

    hlist = sxi_conns_get_hostlist(sxi_cluster_get_conns(cluster));
    if(hlist) {
        unsigned int i;

        printf("Nodes: ");
        for(i = 0; i < sxi_hostlist_get_count(hlist); i++)
            printf("%s%s", i ? ", " : "", sxi_hostlist_get_host(hlist, i));
        printf("\n");
    }

    printf("Port: %d\n", port);
    printf("Use SSL: %s\n", secure ? "yes" : "no");
    if(secure && cluster->cafile)
        printf("CA file: %s\n", cluster->cafile);

    printf("Current profile: %s\n", profile ? profile : "default");
    printf("Configuration directory: %s\n", cluster->config_dir);
    printf("libsx version: %s\n", sxc_get_version());

    config_link = sxc_cluster_configuration_link(cluster, profile, access->auth);
    if(!config_link)
        return 1;
    printf("Configuration link: %s\n", config_link);

    free(config_link);
    return 0;
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

    yactx->cbdata = cbdata; /* must set before using CBDEBUG */
    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
	CBDEBUG("OOM allocating yajl context");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    yactx->state = FN_BEGIN;
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

    if(sxi_getenv("SX_DEBUG_SINGLEHOST")) {
	sxi_hostlist_empty(orighlist);
	if(sxi_hostlist_add_host(sx, orighlist, sxi_getenv("SX_DEBUG_SINGLEHOST"))) {
	    if(sxc_geterrnum(sx) == SXE_EARG) {
		sxc_clearerr(sx);
		sxi_seterr(sx, SXE_EARG, "Invalid value of SX_DEBUG_SINGLEHOST");
	    }
	    return 1;
	}
    }

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
    char *role;
    yajl_handle yh;
    enum whoami_state { FW_ERROR, FW_BEGIN, FW_CLUSTER, FW_WHOAMI, FW_ROLE, FW_COMPLETE } state;
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
        if(l == lenof("role") && !memcmp(s, "role", lenof("role"))) {
            yactx->state = FW_ROLE;
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

    if(yactx->state == FW_WHOAMI) {
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
    } else if(yactx->state == FW_ROLE) {
        if(l<=0)
            return 0;

        if(!(yactx->role = malloc(l+1))) {
            CBDEBUG("OOM duplicating user role '%.*s'", (unsigned)l, s);
            sxi_cbdata_seterr(yactx->cbdata, SXE_EMEM, "Out of memory");
            return 0;
        }

        memcpy(yactx->role, s, l);
        yactx->role[l] = '\0';
        yactx->state = FW_CLUSTER;
    }
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
    yactx->role = NULL;

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

int sxc_cluster_whoami(sxc_cluster_t *cluster, char **user, char **role) {
    struct cb_whoami_ctx yctx;
    yajl_callbacks *yacb = &yctx.yacb;
    sxc_client_t *sx = cluster->sx;
    int ret = -1;

    if(!user) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return ret;
    }

    ya_init(yacb);
    yacb->yajl_start_map = yacb_whoami_start_map;
    yacb->yajl_map_key = yacb_whoami_map_key;
    yacb->yajl_string = yacb_whoami_string;
    yacb->yajl_end_map = yacb_whoami_end_map;
    yctx.yh = NULL;

    sxi_set_operation(sxi_cluster_get_client(cluster), "whoami", sxi_cluster_get_name(cluster), NULL, NULL);
    if(sxi_cluster_query(cluster->conns, NULL, REQ_GET, role ? "?whoami&role" : "?whoami", NULL, 0, whoami_setup_cb, whoami_cb, &yctx) != 200) {
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

    if(!*yctx.whoami) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to get username");
        goto config_whoami_error;
    }

    if(role && (!yctx.role || !*yctx.role)) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to get user role");
        goto config_whoami_error;
    }

    if(role)
        SXDEBUG("whoami: %s (%s)", yctx.whoami, yctx.role);
    else
        SXDEBUG("whoami: %s", yctx.whoami);

    *user = yctx.whoami;
    if(role)
        *role = yctx.role;
    ret = 0;
 config_whoami_error:
    if(yctx.yh)
	yajl_free(yctx.yh);
    if (ret) {
        free(yctx.whoami);
        free(yctx.role);
        *user = NULL;
        if(role)
            *role = NULL;
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
        double ul_speed = 0.0, dl_speed = 0.0;

	if(!touchme) {
	    CFGDEBUG("OOM allocating host file for %s", host);
	    cluster_err(SXE_EMEM, "Cannot save config: Out of memory");
	    free(clusterd);
	    return 1;
	}
	sprintf(touchme, "%s/%s", clusterd, host);
	f = fopen(touchme, "w");
	if(!f) {
	    CFGDEBUG("failed to open host file %s", touchme);
	    cluster_syserr(SXE_EWRITE, "Cannot save config: Failed to touch file %s", touchme);
	    free(clusterd);
	    free(touchme);
	    return 1;
	}

        if(sxi_get_host_speed_stats(cluster->conns, host, &ul_speed, &dl_speed)) {
            CFGDEBUG("Failed to get host %s speed: %s", host, sxc_geterrmsg(cluster->sx));
            ul_speed = 0.0;
            dl_speed = 0.0;
        }

        fprintf(f, "UploadSpeed=%.2lf\nDownloadSpeed=%.2lf\n", ul_speed, dl_speed);
        if(fclose(f)) {
            CFGDEBUG("Failed to close host file %s", touchme);
            cluster_syserr(SXE_EWRITE, "Cannot save config: Failed to close host file %s", touchme);
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
    const char *etag_in;
    char *etag_out;
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

    sxi_cbdata_set_etag(cbdata, yactx->etag_in, yactx->etag_in ? strlen(yactx->etag_in) : 0);
    if(yactx->yh)
	yajl_free(yactx->yh);
    yactx->cbdata = cbdata;
    CBDEBUG("ETag: %s", yactx->etag_in ? yactx->etag_in : "");
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
    if (!yactx->etag_out)
        yactx->etag_out = sxi_cbdata_get_etag(cbdata);

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

static sxc_cluster_lf_t *sxi_conns_listfiles(sxi_conns_t *conns, const char *volume, sxi_hostlist_t *volhosts, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *nfiles, int reverse, int sizeOnly, const char *etag_in, char **etag_out) {
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
    yctx.etag_in = etag_in;
    if (etag_out) *etag_out = NULL;

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
    yctx.etag_out = NULL;

    sxi_set_operation(sx, "list volume files", sxi_conns_get_sslname(conns), volume, NULL);
    qret = sxi_cluster_query(conns, volhosts, REQ_GET, url, NULL, 0, listfiles_setup_cb, listfiles_cb, &yctx);
    free(url);
    free(yctx.fname);
    free(yctx.frev);
    if(qret != 200) {
        SXDEBUG("query returned %d", qret);
	if(yctx.yh)
	    yajl_free(yctx.yh);
        free(yctx.etag_out);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
        if (qret == 304)
            sxi_seterr(sxi_conns_get_client(conns), SXE_SKIP, "Not modified");
	return NULL;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != LF_COMPLETE) {
        if (yctx.state != LF_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "List failed: Communication error");
        }
	if(yctx.yh)
	    yajl_free(yctx.yh);
        free(yctx.etag_out);
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
        free(yctx.etag_out);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
	return NULL;
    }

    ret = malloc(sizeof(*ret));
    if(!ret) {
        SXDEBUG("OOM allocating results");
        sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
        free(yctx.etag_out);
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
    if (yctx.etag_out) {
        if (etag_out && *yctx.etag_out)
            *etag_out = yctx.etag_out;
        else
            free(yctx.etag_out);
    }
    return ret;
}


sxc_cluster_lf_t *sxc_cluster_listfiles_etag(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *nfiles, int reverse, const char *etag_file) {
    sxi_hostlist_t volhosts;
    sxc_cluster_lf_t *ret;
    const char *confdir = sxi_cluster_get_confdir(cluster);
    char *path = NULL;
    char etag[1024];
    char *etag_out = NULL;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);

    sxi_hostlist_init(&volhosts);
    if(sxi_locate_volume(sxi_cluster_get_conns(cluster), volume, &volhosts, NULL, NULL)) {
        CFGDEBUG("Failed to locate volume %s", volume);
        sxi_hostlist_empty(&volhosts);
        return NULL;
    }

    etag[0] = '\0';
    if (etag_file && strchr(etag_file, '/')) {
        sxi_seterr(sx, SXE_EARG, "etag file cannot contain /");
        return NULL;
    }
    if (etag_file && confdir) {
        unsigned n = strlen(confdir) + strlen(volume) + strlen(etag_file) + sizeof("/volumes//etag/");
        path = malloc(n);
        if (!path) {
            cluster_err(SXE_EMEM, "Cannot allocate etag path");
            return NULL;
        }
        snprintf(path, n, "%s/volumes/%s", confdir, volume);
        if(access(path, F_OK) && mkdir(path, 0700))
                sxi_notice(sx, "Failed to mkdir %s", path);
        snprintf(path, n, "%s/volumes/%s/etag", confdir, volume);
        if(access(path, F_OK) && mkdir(path, 0700))
                sxi_notice(sx, "Failed to mkdir %s", path);
        snprintf(path, n, "%s/volumes/%s/etag/%s", confdir, volume, etag_file);
        SXDEBUG("Trying to load ETag from %s", path);
        FILE *f = fopen(path, "r");
        if (f) {
            if (!fgets(etag, sizeof(etag), f)) {
                etag[0] = '\0';
                sxi_notice(sx, "Failed to read old etag from %s", path);
            }
            fclose(f);
        }
    }
    if (*etag)
        SXDEBUG("ETag in: %s", etag);

    ret = sxi_conns_listfiles(sxi_cluster_get_conns(cluster), volume, &volhosts, glob_pattern, recursive, volume_used_size, volume_size, replica_count, nfiles, reverse, 0, *etag ? etag : NULL, &etag_out);
    sxi_hostlist_empty(&volhosts);
    SXDEBUG("ETag out: %s", etag_out ? etag_out : "");

    if (etag_out && confdir && path) {
        FILE *f = fopen(path, "w");
        if (f) {
            if (fwrite(etag_out, strlen(etag_out), 1, f) != 1)
                sxi_notice(sx, "Failed to write etag to %s", path);
            if (fclose(f))
                sxi_notice(sx, "Failed to close etag file %s", path);
        }
    }
    free(etag_out);
    free(path);
    return ret;
}

sxc_cluster_lf_t *sxc_cluster_listfiles(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *nfiles, int reverse) {
    return sxc_cluster_listfiles_etag(cluster, volume, glob_pattern, recursive, volume_used_size, volume_size, replica_count, nfiles, reverse, NULL);
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

static int get_user_info_wrap(sxc_cluster_t *cluster, const char *username, uint8_t *uid, int *role) {
    FILE *authfile = NULL;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    char *authfile_name;
    int r = 0;
    char token[AUTHTOK_ASCII_LEN+1];
    uint8_t buf[AUTHTOK_BIN_LEN];
    unsigned int buffsize = AUTHTOK_ASCII_LEN;

    if(!uid) {
        cluster_err(SXE_EARG, "NULL argument");
        return 1;
    }

    authfile_name = sxi_tempfile_track(sx, NULL, &authfile);
    if(!authfile || !authfile_name) {
        SXDEBUG("Failed to create a tempfile");
        if(authfile)
            fclose(authfile);
	if(authfile_name)
            sxi_tempfile_unlink_untrack(sx, authfile_name);
        return 1;
    }

    /* Get existing user ID */
    if(sxc_user_getinfo(cluster, username, authfile, &r, 0)) {
        SXDEBUG("Failed to get a user %s key", username);
        fclose(authfile);
        sxi_tempfile_unlink_untrack(sx, authfile_name);
        return 1;
    }

    if(role)
        *role = r;

    fclose(authfile);
    if(!(authfile = fopen(authfile_name, "r"))) {
        cluster_err(SXE_ECFG, "Failed to reopen credentials file");
        sxi_tempfile_unlink_untrack(sx, authfile_name);
        return 1;
    }
    if(fread(token, AUTHTOK_ASCII_LEN, 1, authfile) != 1) {
        cluster_err(SXE_ECOMM, "Failed to read an existing user common ID from tempfile");
        fclose(authfile);
        sxi_tempfile_unlink_untrack(sx, authfile_name);
        return 1;
    }
    token[AUTHTOK_ASCII_LEN] = 0;
    fclose(authfile);
    sxi_tempfile_unlink_untrack(sx, authfile_name);

    if(sxi_b64_dec(sx, token, buf, &buffsize)) {
        SXDEBUG("Failed to decode base64 encoded token");
        return 1;
    }
    memcpy(uid, buf, AUTH_UID_LEN);

    return 0;
}

int sxc_read_pass_file(sxc_client_t *sx, const char *pass_file, char *pass, unsigned int pass_len) {
    int fd, c;
    struct stat st;
    uid_t uid;

    if(!pass_file || !pass) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    if(pass_len <= 8) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument: Password buffer too short");
        return 1;
    }

    fd = open(pass_file, O_RDONLY);
    if(fd < 0) {
        sxi_seterr(sx, SXE_ECFG, "Failed to open password file %s: %s", pass_file, strerror(errno));
        return 1;
    }

    if(fstat(fd, &st)) {
        sxi_seterr(sx, SXE_ECFG, "Failed to stat file %s: %s", pass_file, strerror(errno));
        close(fd);
        return 1;
    }

    uid = geteuid();
    if(st.st_uid != uid) {
        struct passwd *pw = getpwuid(uid);
        sxi_seterr(sx, SXE_ECFG, "User '%s' must be the owner of %s", pw ? pw->pw_name : "", pass_file);
        close(fd);
        return 1;
    }

    if(!S_ISREG(st.st_mode)) {
        sxi_seterr(sx, SXE_ECFG, "%s is not a regular file", pass_file);
        close(fd);
        return 1;
    }

    if(st.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
        sxi_seterr(sx, SXE_ECFG, "File %s is group or others accessible", pass_file);
        close(fd);
        return 1;
    }

    if((c = read(fd, pass, pass_len)) < 0) {
        sxi_seterr(sx, SXE_EREAD, "Failed to read pass file %s: %s", pass_file, strerror(errno));
        memset(pass, 0, pass_len);
        close(fd);
        return 1;
    }
    close(fd);

    if((unsigned int)c >= pass_len) {
        sxi_seterr(sx, SXE_EARG, "Password is too long");
        memset(pass, 0, pass_len);
        return 1;
    }

    if(c <= 8) {
        sxi_seterr(sx, SXE_EARG, "Password is too short");
        memset(pass, 0, pass_len);
        return 1;
    }

    pass[c] = '\0';
    if(c && pass[c-1] == '\n')
        pass[c-1] = '\0';

    return 0;
}

static int pass2key(sxc_cluster_t *cluster, const char *user, const char *pass, unsigned char *key, int repeat)
{
    char password[1024];
    char salt[AUTH_UID_LEN];
    char keybuf[61];
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    const char *uuid;
    if(!cluster)
        return -1;
    if(!user || !key) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }

    if(pass && strlen(pass) >= sizeof(password)) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument: Password is too long");
        return -1;
    }

    uuid = sxc_cluster_get_uuid(cluster);
    if(!uuid) {
        sxi_seterr(sx, SXE_EARG, "Cluster uuid is not set");
        return 1;
    }

    if(sxi_sha1_calc(uuid, strlen(uuid), user, strlen(user), (unsigned char*)salt)) {
        sxi_seterr(sx, SXE_ECRYPT, "Failed to compute hash of username");
        return 1;
    }

    mlock(password, sizeof(password));
    if(!pass) { /* Password not supplied, prompt user for it */
        if(sxc_prompt_password(sx, password, sizeof(password), NULL, repeat)) {
            munlock(password, sizeof(password));
            return 1;
        }
    } else {/* Password supplied, copy it to local array */
        if(strlen(pass) < 8) {
            sxi_seterr(sx, SXE_EARG, "Password must be at least 8 characters long");
            munlock(password, sizeof(password));
            return 1;
        }
        sxi_strlcpy(password, pass, sizeof(password));
    } 

    if(sxi_derive_key(password, salt, AUTH_UID_LEN, BCRYPT_TOKEN_ITERATIONS_LOG2, keybuf, sizeof(keybuf))) {
        sxi_seterr(sx, SXE_ECRYPT, "Failed to derive key");
        memset(password, 0, sizeof(password));
        munlock(password, sizeof(password));
        return 1;
    }

    memset(password, 0, sizeof(password));
    munlock(password, sizeof(password));

    if(sxi_sha1_calc(uuid, strlen(uuid), keybuf, strlen(keybuf), key)) {
        sxi_seterr(sx, SXE_ECRYPT, "Failed to compute hash of derived key");
        return 1;
    }

    return 0;
}

static int username_hash(sxc_client_t *sx, const char *user, unsigned char *uid) {
    unsigned int len;
    sxi_md_ctx *ch_ctx;

    if(!sx)
        return 1;
    if(!user) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }
    len = strlen(user);
    ch_ctx = sxi_md_init();
    if (!ch_ctx) {
        sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: Unable to initialize crypto library");
        return 1;
    }
    if(!sxi_sha1_init(ch_ctx)) {
        sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: Unable to initialize crypto library");
        return 1;
    }
    if(!sxi_sha1_update(ch_ctx, user, len) || !sxi_sha1_final(ch_ctx, uid, NULL)) {
        sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: Crypto library failure");
        sxi_md_cleanup(&ch_ctx);
        return 1;
    }
    sxi_md_cleanup(&ch_ctx);
    return 0;
}

int sxc_prompt_username(sxc_client_t *sx, char *buff, unsigned int bufflen, const char *prefix) {
    char prompt[1024];

    if(!sx)
        return 1;
    if(!buff || bufflen < 65) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    snprintf(prompt, sizeof(prompt), "%s%s", prefix ? prefix : "", "Username: ");
    if(sxi_get_input(sx, SXC_INPUT_PLAIN, prompt, NULL, buff, bufflen)) {
        sxi_seterr(sx, SXE_EARG, "Can't obtain username");
        return 1;
    }
    if(!*buff) {
        sxi_seterr(sx, SXE_EARG, "Can't obtain username");
        return 1;
    }
    return 0;
}

/* Remember to mlock(buff, buff_len), buffer length must be greater than 8 characters */
int sxc_prompt_password(sxc_client_t *sx, char *buff, unsigned int buff_len, const char *prefix, int repeat) {
    char pass2[1024];
    char prompt[1024];

    if(!sx)
        return 1;
    if(!buff || buff_len < 1024 || (repeat && buff_len > sizeof(pass2))) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    snprintf(prompt, sizeof(prompt), "%s%s", prefix ? prefix : "", "Enter password: ");
    if(sxi_get_input(sx, SXC_INPUT_SENSITIVE, prompt, NULL, buff, buff_len)) {
        memset(buff, 0, buff_len);
        sxi_seterr(sx, SXE_EARG, "Can't obtain password");
        return 1;
    }

    if(strlen(buff) < 8) {
        memset(buff, 0, buff_len);
        sxi_seterr(sx, SXE_EARG, "Password must be at least 8 characters long");
        return 1;
    }

    if(repeat) {
        snprintf(prompt, sizeof(prompt), "%s%s", prefix ? prefix : "", "Re-enter password: ");
        mlock(pass2, sizeof(pass2));
        if(sxi_get_input(sx, SXC_INPUT_SENSITIVE, prompt, NULL, pass2, sizeof(pass2))) {
            memset(buff, 0, buff_len);
            memset(pass2, 0, sizeof(pass2));
            munlock(pass2, sizeof(pass2));
            sxi_seterr(sx, SXE_EARG, "Can't obtain password");
            return 1;
        }
        if(strcmp(buff, pass2)) {
            memset(buff, 0, buff_len);
            memset(pass2, 0, sizeof(pass2));
            munlock(pass2, sizeof(pass2));
            sxi_seterr(sx, SXE_EARG, "Passwords don't match");
            return 1;
        }
        memset(pass2, 0, sizeof(pass2));
        munlock(pass2, sizeof(pass2));
    }

    return 0;
}

int sxc_pass2token(sxc_cluster_t *cluster, const char *username, const char *password, char *tok_buf, unsigned int tok_size) {
    uint8_t buf[AUTH_UID_LEN + AUTH_KEY_LEN + 2], *uid = buf, *key = &buf[AUTH_UID_LEN];
    char *token;
    sxc_client_t *sx;

    if(!cluster)
        return 1;
    sx = sxi_cluster_get_client(cluster);
    if(!username || !password || !tok_buf || tok_size < AUTHTOK_ASCII_LEN + 1) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    memset(buf, 0, sizeof(buf));

    /* UID part - unsalted username hash */
    if(username_hash(sx, username, uid)) {
        SXDEBUG("Failed to compute unsalted hash of username");
        return 1;
    }

    /* Generate token from username and password */
    if(pass2key(cluster, username, password, key, 0)) {
        SXDEBUG("Failed to prompt user password");
        return 1;
    }

    buf[sizeof(buf) - 2] = 0; /* First reserved byte */
    buf[sizeof(buf) - 1] = 0; /* Second reserved byte */
    token = sxi_b64_enc(sx, buf, sizeof(buf));
    if(!token)
        return 1;
    if(strlen(token) != AUTHTOK_ASCII_LEN) {
        /* Always false but it doesn't hurt to be extra careful */
        sxi_seterr(sx, SXE_ECOMM, "The generated auth token has invalid size");
        free(token);
        return 1;
    }

    memcpy(tok_buf, token, tok_size);
    free(token);
    return 0;
}

static char *user_add(sxc_cluster_t *cluster, const char *username, const char *pass, int admin, const char *oldtoken, const char *existing, int *clone_role, const char *desc, int generate_key) {
    uint8_t buf[AUTH_UID_LEN + AUTH_KEY_LEN + 2], *uid = buf, *key = &buf[AUTH_UID_LEN];
    char *tok = NULL, *retkey = NULL;
    sxc_client_t *sx;
    sxi_query_t *proto = NULL;
    unsigned int l;
    int qret, role = 0;

    if(!cluster)
	return NULL;
    if(!username) {
        cluster_err(SXE_EARG, "Null args");
        return NULL;
    }
    if(!generate_key && !oldtoken && existing) {
        cluster_err(SXE_EARG, "Invalid argument: Cannot use password for user clones");
        return NULL;
    }
    if(generate_key && (oldtoken || pass)) {
        cluster_err(SXE_EARG, "Invalid argument: Cannot generate random key and use old token or password together");
        return NULL;
    }
    sx = sxi_cluster_get_client(cluster);
    memset(buf, 0, sizeof(buf));

    /* Key part */
    if (oldtoken) {
        /* Use key from an existing authentication token */
        char old[AUTHTOK_BIN_LEN];
        l = sizeof(old);
        if (sxi_b64_dec(sx, oldtoken, old, &l))
            return NULL;
        if (l != sizeof(old)) {
            cluster_err(SXE_EARG, "Bad length for old authentication token");
            return NULL;
        }
        memcpy(buf, old, AUTHTOK_BIN_LEN);
    } else if(generate_key) {
        /* Generate random key */
        if (sxi_rand_bytes(key, AUTH_KEY_LEN) != 1) {
            cluster_err(SXE_ECRYPT, "Unable to produce a random key");
            return NULL;
        }
    } else {
        /* Prompt user for password */
        if(pass2key(cluster, username, pass, key, 1)) {
            SXDEBUG("Failed to prompt user password");
            return NULL;
        }
    }

    /* Query */
    if(existing)
        proto = sxi_userclone_proto(sx, existing, username, oldtoken ? uid : NULL, key, desc);
    else
        proto = sxi_useradd_proto(sx, username, NULL, key, admin, desc);
    if(!proto) {
	cluster_err(SXE_EMEM, "Unable to allocate space for request data");
	return NULL;
    }
    sxi_set_operation(sxi_cluster_get_client(cluster), "create user", sxi_cluster_get_name(cluster), NULL, NULL);
    qret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, proto->verb, proto->path, proto->content, proto->content_len);
    if(qret) {
        SXDEBUG("Failed to send useradd query");
        sxi_query_free(proto);
        return NULL;
    }
    sxi_query_free(proto);

    if(existing) {
        if(get_user_info_wrap(cluster, username, uid, &role)) { /* Read existing user ID, which is stored along with his key */
            SXDEBUG("Failed to get existing user common ID");
            return NULL;
        }
    } else {
        /* UID part - unsalted username hash */
        if(username_hash(sx, username, uid)) {
            SXDEBUG("Failed to compute unsalted hash of username");
            return NULL;
        }
    }

    /* Get existing user role */          
    if(clone_role)
        *clone_role = role;

    /* Encode token */
    buf[sizeof(buf) - 2] = 0; /* First reserved byte */
    buf[sizeof(buf) - 1] = 0; /* Second reserved byte */
    tok = sxi_b64_enc(sx, buf, sizeof(buf));
    if(!tok)
        return NULL;
    if(strlen(tok) != AUTHTOK_ASCII_LEN) {
        /* Always false but it doensn't hurt to be extra careful */
        cluster_err(SXE_ECOMM, "The generated auth token has invalid size");
        free(tok);
        return NULL;
    }

    if (oldtoken && strcmp(tok, oldtoken)) {
        cluster_err(SXE_EARG, "The provided old authentication token and username don't match");
        free(tok);
        return NULL;
    }

    retkey = malloc(AUTHTOK_ASCII_LEN + 1);
    if(!retkey)
        cluster_err(SXE_EMEM, "Unable to allocate memory for user key");
    else
        sxi_strlcpy(retkey, tok, AUTHTOK_ASCII_LEN+1);

    free(tok);
    return retkey;
}

char *sxc_user_add(sxc_cluster_t *cluster, const char *username, const char *pass, int admin, const char *oldtoken, const char *desc, int generate_key) {
    return user_add(cluster, username, pass, admin, oldtoken, NULL, NULL, desc, generate_key);
}

char *sxc_user_clone(sxc_cluster_t *cluster, const char *username, const char *clonename, const char *oldtoken, int *role, const char *desc) {
    return user_add(cluster, clonename, NULL, 0, oldtoken, username, role, desc, oldtoken ? 0 : 1);
}

char *sxc_user_newkey(sxc_cluster_t *cluster, const char *username, const char *pass, const char *oldtoken, int generate_key)
{
    uint8_t buf[AUTH_UID_LEN + AUTH_KEY_LEN + 2], *uid = buf, *key = &buf[AUTH_UID_LEN];
    char *tok, *retkey = NULL;
    const char *curtoken;
    char curtoken_bin[AUTHTOK_BIN_LEN];
    unsigned int curtoken_bin_len = AUTHTOK_BIN_LEN;
    sxc_client_t *sx;
    sxi_query_t *proto;
    int qret;
    long http_err;

    if(!cluster)
	return NULL;
    if(!username) {
        cluster_err(SXE_EARG, "Null args");
        return NULL;
    }
    if(generate_key && (oldtoken || pass)) {
        cluster_err(SXE_EARG, "Invalid argument: Cannot generate random key and use old token or password together");
        return NULL;
    }
    sx = sxi_cluster_get_client(cluster);

    curtoken = sxi_conns_get_auth(sxi_cluster_get_conns(cluster));
    if(!curtoken) {
        SXDEBUG("Failed to load current authentication token");
        return NULL;
    }

    if(sxi_b64_dec(sx, curtoken, curtoken_bin, &curtoken_bin_len)) {
        SXDEBUG("Failed to decode current authentication token");
        return NULL;
    }

    if(username_hash(sx, username, uid)) {
        SXDEBUG("Failed to compute hash of a username");
        return NULL;
    }

    /* Only fetch uid if user is not changing his own key. If he's not allowed to do so, the operation will be rejected from get_user_info_wrap() */
    if(memcmp(curtoken_bin, uid, AUTH_UID_LEN)) {
        uint8_t tmpuid[AUTH_UID_LEN];

        memcpy(tmpuid, uid, sizeof(tmpuid));
        if(get_user_info_wrap(cluster, username, uid, NULL)) { /* Read existing user ID, which is stored along with his key */
            SXDEBUG("Failed to get existing user UID");
            if(sxc_geterrnum(sx) == SXE_EAUTH) { /* If not authorized, warn that only admin can change other user's key */
               sxc_clearerr(sx);
               sxi_seterr(sx, SXE_EARG, "Only admin can change other user's key");
            }
            return NULL;
        }

        if(memcmp(tmpuid, uid, AUTH_UID_LEN) && !oldtoken && !generate_key) {
            char zerouid[AUTH_UID_LEN];
            memset(zerouid, 0, AUTH_UID_LEN);

            /* Compatibility notice:
             * 1.0 version of SX server does not return a user UID from usergetkey query.
             * get_user_info_wrap() memsets the uid and then fills it if some data was returned. In 1.0 server
             * case it will be left zeroed, therefore we should first check if the field was filled. */
            if(memcmp(zerouid, uid, AUTH_UID_LEN)) {
                /* UID is not zeroed, it was returned from the server and is different than destination user UID, it is a clone. */
                sxi_seterr(sx, SXE_EARG, "Cannot use username and password for clones");
                return NULL;
            } else {
                SXDEBUG("User '%s' UID was not returned by the server, assuming the user is not a clone", username);
                memcpy(uid, tmpuid, AUTH_UID_LEN);
            }
        }
    }

    /* Key part */
    if (oldtoken) {
        /* Use key from an existing authentication token */
        char old[AUTHTOK_BIN_LEN];
        unsigned l = sizeof(old);
        if (sxi_b64_dec(sx, oldtoken, old, &l))
            return NULL;
        if (l != sizeof(old)) {
            cluster_err(SXE_EARG, "Bad length for old authentication token");
            return NULL;
        }
        memcpy(key, &old[AUTH_UID_LEN], AUTH_KEY_LEN);
    } else if(generate_key) {
        /* Generate random key */
        if (sxi_rand_bytes(key, AUTH_KEY_LEN) != 1) {
            cluster_err(SXE_ECRYPT, "Unable to produce a random key");
            return NULL;
        }
    } else {
        /* Prompt user for a password */
        if(pass2key(cluster, username, pass, key, 1)) {
            SXDEBUG("Failed to prompt user password");
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

int sxc_user_remove(sxc_cluster_t *cluster, const char *username, int remove_clones) {
    char *enc_name, *query;
    sxc_client_t *sx;
    int ret;
    unsigned int len;

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

    len = lenof(".users/") + strlen(enc_name) + 1;
    if(remove_clones)
        len += strlen("?all");
    query = malloc(len);
    if(!query) {
	free(enc_name);
	cluster_err(SXE_EMEM, "Unable to allocate space for request data");
	return 1;
    }
    sprintf(query, ".users/%s%s", enc_name, (remove_clones ? "?all" : ""));
    free(enc_name);

    sxi_set_operation(sx, "remove user", sxi_cluster_get_name(cluster), NULL, NULL);
    ret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, REQ_DELETE, query, NULL, 0);

    free(query);
    return ret;
}

struct cb_userinfo_ctx {
    enum userkey_state { USERINFO_ERROR, USERINFO_BEGIN, USERINFO_MAP, USERINFO_KEY, USERINFO_ID, USERINFO_ROLE, USERINFO_COMPLETE } state;
    struct cb_error_ctx errctx;
    yajl_callbacks yacb;
    curlev_context_t *cbdata;
    yajl_handle yh;
    uint8_t token[AUTHTOK_BIN_LEN];
    FILE *f;
    char role[7];
};

static int userinfo_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host)
{
    struct cb_userinfo_ctx *yactx = ctx;
    if (yactx->yh)
        yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh = yajl_alloc(&yactx->yacb, NULL, yactx))) {
        CBDEBUG("OOM allocating yajl context");
        sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot get user key: Out of memory");
        return 1;
    }

    yactx->state = USERINFO_BEGIN;
    return 0;
}

static int userinfo_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_userinfo_ctx *yactx = ctx;
    if (yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != USERINFO_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
        return 1;
    }
    return 0;
}

static int yacb_userinfo_start_map(void *ctx) {
    struct cb_userinfo_ctx *yactx = ctx;
    if(!ctx)
	return 0;

    if(yactx->state == USERINFO_BEGIN) {
	yactx->state = USERINFO_MAP;
    } else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, USERINFO_BEGIN);
	return 0;
    }
    return 1;
}

static int yacb_userinfo_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_userinfo_ctx *yactx = ctx;
    if(!ctx)
	return 0;

    if (yactx->state == USERINFO_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    if (yactx->state == USERINFO_MAP) {
        if (ya_check_error(yactx->cbdata, &yactx->errctx, s, l)) {
            yactx->state = USERINFO_ERROR;
            return 1;
        }
    }
    if(yactx->state == USERINFO_MAP) {
	if(l == lenof("userKey") && !memcmp(s, "userKey", lenof("userKey"))) {
	    yactx->state = USERINFO_KEY;
	    return 1;
	}
        if(l == lenof("userID") && !memcmp(s, "userID", lenof("userID"))) {
            yactx->state = USERINFO_ID;
            return 1;
        }
        if(l == lenof("userType") && !memcmp(s, "userType", lenof("userType"))) {
            yactx->state = USERINFO_ROLE;
            return 1;
        }
	return 1;
    }

    CBDEBUG("bad state (in %d, expected %d)", yactx->state, USERINFO_KEY);
    return 0;
}

static int yacb_userinfo_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_userinfo_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if (yactx->state == USERINFO_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);

    if(l<=0)
	return 0;
    if (yactx->state == USERINFO_MAP)
        return 1;
    if (yactx->state == USERINFO_KEY) {
	if(sxi_hex2bin((const char *)s, l, yactx->token + AUTH_UID_LEN, AUTH_KEY_LEN)) {
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "Failed to convert user key from hex");
            return 0;
        }
        yactx->state = USERINFO_MAP;
        return 1;
    } else if(yactx->state == USERINFO_ID) {
        if(sxi_hex2bin((const char *)s, l, yactx->token, AUTH_UID_LEN)) {
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "Failed to convert user key from hex");
            return 0;
        }
        yactx->state = USERINFO_MAP;
        return 1;
    } else if(yactx->state == USERINFO_ROLE) {
        if(l != 6 && l != 5) {
            CBDEBUG("Invalid role: bad role string length");
            return 0;
        }

        if(strncmp("admin", (const char*)s, l) && strncmp("normal", (const char*)s, l)) {
            CBDEBUG("Invalid role: should be admin or normal");
            return 0;
        }

        memcpy(yactx->role, s, l);
        yactx->role[l] = '\0';
        yactx->state = USERINFO_MAP;
        return 1;
    }
    return 0;
}

static int yacb_userinfo_end_map(void *ctx) {
    struct cb_userinfo_ctx *yactx = ctx;
    if(!ctx)
	return 0;
    if (yactx->state == USERINFO_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == USERINFO_MAP)
	yactx->state = USERINFO_COMPLETE;
    else {
	CBDEBUG("bad state (in %d, expected %d)", yactx->state, FN_CLUSTER);
	return 0;
    }
    return 1;
}

int sxc_user_getinfo(sxc_cluster_t *cluster, const char *username, FILE *storeauth, int *is_admin, int get_config_link)
{
    sxc_client_t *sx;
    struct cb_userinfo_ctx yctx;
    yajl_callbacks *yacb;
    int ret = 1;
    unsigned n;
    char *url = NULL;
    char *tok = NULL;
    char *link = NULL;

    if(!cluster)
	return 1;
    if(!username || (!storeauth && !is_admin)) {
        cluster_err(SXE_EARG, "Null args");
        return 1;
    }
    memset(&yctx, 0, sizeof(yctx));
    yacb = &yctx.yacb;
    ya_init(yacb);
    yacb->yajl_start_map = yacb_userinfo_start_map;
    yacb->yajl_map_key = yacb_userinfo_map_key;
    yacb->yajl_string = yacb_userinfo_string;
    yacb->yajl_end_map = yacb_userinfo_end_map;
    yctx.yh = NULL;
    yctx.f = storeauth;

    sx = sxi_cluster_get_client(cluster);

    /* Query */
    n = strlen(username) + sizeof(".users/");
    url = malloc(n);
    if (!url) {
	sxi_seterr(sx, SXE_EMEM, "Out of memory");
        goto sxc_user_getinfo_err;
    }
    snprintf(url, n, ".users/%s", username);

    sxi_set_operation(sxi_cluster_get_client(cluster), "get user's key", sxi_cluster_get_name(cluster), NULL, NULL);
    if (sxi_cluster_query(sxi_cluster_get_conns(cluster), NULL, REQ_GET, url, NULL, 0,
                          userinfo_setup_cb, userinfo_cb, &yctx) != 200)
        goto sxc_user_getinfo_err;
    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != USERINFO_COMPLETE) {
        if (yctx.state != USERINFO_ERROR) {
            SXDEBUG("JSON parsing failed");
            sxi_seterr(sx, SXE_ECOMM, "Cannot get user key: Communication error");
        }
        goto sxc_user_getinfo_err;
    }
    ret = 0;

    tok = sxi_b64_enc(sx, yctx.token, sizeof(yctx.token));
    if(!tok)
        goto sxc_user_getinfo_err;

    if(get_config_link) {
        link = sxc_cluster_configuration_link(cluster, username, tok);
        if(!link)
            goto sxc_user_getinfo_err;
    }

    if(storeauth)
        fprintf(storeauth, "%s\n", get_config_link ? link : tok);
    if(is_admin)
        *is_admin = (!strncmp("admin", yctx.role, sizeof(yctx.role)-1) ? 1 : 0);
sxc_user_getinfo_err:
    free(tok);
    free(link);
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

char *sxc_fetch_sxauthd_credentials(sxc_client_t *sx, const char *username, const char *pass, const char *host, int port, int quiet) {
    char *ret = NULL;
    sxi_conns_t *conns = NULL;
    const char *tmpcafile = NULL;
    FILE *f = NULL;
    char unique_name[1024];
    char hostname[1024];
    struct passwd *pw;
    uid_t uid;

    if(!username || !pass || !host || !username) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return NULL;
    }

    uid = geteuid();
    pw = getpwuid(uid);
    if(!pw) {
        sxi_seterr(sx, SXE_ECFG, "Failed to obtain system username: %s", strerror(errno));
        return NULL;
    }

    gethostname(hostname, sizeof(hostname));
    if(!strlen(pw->pw_name) || !strlen(hostname) || strlen(pw->pw_name) + strlen(hostname) + 1 >= sizeof(unique_name)) {
        sxi_seterr(sx, SXE_EARG, "Failed to obtain unique device name");
        return NULL;
    }
    snprintf(unique_name, sizeof(unique_name), "%s@%s", pw->pw_name, hostname);

    tmpcafile = sxi_tempfile_track(sx, NULL, &f);
    if(!tmpcafile)
        goto sxc_fetch_sxauthd_credentials_err;

    conns = sxi_conns_new(sx);
    if(!conns)
        goto sxc_fetch_sxauthd_credentials_err;

    if(sxi_conns_set_dnsname(conns, host))
        goto sxc_fetch_sxauthd_credentials_err;

    /* Create a hostlist from a dns name host (needed to fetch ca) */
    if(sxi_conns_resolve_hostlist(conns)) {
        sxi_seterr(sx, SXE_ECFG, "Failed to resolve hostlist from dns name '%s'\n", host);
        goto sxc_fetch_sxauthd_credentials_err;
    }
    SXDEBUG("Successfully got list sxauthd of hosts");

    sxi_set_operation(sx, "fetch certificate", NULL, NULL, NULL);
    if(sxi_conns_root_noauth(conns, tmpcafile, quiet)) {
        SXDEBUG("Failed to fetch sxauthd CA certificate");
        goto sxc_fetch_sxauthd_credentials_err;
    }
    sxi_conns_set_cafile(conns, tmpcafile);

    sxi_set_operation(sx, "fetch sxauthd credentials", NULL, NULL, NULL);
    ret = sxi_conns_fetch_sxauthd_credentials(conns, username, pass, unique_name, unique_name, host, port, quiet);

sxc_fetch_sxauthd_credentials_err:
    if(f)
        fclose(f);
    sxi_conns_free(conns);
    return ret;
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

struct node_status_ctx {
    sxi_node_status_t status;
    yajl_handle yh;
    yajl_callbacks yacb;
    curlev_context_t *cbdata;
    struct cb_error_ctx errctx;
    enum node_status_state { NS_ERROR, NS_BEGIN, NS_KEY, NS_OSTYPE, NS_ARCH, NS_RELEASE, NS_VERSION, NS_CORES, NS_ENDIANNESS,
        NS_LOCALTIME, NS_UTCTIME, NS_ADDR, NS_INTERNAL_ADDR, NS_UUID, NS_STORAGE_VERSION, NS_LIBSX_VERSION, NS_STORAGE_DIR,
        NS_STORAGE_ALLOC, NS_STORAGE_USED, NS_FS_BLOCK_SIZE, NS_FS_TOTAL_BLOCKS, NS_FS_AVAIL_BLOCKS,
        NS_MEM_TOTAL, NS_HEAL, NS_COMPLETE } state;
};

static int yacb_node_status_start_map(void *ctx) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;

    if(!ctx)
        return 0;
    if(yactx->state == NS_BEGIN)
        yactx->state = NS_KEY;
    else
        CBDEBUG("bad state (in %d, expected %d)", yactx->state, NS_BEGIN);
    return 1;
}

static int yacb_node_status_end_map(void *ctx) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;

    if(!ctx)
        return 0;
    if (yactx->state == NS_ERROR)
        return yacb_error_end_map(&yactx->errctx);
    if(yactx->state == NS_KEY)
        yactx->state = NS_COMPLETE;
    else
        CBDEBUG("bad state (in %d, expected %d)", yactx->state, NS_KEY);
    return 1;
}

static int yacb_node_status_string(void *ctx, const unsigned char *s, size_t l) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;

    if (yactx->state == NS_ERROR)
        return yacb_error_string(&yactx->errctx, s, l);
    else if(yactx->state == NS_OSTYPE) {
        if(l >= sizeof(yactx->status.os_name)) {
            CBDEBUG("ostype string too long");
            return 0;
        }
        memcpy(yactx->status.os_name, s, l);
        yactx->status.os_name[sizeof(yactx->status.os_name)-1] = '\0';
    } else if(yactx->state == NS_ARCH) {
        if(l >= sizeof(yactx->status.os_arch)) {
            CBDEBUG("arch string too long");
            return 0;
        }
        memcpy(yactx->status.os_arch, s, l);
        yactx->status.os_arch[sizeof(yactx->status.os_arch)-1] = '\0';
    } else if(yactx->state == NS_RELEASE) {
        if(l >= sizeof(yactx->status.os_release)) {
            CBDEBUG("release string too long");
            return 0;
        }
        memcpy(yactx->status.os_release, s, l);
        yactx->status.os_release[sizeof(yactx->status.os_release)-1] = '\0';
    } else if(yactx->state == NS_VERSION) {
        if(l >= sizeof(yactx->status.os_version)) {
            CBDEBUG("version string too long");
            return 0;
        }
        memcpy(yactx->status.os_version, s, l);
        yactx->status.os_version[sizeof(yactx->status.os_version)-1] = '\0';
    } else if(yactx->state == NS_LOCALTIME) {
        if(l >= sizeof(yactx->status.localtime)) {
            CBDEBUG("localtime string too long");
            return 0;
        }
        memcpy(yactx->status.localtime, s, l);
        yactx->status.localtime[sizeof(yactx->status.localtime)-1] = '\0';
    } else if(yactx->state == NS_UTCTIME) {
        if(l >= sizeof(yactx->status.utctime)) {
            CBDEBUG("utctime string too long");
            return 0;
        }
        memcpy(yactx->status.utctime, s, l);
        yactx->status.utctime[sizeof(yactx->status.utctime)-1] = '\0';
    } else if(yactx->state == NS_ADDR) {
        if(l >= sizeof(yactx->status.addr)) {
            CBDEBUG("address string too long");
            return 0;
        }
        memcpy(yactx->status.addr, s, l);
        yactx->status.addr[sizeof(yactx->status.addr)-1] = '\0';
    } else if(yactx->state == NS_ENDIANNESS) {
        if(l >= sizeof(yactx->status.endianness)) {
            CBDEBUG("endianness string too long");
            return 0;
        }
        memcpy(yactx->status.endianness, s, l);
        yactx->status.endianness[sizeof(yactx->status.endianness)-1] = '\0';
    } else if(yactx->state == NS_INTERNAL_ADDR) {
        if(l >= sizeof(yactx->status.internal_addr)) {
            CBDEBUG("internal address string too long");
            return 0;
        }
        memcpy(yactx->status.internal_addr, s, l);
        yactx->status.internal_addr[sizeof(yactx->status.internal_addr)-1] = '\0';
    } else if(yactx->state == NS_UUID) {
        if(l >= sizeof(yactx->status.uuid)) {
            CBDEBUG("uuid string too long");
            return 0;
        }
        memcpy(yactx->status.uuid, s, l);
        yactx->status.uuid[sizeof(yactx->status.uuid)-1] = '\0';
    } else if(yactx->state == NS_STORAGE_DIR) {
        if(l >= sizeof(yactx->status.storage_dir)) {
            CBDEBUG("storage dir string too long");
            return 0;
        }
        memcpy(yactx->status.storage_dir, s, l);
        yactx->status.storage_dir[sizeof(yactx->status.storage_dir)-1] = '\0';
    } else if(yactx->state == NS_STORAGE_VERSION) {
        if(l >= sizeof(yactx->status.hashfs_version)) {
            CBDEBUG("hashfs version string too long");
            return 0;
        }
        memcpy(yactx->status.hashfs_version, s, l);
        yactx->status.hashfs_version[sizeof(yactx->status.hashfs_version)-1] = '\0';
    } else if(yactx->state == NS_LIBSX_VERSION) {
        if(l >= sizeof(yactx->status.libsx_version)) {
            CBDEBUG("hashfs version string too long");
            return 0;
        }
        memcpy(yactx->status.libsx_version, s, l);
        yactx->status.libsx_version[sizeof(yactx->status.libsx_version)-1] = '\0';
    } else if(yactx->state == NS_HEAL) {
        if (l >= sizeof(yactx->status.heal_status)) {
            CBDEBUG("heal status too long");
            return 0;
        }
        memcpy(yactx->status.heal_status, s, l);
        yactx->status.heal_status[sizeof(yactx->status.heal_status)-1] = '\0';
    } else if(yactx->state != NS_KEY) {
        CBDEBUG("bad state (in %d, expected %d, %d, %d, %d, %d, %d, %d, %d, %d or %d)", yactx->state, NS_OSTYPE, NS_ARCH,
            NS_RELEASE, NS_VERSION, NS_ADDR, NS_INTERNAL_ADDR, NS_UUID, NS_STORAGE_DIR, NS_STORAGE_VERSION, NS_LIBSX_VERSION);
    }

    yactx->state = NS_KEY;
    return 1;
}

static int yacb_node_status_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;

    if(!ctx)
        return 0;
    if (yactx->state == NS_ERROR)
        return yacb_error_map_key(&yactx->errctx, s, l);
    else if(yactx->state == NS_KEY) {
        if(l == lenof("osType") && !memcmp(s, "osType", lenof("osType")))
            yactx->state = NS_OSTYPE;
        else if(l == lenof("osArch") && !memcmp(s, "osArch", lenof("osArch")))
            yactx->state = NS_ARCH;
        else if(l == lenof("osRelease") && !memcmp(s, "osRelease", lenof("osRelease")))
            yactx->state = NS_RELEASE;
        else if(l == lenof("osVersion") && !memcmp(s, "osVersion", lenof("osVersion")))
            yactx->state = NS_VERSION;
        else if(l == lenof("localTime") && !memcmp(s, "localTime", lenof("localTime")))
            yactx->state = NS_LOCALTIME;
        else if(l == lenof("utcTime") && !memcmp(s, "utcTime", lenof("utcTime")))
            yactx->state = NS_UTCTIME;
        else if(l == lenof("cores") && !memcmp(s, "cores", lenof("cores")))
            yactx->state = NS_CORES;
        else if(l == lenof("osEndianness") && !memcmp(s, "osEndianness", lenof("osEndianness")))
            yactx->state = NS_ENDIANNESS;
        else if(l == lenof("address") && !memcmp(s, "address", lenof("address")))
            yactx->state = NS_ADDR;
        else if(l == lenof("internalAddress") && !memcmp(s, "internalAddress", lenof("internalAddress")))
            yactx->state = NS_INTERNAL_ADDR;
        else if(l == lenof("UUID") && !memcmp(s, "UUID", lenof("UUID")))
            yactx->state = NS_UUID;
        else if(l == lenof("hashFSVersion") && !memcmp(s, "hashFSVersion", lenof("hashFSVersion")))
            yactx->state = NS_STORAGE_VERSION;
        else if(l == lenof("libsxVersion") && !memcmp(s, "libsxVersion", lenof("libsxVersion")))
            yactx->state = NS_LIBSX_VERSION;
        else if(l == lenof("nodeDir") && !memcmp(s, "nodeDir", lenof("nodeDir")))
            yactx->state = NS_STORAGE_DIR;
        else if(l == lenof("storageAllocated") && !memcmp(s, "storageAllocated", lenof("storageAllocated")))
            yactx->state = NS_STORAGE_ALLOC;
        else if(l == lenof("storageUsed") && !memcmp(s, "storageUsed", lenof("storageUsed")))
            yactx->state = NS_STORAGE_USED;
        else if(l == lenof("fsBlockSize") && !memcmp(s, "fsBlockSize", lenof("fsBlockSize")))
            yactx->state = NS_FS_BLOCK_SIZE;
        else if(l == lenof("fsTotalBlocks") && !memcmp(s, "fsTotalBlocks", lenof("fsTotalBlocks")))
            yactx->state = NS_FS_TOTAL_BLOCKS;
        else if(l == lenof("fsAvailBlocks") && !memcmp(s, "fsAvailBlocks", lenof("fsAvailBlocks")))
            yactx->state = NS_FS_AVAIL_BLOCKS;
        else if(l == lenof("memTotal") && !memcmp(s, "memTotal", lenof("memTotal")))
            yactx->state = NS_MEM_TOTAL;
        else if(l == lenof("heal") && !memcmp(s, "heal", lenof("heal")))
            yactx->state = NS_HEAL;
        else
            CBDEBUG("unexpected key '%.*s'", (unsigned)l, s);
        return 1;
    }

    CBDEBUG("bad state (in %d, expected %d)", yactx->state, NS_KEY);
    return 1;
}

static int yacb_node_status_number(void *ctx, const char *s, size_t l) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    char numb[24], *enumb;
    long long number;

    if(!ctx)
        return 0;

    if(l < 1 || l > 20) {
        CBDEBUG("Invalid number '%.*s'", (unsigned)l, s);
        return 0;
    }
    memcpy(numb, s, l);
    numb[l] = '\0';
    number = strtoll(numb, &enumb, 10);
    if(*enumb) {
        CBDEBUG("invalid number '%.*s'", (unsigned)l, s);
        return 0;
    }

    switch(yactx->state) {
        case NS_CORES:
            yactx->status.cores = number;
            break;
        case NS_STORAGE_ALLOC:
            yactx->status.storage_allocated = number;
            break;
        case NS_STORAGE_USED:
            yactx->status.storage_commited = number;
            break;
        case NS_FS_BLOCK_SIZE:
            yactx->status.block_size = number;
            break;
        case NS_FS_TOTAL_BLOCKS:
            yactx->status.total_blocks = number;
            break;
        case NS_FS_AVAIL_BLOCKS:
            yactx->status.avail_blocks = number;
            break;
        case NS_MEM_TOTAL:
            yactx->status.mem_total = number;
            break;
        default:
            CBDEBUG("bad state (in %d, expected %d, %d, %d, %d, %d, %d or %d)", yactx->state, NS_CORES,
                NS_STORAGE_ALLOC, NS_STORAGE_USED, NS_FS_BLOCK_SIZE, NS_FS_TOTAL_BLOCKS, NS_FS_AVAIL_BLOCKS,
                NS_MEM_TOTAL);
    }

    yactx->state = NS_KEY;
    return 1;
}

static int node_status_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok) {
        if (yactx->state != NS_ERROR) {
            CBDEBUG("failed to parse JSON data: %s", sxi_cbdata_geterrmsg(yactx->cbdata));
            sxi_cbdata_seterr(yactx->cbdata, SXE_ECOMM, "communication error");
        }
        return 1;
    }
    return 0;
}

static int node_status_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;

    if(yactx->yh)
        yajl_free(yactx->yh);

    yactx->cbdata = cbdata;
    if(!(yactx->yh  = yajl_alloc(&yactx->yacb, NULL, yactx))) {
        CBDEBUG("failed to allocate yajl structure");
        sxi_cbdata_seterr(cbdata, SXE_EMEM, "Getting node status failed: Out of memory");
        return 1;
    }
    return 0;
}

int sxi_cluster_status(sxc_cluster_t *cluster, const node_status_cb_t status_cb, int human_readable) {
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    int ret = 1, fail = 0;
    sxi_hostlist_t *hosts;
    sxi_hostlist_t hlist;
    unsigned int i;
    unsigned int nnodes;

    if(!cluster)
        return 1;

    if(!status_cb) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return 1;
    }

    hosts = sxi_conns_get_hostlist(conns);
    if(!hosts) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to get cluster host list");
        return 1;
    }

    nnodes = sxi_hostlist_get_count(hosts);
    sxi_hostlist_init(&hlist);

    sxi_set_operation(sx, "check cluster status", NULL, NULL, NULL);
    for(i = 0; i < nnodes; i++) {
        int qret;
        const char *node = sxi_hostlist_get_host(hosts, i);
        struct node_status_ctx *yctx = NULL;
        yajl_callbacks *yacb;

        if(sxi_hostlist_add_host(sx, &hlist, node)) {
            SXDEBUG("Failed to get status of node %s: %s", node, sxc_geterrmsg(sx));
            goto sxc_cluster_status_err;
        }

        if(!(yctx = calloc(1, sizeof(*yctx)))) {
            SXDEBUG("Failed to allocate yajl handle");
            goto sxc_cluster_status_err;
        }

        yacb = &yctx->yacb;
        ya_init(yacb);
        yacb->yajl_start_map = yacb_node_status_start_map;
        yacb->yajl_map_key = yacb_node_status_map_key;
        yacb->yajl_string = yacb_node_status_string;
        yacb->yajl_number = yacb_node_status_number;
        yacb->yajl_end_map = yacb_node_status_end_map;
        yctx->state = NS_BEGIN;

        qret = sxi_cluster_query(conns, &hlist, REQ_GET, ".status", NULL, 0, node_status_setup_cb, node_status_cb, yctx);
        sxi_hostlist_empty(&hlist);
        if(qret != 200) {
            SXDEBUG("Failed to get status of node %s: %s", node, sxc_geterrmsg(sx));
            yajl_free(yctx->yh);
            free(yctx);
            enum sxc_error_t code = SXE_ECOMM;
            char *old_msg = strdup(sxc_geterrmsg(sx));
            if (qret == 403 && strstr(old_msg, "Volume name is reserved")) {
                free(old_msg);
                old_msg = strdup("doesn't support status query (server version older than 1.1?)");
                code = SXE_EAGAIN;
            }
            sxc_clearerr(sx);
            sxi_seterr(sx, code, "Can't query node %s%s%s", node, old_msg ? ": " : "", old_msg ? old_msg : "");
            free(old_msg);
            fail = 1;
            status_cb(sx, qret, NULL, human_readable);
            sxc_clearerr(sx);
            continue;
        }

        if(yajl_complete_parse(yctx->yh) != yajl_status_ok || yctx->state != NS_COMPLETE) {
            SXDEBUG("Failed to complete parsing of node %s status", node);
            yajl_free(yctx->yh);
            free(yctx);
            sxc_clearerr(sx);
            sxi_seterr(sx, SXE_ECOMM, "Can't query node %s", node);
            fail = 1;
            status_cb(sx, qret, NULL, human_readable);
            continue;
        }

        status_cb(sx, qret, &yctx->status, human_readable);
        yajl_free(yctx->yh);
        free(yctx);
    }

    if(fail) {
        sxc_clearerr(sx);
        sxi_seterr(sx, SXE_ECOMM, "Failed to communicate with all cluster nodes");
        goto sxc_cluster_status_err;
    }
    ret = 0;
sxc_cluster_status_err:
    sxi_hostlist_empty(&hlist);
    return ret;
}

static int distribution_lock_common(sxc_cluster_t *cluster, int op, const char *master) {
    sxi_query_t *query;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    sxi_hostlist_t *hosts, new_hosts;
    const char *min_host = NULL;
    unsigned int i;

    if(!cluster) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }
    
    sx = sxi_cluster_get_client(cluster);
    conns = sxi_cluster_get_conns(cluster);

    if(!sx || !conns) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    query = sxi_distlock_proto(sx, op, NULL);
    if(!query) {
        SXDEBUG("Failed to create distlock query");
        return 1;
    }

    hosts = sxi_conns_get_hostlist(conns);
    if(!hosts) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to get cluster host list");
        sxi_query_free(query);
        return 1;
    }

    for(i = 0; i < sxi_hostlist_get_count(hosts); i++) {
        const char *host = sxi_hostlist_get_host(hosts, i);
        if(master) {
            if(!strcmp(master, host)) {
                min_host = host;
                break;
            }
        } else if(!min_host || strcmp(host, min_host) < 0)
            min_host = host;
    }

    if(!min_host) {
        sxi_seterr(sx, SXE_EARG, "Cannot determine master node");
        sxi_query_free(query);
        return 1;
    }

    sxi_hostlist_init(&new_hosts);
    if(sxi_hostlist_add_host(sx, &new_hosts, min_host)) {
        sxi_query_free(query);
        sxi_hostlist_empty(&new_hosts);
        return 1;
    }

    sxi_set_operation(sx, op ? "lock cluster" : "unlock cluster", NULL, NULL, NULL);
    if(sxi_job_submit_and_poll(conns, &new_hosts, query->verb, query->path, query->content, query->content_len)) {
        sxi_query_free(query);
        sxi_hostlist_empty(&new_hosts);
        return 1;
    }

    sxi_query_free(query);
    sxi_hostlist_empty(&new_hosts);
    return 0;
}
    
int sxi_cluster_distribution_lock(sxc_cluster_t *cluster, const char *master) {
    return distribution_lock_common(cluster, 1, master);
}

int sxi_cluster_distribution_unlock(sxc_cluster_t *cluster, const char *master) {
    return distribution_lock_common(cluster, 0, master);
}

int sxi_cluster_set_mode(sxc_cluster_t *cluster, int readonly) {
    sxi_query_t *query;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    sxi_hostlist_t *hosts;

    if(!cluster) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    sx = sxi_cluster_get_client(cluster);
    conns = sxi_cluster_get_conns(cluster);

    if(!sx || !conns) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    query = sxi_cluster_mode_proto(sx, readonly);
    if(!query) {
        SXDEBUG("Failed to create distlock query");
        return 1;
    }

    hosts = sxi_conns_get_hostlist(conns);
    if(!hosts) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to get cluster host list");
        sxi_query_free(query);
        return 1;
    }

    sxi_set_operation(sx, readonly ? "switch cluster to read-only mode" : "switch cluster to read-write mode", NULL, NULL, NULL);
    if(sxi_job_submit_and_poll(conns, hosts, query->verb, query->path, query->content, query->content_len)) {
        sxi_query_free(query);
        return 1;
    }

    sxi_query_free(query);
    return 0;
}

char *sxc_cluster_configuration_link(sxc_cluster_t *cluster, const char *username, const char *token) {
    unsigned int len;
    char *ret = NULL;
    const char *cluster_name;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    const char *host;
    int port, ssl, is_dns = 1;
    uint8_t certhash[SXI_SHA1_BIN_LEN];
    char fingerprint[SXI_SHA1_TEXT_LEN+1];
    unsigned int certhash_len = 0;
    unsigned int offset;
    char *enc_user = NULL, *enc_token, *enc_host = NULL;

    if(!cluster)
        return NULL;
    if(!token) {
        sxi_seterr(sx, SXE_EARG, "NULL argument: %s", !username ? "username" : "token");
        return ret;
    }
    cluster_name = sxc_cluster_get_sslname(cluster);
    if(!cluster_name) {
        sxi_seterr(sx, SXE_EARG, "Cannot get cluster name");
        return NULL;
    }

    host = sxi_conns_get_dnsname(conns);
    if(!host) {
        sxi_hostlist_t *hosts;

        hosts = sxi_conns_get_hostlist(conns);
        if(!hosts || !sxi_hostlist_get_count(hosts)) {
            sxi_seterr(sx, SXE_ECFG, "Invalid host list");
            return NULL;
        }

        host = sxi_hostlist_get_host(hosts, 0);
        if(!host) {
            sxi_seterr(sx, SXE_ECFG, "Invalid host list");
            return NULL;
        }
        is_dns = 0;
    }

    ssl = sxi_conns_is_secure(conns);
    port = sxc_cluster_get_httpport(cluster);
    if(!port)
        port = (ssl ? 443 : 80);

    if(ssl) {
        const char *cafile = sxi_conns_get_cafile(conns);
        if(!cafile) {
            sxi_seterr(sx, SXE_EMEM, "Failed to get ca file name");
            return NULL;
        }

        if(sxi_vcrypt_get_cert_fingerprint(sx, cafile, certhash, &certhash_len) || certhash_len != SXI_SHA1_BIN_LEN) {
            sxi_seterr(sx, SXE_EMEM, "Failed to get certificate fingerprint");
            return NULL;
        }

        sxi_bin2hex(certhash, certhash_len, fingerprint);
        fingerprint[SXI_SHA1_TEXT_LEN] = '\0';
    }

    len = lenof("sx:///?token=&port=&ssl=y") + strlen(cluster_name) + strlen(token) + 11 + 1;
    if(username) {
        enc_user = sxi_urlencode(sx, username, 1);
        if(!enc_user)
            return NULL;
        len += strlen(enc_user) + 1; /* username@ */
    }
    if(ssl)
        len += lenof("&certhash=") + strlen(fingerprint);
    if(!is_dns) {
        enc_host = sxi_urlencode(sx, host, 1);
        if(!enc_host) {
            free(enc_user);
            return NULL;
        }
        len += lenof("&ip=") + strlen(enc_host);
    }

    enc_token = sxi_urlencode(sx, token, 1);
    if(!enc_token) {
        free(enc_user);
        free(enc_host);
        return NULL;
    }

    ret = malloc(len);
    if(!ret) {
        sxi_seterr(sx, SXE_EMEM, "Out of memory");
        free(enc_user);
        free(enc_host);
        free(enc_token);
        return NULL;
    }
    snprintf(ret, len, "sx://%s%s%s/?token=%s&port=%d&ssl=%c", enc_user ? enc_user : "", enc_user ? "@" : "", cluster_name, enc_token, port, ssl ? 'y' : 'n');
    if(ssl) {
        offset = strlen(ret);
        snprintf(ret + offset, len - offset, "&certhash=%s", fingerprint);
    }
    if(!is_dns) {
        offset = strlen(ret);
        snprintf(ret + offset, len - offset, "&ip=%s", enc_host);
    }
    free(enc_user);
    free(enc_host);
    free(enc_token);
    return ret;
}
