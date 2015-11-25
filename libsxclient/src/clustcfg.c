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
#include <fnmatch.h>

#include "libsxclient-int.h"
#include "cluster.h"
#include "clustcfg.h"
#include "sxreport.h"
#include "sxproto.h"
#include "jobpoll.h"
#include "curlevents.h"
#include "vcrypto.h"
#include "volops.h"
#include "misc.h"
#include <sys/mman.h>
#include "filter.h"
#include "jparse.h"

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

static struct sxi_access *cluster_get_access(sxc_cluster_t *cluster, const char *profile_name) {
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

const char *sxc_cluster_get_access(sxc_cluster_t *cluster, const char *profile_name) {
    struct sxi_access *access;
    sxc_client_t *sx;

    if(!cluster)
        return NULL;
    sx = sxi_cluster_get_client(cluster);
    access = cluster_get_access(cluster, profile_name);
    if(!access) {
        sxi_seterr(sx, SXE_ECFG, "Failed to obtain profile '%s' access token", profile_name ? profile_name : "default");
        return NULL;
    }
    return access->auth;
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

    access = cluster_get_access(cluster, profile_name);
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
    struct sxi_access *access = cluster_get_access(cluster, profile_name);
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

    access = cluster_get_access(cluster, profile);
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
    printf("libsxclient version: %s\n", sxc_get_version());

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
    const struct jparse_actions *acts;
    jparse_t *J;
    sxi_hostlist_t hlist;
    enum sxc_error_t err;
};

/* {"nodeList":["node1", "node2"]} */
static void cb_fetchnodes(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
    char *host;

    if(!length) {
	sxi_jparse_cancel(J, "Empty node address received");
	yactx->err = SXE_ECOMM;
	return;
    }

    if(!(host = malloc(length+1))) {
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
	yactx->err = SXE_EMEM;
	return;
    }

    memcpy(host, string, length);
    host[length] = '\0';
    if(sxi_hostlist_add_host(sx, &yactx->hlist, host)) {
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
        yactx->err = SXE_EMEM;
        sxc_clearerr(sx);
	free(host);
	return;
    }

    free(host);
}


static int fetchnodes_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;

    yactx->cbdata = cbdata; /* must set before using CBDEBUG */
    sxi_jparse_destroy(yactx->J);
    yactx->err = SXE_ECOMM;
    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    sxi_hostlist_empty(&yactx->hlist);
    return 0;
}

static int fetchnodes_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_fetchnodes_ctx *yactx = (struct cb_fetchnodes_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

int sxc_cluster_fetchnodes(sxc_cluster_t *cluster) {
    const struct jparse_actions acts = {
	JPACTS_STRING(JPACT(cb_fetchnodes, JPKEY("nodeList"), JPANYITM))
    };
    struct cb_fetchnodes_ctx yctx;
    sxc_client_t *sx = cluster->sx;
    sxi_hostlist_t *orighlist;
    int ret = 1;

    sxi_hostlist_init(&yctx.hlist);
    yctx.acts = &acts;
    yctx.J = NULL;

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

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
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
    sxi_jparse_destroy(yctx.J);
    sxi_hostlist_empty(&yctx.hlist);

    return ret;
}


struct cb_locate_ctx {
    curlev_context_t *cbdata;
    const struct jparse_actions *acts;
    jparse_t *J;
    sxi_hostlist_t *hlist;
    sxc_meta_t *meta;
    sxc_meta_t *custom_meta;
    int64_t blocksize;
    enum sxc_error_t err;
};

/* {"nodeList":["adsd1", "addr2", ...], "blockSize":1234, "volumeMeta":{"key":"hexval", ...}, "customVolumeMeta":{"key":"hexval", ...} } */

static void cb_locate_node(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));
    char *host;

    if(!length) {
	sxi_jparse_cancel(J, "Empty node address received");
	yactx->err = SXE_ECOMM;
	return;
    }

    if(!(host = malloc(length+1))) {
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
	yactx->err = SXE_EMEM;
	return;
    }
    memcpy(host, string, length);
    host[length] = '\0';

    if(sxi_hostlist_add_host(sx, yactx->hlist, host)) {
	sxi_jparse_cancel(J, "Out of memory processing list of nodes");
        yactx->err = SXE_EMEM;
        sxc_clearerr(sx);
	free(host);
	return;
    }

    free(host);
}

static void cb_locate_bs(jparse_t *J, void *ctx, int64_t num) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;

    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid blocksize received");
	yactx->err = SXE_ECOMM;
	return;
    }

    yactx->blocksize = num;
}

static void cb_locate_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));

    if(yactx->meta && sxc_meta_setval_fromhex(yactx->meta, key, string, length)) {
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
}

static void cb_locate_custom_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    sxc_client_t *sx = sxi_conns_get_client(sxi_cbdata_get_conns(yactx->cbdata));

    if(yactx->custom_meta && sxc_meta_setval_fromhex(yactx->custom_meta, key, string, length)) {
	if(sxc_geterrnum(sx) == SXE_EARG) {
	    sxi_jparse_cancel(J, "Invalid custom volume metadata received");
	    yactx->err = SXE_ECOMM;
	} else {
	    sxi_jparse_cancel(J, "Out of memory processing custom metadata");
	    yactx->err = SXE_EMEM;
	}
	sxc_clearerr(sx);
	return;
    }
}

static int locate_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;

    yactx->cbdata = cbdata; /* must set before using CBDEBUG */
    sxi_jparse_destroy(yactx->J);
    yactx->err = SXE_ECOMM;

    if(!(yactx->J = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot update list of nodes: Out of memory");
	return 1;
    }

    yactx->blocksize = -1;
    sxc_meta_empty(yactx->meta);
    sxc_meta_empty(yactx->custom_meta);
    sxi_hostlist_empty(yactx->hlist);
    return 0;
}

static int locate_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_locate_ctx *yactx = (struct cb_locate_ctx *)ctx;
    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

int sxi_volume_info(sxi_conns_t *conns, const char *volume, sxi_hostlist_t *nodes, int64_t *size, sxc_meta_t *meta, sxc_meta_t *custom_meta) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_locate_node, JPKEY("nodeList"), JPANYITM),
		      JPACT(cb_locate_meta, JPKEY("volumeMeta"), JPANYKEY),
		      JPACT(cb_locate_custom_meta, JPKEY("customVolumeMeta"), JPANYKEY)
		      ),
	JPACTS_INT64(JPACT(cb_locate_bs, JPKEY("blockSize")))
    };
    struct cb_locate_ctx yctx;
    char *enc_vol, *url;
    int qret;
    sxc_client_t *sx = sxi_conns_get_client(conns);

    sxc_clearerr(sx);
    if(sxi_getenv("SX_DEBUG_SINGLE_VOLUMEHOST")) {
        sxi_hostlist_empty(nodes);
        sxi_hostlist_add_host(sx, nodes, sxi_getenv("SX_DEBUG_SINGLE_VOLUMEHOST"));
        return 0;
    }
    if(!(enc_vol = sxi_urlencode(sx, volume, 0))) {
	SXDEBUG("failed to encode volume %s", volume);
	return 1;
    }

    if(!(url = malloc(strlen(enc_vol) + lenof("?o=locate&volumeMeta&customVolumeMeta&size=") + 64))) {
	SXDEBUG("OOM allocating url (%lu bytes)", strlen(enc_vol) + lenof("?o=locate&volumeMeta&size=") + 64);
	sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
	free(enc_vol);
	return 1;
    }
    if(size)
	sprintf(url, "%s?o=locate&size=%lld", enc_vol, (long long int)*size);
    else
	sprintf(url, "%s?o=locate", enc_vol);
    if(meta)
	strcat(url, "&volumeMeta");
    if(custom_meta)
        strcat(url, "&customVolumeMeta");
    free(enc_vol);

    yctx.acts = &acts;
    yctx.J = NULL;
    yctx.hlist = nodes;
    yctx.meta = meta;
    yctx.custom_meta = custom_meta;

    sxi_set_operation(sx, "locate volume", sxi_conns_get_sslname(conns), volume, NULL);
    qret = sxi_cluster_query(conns, NULL, REQ_GET, url, NULL, 0, locate_setup_cb, locate_cb, &yctx);
    free(url);
    if(qret != 200) {
	SXDEBUG("query returned %d", qret);
	sxi_jparse_destroy(yctx.J);
	sxc_meta_empty(meta);
        sxc_meta_empty(custom_meta);
        sxi_seterr(sx, SXE_ECOMM, "failed to query volume location");
        /* we must return an error code */
	return qret ? qret : -1;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	sxi_jparse_destroy(yctx.J);
        sxc_meta_empty(custom_meta);
	sxc_meta_empty(meta);
	return -yctx.err;
    }
    sxi_jparse_destroy(yctx.J);

    if(size)
	*size = yctx.blocksize;

    if(sxi_getenv("SX_DEBUG_SINGLEHOST")) {
	sxi_hostlist_empty(nodes);
	sxi_hostlist_add_host(sx, nodes, sxi_getenv("SX_DEBUG_SINGLEHOST"));
    }
    return 0;
}

int sxi_locate_volume(sxi_conns_t *conns, const char *volume, sxi_hostlist_t *nodes, int64_t *size, sxc_meta_t *metadata, sxc_meta_t *custom_metadata) {
    sxi_set_operation(sxi_conns_get_client(conns), "locate volume", volume, NULL, NULL);
    return sxi_volume_info(conns, volume, nodes, size, metadata, custom_metadata);
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
    unsigned int metalen;
    unsigned int fuck_off_valgrind;
};

struct cb_listfiles_ctx {
    curlev_context_t *cbdata;
    const struct jparse_actions *acts;
    jparse_t *J;
    sxc_client_t *sx;
    FILE *f;
    uint64_t volume_size;
    int64_t volume_used_size;
    char *frev;
    struct cbl_file_t file;
    unsigned int replica;
    unsigned int effective_replica;
    unsigned int nfiles;
    const char *etag_in;
    char *etag_out;
    sxc_meta_t *file_meta;
    enum sxc_error_t err;
};

/*
{
   "volumeSize":1234,
   "volumeUsedSize":1234,
   "replicaCount":2,
   "effectiveReplicaCount":1,
   "fileList":{
       "MSDOS.SYS":{
           "fileSize":65536,
	   "blockSize":1024,
	   "createdAt":12345,
	   "fileRevision":"1.0",
	   "fileMeta":{
	       "key":"hexval", ...
	   }
       },
       "COMMAND.COM":{
           "fileSize":32768,
	   "blockSize":1024,
	   "createdAt":12345,
	   "fileRevision":"1.0",
	   "fileMeta":{
	       "key":"hexval", ...
	   }
       }
   }
}
*/

static void cb_listfiles_volsize(jparse_t *J, void *ctx, int64_t num) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid volume size received");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->volume_size = num;
}

static void cb_listfiles_usedvolsize(jparse_t *J, void *ctx, int64_t num) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid used volume size received");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->volume_used_size = num;
}

static void cb_listfiles_replica(jparse_t *J, void *ctx, int32_t num) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid replica count received");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->replica = num;
}

static void cb_listfiles_effreplica(jparse_t *J, void *ctx, int32_t num) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid effective replica count received");
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->effective_replica = num;
}


static void cb_listfiles_file_size(jparse_t *J, void *ctx, int64_t num) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid size for file %s", key);
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->file.filesize = num;
}

static void cb_listfiles_file_ctime(jparse_t *J, void *ctx, int64_t num) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid creation time for file %s", key);
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->file.created_at = num;
}

static void cb_listfiles_file_bs(jparse_t *J, void *ctx, int32_t num) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(num <= 0) {
	sxi_jparse_cancel(J, "Invalid block size for file %s", key);
	yactx->err = SXE_ECOMM;
	return;
    }
    yactx->file.blocksize = num;
}

static void cb_listfiles_file_rev(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    yactx->frev = malloc(length + 1);
    if(!yactx->frev) {
	sxi_jparse_cancel(J, "Invalid block size for file %s", key);
	yactx->err = SXE_EMEM;
	return;
    }
    memcpy(yactx->frev, string, length);
    yactx->file.revlen = length;
}

static void cb_listfiles_file_meta(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    const char *fname = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    const char *key = sxi_jpath_mapkey(sxi_jpath_down(sxi_jpath_down(sxi_jpath_down(sxi_jparse_whereami(J)))));
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(!yactx->file_meta)
	yactx->file_meta = sxc_meta_new(yactx->sx);
    if(!yactx->file_meta) {
	sxi_jparse_cancel(J, "Out of memory processing file metadata");
	yactx->err = SXE_EMEM;
        sxc_clearerr(yactx->sx);
	return;
    }
    if(sxc_meta_setval_fromhex(yactx->file_meta, key, string, length)) {
	if(sxc_geterrnum(yactx->sx) == SXE_EARG) {
	    sxi_jparse_cancel(J, "Invalid file metadata received for file %s (key %s)", fname, key);
	    yactx->err = SXE_ECOMM;
	} else {
	    sxi_jparse_cancel(J, "Out of memory processing file metadata");
	    yactx->err = SXE_EMEM;
	}
	sxc_clearerr(yactx->sx);
	return;
    }

    yactx->file.metalen += strlen(key) + length / 2;
}

static void cb_listfiles_file_init(jparse_t *J, void *ctx) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;
    yactx->file.revlen = 0;
    yactx->file.created_at = -1;
    yactx->file.filesize = -1;
    yactx->file.blocksize = 0;
    yactx->file.metalen = 0;
    yactx->nfiles++;
}

static void cb_listfiles_file_complete(jparse_t *J, void *ctx) {
    const char *fname = sxi_jpath_mapkey(sxi_jpath_down(sxi_jparse_whereami(J)));
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    yactx->file.namelen = strlen(fname);
    if(!yactx->file.namelen) {
	sxi_jparse_cancel(J, "Empty file name received");
	yactx->err = SXE_ECOMM;
	return;
    }
    if(!yactx->file.revlen) {
	if(fname[yactx->file.namelen-1] != '/') {
	    sxi_jparse_cancel(J, "Bad directory name '%s'", fname);
	    yactx->err = SXE_ECOMM;
	    return;
	}
	yactx->file.filesize = 0;
	yactx->file.blocksize = 0;
	yactx->file.created_at = 0;
	yactx->file.metalen = 0;
    } else if(yactx->file.filesize < 0 || !yactx->file.blocksize || yactx->file.created_at < 0) {
	sxi_jparse_cancel(J, "Missing attributes for file '%s'", fname);
	yactx->err = SXE_ECOMM;
	return;
    }

    if(yactx->file_meta)
	yactx->file.metalen += sxc_meta_count(yactx->file_meta) * sizeof(unsigned int) * 2;

    if(!fwrite(&yactx->file, sizeof(yactx->file), 1, yactx->f) ||
       !fwrite(fname, yactx->file.namelen, 1, yactx->f) ||
       (yactx->file.revlen && !fwrite(yactx->frev, yactx->file.revlen, 1, yactx->f))) {
	sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxi_cbdata_geterrmsg(yactx->cbdata));
	yactx->err = SXE_EWRITE;
	return;
    }

    if(yactx->file_meta) {
	unsigned int i;
	for(i = 0; i < sxc_meta_count(yactx->file_meta); i++) {
	    const char *key;
	    const void *value;
	    unsigned int key_len, value_len;

	    if(sxc_meta_getkeyval(yactx->file_meta, i, &key, &value, &value_len)) {
		sxi_jparse_cancel(J, "%s", sxc_geterrmsg(yactx->sx));
		yactx->err = SXE_ECOMM; /* For the lack of a better one */
		sxc_clearerr(yactx->sx);
		return;
	    }

	    key_len = strlen(key);
	    if(!fwrite(&key_len, sizeof(key_len), 1, yactx->f) ||
	       !fwrite(key, key_len, 1, yactx->f) ||
	       !fwrite(&value_len, sizeof(value_len), 1, yactx->f) ||
	       !fwrite(value, value_len, 1, yactx->f)) {
		sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
		sxi_jparse_cancel(J, "%s", sxi_cbdata_geterrmsg(yactx->cbdata));
		yactx->err = SXE_EWRITE;
		return;
	    }
	}
    }

    if(!fwrite(&yactx->file, sizeof(yactx->file), 1, yactx->f)) {
	sxi_cbdata_setsyserr(yactx->cbdata, SXE_EWRITE, "Failed to write to temporary file");
	sxi_jparse_cancel(J, "%s", sxi_cbdata_geterrmsg(yactx->cbdata));
	yactx->err = SXE_EWRITE;
	return;
    }

    free(yactx->frev);
    yactx->frev = NULL;
    sxc_meta_free(yactx->file_meta);
    yactx->file_meta = NULL;
}

static int listfiles_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    yactx->cbdata = cbdata; /* must set before using CBDEBUG */
    sxi_cbdata_set_etag(cbdata, yactx->etag_in, yactx->etag_in ? strlen(yactx->etag_in) : 0);
    CBDEBUG("ETag: %s", yactx->etag_in ? yactx->etag_in : "");

    sxi_jparse_destroy(yactx->J);
    yactx->err = SXE_ECOMM;
    if(!(yactx->J  = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "List failed: Out of memory");
	return 1;
    }

    rewind(yactx->f);
    yactx->volume_size = 0;
    yactx->volume_used_size = 0;
    yactx->replica = 0;
    yactx->effective_replica = 0;
    free(yactx->frev);
    yactx->frev = NULL;
    yactx->file.filesize = -1;
    yactx->file.created_at = -1;
    yactx->file.namelen = 0;
    yactx->file.revlen = 0;
    yactx->file.metalen = 0;
    yactx->file.fuck_off_valgrind = 0;
    yactx->nfiles = 0;
    sxc_meta_free(yactx->file_meta);
    yactx->file_meta = NULL;

    return 0;
}

static int listfiles_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_listfiles_ctx *yactx = (struct cb_listfiles_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
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
    sxf_handle_t *filter;
    char *filter_dir;
    sxc_file_t **processed_list; /* When file list is already processed, then this list will contain all the items. */
    unsigned int nprocessed_entries; /* Number of processed file entries in the processed_list array */
    unsigned int cur_processed_file; /* Index of current processed file entry */
    char *pattern; /* Original pattern used if filter wants to process filenames. Used to locally match processed filenames with pattern. */
    int recursive;
    sxc_meta_t *custom_volume_meta;
    int meta_fetched;
    int meta_requested;
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

static sxc_cluster_lf_t *sxi_cluster_listfiles(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *effective_replica_count, unsigned int *nfiles, int reverse, const char *etag_in, char **etag_out) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_listfiles_file_rev, JPKEY("fileList"), JPANYKEY, JPKEY("fileRevision")),
		      JPACT(cb_listfiles_file_meta, JPKEY("fileList"), JPANYKEY, JPKEY("fileMeta"), JPANYKEY)
		      ),
	JPACTS_INT32(
		     JPACT(cb_listfiles_replica, JPKEY("replicaCount")),
		     JPACT(cb_listfiles_effreplica, JPKEY("effectiveReplicaCount")),
		     JPACT(cb_listfiles_file_bs, JPKEY("fileList"), JPANYKEY, JPKEY("blockSize"))
		     ),
	JPACTS_INT64(
		     JPACT(cb_listfiles_volsize, JPKEY("volumeSize")),
		     JPACT(cb_listfiles_usedvolsize, JPKEY("volumeUsedSize")),
		     JPACT(cb_listfiles_file_size, JPKEY("fileList"), JPANYKEY, JPKEY("fileSize")),
		     JPACT(cb_listfiles_file_ctime, JPKEY("fileList"), JPANYKEY, JPKEY("createdAt"))
		     ),
	JPACTS_MAP_BEGIN(
			 JPACT(
			       cb_listfiles_file_init, JPKEY("fileList"), JPANYKEY)
			 ),
	JPACTS_MAP_END(
			 JPACT(
			       cb_listfiles_file_complete, JPKEY("fileList"), JPANYKEY)
			 )
    };
    char *enc_vol, *enc_glob = NULL, *url, *fname;
    struct cb_listfiles_ctx yctx;
    sxc_cluster_lf_t *ret;
    unsigned int len;
    int qret;
    char *cur;
    sxi_conns_t *conns = sxi_cluster_get_conns(cluster);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    int qm = 1; /* state if we want to add quotation mark or ampersand */
    const void *mval;
    unsigned int mval_len;
    sxc_meta_t *vmeta, *cvmeta;
    struct filter_handle *fh = NULL;
    sxi_hostlist_t volhosts;
    int fetch_meta = 0;
    char *filter_cfgdir = NULL;

    sxc_clearerr(sx);
    memset(&yctx, 0, sizeof(yctx));
    yctx.etag_in = etag_in;
    if (etag_out) *etag_out = NULL;

    if(!volume) {
        SXDEBUG("NULL argument");
        return NULL;
    }

    vmeta = sxc_meta_new(sx);
    if(!vmeta) {
        SXDEBUG("Failed to initialize volume meta");
        return NULL;
    }

    cvmeta = sxc_meta_new(sx);
    if(!cvmeta) {
        SXDEBUG("Failed to initialize volume meta");
        sxc_meta_free(vmeta);
        return NULL;
    }

    /* Locate volume in order to obtain volume meta */
    sxi_set_operation(sx, "get volume metadata", NULL, NULL, NULL);
    sxi_hostlist_init(&volhosts);
    if(sxi_locate_volume(conns, volume, &volhosts, NULL, vmeta, cvmeta)) {
        SXDEBUG("Failed to locate volume %s", volume);
        sxc_meta_free(vmeta);
        sxc_meta_free(cvmeta);
        sxi_hostlist_empty(&volhosts);
        return NULL;
    }

    if(sxi_volume_cfg_check(sx, cluster, vmeta, volume)) {
        sxi_hostlist_empty(&volhosts);
        sxc_meta_free(vmeta);
        sxc_meta_free(cvmeta);
        return NULL;
    }

    if(!sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
        char filter_uuid[37], cfgkey[37 + 5];
        const void *cfgval = NULL;
        unsigned int cfgval_len = 0;
        const char *confdir;

        if(mval_len != 16) {
            SXDEBUG("Filter(s) enabled but can't handle metadata");
            sxc_meta_free(vmeta);
            sxc_meta_free(cvmeta);
            sxi_hostlist_empty(&volhosts);
            return NULL;
        }
        sxi_uuid_unparse(mval, filter_uuid);
        fh = sxi_filter_gethandle(sx, mval);
        if(!fh) {
            SXDEBUG("Filter ID %s required by destination volume not found", filter_uuid);
            sxc_meta_free(vmeta);
            sxc_meta_free(cvmeta);
            sxi_hostlist_empty(&volhosts);
            return NULL;
        }
        snprintf(cfgkey, sizeof(cfgkey), "%s-cfg", filter_uuid);
        sxc_meta_getval(vmeta, cfgkey, &cfgval, &cfgval_len);
        if(cfgval_len && sxi_filter_add_cfg(fh, volume, cfgval, cfgval_len)) {
            sxc_meta_free(vmeta);
            sxc_meta_free(cvmeta);
            sxi_hostlist_empty(&volhosts);
            return NULL;
        }
        confdir = sxi_cluster_get_confdir(cluster);
        if(confdir) {
            filter_cfgdir = sxi_get_filter_dir(sx, confdir, filter_uuid, volume);
            if(!filter_cfgdir) {
                sxc_meta_free(vmeta);
                sxc_meta_free(cvmeta);
                sxi_hostlist_empty(&volhosts);
                return NULL;
            }
        }
        if(fh && (fh->f->file_process || fh->f->filemeta_process))
            fetch_meta = 1;
    }
    sxc_meta_free(vmeta);

    sxi_set_operation(sx, "list files", sxi_conns_get_sslname(conns), volume, NULL);

    if(!(enc_vol = sxi_urlencode(sx, volume, 0))) {
        SXDEBUG("failed to encode volume %s", volume);
        sxi_hostlist_empty(&volhosts);
        sxc_meta_free(cvmeta);
        free(filter_cfgdir);
        return NULL;
    }

    len = strlen(enc_vol) + 1;
    if(!(fh && fh->f->filemeta_process) && glob_pattern) {
        if(!(enc_glob = sxi_urlencode(sx, glob_pattern, 1))) {
            SXDEBUG("failed to encode pattern %s", glob_pattern);
	    free(enc_vol);
            sxi_hostlist_empty(&volhosts);
            free(filter_cfgdir);
            sxc_meta_free(cvmeta);
	    return NULL;
	}
	len += lenof("?filter=") + strlen(enc_glob);
    }

    if(recursive || (fh && fh->f->filemeta_process))
	len += lenof("&recursive");
    if(fetch_meta)
        len += lenof("&meta");

    if(!(url = malloc(len))) {
        SXDEBUG("OOM allocating url (%u bytes)", len);
        sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
	free(enc_vol);
	free(enc_glob);
        sxi_hostlist_empty(&volhosts);
        free(filter_cfgdir);
        sxc_meta_free(cvmeta);
	return NULL;
    }

    sprintf(url, "%s", enc_vol);
    cur = url + strlen(enc_vol);
    if(enc_glob) {
        sprintf(cur, "?filter=%s", enc_glob);
        qm = 0;
        cur += strlen(cur);
    }
    if(recursive || (fh && fh->f->filemeta_process)) {
        sprintf(cur, "%s", qm ? "?recursive" : "&recursive");
        qm = 0;
        cur += strlen(cur);
    }
    if(fetch_meta) {
        sprintf(cur, "%s", qm ? "?meta" : "&meta");
        qm = 0;
        cur += strlen(cur);
    }
    free(enc_vol);
    free(enc_glob);

    if(!(fname = sxi_make_tempfile(sx, NULL, &yctx.f))) {
        SXDEBUG("failed to create temporary storage for file list");
	free(url);
        sxi_hostlist_empty(&volhosts);
        free(filter_cfgdir);
        sxc_meta_free(cvmeta);
	return NULL;
    }

    yctx.sx = sx;
    yctx.acts = &acts;

    sxi_set_operation(sx, "list volume files", sxi_conns_get_sslname(conns), volume, NULL);
    qret = sxi_cluster_query(conns, &volhosts, REQ_GET, url, NULL, 0, listfiles_setup_cb, listfiles_cb, &yctx);
    sxi_hostlist_empty(&volhosts);
    free(url);
    free(yctx.frev);
    if(qret != 200) {
        SXDEBUG("query returned %d", qret);
	sxi_jparse_destroy(yctx.J);
        free(yctx.etag_out);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
        free(filter_cfgdir);
        sxc_meta_free(yctx.file_meta);
        sxc_meta_free(cvmeta);
        if (qret == 304)
            sxi_seterr(sxi_conns_get_client(conns), SXE_SKIP, "Not modified");
	return NULL;
    }

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
	sxi_jparse_destroy(yctx.J);
        free(yctx.etag_out);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
        free(filter_cfgdir);
        sxc_meta_free(yctx.file_meta);
        sxc_meta_free(cvmeta);
	return NULL;
    }
    sxi_jparse_destroy(yctx.J);

    if(fflush(yctx.f) ||
       ftruncate(fileno(yctx.f), ftell(yctx.f)) ||
       fseek(yctx.f, 0, reverse ? SEEK_END : SEEK_SET)) {
        sxi_seterr(sx, SXE_EWRITE, "List failed: Failed to write temporary data");
        free(yctx.etag_out);
	fclose(yctx.f);
	unlink(fname);
	free(fname);
        free(filter_cfgdir);
        sxc_meta_free(yctx.file_meta);
        sxc_meta_free(cvmeta);
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
        free(filter_cfgdir);
        sxc_meta_free(yctx.file_meta);
        sxc_meta_free(cvmeta);
	return NULL;
    }

    ret->pattern = glob_pattern  && *glob_pattern ? strdup(glob_pattern) : strdup("*");
    if(!ret->pattern) {
        SXDEBUG("OOM allocating original pattern");
        sxi_seterr(sx, SXE_EMEM, "List failed: Out of memory");
        free(yctx.etag_out);
        fclose(yctx.f);
        unlink(fname);
        free(fname);
        free(ret);
        free(filter_cfgdir);
        sxc_meta_free(yctx.file_meta);
        sxc_meta_free(cvmeta);
        return NULL;
    }

    if(volume_used_size)
        *volume_used_size = yctx.volume_used_size;

    if(volume_size)
	*volume_size = yctx.volume_size;

    if(replica_count)
	*replica_count = yctx.replica;

    if(effective_replica_count)
	*effective_replica_count = yctx.effective_replica > 0 ? yctx.effective_replica : yctx.replica;

    if(nfiles)
	*nfiles = yctx.nfiles;

    ret->sx = sx;
    ret->f = yctx.f;
    ret->fname = fname;
    ret->want_relative = glob_pattern && *glob_pattern && glob_pattern[strlen(glob_pattern)-1] == '/';
    ret->pattern_slashes = sxi_count_slashes(glob_pattern);
    ret->reverse = reverse;
    ret->filter = fh;
    ret->filter_dir = filter_cfgdir;
    ret->processed_list = NULL;
    ret->nprocessed_entries = 0;
    ret->cur_processed_file = 0;
    ret->recursive = recursive;
    ret->custom_volume_meta = cvmeta;
    ret->meta_fetched = (fetch_meta && yctx.file_meta) ? 1 : 0;
    ret->meta_requested = fetch_meta;
    if (yctx.etag_out) {
        if (etag_out && *yctx.etag_out)
            *etag_out = yctx.etag_out;
        else
            free(yctx.etag_out);
    }
    return ret;
}

static void listfiles_reset(sxc_cluster_lf_t *lf) {
    if(lf) {
        rewind(lf->f);
        lf->cur_processed_file = 0;
    }
}

static int file_entry_cmp(const void *a, const void *b) {
   const sxc_file_t **f1 = (const sxc_file_t**)a;
   const sxc_file_t **f2 = (const sxc_file_t**)b;
   return strcmp(sxc_file_get_path(*f1), sxc_file_get_path(*f2));
}

sxc_cluster_lf_t *sxc_cluster_listfiles_etag(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *effective_replica_count, unsigned int *nfiles, int reverse, const char *etag_file) {
    sxc_cluster_lf_t *ret;
    const char *confdir = sxi_cluster_get_confdir(cluster);
    char *path = NULL;
    char etag[1024];
    char *etag_out = NULL;
    sxc_client_t *sx = sxi_cluster_get_client(cluster);

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

    ret = sxi_cluster_listfiles(cluster, volume, glob_pattern, recursive, volume_used_size, volume_size, replica_count, effective_replica_count, nfiles, reverse, *etag ? etag : NULL, &etag_out);
    SXDEBUG("ETag out: %s", etag_out ? etag_out : "");

    /* Returned list requires processing filenames, will need to iterate the list and process it first */
    if(ret && ret->filter && ret->filter->f->filemeta_process) {
        sxc_file_t **list;
        unsigned int nitems = 0;
        unsigned int alloc_items = 128;
        int n;
        sxc_file_t *file = NULL;

        list = malloc(alloc_items * sizeof(sxc_file_t*));
        if(!list) {
            SXDEBUG("Out of memory allocating file list array");
            sxc_cluster_listfiles_free(ret);
            free(etag_out);
            free(path);
            return NULL;
        }

        while((n = sxc_cluster_listfiles_next(cluster, volume, ret, &file)) >= 1) {
            if(n == 2 && sxc_geterrnum(sx) == SXE_SKIP) {
                SXDEBUG("Skipping file");
                continue;
            }

            if(nitems + 1 > alloc_items) {
                void **oldptr = (void**)list;
                alloc_items *= 2;
                list = realloc(oldptr, alloc_items * sizeof(sxc_file_t*));
                if(!list) {
                    unsigned int i;

                    SXDEBUG("Failed to realloc file list array");
                    sxi_seterr(sx, SXE_EMEM, "Failed to realloc file list array");
                    for(i = 0; i < nitems; i++)
                        sxc_file_free(oldptr[i]);
                    free(oldptr);
                    sxc_file_free(file);
                    free(etag_out);
                    free(path);
                    return NULL;
                }
            }

            list[nitems] = file;
            nitems++;
        }

        if(n < 0) {
            unsigned int i;

            SXDEBUG("Failed to process all files: %s", sxc_geterrmsg(sx));
            sxi_seterr(sx, SXE_EARG, "Failed to process file list");
            free(etag_out);
            free(path);
            for(i = 0; i < nitems; i++)
                sxc_file_free(list[i]);
            free(list);
            sxc_cluster_listfiles_free(ret);
            return NULL;
        }

        qsort(list, nitems, sizeof(sxc_file_t*), file_entry_cmp);
        listfiles_reset(ret);
        ret->processed_list = list;
        ret->nprocessed_entries = nitems;
        if(nfiles)
            *nfiles = nitems;
    }

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

sxc_cluster_lf_t *sxc_cluster_listfiles(sxc_cluster_t *cluster, const char *volume, const char *glob_pattern, int recursive, int64_t *volume_used_size, int64_t *volume_size, unsigned int *replica_count, unsigned int *effective_replica_count, unsigned int *nfiles, int reverse) {
    return sxc_cluster_listfiles_etag(cluster, volume, glob_pattern, recursive, volume_used_size, volume_size, replica_count, effective_replica_count, nfiles, reverse, NULL);
}

/* Perform listed file postprocessing, return 1 when file can be listed, return 2 when it is skipped due to pattern matching fail. Return negative
 * value when error encountered. */
static int listfiles_postproc_file(sxc_cluster_lf_t *lf, sxc_file_t *f) {
    sxc_client_t *sx = lf ? lf->sx : NULL;

    if(!sx)
        return -1;
    if(!lf || !f) {
        sxi_seterr(sx, SXE_EARG, "NULL argument");
        return -1;
    }

    /* Perform processing only when filename processing filter is applied (pattern should be set correctly too, but checked just in case) */
    if(lf->filter && lf->filter->f->filemeta_process && lf->pattern) {
        char *path = strdup(sxc_file_get_path(f)), *origpath;
        char *q1 = NULL, *q2 = NULL; /* Used to modify the path */
        char tmp; /* Byte stored at q1 */
        int last_slash = 0; /* Set to 1 if pattern ends with slash */

        if(!path) {
            SXDEBUG("Failed to duplicate file path");
            sxi_seterr(sx, SXE_EMEM, "Out of memory");
            return -1;
        }

        /*      sample          - pattern    *
         *     /sample/path/1   - 'origpath' *
         *      ^               - 'path'     *
         *            ^         - 'q1'       *
         *                 ^    - 'q2'       */

        /* In this example pattern ends with slash *
         *      sample/          - pattern         *
         *     /sample/path/1    - 'origpath'      *
         *      ^                - 'path'          *
         *             ^         - 'q1'            *
         *                 ^     - 'q2'            */

        origpath = path;
        /* Cut off preceding slashes */
        if(lf->pattern && *lf->pattern != '/' && *path == '/')
            path++;

        /* Check if pattern ends with slash */
        if(strlen(lf->pattern) && lf->pattern[strlen(lf->pattern)-1] == '/')
            last_slash = 1;

        /* Cut path in the place, where pattern ends with slash */
        q1 = sxi_ith_slash(path, lf->pattern_slashes + 1 - last_slash);

        /* More slashes in path (or the same when pattern ends with slas), cut off the rest*/
        if(q1) {
            if(last_slash) /* If pattern ends with slash, cut off the part after last slash */
                tmp = *++q1;
            else
                tmp = *q1;
            *q1 = '\0';
        }

        /* Path (may be modified by q1) do not contain more slashes than pattern, use fnmatch to match with pattern */
        if(fnmatch(lf->pattern, path, 0)) {
            SXDEBUG("Skipping file %s due to failed pattern match with %s", path, lf->pattern);
            sxi_seterr(sx, SXE_SKIP, "Filename does not match provided pattern");
            free(origpath);
            return 2;
        }

        /* At this stage only paths which match the pattern up to lf->pattern_slashes + 1 are possible */

        if(q1)
            *q1 = tmp;

        /* Non-recursive listing requires cutting off fakedir contents and leaving only filenames ending with slashes. */
        if(!lf->recursive) {
            /* Non-recursive listing, find next slash */
            q2 = sxi_ith_slash(path, lf->pattern_slashes + 1);
            if(q2) {
                /* Drop dir contents */
                q2[1] = '\0';

                if(sxi_file_set_size(f, SXC_UINT64_UNDEFINED) || sxi_file_set_remote_size(f, SXC_UINT64_UNDEFINED) ||
                   sxi_file_set_created_at(f, SXC_UINT64_UNDEFINED) || sxi_file_set_atime(f, SXC_UINT64_UNDEFINED) ||
                   sxi_file_set_ctime(f, SXC_UINT64_UNDEFINED) || sxi_file_set_mtime(f, SXC_UINT64_UNDEFINED) ||
                   sxi_file_set_uid(f, SXC_UINT32_UNDEFINED) || sxi_file_set_gid(f, SXC_UINT32_UNDEFINED) ||
                   sxi_file_set_uid(f, SXC_UINT32_UNDEFINED)) {
                    SXDEBUG("Failed to reset file properties");
                    free(origpath);
                    return -1;
                }

                /* Save the modified origpath (path with preceding slashes included) */
                SXDEBUG("Saving modified path: %s -> %s", sxc_file_get_path(f), origpath);
                if(sxc_file_set_path(f, origpath)) {
                    SXDEBUG("Failed to update file path");
                    free(origpath);
                    return -1;
                }
            }
        } /* else origpath was not changed, which is desired for recursive listing */

        free(origpath);
    }

    return 1;
}

static int listfiles_next_list(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file) {
    unsigned int i;
    sxc_file_t *out;

    if(!cluster || !volume || !lf || !file)
        return -1;
    if(lf->cur_processed_file >= lf->nprocessed_entries)
        return 0;
    i = lf->cur_processed_file + 1;
    while(i < lf->nprocessed_entries && (!lf->processed_list[i] || !file_entry_cmp(&lf->processed_list[lf->cur_processed_file], &lf->processed_list[i])))
        i++; /* Iterate over list until different file is encountered, list is already sorted */
    out = sxi_file_dup(lf->processed_list[lf->cur_processed_file]);
    if(!out)
        return -1;
    *file = out;
    lf->cur_processed_file = i;
    return 1;
}

static int listfiles_next_file(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file) {
    struct cbl_file_t cb_file;
    sxc_client_t *sx = lf->sx;
    int ret = -1;
    sxc_file_t *f = NULL;
    char *remote_path = NULL;
    unsigned int remote_path_len = 0;
    char *rev = NULL;
    sxc_meta_t *meta = NULL;

    if(!file) {
        SXDEBUG("Invalid argument: File pointer not provided");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return -1;
    }

    *file = NULL;

    if(!fread(&cb_file, sizeof(cb_file), 1, lf->f)) {
        if(ferror(lf->f)) {
            SXDEBUG("error reading attributes from results file");
            sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
        } else
            ret = 0;
        goto lfnext_out;
    }
    if((cb_file.namelen | cb_file.revlen) & 0x80000000) {
        SXDEBUG("Invalid data length from cache file");
        sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Bad data from cache file");
        goto lfnext_out;
    }

    remote_path = malloc(cb_file.namelen + 1);
    if(!remote_path) {
        SXDEBUG("OOM allocating result file name (%u bytes)", cb_file.namelen);
        sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
        goto lfnext_out;
    }
    if(!fread(remote_path, cb_file.namelen, 1, lf->f)) {
        SXDEBUG("error reading name from results file");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
        goto lfnext_out;
    }
    remote_path[cb_file.namelen] = '\0';
    remote_path_len = cb_file.namelen;
    cb_file.namelen = 0;

    if(cb_file.revlen) {
        fseek(lf->f, cb_file.namelen, SEEK_CUR);
        rev = malloc(cb_file.revlen + 1);
        if(!rev) {
            SXDEBUG("OOM allocating result file revision (%u bytes)", cb_file.revlen);
            sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
            goto lfnext_out;
        }
        if(!fread(rev, cb_file.revlen, 1, lf->f)) {
            SXDEBUG("error reading revision from results file");
            sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
            goto lfnext_out;
        }
        rev[cb_file.revlen] = '\0';
        cb_file.revlen = 0;
    }

    if(cb_file.metalen) {
        fseek(lf->f, cb_file.namelen + cb_file.revlen, SEEK_CUR);
        meta = sxc_meta_new(sx);
        if(!meta) {
            SXDEBUG("OOM allocating result file meta");
            sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
            goto lfnext_out;
        }

        while(cb_file.metalen) {
            char *key;
            void *value;
            unsigned int key_len;
            unsigned int value_len;
            unsigned int len = 0;

            if(!fread(&key_len, sizeof(key_len), 1, lf->f)) {
                SXDEBUG("Error reading meta key length from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
                goto lfnext_out;
            }

            if(key_len & 0x80000000) {
                SXDEBUG("Invalid meta key length from cache file");
                sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Bad data from cache file");
                goto lfnext_out;
            }

            key = malloc(key_len + 1);
            if(!key) {
                SXDEBUG("Out of memory allocating meta key");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Out of memory");
                goto lfnext_out;
            }

            if(!fread(key, key_len, 1, lf->f)) {
                SXDEBUG("Error reading meta key from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
                free(key);
                goto lfnext_out;
            }
            key[key_len] = '\0';

            len += key_len + sizeof(key_len);

            if(!fread(&value_len, sizeof(value_len), 1, lf->f)) {
                SXDEBUG("Error reading meta value length from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
                free(key);
                goto lfnext_out;
            }

            value = malloc(value_len);
            if(!value) {
                SXDEBUG("Out of memory allocating meta value");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Out of memory");
                free(key);
                goto lfnext_out;
            }

            if(!fread(value, value_len, 1, lf->f)) {
                SXDEBUG("Error reading meta value from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
                free(key);
                free(value);
                goto lfnext_out;
            }

            len += value_len + sizeof(value_len);

            if(sxc_meta_setval(meta, key, value, value_len)) {
                SXDEBUG("Failed to add entry to file meta");
                free(key);
                free(value);
                goto lfnext_out;
            }

            free(key);
            free(value);

            if(len > cb_file.metalen) {
                SXDEBUG("Cache file out of sync");
                sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Out of sync");
                goto lfnext_out;
            }

            cb_file.metalen -= len;
        }
    }

    fseek(lf->f, cb_file.namelen + cb_file.revlen + cb_file.metalen + sizeof(cb_file), SEEK_CUR);

    f = sxi_file_remote(cluster, volume, NULL, remote_path, rev, meta, lf->meta_fetched);
    if(!f) {
        SXDEBUG("Failed to allocate remote file");
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate remote file");
        goto lfnext_out;
    }

    if(sxi_file_set_remote_size(f, cb_file.filesize) || sxi_file_set_created_at(f, cb_file.created_at) ||
       sxi_file_set_atime(f, cb_file.created_at) || sxi_file_set_ctime(f, cb_file.created_at) || sxi_file_set_mtime(f, cb_file.created_at)) {
        SXDEBUG("Failed to set size and ctime for the output file");
        sxi_seterr(sx, SXE_EARG, "Failed to retrieve next file");
        goto lfnext_out;
    }

    if(sxi_filemeta_process(sx, lf->filter, lf->filter_dir, f, lf->custom_volume_meta)) {
        SXDEBUG("Failed to process output file name");
        goto lfnext_out;
    }

    if(sxi_file_process(sx, lf->filter, lf->filter_dir, f, SXF_MODE_LIST)) {
        SXDEBUG("Failed to process output file meta");
        goto lfnext_out;
    }

    ret = listfiles_postproc_file(lf, f);
 lfnext_out:
    sxc_meta_free(meta);
    free(remote_path);
    free(rev);
    if(ret != 1) {
        sxc_file_free(f);
        *file = NULL;
    } else
        *file = f;

    return ret;
}

int sxc_cluster_listfiles_next(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file) {
    sxc_client_t *sx = lf->sx;

    if(!file) {
        SXDEBUG("Invalid argument: File pointer not provided");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return -1;
    }

    *file = NULL;

    if(lf->processed_list)
        return listfiles_next_list(cluster, volume, lf, file);
    else
        return listfiles_next_file(cluster, volume, lf, file);
}

static int listfiles_prev_file(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file) {
    struct cbl_file_t cb_file;
    long pos;
    sxc_client_t *sx = lf->sx;
    int ret = -1;
    sxc_file_t *f = NULL;
    char *remote_path;
    char *rev = NULL;
    sxc_meta_t *meta = NULL;

    if(!file) {
        SXDEBUG("Invalid argument: File pointer not provided");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return -1;
    }

    *file = NULL;

    pos = ftell(lf->f);
    if(pos < 0) {
        SXDEBUG("error getting the current position in the result file");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
        return -1;
    }
    if((size_t) pos < sizeof(cb_file) * 2)
        return 0;
    fseek(lf->f, pos-sizeof(cb_file), SEEK_SET);

    if(!fread(&cb_file, sizeof(cb_file), 1, lf->f)) {
        SXDEBUG("error reading attributes from results file");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
        return -1;
    }
    if((cb_file.namelen | cb_file.revlen) & 0x80000000) {
        SXDEBUG("Invalid data length from cache file");
        sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Bad data from cache file");
        return -1;
    }
    if((size_t) pos < sizeof(cb_file) * 2 + cb_file.namelen + cb_file.revlen + cb_file.metalen)
        return 0;

    fseek(lf->f, pos - cb_file.namelen - cb_file.revlen - cb_file.metalen - sizeof(cb_file), SEEK_SET);
    remote_path = malloc(cb_file.namelen + 1);
    if(!remote_path) {
        SXDEBUG("OOM allocating result file name (%u bytes)", cb_file.namelen);
        sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
        goto lfprev_out;
    }
    if(!fread(remote_path, cb_file.namelen, 1, lf->f)) {
        SXDEBUG("error reading name from results file");
        sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
        goto lfprev_out;
    }
    remote_path[cb_file.namelen] = '\0';

    if(cb_file.revlen) {
        fseek(lf->f, pos - cb_file.revlen - cb_file.metalen - sizeof(cb_file), SEEK_SET);
        rev = malloc(cb_file.revlen + 1);
        if(!rev) {
            SXDEBUG("OOM allocating result file rev (%u bytes)", cb_file.revlen);
            sxi_seterr(sx, SXE_EMEM, "Failed to retrieve next file: Out of memory");
            goto lfprev_out;
        }
        if(!fread(rev, cb_file.revlen, 1, lf->f)) {
            SXDEBUG("error reading revision name from results file");
            sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
            goto lfprev_out;
        }
        rev[cb_file.revlen] = '\0';
    }

    if(cb_file.metalen) {
        unsigned int len = 0;
        fseek(lf->f, pos - cb_file.metalen - sizeof(cb_file), SEEK_SET);
        meta = sxc_meta_new(sx);
        if(!meta) {
            SXDEBUG("OOM allocating result file meta");
            sxi_seterr(sx, SXE_EMEM, "Failed to retrieve prev file: Out of memory");
            goto lfprev_out;
        }

        while(len < cb_file.metalen) {
            char *key;
            void *value;
            unsigned int key_len;
            unsigned int value_len;

            if(!fread(&key_len, sizeof(key_len), 1, lf->f)) {
                SXDEBUG("Error reading meta key length from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve prev file: Read item from cache failed");
                goto lfprev_out;
            }

            if(key_len & 0x80000000) {
                SXDEBUG("Invalid meta key length from cache file");
                sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Bad data from cache file");
                goto lfprev_out;
            }

            key = malloc(key_len + 1);
            if(!key) {
                SXDEBUG("Out of memory allocating meta key");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve prev file: Out of memory");
                goto lfprev_out;
            }

            if(!fread(key, key_len, 1, lf->f)) {
                SXDEBUG("Error reading meta key from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve prev file: Read item from cache failed");
                free(key);
                goto lfprev_out;
            }
            key[key_len] = '\0';

            len += key_len + sizeof(key_len);

            if(!fread(&value_len, sizeof(value_len), 1, lf->f)) {
                SXDEBUG("Error reading meta value length from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
                free(key);
                goto lfprev_out;
            }

            value = malloc(value_len);
            if(!value) {
                SXDEBUG("Out of memory allocating meta value");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Out of memory");
                free(key);
                goto lfprev_out;
            }

            if(!fread(value, value_len, 1, lf->f)) {
                SXDEBUG("Error reading meta value from results file");
                sxi_setsyserr(sx, SXE_EREAD, "Failed to retrieve next file: Read item from cache failed");
                free(key);
                free(value);
                goto lfprev_out;
            }

            len += value_len + sizeof(value_len);

            if(sxc_meta_setval(meta, key, value, value_len)) {
                SXDEBUG("Failed to add entry to file meta");
                free(key);
                free(value);
                goto lfprev_out;
            }

            free(key);
            free(value);

            if(len > cb_file.metalen) {
                SXDEBUG("Cache file out of sync");
                sxi_seterr(sx, SXE_EREAD, "Failed to retrieve next file: Out of sync");
                goto lfprev_out;
            }
        }
    }

    fseek(lf->f, pos - cb_file.namelen - cb_file.revlen - cb_file.metalen - sizeof(cb_file)*2, SEEK_SET);
    f = sxi_file_remote(cluster, volume, NULL, remote_path, rev, meta, lf->meta_fetched);
    if(!f) {
        SXDEBUG("Failed to allocate remote file");
        sxi_seterr(sx, SXE_EMEM, "Failed to allocate remote file");
        goto lfprev_out;
    }

    if(sxi_file_set_remote_size(f, cb_file.filesize) || sxi_file_set_created_at(f, cb_file.created_at) ||
       sxi_file_set_atime(f, cb_file.created_at) || sxi_file_set_ctime(f, cb_file.created_at) || sxi_file_set_mtime(f, cb_file.created_at)) {
        SXDEBUG("Failed to set size and ctime for the output file");
        sxi_seterr(sx, SXE_EARG, "Failed to retrieve next file");
        goto lfprev_out;
    }

    if(sxi_filemeta_process(sx, lf->filter, lf->filter_dir, f, lf->custom_volume_meta)) {
        SXDEBUG("Failed to process output filename");
        goto lfprev_out;
    }

    if(sxi_file_process(sx, lf->filter, lf->filter_dir, f, SXF_MODE_LIST)) {
        SXDEBUG("Failed to process output file meta");
        goto lfprev_out;
    }

    ret = listfiles_postproc_file(lf, f);
lfprev_out:
    if(ret != 1) {
        sxc_file_free(f);
        *file = NULL;
    } else
        *file = f;
    free(remote_path);
    free(rev);
    sxc_meta_free(meta);

    return ret;
}

static int listfiles_prev_list(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file) {
    unsigned int begin_pos;
    sxc_file_t *out;

    if(!cluster || !volume || !lf || !file)
        return -1;
    if(!lf->cur_processed_file)
        return 0;
    lf->cur_processed_file--;

    begin_pos = lf->cur_processed_file;
    while(lf->cur_processed_file && !file_entry_cmp(&lf->processed_list[lf->cur_processed_file-1], &lf->processed_list[begin_pos]))
        lf->cur_processed_file--; /* Iterate over list until different file is encountered, list is already sorted */
    out = sxi_file_dup(lf->processed_list[lf->cur_processed_file]);
    if(!out)
        return -1;
    *file = out;
    return 1;
}

int sxc_cluster_listfiles_prev(sxc_cluster_t *cluster, const char *volume, sxc_cluster_lf_t *lf, sxc_file_t **file) {
    sxc_client_t *sx = lf->sx;

    if(!file) {
        SXDEBUG("Invalid argument: File pointer not provided");
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return -1;
    }

    *file = NULL;

    if(lf->processed_list)
        return listfiles_prev_list(cluster, volume, lf, file);
    else
        return listfiles_prev_file(cluster, volume, lf, file);
}

void sxc_cluster_listfiles_free(sxc_cluster_lf_t *lf) {
    unsigned int i;

    if (!lf)
        return;
    if(lf->f)
	fclose(lf->f);
    if(lf->fname) {
	unlink(lf->fname);
	free(lf->fname);
    }

    for(i = 0; i < lf->nprocessed_entries; i++)
        sxc_file_free(lf->processed_list[i]);
    free(lf->processed_list);
    free(lf->pattern);
    free(lf->filter_dir);
    sxc_meta_free(lf->custom_volume_meta);
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
        if(sxc_prompt_password(sx, password, sizeof(password), NULL, repeat, 8)) {
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
        sxi_md_cleanup(&ch_ctx);
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
int sxc_prompt_password(sxc_client_t *sx, char *buff, unsigned int buff_len, const char *prefix, int repeat, unsigned int min_length) {
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

    if(min_length && strlen(buff) < min_length) {
        memset(buff, 0, buff_len);
        sxi_seterr(sx, SXE_EARG, "Password must be at least %u characters long", min_length);
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

static char *user_add(sxc_cluster_t *cluster, const char *username, const char *pass, int admin, const char *oldtoken, const char *existing, int *clone_role, const char *desc, int generate_key, int64_t quota) {
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
        if (sxi_rand_bytes(key, AUTH_KEY_LEN)) {
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
        proto = sxi_useradd_proto(sx, username, NULL, key, admin, desc, quota);
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

char *sxc_user_add(sxc_cluster_t *cluster, const char *username, const char *pass, int admin, const char *oldtoken, const char *desc, int generate_key, int64_t quota) {
    return user_add(cluster, username, pass, admin, oldtoken, NULL, NULL, desc, generate_key, quota);
}

char *sxc_user_clone(sxc_cluster_t *cluster, const char *username, const char *clonename, const char *oldtoken, int *role, const char *desc) {
    return user_add(cluster, clonename, NULL, 0, oldtoken, username, role, desc, oldtoken ? 0 : 1, 0);
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
        if (sxi_rand_bytes(key, AUTH_KEY_LEN)) {
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
    proto = sxi_usermod_proto(sx, username, key, -1, NULL);
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

int sxc_user_modify(sxc_cluster_t *cluster, const char *username, int64_t quota, const char *description) {
    sxi_query_t *query;
    sxc_client_t *sx;
    int ret;

    if(!cluster)
        return 1;
    if(!username || !*username || quota < -1 || (quota == -1 && !description)) {
        cluster_err(SXE_EARG, "Invalid argument");
        return 1;
    }
    sx = sxi_cluster_get_client(cluster);

    query = sxi_usermod_proto(sx, username, NULL, quota, description);
    if(!query)
        return 1;

    sxi_set_operation(sx, "modify user", NULL, NULL, NULL);
    ret = sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, query->verb, query->path, query->content, query->content_len);

    sxi_query_free(query);
    return ret;
}

struct cb_userinfo_ctx {
    curlev_context_t *cbdata;
    const struct jparse_actions *acts;
    jparse_t *J;
    uint8_t token[AUTHTOK_BIN_LEN];
    FILE *f;
    char role[7];
    int64_t quota;
    enum sxc_error_t err;
};

/* {"userKey":"KEY", "userID":"UID", "userType":"normal|admin", "userQuota":12345} */

static int userinfo_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host)
{
    struct cb_userinfo_ctx *yactx = (struct cb_userinfo_ctx *)ctx;
    yactx->cbdata = cbdata; /* must set before using CBDEBUG */

    sxi_jparse_destroy(yactx->J);
    yactx->err = SXE_ECOMM;
    if(!(yactx->J  = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot get user info: Out of memory");
	return 1;
    }
    return 0;
}

static int userinfo_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct cb_userinfo_ctx *yactx = (struct cb_userinfo_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

static void cb_userinfo_id(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_userinfo_ctx *yactx = (struct cb_userinfo_ctx *)ctx;
    if(length != AUTH_UID_LEN * 2 || sxi_hex2bin(string, length, yactx->token, AUTH_UID_LEN)) {
	sxi_jparse_cancel(J, "Invalid user id received");
        yactx->err = SXE_ECOMM;
	return;
    }
}

static void cb_userinfo_key(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_userinfo_ctx *yactx = (struct cb_userinfo_ctx *)ctx;
    if(length != AUTH_KEY_LEN * 2 || sxi_hex2bin(string, length, yactx->token + AUTH_UID_LEN, AUTH_KEY_LEN)) {
	sxi_jparse_cancel(J, "Invalid user key received");
        yactx->err = SXE_ECOMM;
	return;
    }
}

static void cb_userinfo_type(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct cb_userinfo_ctx *yactx = (struct cb_userinfo_ctx *)ctx;
    if((length == lenof("admin") && !memcmp(string, "admin", lenof("admin"))) ||
       (length == lenof("normal") && !memcmp(string, "normal", lenof("normal")))) {
        memcpy(yactx->role, string, length);
        yactx->role[length] = '\0';
    } else {
	sxi_jparse_cancel(J, "Invalid user role received");
        yactx->err = SXE_ECOMM;
	return;
    }
}

static void cb_userinfo_quota(jparse_t *J, void *ctx, int64_t num) {
    struct cb_userinfo_ctx *yactx = (struct cb_userinfo_ctx *)ctx;

    if(num < 0) {
	sxi_jparse_cancel(J, "Invalid quota received");
	yactx->err = SXE_ECOMM;
    }
    yactx->quota = num;
}

int sxc_user_getinfo(sxc_cluster_t *cluster, const char *username, FILE *storeauth, int *is_admin, int get_config_link)
{
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_userinfo_id, JPKEY("userID")),
		      JPACT(cb_userinfo_key, JPKEY("userKey")),
		      JPACT(cb_userinfo_type, JPKEY("userType"))
		      ),
	JPACTS_INT64(
		     JPACT(cb_userinfo_quota, JPKEY("userQuota"))
		     )
    };
    sxc_client_t *sx;
    struct cb_userinfo_ctx yctx;
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
    yctx.acts = &acts;
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

    if(sxi_jparse_done(yctx.J)) {
	sxi_seterr(sx, yctx.err, "%s", sxi_jparse_geterr(yctx.J));
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
    sxi_jparse_destroy(yctx.J);
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
    curlev_context_t *cbdata;
    const struct jparse_actions *acts;
    jparse_t *J;
    sxi_node_status_t status;
    enum sxc_error_t err;
};


static void cb_nodest_ostype(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.os_name, string, MIN(sizeof(yactx->status.os_name), length+1));
}
static void cb_nodest_osarch(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.os_arch, string, MIN(sizeof(yactx->status.os_arch), length+1));
}
static void cb_nodest_osrel(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.os_release, string, MIN(sizeof(yactx->status.os_release), length+1));
}
static void cb_nodest_osver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.os_version, string, MIN(sizeof(yactx->status.os_version), length+1));
}
static void cb_nodest_localtime(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.localtime, string, MIN(sizeof(yactx->status.localtime), length+1));
}
static void cb_nodest_utctime(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.utctime, string, MIN(sizeof(yactx->status.utctime), length+1));
}
static void cb_nodest_addr(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.addr, string, MIN(sizeof(yactx->status.addr), length+1));
}
static void cb_nodest_intaddr(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.internal_addr, string, MIN(sizeof(yactx->status.internal_addr), length+1));
}
static void cb_nodest_endianness(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.endianness, string, MIN(sizeof(yactx->status.endianness), length+1));
}
static void cb_nodest_uuid(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.uuid, string, MIN(sizeof(yactx->status.uuid), length+1));
}
static void cb_nodest_stdir(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.storage_dir, string, MIN(sizeof(yactx->status.storage_dir), length+1));
}
static void cb_nodest_stver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.hashfs_version, string, MIN(sizeof(yactx->status.hashfs_version), length+1));
}
static void cb_nodest_libver(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.libsxclient_version, string, MIN(sizeof(yactx->status.libsxclient_version), length+1));
}
static void cb_nodest_heal(jparse_t *J, void *ctx, const char *string, unsigned int length) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    sxi_strlcpy(yactx->status.heal_status, string, MIN(sizeof(yactx->status.heal_status), length+1));
}

static void cb_nodest_cores(jparse_t *J, void *ctx, int32_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.cores = num;
}

static void cb_nodest_stallocd(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.storage_allocated = num;
}
static void cb_nodest_stused(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.storage_commited = num;
}
static void cb_nodest_fsbs(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.block_size = num;
}
static void cb_nodest_fsblocks(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.total_blocks = num;
}
static void cb_nodest_fsavblocks(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.avail_blocks = num;
}
static void cb_nodest_mem(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.mem_total = num;
}
static void cb_nodest_mem_avail(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.mem_avail = num;
}
static void cb_nodest_swap(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.swap_total = num;
}
static void cb_nodest_swap_free(jparse_t *J, void *ctx, int64_t num) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->status.swap_free = num;
}

static int node_status_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;

    if(sxi_jparse_digest(yactx->J, data, size)) {
	sxi_cbdata_seterr(yactx->cbdata, yactx->err, sxi_jparse_geterr(yactx->J));
	return 1;
    }
    return 0;
}

static int node_status_setup_cb(curlev_context_t *cbdata, void *ctx, const char *host) {
    struct node_status_ctx *yactx = (struct node_status_ctx *)ctx;
    yactx->cbdata = cbdata; /* must set before using CBDEBUG */

    sxi_jparse_destroy(yactx->J);
    yactx->err = SXE_ECOMM;
    if(!(yactx->J  = sxi_jparse_create(yactx->acts, yactx, 1))) {
	CBDEBUG("OOM allocating JSON parser");
	sxi_cbdata_seterr(cbdata, SXE_EMEM, "Cannot get node status: Out of memory");
	return 1;
    }
    return 0;
}

int sxi_cluster_status(sxc_cluster_t *cluster, const node_status_cb_t status_cb, int human_readable) {
    const struct jparse_actions acts = {
	JPACTS_STRING(
		      JPACT(cb_nodest_ostype, JPKEY("osType")),
		      JPACT(cb_nodest_osarch, JPKEY("osArch")),
		      JPACT(cb_nodest_osrel, JPKEY("osRelease")),
		      JPACT(cb_nodest_osver, JPKEY("osVersion")),
		      JPACT(cb_nodest_localtime, JPKEY("localTime")),
		      JPACT(cb_nodest_utctime, JPKEY("utcTime")),
		      JPACT(cb_nodest_addr, JPKEY("address")),
		      JPACT(cb_nodest_intaddr, JPKEY("internalAddress")),
		      JPACT(cb_nodest_endianness, JPKEY("osEndianness")),
		      JPACT(cb_nodest_uuid, JPKEY("UUID")),
		      JPACT(cb_nodest_stdir, JPKEY("nodeDir")),
		      JPACT(cb_nodest_stver, JPKEY("hashFSVersion")),
		      JPACT(cb_nodest_libver, JPKEY("libsxclientVersion")),
		      JPACT(cb_nodest_heal, JPKEY("heal"))
		      ),
	JPACTS_INT64(
		     JPACT(cb_nodest_stallocd, JPKEY("storageAllocated")),
		     JPACT(cb_nodest_stused, JPKEY("storageUsed")),
		     JPACT(cb_nodest_fsbs, JPKEY("fsBlockSize")),
		     JPACT(cb_nodest_fsblocks, JPKEY("fsTotalBlocks")),
		     JPACT(cb_nodest_fsavblocks, JPKEY("fsAvailBlocks")),
		     JPACT(cb_nodest_mem, JPKEY("memTotal")),
                     JPACT(cb_nodest_mem_avail, JPKEY("memAvailable")),
                     JPACT(cb_nodest_swap, JPKEY("swapTotal")),
                     JPACT(cb_nodest_swap_free, JPKEY("swapFree"))
		     ),
	JPACTS_INT32(
		     JPACT(cb_nodest_cores, JPKEY("cores"))
		     )
    };
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

        if(sxi_hostlist_add_host(sx, &hlist, node)) {
            SXDEBUG("Failed to get status of node %s: %s", node, sxc_geterrmsg(sx));
            goto sxc_cluster_status_err;
        }

        if(!(yctx = calloc(1, sizeof(*yctx)))) {
            SXDEBUG("Failed to allocate JSON parser context");
            goto sxc_cluster_status_err;
        }

        yctx->acts = &acts;

        qret = sxi_cluster_query(conns, &hlist, REQ_GET, ".status", NULL, 0, node_status_setup_cb, node_status_cb, yctx);
        sxi_hostlist_empty(&hlist);
        if(qret != 200) {
            SXDEBUG("Failed to get status of node %s: %s", node, sxc_geterrmsg(sx));
	    sxi_jparse_destroy(yctx->J);
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

        if(sxi_jparse_done(yctx->J)) {
            SXDEBUG("Failed to complete parsing of node %s status", node);
	    sxi_jparse_destroy(yctx->J);
            free(yctx);
            sxc_clearerr(sx);
            sxi_seterr(sx, SXE_ECOMM, "Can't query node %s", node);
            fail = 1;
            status_cb(sx, qret, NULL, human_readable);
            continue;
        }

        status_cb(sx, qret, &yctx->status, human_readable);
	sxi_jparse_destroy(yctx->J);
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
    long http_code = 0;

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
    if(sxi_job_submit_and_poll_err(conns, &new_hosts, query->verb, query->path, query->content, query->content_len, &http_code)) {
        sxi_query_free(query);
        sxi_hostlist_empty(&new_hosts);
        if(http_code == 409 && !op) {
            /* For unlock operation do not print "Cluster is already locked message", this could happen if
             * existing job was pending */
            SXDEBUG("Clearing the error message: %s, the error is expected", sxc_geterrmsg(sx));
            sxc_clearerr(sx);
            return 0;
        }
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
    sxc_client_t *sx;
    sxi_conns_t *conns;
    sxi_hostlist_t *hosts;

    if(!cluster)
        return 1;

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

static int cluster_set_meta_common(sxc_cluster_t *cluster, sxc_meta_t *meta, int is_cluster_meta) {
    sxi_query_t *query;
    sxc_client_t *sx;
    sxi_conns_t *conns;
    sxi_hostlist_t *hosts;

    if(!cluster)
        return 1;

    sx = sxi_cluster_get_client(cluster);
    conns = sxi_cluster_get_conns(cluster);

    if(!sx || !conns) {
        sxi_seterr(sx, SXE_EARG, "Invalid argument");
        return 1;
    }

    hosts = sxi_conns_get_hostlist(conns);
    if(!hosts) {
        sxi_seterr(sx, SXE_ECOMM, "Failed to get cluster host list");
        return 1;
    }

    if(is_cluster_meta)
        query = sxi_cluster_setmeta_proto(sx, -1, meta);
    else
        query = sxi_cluster_settings_proto(sx, -1, meta);
    if(!query) {
        SXDEBUG("Failed to prepare query");
        return 1;
    }

    sxi_set_operation(sx, is_cluster_meta ? "set cluster meta" : "set cluster settings", NULL, NULL, NULL);
    if(sxi_job_submit_and_poll(conns, hosts, query->verb, query->path, query->content, query->content_len)) {
        sxi_query_free(query);
        return 1;
    }

    sxi_query_free(query);
    return 0;
}

int sxi_cluster_set_meta(sxc_cluster_t *cluster, sxc_meta_t *meta) {
    return cluster_set_meta_common(cluster, meta, 1);
}

int sxi_cluster_set_settings(sxc_cluster_t *cluster, sxc_meta_t *meta) {
    return cluster_set_meta_common(cluster, meta, 0);
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

    enc_token = sxi_urlencode(sx, token, 1);
    if(!enc_token)
        return NULL;

    len = lenof("sx:///?token=&port=&ssl=y") + strlen(cluster_name) + strlen(enc_token) + 11 + 1;
    if(username) {
        enc_user = sxi_urlencode(sx, username, 1);
        if(!enc_user) {
            free(enc_token);
            return NULL;
        }
        len += strlen(enc_user) + 1; /* username@ */
    }
    if(ssl)
        len += lenof("&certhash=") + strlen(fingerprint);
    if(!is_dns) {
        enc_host = sxi_urlencode(sx, host, 1);
        if(!enc_host) {
            free(enc_token);
            free(enc_user);
            return NULL;
        }
        len += lenof("&ip=") + strlen(enc_host);
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
