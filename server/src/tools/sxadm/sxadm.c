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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <yajl/yajl_parse.h>
#include <unistd.h>
#include <errno.h>

#include "../libsx/src/clustcfg.h"
#include "../libsx/src/jobpoll.h"
#include "../libsx/src/vcrypto.h"
#include "../libsx/src/misc.h"
#include "../libsx/src/hostlist.h"

#include "cmd_main.h"
#include "cmd_node.h"
#include "cmd_cluster.h"

#include "hashfs.h"
#include "clstqry.h"
#include "sx.h"
#include "init.h"

struct token_pair_t {
    char token[AUTHTOK_ASCII_LEN + 2];
    uint8_t *uid;
    uint8_t uid_store[AUTH_UID_LEN];
    uint8_t key[AUTH_KEY_LEN];
};

static int read_or_gen_key(const char *token_file, int role, struct token_pair_t *result) {
    const char *token_type, *token_uid;

    if(role == ROLE_CLUSTER) {
	token_type = "cluster";
	token_uid = CLUSTER_USER;
    } else if(role == ROLE_ADMIN) {
	token_type = "admin";
	token_uid = ADMIN_USER;
    } else {
	CRIT("Invalid role requested");
	return -1;
    }

    if(token_file) {
	uint8_t bintok[AUTHTOK_BIN_LEN];
	unsigned int toklen;
	char *have_tok;

	if(strcmp(token_file, "-")) {
	    FILE *f = fopen(token_file, "r");
	    if(!f) {
		CRIT("Failed to open %s authentication token file %s", token_type, token_file);
		return -1;
	    }
	    have_tok = fgets(result->token, sizeof(result->token), f);
	    fclose(f);
	} else {
	    printf("Please enter the %s authentication token\n", token_type);
	    have_tok = fgets(result->token, sizeof(result->token), stdin);
	}

	if(!have_tok) {
	    CRIT("Failed to read %s authentication token", token_type);
	    return -1;
	}

	toklen = strlen(result->token);
	if(toklen == AUTHTOK_ASCII_LEN + 1 && result->token[AUTHTOK_ASCII_LEN] == '\n') {
	    result->token[AUTHTOK_ASCII_LEN] = '\0';
	    toklen--;
	}
	if(toklen != AUTHTOK_ASCII_LEN) {
	    CRIT("Bad %s authentication token (length %u, expected %u)", token_type, toklen, AUTHTOK_ASCII_LEN);
	    return -1;
	}
	toklen = sizeof(bintok);
	if(sxi_b64_dec_core(result->token, bintok, &toklen)) {
	    CRIT("Invalid %s authentication token", token_type);
	    return -1;
	}
	if(memcmp(bintok, CLUSTER_USER, AUTH_UID_LEN)) {
	    if(role == ROLE_CLUSTER) {
		CRIT("The authentication token is not a valid cluster identificator (maybe you provided a user authentication token?)");
		return -1;
	    }
	} else {
	    if(role == ROLE_ADMIN) {
		CRIT("The token provided is a cluster identificator and cannot be used for admin authentication");
		return -1;
	    }
	}
	memcpy(result->uid_store, bintok, AUTH_UID_LEN);
	memcpy(result->key, bintok+AUTH_UID_LEN, AUTH_KEY_LEN);
	result->uid = result->uid_store;
    } else {
	gen_key(result->key, sizeof(result->key));
	encode_auth_bin(token_uid, result->key, sizeof(result->key), result->token, sizeof(result->token));
	result->uid = NULL;
    }

    return 0;
}

/*
 * def == 1 -> [Y/n], 0 ==> [y/N]
 * return 1 ==> yes, 0 ==> no
 */
int yesno(const char *prompt, int def)
{
    char c;
    while(1) {
	if(def)
	    printf("%s [Y/n] ", prompt);
	else
	    printf("%s [y/N] ", prompt);
	fflush(stdout);
	c = sxi_read_one_char();
	if(c == 'y' || c == 'Y')
	    return 1;
	if(c == 'n' || c == 'N')
	    return 0;
	if(c == '\n' || c == EOF)
	    return def;
    }
    return 0;
}

static int create_node(struct node_args_info *args) {
    struct token_pair_t auth;
    sx_uuid_t cluster_uuid;

    if(args->cluster_uuid_given) {
	if(uuid_from_string(&cluster_uuid, args->cluster_uuid_arg)) {
	    CRIT("Invalid cluster UUID %s", args->cluster_uuid_arg);
	    return 1;
	}
    } else
	uuid_generate(&cluster_uuid);

    if(read_or_gen_key(args->cluster_key_arg, ROLE_CLUSTER, &auth))
	return 1;

    if(!args->batch_mode_given) {
	printf("A new node is about to be created in \"%s\"...\nIf this node shall be joined to an existing SX cluster, please make sure the following info matches:\n  - Cluster UUID: %s\n  - Cluster key: %s\n\n", args->inputs[0], cluster_uuid.string, auth.token);
	if(!yesno("Confirm?", 1)) {
	    printf("Node creation aborted by the user\n");
	    return 1;
	}
    }

    if(mkdir(args->inputs[0], 0770)) {
	printf("Cannot create storage directory %s: %s\n", args->inputs[0], strerror(errno));
	return 1;
    }

    if(args->owner_given) {
	uid_t uid;
	gid_t gid;
	if(parse_usergroup(args->owner_arg, &uid, &gid))
	    return 1;

	if(chown(args->inputs[0], uid, gid)) {
	    printf("Can't set ownership of %s to %u:%u\n", args->inputs[0], (unsigned int) uid, (unsigned int) gid);
	    return 1;
	}
	if(runas(args->owner_arg))
	    return 1;
    }

    rc_ty create_fail = sx_storage_create(args->inputs[0], &cluster_uuid, auth.key, sizeof(auth.key));
    if(create_fail) {
	printf("Failed to create storage for new node: %s\n", rc2str(create_fail));
	return 1;
    }

    if(!args->batch_mode_given) {
	printf("Node successfully created!\n\n");
	char *datadir = realpath(args->inputs[0], NULL);
	if(datadir) {
	    printf("Please make sure that you set the \"data-dir=%s\" directive in the configuration file (sxfcgi.conf) for this node before starting SX server.\n", datadir);
	    free(datadir);
	}
	printf("To start making use of this node, you shall run the \"sxadm cluster\" command.\nUse the \"--new\" argument if you intend to create a new cluster.\nOtherwise, use the \"--mod\" argument if you want to add this node to an existing SX cluster.\n");
    }

    return 0;
}

static sx_node_t *parse_nodef(const char *nodef) {
    char *n = strdup(nodef);
    sx_node_t *ret = NULL;
    if(!n) {
	CRIT("Out of memory parsing node definition");
	return NULL;
    }

    do {
	int len = strlen(n);
	while(len-- && n[len] == '/')
	    n[len] = '\0';

	char *addr, *int_addr, *uuid = NULL;
	int64_t capa = strtoll(n, &addr, 10);
	sx_uuid_t nodeid;

	if(capa <= 0 || capa == LLONG_MAX)
	    break;
	switch(*addr) {
	case 'T':
	case 't':
	    capa *= 1024;
	case 'G':
	case 'g':
	    capa *= 1024;
	case 'M':
	case 'm':
	    capa *= 1024;
	case 'K':
	case 'k':
	    capa *= 1024;
	    addr++;
	    if(*addr == 'i' || *addr == 'I')
		addr++;
	    if(*addr == 'b' || *addr == 'B')
		addr++;
	    break;
	}
	if(capa <=0 || *addr != '/')
	    break;
	*addr = '\0';
	addr++;
	int_addr = strchr(addr, '/');
	if(int_addr) {
	    *int_addr = '\0';
	    int_addr++;
	    uuid = strchr(int_addr, '/');
	    if(!uuid) {
		/* Maybe user's forgotten the double slash */
		if(!uuid_from_string(&nodeid, int_addr)) {
		    uuid = int_addr;
		    int_addr = NULL;
		}
	    } else {
		*uuid = '\0';
		uuid++;
		if(uuid_from_string(&nodeid, uuid))
		    break;
		if(!*int_addr)
		    int_addr = NULL;
	    }
	}

	if(!uuid)
	    uuid_generate(&nodeid);

	ret = sx_node_new(&nodeid, addr, int_addr, capa);

    } while(0);
    free(n);
    if(!ret)
	CRIT("Malformed node definition %s", nodef);

    return ret;
}

static void fmt_capa(uint64_t bytes, char *buf, unsigned int buflen, int human) {
    const char *suffix = NULL;
    double qty = bytes;

    if(buflen <= 0)
	return;
    if(human && qty >= 1024) {
	qty /= 1024;
	if(qty >= 1024) {
	    qty /= 1024;
	    if(qty >= 1024) {
		qty /= 1024;
		if(qty >= 1024) {
		    qty /= 1024;
		    suffix = "T";
		} else
		    suffix = "G";
	    } else
		suffix = "M";
	} else
	    suffix = "K";
    }
    if(!suffix)
	snprintf(buf, buflen, "%llu", (unsigned long long) bytes);
    else
	snprintf(buf, buflen, "%.2f%s", qty, suffix);
}

static int create_cluster(sxc_client_t *sx, struct cluster_args_info *args) {
    sx_node_t *node = NULL;
    sx_hashfs_t *stor = NULL;
    sxc_cluster_t *clust = NULL;
    sx_nodelist_t *single_node = NULL;
    struct addrinfo *nodeai = NULL, *uriai = NULL, hint;
    const char *profile, *clust_token;
    const sx_uuid_t *clust_uuid;
    struct token_pair_t auth;
    char *copy_cafile = NULL;
    sxc_uri_t *uri = NULL;
    int ret = 1;
    unsigned int http_port;

    node = parse_nodef(args->inputs[0]);
    if(!node)
	goto create_cluster_err;
    single_node = sx_nodelist_new();
    if(!single_node || sx_nodelist_add(single_node, sx_node_dup(node))) {
	CRIT("Failed to create the cluster nodelist");
	goto create_cluster_err;
    }

    nodeai = sxi_gethostai(sx_node_addr(node));
    if(!nodeai) {
	CRIT("Invalid node address %s", sx_node_addr(node));
	goto create_cluster_err;
    }

    uri = sxc_parse_uri(sx, args->inputs[1]);
    if(!uri) {
	CRIT("Invalid SX URI %s", args->inputs[1]);
	goto create_cluster_err;
    }
    profile = uri->profile ? uri->profile : "admin";

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    if(!getaddrinfo(uri->host, NULL, &hint, &uriai)) {
	struct addrinfo *curai = uriai;
	while(curai) {
	    /* NOTE: compare the family and addr alone, should memcmp prove unreliable */
	    if(curai->ai_addrlen == nodeai->ai_addrlen && !memcmp(curai->ai_addr, nodeai->ai_addr, curai->ai_addrlen))
		break;
	    curai = curai->ai_next;
	}
	freeaddrinfo(uriai);
	if(!curai) {
	    if(!args->batch_mode_given) {
		printf("The address specified for the node (%s) is not returned when resolving the cluster name (%s).\nThis is generally the result of a DNS misconfiguration.\nIf the mismatch is intended (or if you'd rather fix the issue later) you can still create the cluster now, but please note that in the meantime the cluster may be hard to reach.\n", sx_node_addr(node), uri->host);
		if(!yesno("Do you wish to proceed?", 1)) {
		    printf("Cluster creation aborted by the user\n");
		    goto create_cluster_err;
		}
	    } else
		WARN("DNS resolution of %s returns no record containing the address specified for the node (%s)", uri->host, sx_node_addr(node));
	}
    } else {
	if(!args->batch_mode_given) {
	    printf("The SX cluster you are creating appears to be DNS-less: i.e. the cluster name (%s) cannot be resolved.\nWhile this may be perfectly fine in certain local or specific environments, a DNS-less SX cluster is generally harder to reach.\n", uri->host);
	    if(!yesno("Do you confirm you are ok with a DNS-less SX cluster?", 1)) {
		printf("Cluster creation aborted by the user\n");
		goto create_cluster_err;
	    }
	}
    }

    stor = sx_hashfs_open(args->node_dir_arg, sx);
    if(!stor) {
	CRIT("Cannot open node in %s", args->node_dir_arg);
	goto create_cluster_err;
    }

    if(!sx_storage_is_bare(stor)) {
	CRIT("The node indicated was already activated");
	goto create_cluster_err;
    }

    clust_uuid = sx_hashfs_uuid(stor);
    clust_token = sx_hashfs_authtoken(stor);
    if(!clust_uuid || !clust_token) {
	CRIT("Invalid/corrupted node data");
	goto create_cluster_err;
    }

    if(!args->batch_mode_given) {
	clust = sxc_cluster_load(sx, args->config_dir_arg, uri->host);
	if(clust) {
	    printf("It appears that a configuration for the SX cluster %s already exists.\nSince you are creating a new cluster, the existing configuration will be overwritten.\n", uri->host);
	    if(!yesno("Do you wish to continue?", 1)) {
		printf("Cluster creation aborted by the user\n");
		goto create_cluster_err;
	    }
	    sxc_cluster_free(clust);
	    clust = NULL;
	}
    }

    clust = sxc_cluster_new(sx);
    if(!clust) {
	CRIT("Failed to instantiate the new cluster");
	goto create_cluster_err;
    }

    if(sxc_cluster_set_uuid(clust, clust_uuid->string)) {
	CRIT("Failed to set cluster UUID");
	goto create_cluster_err;
    }
    if(uriai && sxc_cluster_set_dnsname(clust, uri->host)) {
	CRIT("Failed to set cluster dnsname");
	goto create_cluster_err;
    }
    if(sxc_cluster_set_sslname(clust, uri->host)) {
	CRIT("Failed to set cluster name");
	goto create_cluster_err;
    }
    if(args->port_given) {
	http_port = args->port_arg;
	if(sxc_cluster_set_httpport(clust, http_port)) {
	    CRIT("Failed to set cluster port");
	    goto create_cluster_err;
	}
    } else
	http_port = 0;

    if(!args->ssl_ca_file_given) {
	/* NON-SSL cluster */
	if(!args->batch_mode_given) {
	    printf("The SX cluster you are creating will not support SSL encryption.\nThis is generally a bad idea because all the communication will be in clear text and it's strongly discouraged.\nIf you intend to create a secure cluster, please rerun this tool with the \"--ssl-ca-file\" parameter.\n");
	    if(!yesno("Do you wish to create an INSECURE cluster?", 1)) {
		printf("Cluster creation aborted by the user\n");
		goto create_cluster_err;
	    }
	}
	/* if(sxc_cluster_set_cafile(clust, NULL)) { */
	/*     CRIT("Failed to configure cluster security"); */
	/*     goto create_cluster_err; */
	/* } */
    } else {
        unsigned int len;
	/* SSL cluster with certificate check */
        if (sxi_vcrypt_print_cert_info(sx, args->ssl_ca_file_arg, args->batch_mode_given)) {
	    CRIT("Bad certificate file %s: %s", args->ssl_ca_file_arg, sxc_geterrmsg(sx));
	    goto create_cluster_err;
	}

	if(!args->batch_mode_given) {
	    if(!yesno("Is the certificate correct?", 1)) {
		printf("Cluster creation aborted by the user\n");
		goto create_cluster_err;
	    }
	}

	if(sxc_cluster_set_cafile(clust, args->ssl_ca_file_arg)) {
	    CRIT("Failed to configure cluster security");
	    goto create_cluster_err;
	}

	len = strlen(args->node_dir_arg) + sizeof("/ca.pem");
	copy_cafile = malloc(len);
	if(!copy_cafile) {
	    CRIT("Failed to allocate destination ca file");
	    goto create_cluster_err;
	}
	sprintf(copy_cafile, "%s/ca.pem", args->node_dir_arg);
    }

    if(read_or_gen_key(args->admin_key_arg, ROLE_ADMIN, &auth))
	goto create_cluster_err;

    if(sxc_cluster_add_access(clust, profile, auth.token) ||
       sxc_cluster_set_access(clust, profile)) {
	CRIT("Failed to set profile authentication");
	goto create_cluster_err;
    }

    if(sxc_cluster_add_host(clust, sx_node_addr(node))) {
	CRIT("Failed to add node to cluster");
	goto create_cluster_err;
    }

    if(!args->batch_mode_given) {
	char capastr[32];
	printf("\nPlease review the summary of your new SX cluster below and make sure all the information reported are correct.\n  - Cluster name: %s\n  - Cluster UUID: %s\n  - Cluster is %s\n  - Cluster security is: ", sxc_cluster_get_sslname(clust), sxc_cluster_get_uuid(clust), sxc_cluster_get_dnsname(clust) ? "reachable via DNS name resolution" : "DNS-less");
	if(args->ssl_ca_file_arg)
	    printf("secure (SSL is enabled and certificate validation is enforced)");
	else
	    printf("insecure (SSL is disabled)");
	printf("\n  - Cluster key: %s\n  - Admin key: %s\n\nThe initial node of your new SX cluster is:\n  - Node UUID: %s\n  - Node address: %s\n", clust_token, auth.token, sx_node_uuid_str(node), sx_node_addr(node));
	if(strcmp(sx_node_addr(node), sx_node_internal_addr(node)))
	    printf("  - Node internal address: %s\n", sx_node_internal_addr(node));
	fmt_capa(sx_node_capacity(node), capastr, sizeof(capastr), args->human_readable_flag);
	printf("  - Node capacity: %s\n\nThe access configuration for the cluster will be saved under \"%s\" with the name \"%s\"\n\n", capastr, args->config_dir_given ? args->config_dir_arg : "~/.sx", sxc_cluster_get_sslname(clust));
	if(!yesno("Confirm cluster creation?", 1)) {
	    printf("Cluster creation aborted by the user\n");
	    goto create_cluster_err;
	}
    }

    if(sxc_cluster_remove(clust, args->config_dir_arg)) {
	CRIT("Failed to wipe the existing access configuration at %s: %s", args->config_dir_given ? args->config_dir_arg : "~/.sx", sxc_geterrmsg(sx));
	goto create_cluster_err;
    }

    if(sxc_cluster_save(clust, args->config_dir_arg)) {
	CRIT("Failed to save the access configuration at %s: %s", args->config_dir_given ? args->config_dir_arg : "~/.sx", sxc_geterrmsg(sx));
	goto create_cluster_err;
    }

    if(copy_cafile) {
	FILE *rf, *wf;

	rf = fopen(args->ssl_ca_file_arg, "r");
	if(!rf) {
	    CRIT("Failed to open SSL CA certificate file");
	    goto create_cluster_err;
	}
	wf = fopen(copy_cafile, "w");
	if(!wf) {
	    CRIT("Failed to open copy of SSL CA certificate file");
	    fclose(rf);
	    goto create_cluster_err;
	}

	while(!feof(rf)) {
	    char buf[1024];
	    size_t len = fread(buf, 1, sizeof(buf), rf);
	    if(!len && !ferror(rf))
		continue;
	    if(!len || !fwrite(buf, len, 1, wf)) {
		fclose(rf);
		fclose(wf);
		CRIT("Failed to copy the SSL CA certificate file to the node directory");
		goto create_cluster_err;
	    }
	}
	fclose(rf);
	if(fclose(wf)) {
	    CRIT("Failed to copy the SSL CA certificate file to the node directory (fclose() failed)");
	    goto create_cluster_err;
	}
    }

    rc_ty rs = sx_storage_activate(stor, sxc_cluster_get_sslname(clust), sx_node_uuid(node), auth.uid, AUTH_UID_LEN, auth.key, AUTH_KEY_LEN, http_port, copy_cafile ? "ca.pem" : NULL, single_node);
    if(rs != OK) {
	CRIT("Failed to activate node");
	goto create_cluster_err;
    }
    if(!args->batch_mode_given)
	printf("\nCongratulations!\nYour new SX cluster was created successfully.\nYou should now (re)start the local sxserver and point your browser to http%s://%s in order to check that the cluster is reachable\nYou can then start uploading data or you can add more nodes using the --mod option\nEnjoy!\n\n", args->ssl_ca_file_given ? "s" : "", sx_node_addr(node));
    ret = 0;

 create_cluster_err:
    sx_nodelist_delete(single_node);
    free(copy_cafile);
    sx_hashfs_close(stor);
    sxc_cluster_free(clust);
    sxc_free_uri(uri);
    freeaddrinfo(nodeai);
    sx_node_delete(node);

    return ret;
}



static sxc_cluster_t *cluster_load(sxc_client_t *sx, struct cluster_args_info *args, int fetch_nodes) {
    const char *uristr = args->inputs[args->inputs_num - 1];
    sxc_cluster_t *clust = NULL;
    sxc_uri_t *uri;
    int r;

    uri = sxc_parse_uri(sx, uristr);
    if(!uri) {
	CRIT("Invalid SX URI %s", uristr);
	return NULL;
    }

    clust = sxc_cluster_load(sx, args->config_dir_arg, uri->host);
    if(!clust) {
	printf("The configuration for %s could not be found.\n", uristr);
	if(args->config_dir_given)
	    printf("Please make sure the --config-dir points to the correct location.\n");
	else
	    printf("Please run sxinit first to generate it.\n");
	sxc_free_uri(uri);
	return NULL;
    }

    if(uri->profile) /* Use the given profile */
	r = sxc_cluster_set_access(clust, uri->profile);
    else if((r = sxc_cluster_set_access(clust, "admin"))) /* or "admin" as default */
	r = sxc_cluster_set_access(clust, NULL); /* or fall back to default, just in case */
    if(r) {
	printf("The selected SX profile could not be loaded.\n");
	if(uri->profile)
	    printf("Do you have a typo in \"%s\" ?\n", uri->profile);
	else
	    printf("If you intended to select a non admin profile, please use the sx://profile@%s syntax\n", uri->host);
	sxc_cluster_free(clust);
	sxc_free_uri(uri);
	return NULL;
    }

    /* MODHDIST: update cluster */

    sxc_free_uri(uri);
    if(fetch_nodes && sxc_cluster_fetchnodes(clust)) {
	CRIT("%s", sxc_geterrmsg(sx));
        sxc_cluster_free(clust);
        return NULL;
    }

    return clust;
}

static int change_commit(sxc_client_t *sx, sxc_cluster_t *clust, sx_node_t **nodes, int nnodes, struct cluster_args_info *args) {
    char *query = NULL;
    unsigned int i, query_sz, query_at;
    int ret = 1;

    query = malloc(4096);
    if(!query) {
	CRIT("Out of memory when allocating the update query");
	return 1;
    }
    query_sz = 4096;
    strcpy(query, "{\"nodeList\":[");
    query_at = strlen(query);

    for(i=0; i<nnodes; i++) {
	unsigned int need;
	const char *uuid, *addr, *int_addr;

	uuid = sx_node_uuid_str(nodes[i]);
	addr = sx_node_addr(nodes[i]);
	int_addr = sx_node_internal_addr(nodes[i]);
	if(!strcmp(int_addr, addr))
	    int_addr = NULL;
	need = sizeof("{\"nodeUUID\":\"\",\"nodeAddress\":\"\",\"nodeInternalAddress\":\"\",\"nodeCapacity\":},") + 32;
	need += strlen(uuid);
	need += strlen(addr);
	if(int_addr)
	    need += strlen(int_addr);
	if(need > query_sz - query_at) {
	    char *newquery;

	    query_sz += MAX(4096, need);
	    newquery = realloc(query, query_sz + 4096);
	    if(!newquery) {
		CRIT("Out of memory when generating the update query");
		goto change_commit_err;
	    }
	    query = newquery;
	}
	if(int_addr)
	    sprintf(query + query_at, "{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",\"nodeInternalAddress\":\"%s\",\"nodeCapacity\":%lld}", uuid, addr, int_addr, (long long)sx_node_capacity(nodes[i]));
	else
	    sprintf(query + query_at, "{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",\"nodeCapacity\":%lld}", uuid, addr, (long long)sx_node_capacity(nodes[i]));
	query_at = strlen(query);

	if(i != nnodes - 1) {
	    query[query_at++] = ',';
	    query[query_at] = '\0';
	}
    }

    strcat(query, "]}"); /* Always fits due to need above */

    if(sxi_job_submit_and_poll(sxi_cluster_get_conns(clust), NULL, REQ_PUT, ".nodes", query, strlen(query))) {
	CRIT("The update request failed: %s", sxc_geterrmsg(sx));
	goto change_commit_err;
    }

    if(sxc_cluster_fetchnodes(clust) ||
       sxc_cluster_save(clust, args->config_dir_arg))
	WARN("Cannot update local cluster configuration: %s", sxc_geterrmsg(sx));

    ret = 0;

 change_commit_err:
    free(query);
    return ret;
}

static int change_cluster(sxc_client_t *sx, struct cluster_args_info *args) {
    unsigned int i, j, nnodes = args->inputs_num - 1;
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    char *query = NULL;
    int ret = 1;
    sx_node_t **nodes;

    if(!clust)
	return 1;

    nodes = (sx_node_t **) calloc(nnodes, sizeof(sx_node_t *));
    if(!nodes) {
	CRIT("Out of memory when allocating the list of nodes");
	sxc_cluster_free(clust);
	return 1;
    }

    for(i=0; i<nnodes; i++) {
	nodes[i] = parse_nodef(args->inputs[i]);
	if(!nodes[i])
	    goto change_cluster_err;

	if(i) {
	    const char *uuid, *addr, *int_addr;
	    uuid = sx_node_uuid_str(nodes[i]);
	    addr = sx_node_addr(nodes[i]);
	    int_addr = sx_node_internal_addr(nodes[i]);

	    for(j = 0; j < i; j++) {
		if(!strcmp(sx_node_uuid_str(nodes[j]), uuid)) {
		    CRIT("Same UUID '%s' specified for multiple nodes", uuid);
		    goto change_cluster_err;
		}
		if(!strcmp(sx_node_addr(nodes[j]), addr) || !strcmp(sx_node_internal_addr(nodes[j]), addr)) {
		    CRIT("Same IP address '%s' specified for multiple nodes", addr);
		    goto change_cluster_err;
		}
		if(!strcmp(sx_node_addr(nodes[j]), int_addr) || !strcmp(sx_node_internal_addr(nodes[j]), int_addr)) {
		    CRIT("Same IP address '%s' specified for multiple nodes", int_addr);
		    goto change_cluster_err;
		}
	    }
	}
    }

    ret = change_commit(sx, clust, nodes, nnodes, args);

 change_cluster_err:
    for(i=0; i<nnodes; i++)
	sx_node_delete(nodes[i]);
    free(nodes);
    free(query);
    sxc_cluster_free(clust);
    return ret;
}

static int replace_nodes(sxc_client_t *sx, struct cluster_args_info *args) {
    unsigned int i, j, query_sz, query_at, ncnodes, nnodes = args->inputs_num - 1;
    sx_node_t **nodes;
    sxc_cluster_t *clust = cluster_load(sx, args, 0);
    sxi_conns_t *conns;
    sxi_hostlist_t *hlist;
    sxi_hostlist_t newhlist;
    sx_nodelist_t *rplnodes = NULL;
    const sx_nodelist_t *curnodes;
    char *query = NULL;
    clst_t *clst = NULL;
    int ret = 1;

    if(!clust)
	return 1;

    sxi_hostlist_init(&newhlist);
    nodes = (sx_node_t **) calloc(nnodes, sizeof(sx_node_t *));
    if(!nodes) {
	CRIT("OOM allocating nodes");
	return 1;
    }
    for(i = 0; i < nnodes; i++) {
	nodes[i] = parse_nodef(args->inputs[i]);
	if(!nodes[i])
	    goto replace_node_err;
    }

    conns = sxi_cluster_get_conns(clust);
    hlist = sxi_conns_get_hostlist(conns);
    for(i = 0; i < sxi_hostlist_get_count(hlist); i++) {
	const char *h = sxi_hostlist_get_host(hlist, i);
	int faulty = 0;
	for(j = 0; j < nnodes; j++) {
	    if(!strcmp(sx_node_addr(nodes[j]), h) || !strcmp(sx_node_internal_addr(nodes[j]), h)) {
		faulty = 1;
		break;
	    }
	}
	if(!faulty && sxi_hostlist_add_host(sx, &newhlist, h)) {
	    CRIT("Cannot update list of nodes: %s", sxc_geterrmsg(sx));
	    goto replace_node_err;
	}
    }
    sxi_hostlist_empty(hlist);
    if(sxi_hostlist_add_list(sx, hlist, &newhlist)) {
	CRIT("Cannot update list of nodes: %s", sxc_geterrmsg(sx));
	goto replace_node_err;
    }

    if(!sxi_hostlist_get_count(hlist)) {
	CRIT("Failed to update list of non-faulty nodes");
	goto replace_node_err;
    }
    sxi_hostlist_shuffle(hlist);

    clst = clst_query(conns, NULL);
    if(!clst) {
	CRIT("Failed to query cluster status: %s", sxc_geterrmsg(sx));
	goto replace_node_err;
    }

    if(clst_ndists(clst) != 1) {
	CRIT("Cluster is currently rebalancing, cannot replace nodes");
	goto replace_node_err;
    }

    curnodes = clst_nodes(clst, 0);
    if(!curnodes || !(ncnodes = sx_nodelist_count(curnodes))) {
	CRIT("Failed to determine the current cluster members");
	goto replace_node_err;
    }

    if(nnodes >= ncnodes) {
	CRIT("Number of faulty nodes must be lower than number of cluster members");
	goto replace_node_err;
    }

    rplnodes = sx_nodelist_new();
    if(!rplnodes) {
	CRIT("Out of memory allocating list of replacement nodes");
	goto replace_node_err;
    }

    query = malloc(4096);
    if(!query) {
	CRIT("Out of memory when allocating the update query");
	goto replace_node_err;
    }
    query_sz = 4096;
    strcpy(query, "{\"nodeList\":[");
    query_at = strlen(query);

    for(i=0; i<nnodes; i++) {
	sx_node_t *n = nodes[i];
	const char *addr, *int_addr;
	const sx_uuid_t *nuuid;
	const sx_node_t *cn;
	unsigned int need, skipme;
	int64_t capa;

	nuuid = sx_node_uuid(n);
	if(sx_nodelist_lookup(rplnodes, nuuid)) {
	    CRIT("Replacement for node '%s' was specified multiple times", nuuid->string);
	    goto replace_node_err;
	}
	cn = sx_nodelist_lookup_index(curnodes, nuuid, &skipme);
	if(!cn) {
	    CRIT("Node '%s' is not a current cluster member", nuuid->string);
	    goto replace_node_err;
	}
	capa = sx_node_capacity(n);
	if(sx_node_capacity(cn) != capa) {
	    CRIT("Replacement for '%s' should have a capacity of exactly %lld bytes", nuuid->string, (long long)capa);
	    goto replace_node_err;
	}
	addr = sx_node_addr(n);
	int_addr = sx_node_internal_addr(n);

	for(j = 0; j < ncnodes; j++) {
	    if(j == skipme)
		continue;
	    cn = sx_nodelist_get(curnodes, j);
	    if(!strcmp(sx_node_addr(cn), addr) || !strcmp(sx_node_internal_addr(cn), addr)) {
		CRIT("IP address '%s' is already owned by node %s", addr, sx_node_uuid_str(cn));
		break;
	    }
	    if(!strcmp(sx_node_addr(cn), int_addr) || !strcmp(sx_node_internal_addr(cn), int_addr)) {
		CRIT("IP address '%s' is already owned by node %s", int_addr, sx_node_uuid_str(cn));
		break;
	    }
	}
	if(j < ncnodes)
	    goto replace_node_err;

	for(j = 0; j < sx_nodelist_count(rplnodes); j++) {
	    cn = sx_nodelist_get(rplnodes, j);
	    if(!strcmp(sx_node_addr(cn), addr) || !strcmp(sx_node_internal_addr(cn), addr)) {
		CRIT("Same IP address '%s' specified for multiple nodes", addr);
		break;
	    }
	    if(!strcmp(sx_node_addr(cn), int_addr) || !strcmp(sx_node_internal_addr(cn), int_addr)) {
		CRIT("Same IP address '%s' specified for multiple nodes", int_addr);
		break;
	    }
	}
	if(j < sx_nodelist_count(rplnodes))
	    goto replace_node_err;

	if(sx_nodelist_add(rplnodes, n)) {
	    CRIT("Out of memory generating list of replacement nodes");
	    goto replace_node_err;
	}
	nodes[i] = NULL;

	if(!strcmp(int_addr, addr))
	    int_addr = NULL;
	need = sizeof("{\"nodeUUID\":\"\",\"nodeAddress\":\"\",\"nodeInternalAddress\":\"\",\"nodeCapacity\":},") + 32;
	need += strlen(nuuid->string);
	need += strlen(addr);
	if(int_addr)
	    need += strlen(int_addr);
	if(need > query_sz - query_at) {
	    char *newquery;

	    query_sz += MAX(4096, need);
	    newquery = realloc(query, query_sz + 4096);
	    if(!newquery) {
		CRIT("Out of memory when generating the replace nodes query");
		goto replace_node_err;
	    }
	    query = newquery;
	}
	if(int_addr)
	    sprintf(query + query_at, "{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",\"nodeInternalAddress\":\"%s\",\"nodeCapacity\":%lld}", nuuid->string, addr, int_addr, (long long)capa);
	else
	    sprintf(query + query_at, "{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",\"nodeCapacity\":%lld}", nuuid->string, addr, (long long)capa);
	query_at = strlen(query);

	if(i != args->inputs_num-2) {
	    query[query_at++] = ',';
	    query[query_at] = '\0';
	}
    }
    strcat(query, "]}"); /* Always fits due to need above */

    hlist = sxi_conns_get_hostlist(conns);
    sxi_hostlist_empty(hlist);
    for(i = 0; i < ncnodes; i++) {
	const sx_node_t *cn = sx_nodelist_get(curnodes, i);
	if(!sx_nodelist_lookup(rplnodes, sx_node_uuid(cn)) && sxi_hostlist_add_host(sx, hlist, sx_node_internal_addr(cn))) {
	    CRIT("Cannot update list of nodes: %s", sxc_geterrmsg(sx));
	    goto replace_node_err;
	}
    }
    if(!sxi_hostlist_get_count(hlist)) {
	CRIT("Failed to update list of nodes");
	goto replace_node_err;
    }
    sxi_hostlist_shuffle(hlist);

    if(sxi_job_submit_and_poll(conns, NULL, REQ_PUT, ".nodes?replace", query, strlen(query))) {
	CRIT("The replace nodes request failed: %s", sxc_geterrmsg(sx));
	goto replace_node_err;
    }

    if(sxc_cluster_fetchnodes(clust) ||
       sxc_cluster_save(clust, args->config_dir_arg))
	WARN("Cannot update local cluster configuration: %s", sxc_geterrmsg(sx));

    ret = 0;

 replace_node_err:
    for(i = 0; i < nnodes; i++)
	sx_node_delete(nodes[i]);
    free(nodes);
    free(query);
    sxi_hostlist_empty(&newhlist);
    sx_nodelist_delete(rplnodes);
    clst_destroy(clst);
    sxc_cluster_free(clust);
    return ret;
}


static int info_node(sxc_client_t *sx, const char *path, struct node_args_info *args)
{
    int ret = 0;
    const sx_nodelist_t *nodes;
    sx_hashfs_t *h;
    char *hpath = malloc(strlen(path) + 1 + sizeof("hashfs.db")), *admin;
    int64_t dsk_alloc, dsk_used;
    char capastr[32];

    if(!hpath) {
	CRIT("OOM");
	return 1;
    }
    sprintf(hpath, "%s/hashfs.db", path);
    if(access(hpath, R_OK)) {
	if(errno == EACCES)
	    fprintf(stderr, "ERROR: Can't access %s\n", path);
	else if(errno == ENOENT)
	    fprintf(stderr, "ERROR: No valid SX storage found at %s\n", path);
	else
	    fprintf(stderr, "ERROR: Can't open SX storage at %s\n", path);
	free(hpath);
	return 1;
    }
    free(hpath);
    h = sx_hashfs_open(path, sx);
    if(!h)
	return 1;
    printf("HashFS Version: %s\n", sx_hashfs_version(h));
    printf("Cluster UUID: %s\n", sx_hashfs_uuid(h)->string);
    printf("Cluster key: %s\n", sx_hashfs_authtoken(h));
    admin = sxi_hashfs_admintoken(h);
    if(admin) {
	printf("Admin key: %s\n", admin);
	free(admin);
    }
    printf("Internal cluster protocol: %s\n", sx_hashfs_uses_secure_proto(h) ? "SECURE" : "INSECURE");
    sx_storage_usage(h, &dsk_alloc, &dsk_used);
    fmt_capa(dsk_alloc, capastr, sizeof(capastr), args->human_readable_flag);
    printf("Used disk space: %s\n", capastr);
    fmt_capa(dsk_used, capastr, sizeof(capastr), args->human_readable_flag);
    printf("Actual data size: %s\n", capastr);

    nodes = sx_hashfs_nodelist(h, NL_NEXT);
    if(nodes && sx_nodelist_count(nodes)) {
	unsigned int i, nnodes = sx_nodelist_count(nodes);
	const sx_node_t *self = sx_hashfs_self(h);
	printf("List of nodes:\n");
	for(i=0; i<nnodes; i++) {
	    const sx_node_t *n = sx_nodelist_get(nodes, i);
	    if(!n) {
		printf("Error while retrieving the node list\n");
		break;
	    }
	    fmt_capa(sx_node_capacity(n), capastr, sizeof(capastr), args->human_readable_flag);
	    printf("\t %c %s %s (%s) %s\n", (sx_node_cmp(n, self) ? '-' : '*'), sx_node_uuid_str(n), sx_node_addr(n), sx_node_internal_addr(n), capastr);
	}
    } else
	printf("No node was set yet\n");

    sx_hashfs_close(h);
    return ret;
}

static int force_gc_cluster(sxc_client_t *sx, struct cluster_args_info *args, int delete_reservations)
{
    int ret;
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    if(!clust)
	return 1;
    ret = sxc_cluster_trigger_gc(clust, delete_reservations);
    if(sxc_cluster_save(clust, args->config_dir_arg)) {
	CRIT("Failed to save the access configuration at %s: %s", args->config_dir_given ? args->config_dir_arg : "~/.sx", sxc_geterrmsg(sx));
        ret = 1;
    }
    sxc_cluster_free(clust);
    return ret;
}

void print_dist(const sx_nodelist_t *nodes) {
    if(nodes) {
	unsigned int i, nnodes = sx_nodelist_count(nodes);
	for(i = 0; i < nnodes; i++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, i);
	    const char *addr = sx_node_addr(node);
	    const char *int_addr = sx_node_internal_addr(node);

	    if(strcmp(addr, int_addr))
		printf("%lld/%s/%s/%s ", (long long)sx_node_capacity(node), addr, int_addr, sx_node_uuid_str(node));
	    else
		printf("%lld/%s/%s ", (long long)sx_node_capacity(node), addr, sx_node_uuid_str(node));
	}
	printf("\n");
    } else
	printf("Invalid distribution\n");
}

static int info_cluster(sxc_client_t *sx, struct cluster_args_info *args, int keyonly) {
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    clst_t *clst;
    const sx_nodelist_t *nodes = NULL;
    int ret = 0;

    if(!clust)
	return 1;

    clst = clst_query(sxi_cluster_get_conns(clust), NULL);
    if(!clst) {
	CRIT("Failed to query cluster status");
	sxc_cluster_free(clust);
	return 1;
    }

    switch(clst_ndists(clst)) {
    case 0:
	printf("Node is not part of a cluster\n");
	break;
    case 2:
	nodes = clst_nodes(clst, 1);
	if(!keyonly) {
	    printf("Target configuration: ");
	    print_dist(nodes);
	}
    case 1:
	if(!nodes)
	    nodes = clst_nodes(clst, 0);
	if(!keyonly) {
	    printf("Current configuration: ");
	    print_dist(clst_nodes(clst, 0));
	}
    }

    if(nodes) {
	unsigned int i, nnodes = sx_nodelist_count(nodes), header = 0;
	unsigned int version;
	uint64_t checksum;
	const sx_uuid_t *distid = clst_distuuid(clst, &version, &checksum);
	const char *auth = clst_auth(clst);
	sxi_hostlist_t hlist;

	if(keyonly) {
	    if(!auth)
		CRIT("Failed to obtain cluster key");
	    else
		printf("Cluster key: %s\n", auth);
	    clst_destroy(clst);
	    sxc_cluster_free(clust);
	    return 0;
	}

	sxi_hostlist_init(&hlist);
	for(i = 0; i < nnodes; i++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, i);
	    const char *op = NULL;
	    clst_t *clstnode;

	    if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node))) {
		CRIT("OOM adding to hostlist");
		clst_destroy(clst);
		sxc_cluster_free(clust);
		return 1;
	    }
            clstnode = clst_query(sxi_cluster_get_conns(clust), &hlist);
	    sxi_hostlist_empty(&hlist);
	    if(!clstnode) {
		printf("! Failed to get status of node %s (%s)\n", sx_node_uuid_str(node), sx_node_internal_addr(node));
		ret = 1;
		continue;
	    }
	    if(clst_rebalance_state(clstnode, &op) != CLSTOP_NOTRUNNING || clst_replace_state(clstnode, &op) != CLSTOP_NOTRUNNING) {
		if(!header) {
		    printf("Operations in progress:\n");
		    header = 1;
		}
		printf("  * node %s (%s): %s\n", sx_node_uuid_str(node), sx_node_internal_addr(node), op);
	    }
	    clst_destroy(clstnode);
	}

	if(distid)
	    printf("Distribution: %s(v.%u) - checksum: %llu\n", distid->string, version, (unsigned long long)checksum);
	printf("Cluster UUID: %s\n", sxc_cluster_get_uuid(clust));
    }

    clst_destroy(clst);
    sxc_cluster_free(clust);
    return ret;
}

static int resize_cluster(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    clst_t *clst = NULL;
    sx_node_t **nodes = NULL;
    unsigned int nnodes = 0;
    int64_t oldsize = 0, newsize;
    const char *s = args->resize_arg;
    int ret = 1, i;

    if(!clust)
	return 1;

    if(strlen(s) < 3 || (*s != '+' && *s != '-') || (newsize = sxi_parse_size(&s[1])) <= 0) {
	CRIT("Invalid resize argument: must be in format <+/->SIZE[MODIFIER], eg. +1T");
	goto resize_cluster_err;
    }
    if(*s == '-')
	newsize *= -1;

    clst = clst_query(sxi_cluster_get_conns(clust), NULL);
    if(!clst) {
	CRIT("Failed to query cluster status");
	goto resize_cluster_err;
    }

    switch(clst_ndists(clst)) {
	case 0:
	    printf("Node is not part of a cluster\n");
	    break;
	case 2:
	    printf("The cluster is currently being rebalanced and cannot be resized\n");
	    break;
	case 1: {
	    const sx_nodelist_t *nodelst = clst_nodes(clst, 0);
	    nnodes = sx_nodelist_count(nodelst);

	    nodes = (sx_node_t **) calloc(nnodes, sizeof(sx_node_t *));
	    if(!nodes) {
		CRIT("Out of memory when allocating the list of nodes");
		nnodes = 0;
		goto resize_cluster_err;
	    }

	    for(i = 0; i < nnodes; i++) {
		const sx_node_t *n = sx_nodelist_get(nodelst, i);
		oldsize += sx_node_capacity(n);
	    }

	    if(oldsize + newsize <= 0) {
		CRIT("Resize value exceeds cluster size");
		goto resize_cluster_err;
	    }
	    newsize += oldsize;

	    for(i = 0; i < nnodes; i++) {
		const sx_node_t *n = sx_nodelist_get(nodelst, i);
		int64_t newcap = ((double) sx_node_capacity(n) / oldsize) * newsize;
		nodes[i] = sx_node_new(sx_node_uuid(n), sx_node_addr(n), sx_node_internal_addr(n), newcap);
		if(!nodes[i]) {
		    CRIT("Out of memory when preparing new list of nodes");
		    goto resize_cluster_err;
		}
	    }
	    ret = change_commit(sx, clust, nodes, nnodes, args);
	}
    }

resize_cluster_err:
    for(i = 0; i < nnodes; i++)
	sx_node_delete(nodes[i]);
    free(nodes);
    clst_destroy(clst);
    sxc_cluster_free(clust);
    return ret;
}

static int check_node(sxc_client_t *sx, const char *path, int debug) {
    int ret = -1;
    sx_hashfs_t *h = NULL;

    if(!sx || !path) {
        sxi_seterr(sx, SXE_EARG, "Failed to check HashFS: NULL argument");
        goto check_node_err;
    }

    if(access(path, R_OK)) {
        if(errno == EACCES)
            fprintf(stderr, "ERROR: Can't access %s\n", path);
        else if(errno == ENOENT)
            fprintf(stderr, "ERROR: No valid SX storage found at %s\n", path);
        else
            fprintf(stderr, "ERROR: Can't open SX storage at %s\n", path);
        goto check_node_err;
    }

    h = sx_hashfs_open(path, sx);
    if(!h) {
        sxi_seterr(sx, SXE_ECFG, "Failed to open HashFS storage");
        goto check_node_err;
    }

    ret = sx_hashfs_check(h, debug);

check_node_err:
    sx_hashfs_close(h);
    if(ret > 0) {
        fprintf(stderr, "Found %d error(s) during HashFS integrity check\n", ret);
        ret = 1;
    } else if(ret)
        fprintf(stderr, "Failed to check HashFS integrity\n");
    else
        printf("HashFS is clean, no errors found\n");
    return ret;
}

static int extract_node(sxc_client_t *sx, const char *path, const char *destpath) {
    int ret = -1;
    sx_hashfs_t *h = NULL;

    if(!path || !destpath || !sx) {
        fprintf(stderr, "ERROR: Failed to extract data: NULL argument\n");
        return 1;
    }

    /* Chekc if we can read hashfs */
    if(access(path, R_OK)) {
        if(errno == EACCES)
            fprintf(stderr, "ERROR: Can't access %s\n", path);
        else if(errno == ENOENT)
            fprintf(stderr, "ERROR: No valid SX storage found at %s\n", path);
        else
            fprintf(stderr, "ERROR: Can't open SX storage at %s\n", path);
        goto extract_node_err;
    }

    h = sx_hashfs_open(path, sx);
    if(!h)
        goto extract_node_err;

    /* Perform data extraction */
    ret = sx_hashfs_extract(h, destpath);

extract_node_err:
    sx_hashfs_close(h);
    if(ret)
        fprintf(stderr, "Failed to extract data from node %s\n", path);
    else
        printf("Finished data extraction from node %s\n", path);
    return ret;
}

int main(int argc, char **argv) {
    struct main_args_info main_args;
    struct node_args_info node_args;
    struct cluster_args_info cluster_args;
    struct rlimit rlim;
    sxc_logger_t log;
    int have_command=(argc >= 2), ret = 1;
    sxc_client_t *sx = sx_init(sxc_default_logger(&log, argv[0]), NULL, NULL, 0, argc, argv);

    if(!sx) {
	fprintf(stderr, "Fatal error: sx_init() failed\n");
	return 1;
    }
    log_setminlevel(sx, SX_LOG_WARNING);

    if(!getrlimit(RLIMIT_NOFILE, &rlim) && (rlim.rlim_cur < MAX_FDS || rlim.rlim_max < MAX_FDS)) {
	unsigned int l_soft = rlim.rlim_cur, l_hard = rlim.rlim_max;
	rlim.rlim_cur = rlim.rlim_max = MAX_FDS;
	if(setrlimit(RLIMIT_NOFILE, &rlim))
	    WARN("Can't increase the limit for maximum number of open files (current: %u/%u)", l_soft, l_hard);
    }

    if(have_command && !strcmp(argv[1], "node")) {
	if(node_cmdline_parser(argc-1, argv+1, &node_args)) {
	    printf("See 'sxadm node --help' for usage information.\n");
            sx_done(&sx);
	    return 1;
        }
	sxc_set_debug(sx, node_args.debug_flag);
	if(node_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
	    ret = 0;
	    goto node_out;
	}
	if(node_args.inputs_num != 1) {
            if(node_args.extract_given)
                node_cmdline_parser_print_full_help();
            else
	        node_cmdline_parser_print_help();
	    goto node_out;
	}
	if(node_args.new_given)
	    ret = create_node(&node_args);
	else if(node_args.info_given)
	    ret = info_node(sx, node_args.inputs[0], &node_args);
        else if(node_args.check_given)
            ret = check_node(sx, node_args.inputs[0], node_args.debug_flag);
        else if(node_args.extract_given)
            ret = extract_node(sx, node_args.inputs[0], node_args.extract_arg);
    node_out:
	node_cmdline_parser_free(&node_args);
        sx_done(&sx);
	return ret;

    } else if(have_command && !strcmp(argv[1], "cluster")) {
	if(cluster_cmdline_parser(argc-1, argv+1, &cluster_args)) {
	    printf("See 'sxadm cluster --help' for usage information.\n");
            sx_done(&sx);
	    return 1;
        }
	sxc_set_debug(sx, cluster_args.debug_flag);
	if(cluster_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
	    ret = 0;
	    goto cluster_out;
	}

	if(cluster_args.new_given && cluster_args.inputs_num == 2)
	    ret = create_cluster(sx, &cluster_args);
	else if(cluster_args.info_given && cluster_args.inputs_num == 1)
	    ret = info_cluster(sx, &cluster_args, 0);
	else if(cluster_args.get_cluster_key_given && cluster_args.inputs_num == 1)
	    ret = info_cluster(sx, &cluster_args, 1);
	else if(cluster_args.mod_given && cluster_args.inputs_num >= 2)
	    ret = change_cluster(sx, &cluster_args);
	else if(cluster_args.resize_given && cluster_args.inputs_num == 1)
	    ret = resize_cluster(sx, &cluster_args);
	else if(cluster_args.replace_faulty_given && cluster_args.inputs_num >= 2)
	    ret = replace_nodes(sx, &cluster_args);
	else if(cluster_args.force_gc_given && cluster_args.inputs_num == 1)
	    ret = force_gc_cluster(sx, &cluster_args, 0);
	else if(cluster_args.force_expire_given && cluster_args.inputs_num == 1)
	    ret = force_gc_cluster(sx, &cluster_args, 1);
	else
	    cluster_cmdline_parser_print_help();
    cluster_out:
	cluster_cmdline_parser_free(&cluster_args);
        sx_done(&sx);
	return ret;
    } else {
	if(main_cmdline_parser(argc, argv, &main_args)) {
            sx_done(&sx);
	    return 1;
        }
	if(main_args.version_given)
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
	else
	    main_cmdline_parser_print_help();
	main_cmdline_parser_free(&main_args);
    }

    sx_done(&sx);
    return 0;

}
