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
#include <unistd.h>
#include <errno.h>

#include "../libsxclient/src/clustcfg.h"
#include "../libsxclient/src/jobpoll.h"
#include "../libsxclient/src/vcrypto.h"
#include "../libsxclient/src/misc.h"
#include "../libsxclient/src/hostlist.h"

#include "cmd_main.h"
#include "cmd_node.h"
#include "cmd_cluster.h"

#include "hashfs.h"
#include "hdist.h"
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
	if(sxi_rand_bytes(result->key, sizeof(result->key))) {
	    CRIT("Failed to generate random stream");
	    return -1;
	}
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

static int handle_owner(struct node_args_info *args) {
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
    } else if (uuid_generate(&cluster_uuid))
        return 1;

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

    if(handle_owner(args))
        return 1;
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

	if(!uuid && uuid_generate(&nodeid))
            break;

	ret = sx_node_new(&nodeid, addr, int_addr, capa);

    } while(0);
    free(n);
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
    struct addrinfo *nodeai = NULL, *uriai = NULL, hint;
    const char *clust_token;
    const sx_uuid_t *clust_uuid;
    struct token_pair_t auth;
    char *copy_cafile = NULL;
    sxc_uri_t *uri = NULL;
    int ret = 1;
    unsigned int http_port;

    node = parse_nodef(args->inputs[0]);
    if(!node) {
	CRIT("Malformed node definition %s", args->inputs[0]);
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

    if(sxc_cluster_add_access(clust, uri->profile, auth.token) ||
       sxc_cluster_set_access(clust, uri->profile)) {
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

    rc_ty rs = sx_storage_activate(stor, sxc_cluster_get_sslname(clust), node, auth.uid, AUTH_UID_LEN, auth.key, AUTH_KEY_LEN, http_port, copy_cafile ? "ca.pem" : NULL);
    if(rs != OK) {
	CRIT("Failed to activate node: %s", sx_hashfs_geterrmsg(stor));
	goto create_cluster_err;
    }
    if(!args->batch_mode_given)
	printf("\nCongratulations!\nYour new SX cluster was created successfully.\nYou should now (re)start the local sxserver and point your browser to http%s://%s in order to check that the cluster is reachable\nYou can then start uploading data or you can add more nodes using the --mod option\nEnjoy!\n\n", args->ssl_ca_file_given ? "s" : "", sx_node_addr(node));
    ret = 0;

 create_cluster_err:
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

    if(sxc_cluster_set_access(clust, uri->profile)) {
	printf("The selected SX profile could not be loaded.\n");
	if(uri->profile)
	    printf("Do you have a typo in \"%s\" ?\n", uri->profile);
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

static int change_commit(sxc_client_t *sx, sxc_cluster_t *clust, sx_node_t **nodes, int nnodes, const char *zones, struct cluster_args_info *args) {
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

    if(zones) {
	char *qzones = sxi_json_quote_string(zones);
	unsigned int need;

	if(!qzones) {
	    CRIT("Out of memory encoding the zone definition");
	    goto change_commit_err;
	}
	need = strlen(qzones) + sizeof("],\"distZones\":}");
	if(need > query_sz - query_at) {
	    char *newquery;
	    query_sz += need;
	    newquery = realloc(query, query_sz + 4096);
	    if(!newquery) {
		CRIT("Out of memory when generating the update query");
		free(qzones);
		goto change_commit_err;
	    }
	    query = newquery;
	}
	sprintf(query + query_at, "],\"distZones\":%s}", qzones);
	free(qzones);
    } else
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
    sxc_cluster_t *clust = cluster_load(sx, args, 0);
    const char *zones = NULL;
    char *query = NULL;
    int ret = 1;
    sx_node_t **nodes;
    sxi_hostlist_t *hlist;

    if(!clust)
	return 1;

    sxc_cluster_fetchnodes(clust);
    hlist = sxi_conns_get_hostlist(sxi_cluster_get_conns(clust));
    if(!hlist) {
	CRIT("Failed to retrieve node list for cache or cluster");
	sxc_cluster_free(clust);
	return 1;
    }

    nodes = (sx_node_t **) calloc(nnodes, sizeof(sx_node_t *));
    if(!nodes) {
	CRIT("Out of memory when allocating the list of nodes");
	sxc_cluster_free(clust);
	return 1;
    }

    for(i=0; i<nnodes; i++) {
	const char *uuid, *addr, *int_addr;
	nodes[i] = parse_nodef(args->inputs[i]);
	if(!nodes[i]) {
	    zones = args->inputs[i];
	    if(i+1 == nnodes && sxi_hdist_check_zones(zones) == OK) {
		nnodes--;
		break;
	    }
	    CRIT("Malformed definition %s", zones);
	    goto change_cluster_err;
	}

	uuid = sx_node_uuid_str(nodes[i]);
	addr = sx_node_addr(nodes[i]);
	int_addr = sx_node_internal_addr(nodes[i]);
	if(i) {
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
	if(sxi_hostlist_add_host(sx, hlist, addr) || sxi_hostlist_add_host(sx, hlist, int_addr)) {
	    CRIT("Out of memory updating the list of nodes");
	    goto change_cluster_err;
	}
    }
    if(!nnodes) {
	CRIT("Invalid distribution: no nodes provided");
	ret = 1;
    } else
	ret = change_commit(sx, clust, nodes, nnodes, zones, args);

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
	if(!nodes[i]) {
	    CRIT("Malformed node definition %s", args->inputs[i]);
	    goto replace_node_err;
	}
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
		CRIT("IP address '%s' is already assigned to node %s", addr, sx_node_uuid_str(cn));
		break;
	    }
	    if(!strcmp(sx_node_addr(cn), int_addr) || !strcmp(sx_node_internal_addr(cn), int_addr)) {
		CRIT("IP address '%s' is already assigned to node %s", int_addr, sx_node_uuid_str(cn));
		break;
	    }
	}
	if(j < ncnodes)
	    goto replace_node_err;

	for(j = 0; j < sx_nodelist_count(rplnodes); j++) {
	    cn = sx_nodelist_get(rplnodes, j);
	    if(!strcmp(sx_node_addr(cn), addr) || !strcmp(sx_node_internal_addr(cn), addr)) {
		CRIT("Same IP address '%s' specified for multiple replacement nodes", addr);
		break;
	    }
	    if(!strcmp(sx_node_addr(cn), int_addr) || !strcmp(sx_node_internal_addr(cn), int_addr)) {
		CRIT("Same IP address '%s' specified for multiple replacement nodes", int_addr);
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

    for(i = 0; i < sx_nodelist_count(rplnodes); i++) {
	const sx_node_t *rn = sx_nodelist_get(rplnodes, i);
	const sx_node_t *cn = sx_nodelist_lookup(curnodes, sx_node_uuid(rn));
	const char *addr;
	sxi_hostlist_t deadnode;

	if(!cn)
	    continue;
	sxi_hostlist_init(&deadnode);

	addr = sx_node_addr(cn);
	if(strcmp(sx_node_addr(rn), addr) &&
	   sxi_hostlist_add_host(sx, &deadnode, addr))  {
	    WARN("Cannot check replaced nodes status");
	    break;
	}

	addr = sx_node_internal_addr(cn);
	if(strcmp(sx_node_internal_addr(rn), addr) &&
	   sxi_hostlist_add_host(sx, &deadnode, addr))  {
	    sxi_hostlist_empty(&deadnode);
	    WARN("Cannot check replaced nodes status");
	    break;
	}

	if(sxi_hostlist_get_count(&deadnode) > 0) {
	    clst_destroy(clst);
	    clst = clst_query(conns, &deadnode);
	    if(clst)
		WARN("The replaced node %s appears to be still running on the old address. Please make sure it is properly shut down!", sx_node_uuid_str(rn));
	}
	sxi_hostlist_empty(&deadnode);
    }

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

static int setfaulty_nodes(sxc_client_t *sx, struct cluster_args_info *args) {
    unsigned int i, j, query_at, nnodes = args->inputs_num - 1;
    sx_node_t **nodes;
    sxc_cluster_t *clust = cluster_load(sx, args, 0);
    sxi_conns_t *conns;
    sxi_hostlist_t *hlist;
    sxi_hostlist_t usblhlist;
    char *query = NULL;
    clst_t *clst = NULL;
    int ret = 1;

    if(!clust)
	return 1;

    sxi_hostlist_init(&usblhlist);
    nodes = (sx_node_t **) calloc(nnodes, sizeof(sx_node_t *));
    if(!nodes) {
	CRIT("OOM allocating nodes");
	return 1;
    }
    for(i = 0; i < nnodes; i++) {
	nodes[i] = parse_nodef(args->inputs[i]);
	if(!nodes[i]) {
	    CRIT("Malformed node definition %s", args->inputs[i]);
	    goto setfaulty_err;
	}
	for(j = 0; j < i; j++) {
	    if(!sx_node_cmp(nodes[i], nodes[j])) {
		CRIT("Node '%s' was specified multiple times", sx_node_uuid_str(nodes[i]));
		goto setfaulty_err;
	    }
	}
    }

    conns = sxi_cluster_get_conns(clust);
    hlist = sxi_conns_get_hostlist(conns);
    /* We don't really care about addresses at this point,
     * we just remove the addresses we don't want to connect to */
    for(i = 0; i < sxi_hostlist_get_count(hlist); i++) {
	const char *h = sxi_hostlist_get_host(hlist, i);
	int faulty = 0;
	for(j = 0; j < nnodes; j++) {
	    if(!strcmp(sx_node_addr(nodes[j]), h) || !strcmp(sx_node_internal_addr(nodes[j]), h)) {
		faulty = 1;
		break;
	    }
	}
	if(!faulty && sxi_hostlist_add_host(sx, &usblhlist, h)) {
	    CRIT("Cannot update list of nodes: %s", sxc_geterrmsg(sx));
	    goto setfaulty_err;
	}
    }
    sxi_hostlist_empty(hlist);
    if(sxi_hostlist_add_list(sx, hlist, &usblhlist)) {
	CRIT("Cannot update list of nodes: %s", sxc_geterrmsg(sx));
	goto setfaulty_err;
    }

    if(!sxi_hostlist_get_count(hlist)) {
	CRIT("Failed to update list of usable nodes");
	goto setfaulty_err;
    }
    sxi_hostlist_shuffle(hlist);

    clst = clst_query(conns, NULL);
    if(!clst) {
	CRIT("Failed to query cluster status: %s", sxc_geterrmsg(sx));
	goto setfaulty_err;
    }

    if(clst_ndists(clst) != 1) {
	CRIT("Cluster is currently rebalancing, cannot update node status");
	goto setfaulty_err;
    }

    for(i = 0; i < nnodes; i++) {
	const sx_uuid_t *nid = sx_node_uuid(nodes[i]);
	const sx_node_t *refnode = sx_nodelist_lookup(clst_nodes(clst, 0), nid);
	if(refnode && !sx_node_cmp_addrs(nodes[i], refnode))
	    continue;
	CRIT("Node %lld/%s/%s/%s doesn't match any node in the cluster definition",
	     (long long)sx_node_capacity(nodes[i]), sx_node_addr(nodes[i]), sx_node_internal_addr(nodes[i]), nid->string);
	goto setfaulty_err;
    }

    query = malloc((UUID_STRING_SIZE+3) * nnodes + sizeof("{\"faultyNodes\":[]}"));
    if(!query) {
	CRIT("Out of memory when allocating the update query");
	goto setfaulty_err;
    }
    query_at = lenof("{\"faultyNodes\":[");
    strcpy(query, "{\"faultyNodes\":[");

    for(i=0; i<nnodes; i++) {
	sprintf(query + query_at, "\"%s\"%s", sx_node_uuid_str(nodes[i]), i != nnodes-1 ? "," : "]}");
	query_at += strlen(query + query_at);
    }

    if(sxi_job_submit_and_poll(conns, NULL, REQ_PUT, ".nodes?setfaulty", query, strlen(query))) {
	CRIT("Failed to update node health: %s", sxc_geterrmsg(sx));
	goto setfaulty_err;
    }

    if(sxc_cluster_fetchnodes(clust) ||
       sxc_cluster_save(clust, args->config_dir_arg))
	WARN("Cannot update local cluster configuration: %s", sxc_geterrmsg(sx));

    ret = 0;

    for(i = 0; i < nnodes; i++) {
	sxi_hostlist_t deadnode;
	sxi_hostlist_init(&deadnode);
	if(sxi_hostlist_add_host(sx, &deadnode, sx_node_addr(nodes[i])) ||
	   sxi_hostlist_add_host(sx, &deadnode, sx_node_internal_addr(nodes[i]))) {
	    sxi_hostlist_empty(&deadnode);
	    WARN("Cannot check faulty nodes status");
	    break;
	}
	clst_destroy(clst);
	clst = clst_query(conns, &deadnode);
	sxi_hostlist_empty(&deadnode);
	if(clst)
	    WARN("Faulty node %s appears to be still running. Please make sure it is properly shut down!", sx_node_uuid_str(nodes[i]));
    }

 setfaulty_err:
    for(i = 0; i < nnodes; i++)
	sx_node_delete(nodes[i]);
    free(nodes);
    free(query);
    sxi_hostlist_empty(&usblhlist);
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
    printf("HashFS Version: %s\n", sx_hashfs_version(h)->string);
    printf("Cluster UUID: %s\n", sx_hashfs_uuid(h)->string);
    printf("Cluster key: %s\n", sx_hashfs_authtoken(h));
    admin = sxi_hashfs_admintoken(h);
    if(admin) {
	printf("Admin key: %s\n", admin);
	free(admin);
    }
    printf("Internal cluster protocol: %s\n", sx_hashfs_uses_secure_proto(h) ? "SECURE" : "INSECURE");
    float data_incore, other_incore;
    if (!sx_hashfs_incore(h, &data_incore, &other_incore))
        printf("Database resident in memory: blocks %.2f%%, other %.2f%%\n", data_incore, other_incore);
    sx_storage_usage(h, &dsk_alloc, &dsk_used);
    fmt_capa(dsk_alloc, capastr, sizeof(capastr), args->human_readable_flag);
    printf("Used disk space: %s\n", capastr);
    fmt_capa(dsk_used, capastr, sizeof(capastr), args->human_readable_flag);
    printf("Actual data size: %s\n", capastr);

    nodes = sx_hashfs_all_nodes(h, NL_NEXT);
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

static int get_node_definition(sxc_client_t *sx, const char *path)
{
    int ret = 0;
    sx_hashfs_t *h;

    h = sx_hashfs_open(path, sx);
    if(!h)
	return 1;
    const sx_node_t *self = sx_hashfs_self(h);
    if (!self)
        return 1;
    if(strcmp(sx_node_addr(self), sx_node_internal_addr(self)))
	printf("%lld/%s/%s/%s\n", (long long)sx_node_capacity(self), sx_node_addr(self), sx_node_internal_addr(self), sx_node_uuid(self)->string);
    else
	printf("%lld/%s/%s\n", (long long)sx_node_capacity(self), sx_node_addr(self), sx_node_uuid(self)->string);
    sx_hashfs_close(h);
    return ret;
}

/* sxadm node --rename-cluster <STORAGE_PATH> */
static int rename_cluster(sxc_client_t *sx, const char *path, const char *name)
{
    int ret = 1;
    sx_hashfs_t *h = NULL;
    char *hpath;
    const char *old_name;

    if(!path || !name) {
        fprintf(stderr, "Invalid argument\n");
        return 1;
    }

    hpath = malloc(strlen(path) + 1 + sizeof("hashfs.db"));
    if(!hpath) {
        fprintf(stderr, "Failed to prepare storage database path\n");
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
        goto rename_cluster_err;
    }

    h = sx_hashfs_open(path, sx);
    if(!h)
        goto rename_cluster_err;

    if(sx_hashfs_cluster_get_name(h, &old_name)) {
        fprintf(stderr, "ERROR: Failed to get old cluster name\n");
        goto rename_cluster_err;
    }

    if(!strcmp(name, old_name)) {
        fprintf(stderr, "ERROR: New cluster name is the same as the old one\n");
        goto rename_cluster_err;
    }

    if(!strlen(name)) {
        fprintf(stderr, "ERROR: Cluster name is too short\n");
        goto rename_cluster_err;
    }

    if(sx_hashfs_cluster_set_name(h, name)) {
        fprintf(stderr, "ERROR: Failed to set cluster name\n");
        goto rename_cluster_err;
    }

    printf("New cluster name is '%s'\n", name);
    ret = 0;
rename_cluster_err:
    free(hpath);
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

static int junlock_cluster(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster = cluster_load(sx, args, 1);
    int ret;

    if(!cluster)
        return 1;

    if(sxi_job_submit_and_poll(sxi_cluster_get_conns(cluster), NULL, REQ_DELETE, ".jlock", NULL, 0)) {
	CRIT("The request failed: %s", sxc_geterrmsg(sx));
	ret = 1;
    } else {
	ret = 0;
        printf("Successfully forced job allowance\n");
    }
    sxc_cluster_free(cluster);
    return ret;
}


static void print_dist(const sx_nodelist_t *nodes, const char *zones) {
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
	if(i && zones)
	    printf("%s", zones);
	printf("\n");
    } else
	printf("Invalid distribution\n");
}

static int sortnodes(const void *a, const void *b) {
    const sx_node_t *nodea = *(const sx_node_t **)a;
    const sx_node_t *nodeb = *(const sx_node_t **)b;
    int64_t capaa = sx_node_capacity(nodea);
    int64_t capab = sx_node_capacity(nodeb);
    const sx_uuid_t *uuida, *uuidb;

    if(capaa > capab)
	return -1;
    if(capaa < capab)
	return 1;

    uuida = sx_node_uuid(nodea);
    uuidb = sx_node_uuid(nodeb);
    return memcmp(uuida->binary, uuidb->binary, sizeof(uuida->binary));
}

enum infotype {
    INFO_ALL,
    INFO_KEY,
    INFO_REPLICA
};

static int info_cluster(sxc_client_t *sx, struct cluster_args_info *args, enum infotype itype) {
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    clst_t *clst = NULL, *clstleader = NULL;
    const sx_nodelist_t *nodes = NULL, *nodes_prev = NULL, *faulty_nodes = NULL;
    const raft_node_data_t *raft_status = NULL;
    sx_nodelist_t *merged = NULL;
    const sx_node_t **sorted = NULL;
    const sx_uuid_t *distid;
    sx_uuid_t leaderid;
    unsigned int i, nnodes, distver, raft_nstatus;
    uint64_t distchk;
    const char *zonedef = NULL;
    sxi_hdist_t *zmodel = NULL;
    char capastr[32];
    int ret = 1, is_rebalancing = 0;

    if(!clust)
	return 1;

    clst = clst_query(sxi_cluster_get_conns(clust), NULL);
    if(!clst) {
	CRIT("Failed to query cluster status");
	goto info_out;
    }

    if(itype == INFO_KEY) {
	const char *auth = clst_auth(clst);
	if(!auth)
	    CRIT("Failed to obtain cluster key");
	else
	    printf("Cluster key: %s\n", auth);
	ret = 0;
	goto info_out;
    } else if(itype == INFO_REPLICA) {
	unsigned int max_replica = clst_get_maxreplica(clst);
	unsigned int min_replica = 1 + (max_replica - clst_get_current_maxreplica(clst));
	printf("Currently allowed volume replicas (min:max): %u:%u\n", min_replica, max_replica);
	ret = 0;
	goto info_out;
    }

    printf("Cluster UUID: %s\n", sxc_cluster_get_uuid(clust));
    printf("Operating mode: %s\n", clst_readonly(clst) ? "read-only" : "read-write");

    switch(clst_ndists(clst)) {
    case 0:
	printf("Node is not part of a cluster\n");
	ret = 0;
	goto info_out;
    case 2:
	nodes = clst_nodes(clst, 1);
	zonedef = clst_zones(clst, 1);
	printf("Target configuration: ");
	print_dist(nodes, zonedef);
        is_rebalancing = 1;
    case 1:
	nodes_prev = clst_nodes(clst, 0);
	if(!nodes) {
	    nodes = nodes_prev;
	    zonedef = clst_zones(clst, 0);
	}
    }

    printf("Current configuration: ");
    print_dist(nodes_prev, zonedef);
    distid = clst_distuuid(clst, &distver, &distchk);
    if(distid)
	printf("Distribution: %s(v.%u) - checksum: %llu\n", distid->string, distver, (unsigned long long)distchk);
    else
	printf("Distribution: unavailable");

    if(zonedef) {
	sxi_hdist_t *mod = NULL;
	do {
	    mod = sxi_hdist_new(0, 1, NULL);
	    if(!mod) {
		CRIT("Failed to allocate zone distribution model");
		break;
	    }
	    nnodes = sx_nodelist_count(nodes);
	    for(i=0; i<nnodes; i++) {
		const sx_node_t *node = sx_nodelist_get(nodes, i);
		if(sxi_hdist_addnode(mod, sx_node_uuid(node), sx_node_addr(node), sx_node_internal_addr(node), sx_node_capacity(node), NULL))
		    break;
	    }
	    if(i<nnodes) {
		CRIT("Failed to compose zone distribution model");
		break;
	    }
	    if(sxi_hdist_build(mod, zonedef)) {
		CRIT("Failed to build zone distribution model");
		break;
	    }
	    zmodel = mod;
	} while(0);
	if(!zmodel) {
	    sxi_hdist_free(mod);
	    goto info_out;
	}
    }

    if(!is_rebalancing && sx_nodelist_count(nodes) >= 3) {
	/* There should be a leader */
	if(!uuid_from_string(&leaderid, clst_leader_node(clst))) {
	    const char *role = clst_raft_role(clst);
	    if(!role || strcmp(role, "leader")) {
		const sx_node_t *leadernode;
		/* Query the leader */

		if((leadernode = sx_nodelist_lookup(nodes_prev, &leaderid))) {
		    sxi_hostlist_t hlist;

		    sxi_hostlist_init(&hlist);
		    if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(leadernode))) {
			CRIT("OOM checking leader status");
			goto info_out;
		    }
		    clstleader = clst_query(sxi_cluster_get_conns(clust), &hlist);
		    sxi_hostlist_empty(&hlist);
		    if(clstleader) {
			role = clst_raft_role(clstleader);
			if(!role || strcmp(role, "leader")) {
			    clst_destroy(clstleader);
			    clstleader = NULL;
			}
		    }
		}
	    } else
		clstleader = clst; /* We happen to have already queried the leader */
	}
	if(clstleader)
	    raft_status = clst_raft_nodes_data(clstleader, &raft_nstatus);
	else
	    WARN("Election in progress: reported roles may not be accurate");
    }

    faulty_nodes = clst_faulty_nodes(clst);
    merged = sx_nodelist_new();
    if(!merged ||
       sx_nodelist_addlist(merged, nodes) ||
       sx_nodelist_addlist(merged, nodes_prev)) {
	CRIT("Failed to allocate list of nodes");
	goto info_out;
    }
    nnodes = sx_nodelist_count(merged);
    sorted = malloc(sizeof(sorted[0]) * nnodes);
    if(!sorted) {
	CRIT("Failed to allocate array of nodes");
	goto info_out;
    }
    for(i=0; i<nnodes; i++)
	sorted[i] = sx_nodelist_get(merged, i);
    qsort(sorted, nnodes, sizeof(sorted[0]), sortnodes);

    printf("State of nodes:\n");
    ret = 0;
    for(i=0; i<nnodes; i++) {
	const sx_node_t *node = sorted[i];
	const sx_uuid_t *nodeuuid = sx_node_uuid(node);
	const char *nodeaddr = sx_node_addr(node), *nodeintaddr = sx_node_internal_addr(node);;
	const char *zone = NULL, *op = NULL;
	sxi_hostlist_t hlist;
	clst_t *clstnode = NULL;
	int isleader = 0, isonline = 1;
	int64_t last_seen = 0;

	enum state_t { ST_NONE, ST_FAULTY, ST_LEAVING, ST_JOINING, ST_LEADER, ST_FOLLOWER } st = ST_NONE;

	zone = zmodel ? sxi_hdist_get_node_zone(zmodel, 0, nodeuuid) : NULL;

	if(sx_nodelist_lookup(faulty_nodes, nodeuuid))
	    st = ST_FAULTY;
	else if(!sx_nodelist_lookup(nodes, nodeuuid))
	    st = ST_LEAVING;
	else if(!sx_nodelist_lookup(nodes_prev, nodeuuid))
	    st = ST_JOINING;
	if(clstleader && !memcmp(nodeuuid, &leaderid, sizeof(leaderid)))
	    isleader = 1;
	if(st == ST_NONE)
	    st = isleader ? ST_LEADER : ST_FOLLOWER;

	if(st == ST_FAULTY)
	    isonline = 0;
	else if(st != ST_JOINING && raft_status) {
	    unsigned int j;
	    for(j=0; j<raft_nstatus; j++) {
		if(memcmp(&raft_status[j].uuid, nodeuuid, sizeof(*nodeuuid)))
		    continue;
		if(!raft_status[j].state) {
		    last_seen = raft_status[j].last_contact;
		    isonline = 0;
		}
		break;
	    }
	}

	if(isonline) {
	    if(!isleader) {
		sxi_hostlist_init(&hlist);
		if(sxi_hostlist_add_host(sx, &hlist, nodeintaddr)) {
		    CRIT("OOM checking node status");
		    ret = 1;
		    goto info_out;
		}
		clstnode = clst_query(sxi_cluster_get_conns(clust), &hlist);
		sxi_hostlist_empty(&hlist);
	    } else
		clstnode = clstleader; /* We have already queried the leader */

	    if(clstnode) {
		if(clst_rebalance_state(clstnode, &op) == CLSTOP_NOTRUNNING &&
		   clst_replace_state(clstnode, &op) == CLSTOP_NOTRUNNING &&
		   clst_upgrade_state(clstnode, &op) == CLSTOP_NOTRUNNING)
		    op = NULL;
	    } else
		isonline = 0;
	}

	printf("  * node %s: addr: %s", nodeuuid->string, nodeaddr);
	if(strcmp(nodeaddr, nodeintaddr))
	    printf(", int.addr: %s", nodeintaddr);
	fmt_capa(sx_node_capacity(node), capastr, sizeof(capastr), args->human_readable_flag);
	printf(", capacity: %s", capastr);
	if(zone)
	    printf(", zone: %s", zone);

	printf(", status: ");
	switch(st) {
	case ST_FAULTY:
	    printf("** FAULTY **");
	    op = "this node is currently being ignored";
	    break;
	case ST_LEAVING:
	    printf("leaving");
	    break;
	case ST_JOINING:
	    printf("joining");
	    break;
	case ST_LEADER:
	    printf("leader");
	    break;
	case ST_FOLLOWER:
	default:
	    printf("follower");
	    break;
	}
	if(!isonline) {
	    if(last_seen)
		printf(", online: ** NO ** (last contact: %lld seconds ago)", (long long)last_seen);
	    else
		printf(", online: ** NO **");
	} else if(op)
	    printf(", online: yes, activity: %s", op);
	else
	    printf(", online: yes" );

        if(isleader && clst_raft_message(clstleader))
            printf(", notice: %s\n", clst_raft_message(clstleader));
        else
            printf("\n");

	if(!isleader)
	    clst_destroy(clstnode);
    }

 info_out:
    free(sorted);
    sxi_hdist_free(zmodel);
    sx_nodelist_delete(merged);
    if(clstleader != clst) /* Don't free it twice if they are the same */
	clst_destroy(clstleader);
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

    if(strlen(s) < 3 || (*s != '+' && *s != '-') || (newsize = sxi_parse_size(sx, &s[1], 0)) <= 0) {
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
	    ret = change_commit(sx, clust, nodes, nnodes, clst_zones(clst, 0), args);
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

static int check_node(sxc_client_t *sx, const char *path, int debug, int show_progress) {
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

    ret = sx_hashfs_check(h, debug, show_progress);

check_node_err:
    sx_hashfs_close(h);
    if(ret > 0) {
        fprintf(stderr, "Found %d error(s) during HashFS integrity check\n", ret);
        ret = 1;
    } else if(ret)
        fprintf(stderr, "Failed to check HashFS integrity\n");
    else if(show_progress)
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

static int compact_data(sxc_client_t *sx, const char *path, int human_readable) {
    sx_hashfs_t *h = NULL;
    char szstr[32];
    int64_t freed;
    rc_ty s;

    if(!path || !sx) {
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
        return 1;
    }

    h = sx_hashfs_open(path, sx);
    if(!h)
        return 1;

    /* Compact hashfs data */
    s = sx_hashfs_compact(h, &freed);
    sx_hashfs_close(h);
    if(s) {
        fprintf(stderr, "Failed to compact node data\n");
	return 1;
    }

    fmt_capa(freed, szstr, sizeof(szstr), human_readable);
    printf("Operation complete (disk space freed: %s)\n", szstr);

    if(freed < 4 * 1024 * 1024)
	printf("NOTE: If you have recently removed a lot of files and want to reclaim that space, please force a GC run first (see \"sxadm cluster --help\")\n");

    return 0;
}

static void print_status(sxc_client_t *sx, int http_code, const sxi_node_status_t *status, int human_readable) {
    char str[64];

    if(!sx)
        return;

    if(!status) {
        printf("ERROR: %s\n\n", sxc_geterrmsg(sx));
        return;
    }

    printf("Node %s status:\n", status->uuid);
    printf("    Versions:\n");
    printf("        SX: %s\n", status->libsxclient_version);
    printf("        HashFS: %s\n", status->hashfs_version);
    printf("    System:\n");
    printf("        Name: %s\n", status->os_name);
    printf("        Architecture: %s\n", status->os_arch);
    printf("        Release: %s\n", status->os_release);
    printf("        Version: %s\n", status->os_version);
    if(status->cores != -1)
        printf("        CPU(s): %d\n", status->cores);
    else
        printf("        CPU(s): N/A\n");
    printf("        Endianness: %s\n", status->endianness);
    printf("        Local time: %s\n", status->localtime);
    printf("        UTC time: %s\n", status->utctime);
    printf("    Network:\n");
    printf("        Public address: %s\n", status->addr);
    printf("        Internal address: %s\n", status->internal_addr);
    printf("    Storage:\n");
    printf("        Storage directory: %s\n", status->storage_dir);
    fmt_capa(status->storage_allocated, str, sizeof(str), human_readable);
    printf("        Allocated space: %s\n", str);
    fmt_capa(status->storage_commited, str, sizeof(str), human_readable);
    printf("        Used space: %s\n", str);
    printf("    Storage filesystem:\n");
    if(status->block_size != -1) {
        fmt_capa(status->block_size, str, sizeof(str), human_readable);
        printf("        Block size: %s\n", str);
    } else
        printf("        Block size: N/A\n");

    if(status->avail_blocks != -1) {
        fmt_capa(status->block_size * status->total_blocks, str, sizeof(str), human_readable);
        printf("        Total size: %s\n", str);
    } else
        printf("        Total size: N/A\n");

    if(status->total_blocks != -1) {
        fmt_capa(status->block_size * status->avail_blocks, str, sizeof(str), human_readable);
        printf("        Available: %s\n", str);
    } else
        printf("        Available: N/A\n");

    if(status->total_blocks > 0 && status->avail_blocks > 0) /* Avoid division by 0 and printing not assigned (-1) values */
        printf("        Used: %.2lf%%\n", (double)(status->total_blocks - status->avail_blocks) * 100.0 / status->total_blocks);
    else
        printf("        Used: N/A\n");
    
    printf("    Memory:\n");
    if(status->mem_total != -1) {
        fmt_capa(status->mem_total, str, sizeof(str), human_readable);
        printf("        Total: %s\n", str);
    } else
        printf("        Total: N/A\n");

    if(status->mem_avail != -1) {
        fmt_capa(status->mem_avail, str, sizeof(str), human_readable);
        printf("        Available: %s\n", str);
    } else
        printf("        Available: N/A\n");

    if(status->swap_total != -1) {
        fmt_capa(status->swap_total, str, sizeof(str), human_readable);
        printf("        Swap total: %s\n", str);
    } else
        printf("        Swap total: N/A\n");

    if(status->swap_free != -1) {
        fmt_capa(status->swap_free, str, sizeof(str), human_readable);
        printf("        Swap free: %s\n", str);
    } else
        printf("        Swap free: N/A\n");

    printf("\n");
}

static int cluster_status(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    int ret;

    if(!clust) {
        fprintf(stderr, "ERROR: Failed to load cluster\n");
        return 1;
    }

    ret = sxi_cluster_status(clust, print_status, args->human_readable_given);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));

    sxc_cluster_free(clust);
    return ret;
}

enum mismatch {
    NONE=0,
    MISMATCH_STORAGE_VERSION,
    MISMATCH_LIBSXCLIENT_VERSION,
    MISMATCH_OLD_VERSION,
    MISMATCH_NOREPLY,
    MISMATCH_OFFLINE,
};
static int check_upgrade_mismatch;
static int upgrade_complete;
static int upgrade_nodes;

static void check_status(sxc_client_t *sx, int http_code, const sxi_node_status_t *status, int human_readable)
{
    static sxi_node_status_t last_status;
    static int has_last_status = 0;
    if (!sx)
        return;
    upgrade_nodes++;
    if (!status) {
        if (http_code == -1)
            check_upgrade_mismatch |= 1 << MISMATCH_OFFLINE;
        else if (sxc_geterrnum(sx) == SXE_EAGAIN)
            check_upgrade_mismatch |= 1 << MISMATCH_OLD_VERSION;
        else
            check_upgrade_mismatch |= 1 << MISMATCH_NOREPLY;
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return;
    }
    printf("\t%s: %s (%s)\n", status->addr, status->hashfs_version, status->libsxclient_version);
    if (!has_last_status) {
        memcpy(&last_status, status, sizeof(last_status));
        has_last_status = 1;
    } else if (strcmp(last_status.hashfs_version, status->hashfs_version))
        check_upgrade_mismatch |= 1 << MISMATCH_STORAGE_VERSION;
    else if (strcmp(last_status.libsxclient_version, status->libsxclient_version))
        check_upgrade_mismatch |= 1 << MISMATCH_LIBSXCLIENT_VERSION;
    if (!strcmp(status->heal_status, "DONE"))
        upgrade_complete++;
}

static int cluster_upgrade(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *clust = cluster_load(sx, args, 1);
    int ret;

    if(!clust) {
        fprintf(stderr, "ERROR: Failed to load cluster\n");
        return 1;
    }

    printf("Versions:\n");
    ret = sxi_cluster_status(clust, check_status, 0);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    if (check_upgrade_mismatch) {
        fprintf(stderr, "Warning: Upgrade aborted\n");
        if (check_upgrade_mismatch & (1 << MISMATCH_OFFLINE))
            fprintf(stderr,"\tSome nodes are offline\n");
        if (check_upgrade_mismatch & (1 << MISMATCH_NOREPLY))
            fprintf(stderr,"\tNot all replies could be parsed\n");
        if (check_upgrade_mismatch & (1 << MISMATCH_OLD_VERSION))
            fprintf(stderr,"\tSome nodes are still running version 1.0\n");
        if (check_upgrade_mismatch & (1 << MISMATCH_STORAGE_VERSION))
            fprintf(stderr,"\tSome nodes are still running an old server version\n");
        if (check_upgrade_mismatch & (1 << MISMATCH_LIBSXCLIENT_VERSION))
            fprintf(stderr,"\tlibsxclient versions don't match\n");
        ret = 1;
    } else {
        if (upgrade_complete == upgrade_nodes) {
            printf("Cluster already fully upgraded\n");
	    ret = 2;
        } else {
            printf("Triggering upgrade and garbage collector\n");
            ret = force_gc_cluster(sx, args, 0);
        }
    }

    sxc_cluster_free(clust);
    return ret;
}

static int cluster_dist_lock(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster = cluster_load(sx, args, 1);
    int ret;

    if(!cluster)
        return 1;
    ret = sxi_cluster_distribution_lock(cluster, args->locking_node_given ? args->locking_node_arg : NULL);
    sxc_cluster_free(cluster);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    else
        printf("Successfully locked cluster for changes\n");
    return ret;
}

static int cluster_dist_unlock(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster = cluster_load(sx, args, 1);
    int ret;

    if(!cluster)
        return 1;
    ret = sxi_cluster_distribution_unlock(cluster, args->locking_node_given ? args->locking_node_arg : NULL);
    sxc_cluster_free(cluster);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    else
        printf("Successfully unlocked cluster\n");
    return ret;
}

static int cluster_set_mode(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster;
    int ret;
    int readonly = 0;

    if(!args || !args->set_mode_arg) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    if(!strcmp(args->set_mode_arg, "ro"))
        readonly = 1;
    else if(strcmp(args->set_mode_arg, "rw")) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    cluster = cluster_load(sx, args, 1);
    if(!cluster)
        return 1;
    ret = sxi_cluster_set_mode(cluster, readonly);
    sxc_cluster_free(cluster);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    else
        printf("Successfully switched cluster to %s mode\n", readonly ? "read-only" : "read-write");
    return ret;
}

static int upgrade_node(sxc_client_t *sx, const char *path)
{
    unsigned hpath_len = strlen(path) + 1 + sizeof("hashfs.db");
    char *hpath = wrap_malloc(hpath_len);
    if (!hpath)
        return 1;
    snprintf(hpath, hpath_len, "%s/hashfs.db", path);
    if (access(hpath, R_OK)) {
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
    log_setminlevel(sx, SX_LOG_INFO);
    rc_ty rc = sx_storage_upgrade(path);
    if (rc) {
        fprintf(stderr, "ERROR: Failed to upgrade storage at path %s: %s\n", path, rc2str(rc));
        return 1;
    }
    sx_hashfs_t *h = sx_hashfs_open(path, sx);
    if (!h)
        return 1;
    rc = sx_storage_upgrade_job(h);
    if (rc)
        fprintf(stderr, "ERROR: Failed to add upgrade job: %s (%s)\n", rc2str(rc), msg_get_reason());
    sx_hashfs_close(h);
    INFO("Storage is up to date");
    return rc != OK;
}

static int upgrade_job_node(sxc_client_t *sx, const char *path)
{
    log_setminlevel(sx, SX_LOG_INFO);
    sx_hashfs_t *hashfs = sx_hashfs_open(path, sx);
    if (!hashfs)
        return 1;
    rc_ty s;
    do {
        if ((s = sx_hashfs_upgrade_1_0_or_1_1_prepare(hashfs))) {
            WARN("Failed to prepare upgrade job: %s", rc2str(s));
            break;
        }
        if ((s = sx_hashfs_upgrade_1_0_or_1_1_local(hashfs))) {
            WARN("Failed to run upgrade job: %s", rc2str(s));
            break;
        }
    } while(0);
    sx_hashfs_close(hashfs);
    return s == OK ? 0 : 1;
}

static int gc_node(sxc_client_t *sx, const char *path, int force_expire)
{
    if (!sxc_is_verbose(sx)) {
        log_setminlevel(sx, SX_LOG_INFO);
        sxc_set_verbose(sx, 1);
    }
    sx_hashfs_t *hashfs = sx_hashfs_open(path, sx);
    if (!hashfs)
        return 1;
    int term = 0;
    gc_max_batch_time = 1;
    gc_yield_time = 1.1;
    gc_slow_check = 0;
    rc_ty s = sx_hashfs_gc_periodic(hashfs, &term, force_expire ? -1 : GC_GRACE_PERIOD);
    s |= sx_hashfs_gc_run(hashfs, &term);
    sx_hashfs_close(hashfs);
    return s == OK ? 0 : 1;
}

static int warm_cache_node(sxc_client_t *sx, const char *path)
{
    if (!sxc_is_verbose(sx)) {
        log_setminlevel(sx, SX_LOG_INFO);
        sxc_set_verbose(sx, 1);
    }
    sx_hashfs_t *hashfs = sx_hashfs_open(path, sx);
    if (!hashfs)
        return 1;
    sx_hashfs_warm_cache(hashfs);
    sx_hashfs_close(hashfs);
    return OK;
}

static int vacuum_node(sxc_client_t *sx, const char *path)
{
    if (!sxc_is_verbose(sx)) {
        log_setminlevel(sx, SX_LOG_INFO);
        sxc_set_verbose(sx, 1);
    }
    sx_hashfs_t *hashfs = sx_hashfs_open(path, sx);
    if (!hashfs)
        return 1;
    printf("Vacuuming databases\n");
    fflush(stdout);
    int s = sx_hashfs_vacuum(hashfs);
    if (s == 0)
        printf("Vacuum done\n");
    sx_hashfs_close(hashfs);
    return s;
}

static int get_cluster_meta_common(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_meta_t *meta, const char *key, int is_cluster_meta) {
    unsigned int i, count;
    unsigned int max_value_len = is_cluster_meta ? SXLIMIT_META_MAX_VALUE_LEN : SXLIMIT_SETTINGS_MAX_VALUE_LEN;

    if(!sx || !cluster || !meta || !key) {
        fprintf(stderr, "ERROR: NULL argument\n");
        return 1;
    }

    count = sxc_meta_count(meta);
    if(!strcmp(key, "ALL")) {
        for(i = 0; i < count; i++) {
            const char *metakey = NULL;
            const void *metaval = NULL;
            char metaval_str[MAX(SXLIMIT_SETTINGS_MAX_VALUE_LEN,SXLIMIT_META_MAX_VALUE_LEN)+1];
            unsigned int l;

            if(sxc_meta_getkeyval(meta, i, &metakey, &metaval, &l) || !metakey || !metaval || l > max_value_len) {
                fprintf(stderr, "ERROR: Failed to get cluster %s\n", is_cluster_meta ? "meta" : "settings");
                return 1;
            }

            memcpy(metaval_str, metaval, l);
            metaval_str[l] = '\0';
            printf("%s=%s\n", metakey, metaval_str);
        }
    } else {
        const void *metaval = NULL;
        char metaval_str[MAX(SXLIMIT_SETTINGS_MAX_VALUE_LEN,SXLIMIT_META_MAX_VALUE_LEN)+1];
        unsigned int l;

        if(sxc_meta_getval(meta, key, &metaval, &l) || !metaval || l > max_value_len) {
            fprintf(stderr, "ERROR: Cluster %s key '%s' does not exist\n", is_cluster_meta ? "meta" : "settings", key);
            return 1;
        }

        memcpy(metaval_str, metaval, l);
        metaval_str[l] = '\0';
        printf("%s=%s\n", key, metaval_str);
    }
    return 0;
}

static int get_cluster_meta(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster;
    sxc_meta_t *meta;
    int ret;

    cluster = cluster_load(sx, args, 1);
    if(!cluster || !args->get_meta_arg)
        return 1;

    meta = sxc_clustermeta_new(cluster);
    if(!meta) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        sxc_cluster_free(cluster);
        return 1;
    }

    ret = get_cluster_meta_common(sx, cluster, meta, args->get_meta_arg, 1);
    sxc_meta_free(meta);
    sxc_cluster_free(cluster);
    return ret;
}

static int get_cluster_settings(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster;
    sxc_meta_t *meta;
    int ret;

    cluster = cluster_load(sx, args, 1);
    if(!cluster || !args->get_param_arg) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    meta = sxc_cluster_settings_new(cluster, args->get_param_arg);
    if(!meta) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        sxc_cluster_free(cluster);
        return 1;
    }

    ret = get_cluster_meta_common(sx, cluster, meta, args->get_param_arg, 0);
    sxc_meta_free(meta);
    sxc_cluster_free(cluster);
    return ret;
}

static int set_cluster_meta_common(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_meta_t *meta, const char **entries, unsigned int nentries, int is_cluster_meta) {
    unsigned int i;
    int ret;

    if(!sx || !cluster || !meta || !entries) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    for(i = 0; i < nentries; i++) {
        char metakey[MAX(SXLIMIT_META_MAX_KEY_LEN,SXLIMIT_SETTINGS_MAX_KEY_LEN)+1];
        size_t off;
        const char *val, *str = entries[i];
        unsigned int value_len;

        /* Look for '='' char to separate key and value */
        val = strchr(str, '=');
        if(!val) {
            fprintf(stderr, "ERROR: Meta entries must be in 'key=value' format\n");
            return 1;
        }

        off = val - str;
        if((is_cluster_meta && off > SXLIMIT_META_MAX_KEY_LEN) || (!is_cluster_meta && off > SXLIMIT_SETTINGS_MAX_KEY_LEN)) {
            fprintf(stderr, "ERROR: Meta key too long\n");
            return 1;
        }

        memcpy(metakey, str, off);
        metakey[off] = '\0';
        val++;
        value_len = strlen(val);

        if((is_cluster_meta && value_len > SXLIMIT_META_MAX_VALUE_LEN) ||
           (is_cluster_meta && value_len > SXLIMIT_SETTINGS_MAX_VALUE_LEN)) {
            fprintf(stderr, "ERROR: Meta value too long\n");
            return 1;
        }

        if(sxc_meta_setval(meta, metakey, val, value_len)) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            return 1;
        }
    }

    ret = is_cluster_meta ? sxi_cluster_set_meta(cluster, meta) : sxi_cluster_set_settings(cluster, meta);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    return ret;
}

static int set_cluster_meta(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster;
    int ret;
    sxc_meta_t *meta;

    if(!args || !args->set_meta_given) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    cluster = cluster_load(sx, args, 1);
    if(!cluster)
        return 1;

    meta = sxc_clustermeta_new(cluster);
    if(!meta) {
        sxc_cluster_free(cluster);
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return 1;
    }

    ret = set_cluster_meta_common(sx, cluster, meta, (const char**)args->set_meta_arg, args->set_meta_given, 1);
    sxc_cluster_free(cluster);
    sxc_meta_free(meta);
    if(!ret)
        printf("Successfully updated cluster metadata\n");
    return ret;
}

static int set_cluster_param(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster;
    int ret;
    sxc_meta_t *meta;

    if(!args || !args->set_param_given) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    cluster = cluster_load(sx, args, 1);
    if(!cluster)
        return 1;

    meta = sxc_meta_new(sx);
    if(!meta) {
        sxc_cluster_free(cluster);
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return 1;
    }

    ret = set_cluster_meta_common(sx, cluster, meta, (const char **)args->set_param_arg, args->set_param_given, 0);
    sxc_cluster_free(cluster);
    sxc_meta_free(meta);
    if(!ret)
        printf("Successfully updated cluster settings\n");
    return ret;
}

static int del_cluster_meta(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *cluster;
    sxc_meta_t *meta;
    int ret;

    cluster = cluster_load(sx, args, 1);
    if(!cluster)
        return 1;

    meta = sxc_clustermeta_new(cluster);
    if(!meta) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        sxc_cluster_free(cluster);
        return 1;
    }

    if(sxc_meta_getval(meta, args->delete_meta_arg, NULL, NULL)) {
        fprintf(stderr, "ERROR: Cluster meta key '%s' does not exist\n", args->delete_meta_arg);
        sxc_meta_free(meta);
        sxc_cluster_free(cluster);
        return 1;
    }

    sxc_meta_delval(meta, args->delete_meta_arg);
    ret = sxi_cluster_set_meta(cluster, meta);
    sxc_cluster_free(cluster);
    sxc_meta_free(meta);
    if(ret)
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    else
        printf("Successfully removed cluster meta key '%s'\n", args->delete_meta_arg);
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
        if (node_args.debug_flag) {
            sxc_set_verbose(sx, 1);
            log_setminlevel(sx, SX_LOG_DEBUG);
        }
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
	else {
            if(handle_owner(&node_args))
                ret = 1;
            else if(node_args.info_given)
                ret = info_node(sx, node_args.inputs[0], &node_args);
            else if(node_args.check_given)
                ret = check_node(sx, node_args.inputs[0], node_args.debug_flag, !node_args.batch_mode_given);
            else if(node_args.extract_given)
                ret = extract_node(sx, node_args.inputs[0], node_args.extract_arg);
            else if(node_args.rename_cluster_given)
                ret = rename_cluster(sx, node_args.inputs[0], node_args.rename_cluster_arg);
            else if(node_args.upgrade_given)
                ret = upgrade_node(sx, node_args.inputs[0]);
            else if(node_args.upgrade_job_given)
                ret = upgrade_job_node(sx, node_args.inputs[0]);
	    else if(node_args.compact_given)
		ret = compact_data(sx, node_args.inputs[0], node_args.human_readable_flag);
            else if(node_args.gc_given || node_args.gc_expire_given)
                ret = gc_node(sx, node_args.inputs[0], node_args.gc_expire_given);
            else if(node_args.warm_cache_given)
                ret = warm_cache_node(sx, node_args.inputs[0]);
            else if(node_args.vacuum_given)
                ret = vacuum_node(sx, node_args.inputs[0]);
            else if(node_args.get_definition_given)
                ret = get_node_definition(sx, node_args.inputs[0]);
        }
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
	    ret = info_cluster(sx, &cluster_args, INFO_ALL);
	else if(cluster_args.get_cluster_key_given && cluster_args.inputs_num == 1)
	    ret = info_cluster(sx, &cluster_args, INFO_KEY);
	else if(cluster_args.get_allowed_replica_given && cluster_args.inputs_num == 1)
	    ret = info_cluster(sx, &cluster_args, INFO_REPLICA);
	else if(cluster_args.modify_given && cluster_args.inputs_num >= 2)
	    ret = change_cluster(sx, &cluster_args);
        else if(cluster_args.lock_given && cluster_args.inputs_num == 1)
            ret = cluster_dist_lock(sx, &cluster_args);
        else if(cluster_args.unlock_given && cluster_args.inputs_num == 1)
            ret = cluster_dist_unlock(sx, &cluster_args);
	else if(cluster_args.resize_given && cluster_args.inputs_num == 1)
	    ret = resize_cluster(sx, &cluster_args);
	else if(cluster_args.replace_faulty_given && cluster_args.inputs_num >= 2)
	    ret = replace_nodes(sx, &cluster_args);
	else if(cluster_args.set_faulty_given && cluster_args.inputs_num >= 2)
	    ret = setfaulty_nodes(sx, &cluster_args);
	else if(cluster_args.force_gc_given && cluster_args.inputs_num == 1)
	    ret = force_gc_cluster(sx, &cluster_args, 0);
	else if(cluster_args.force_expire_given && cluster_args.inputs_num == 1)
	    ret = force_gc_cluster(sx, &cluster_args, 1);
        else if(cluster_args.list_nodes_given && cluster_args.inputs_num == 1)
            ret = cluster_status(sx, &cluster_args);
        else if(cluster_args.set_mode_given && cluster_args.inputs_num == 1)
            ret = cluster_set_mode(sx, &cluster_args);
        else if(cluster_args.upgrade_given && cluster_args.inputs_num == 1)
            ret = cluster_upgrade(sx, &cluster_args);
        else if(cluster_args.set_meta_given && cluster_args.inputs_num == 1)
            ret = set_cluster_meta(sx, &cluster_args);
        else if(cluster_args.get_meta_given && cluster_args.inputs_num == 1)
            ret = get_cluster_meta(sx, &cluster_args);
        else if(cluster_args.get_param_given && cluster_args.inputs_num == 1)
            ret = get_cluster_settings(sx, &cluster_args);
        else if(cluster_args.set_param_given && cluster_args.inputs_num == 1)
            ret = set_cluster_param(sx, &cluster_args);
        else if(cluster_args.delete_meta_given && cluster_args.inputs_num == 1)
            ret = del_cluster_meta(sx, &cluster_args);
        else if(cluster_args.force_job_allowance_given && cluster_args.inputs_num == 1)
            ret = junlock_cluster(sx, &cluster_args);
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
