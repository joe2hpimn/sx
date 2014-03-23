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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <yajl/yajl_parse.h>

#include "../libsx/src/clustcfg.h"
#include "../libsx/src/jobpoll.h"

#include "cmd_main.h"
#include "cmd_node.h"
#include "cmd_cluster.h"

#include "hashfs.h"
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

    if(read_or_gen_key(args->key_arg, ROLE_CLUSTER, &auth))
	return 1;

    if(!args->batch_mode_given) {
	printf("A new node is about to be created in \"%s\"...\nIf this node shall be joined to an existing SX cluster, please make sure the following info matches:\n  - Cluster UUID: %s\n  - Cluster authentication: %s\n\n", args->inputs[0], cluster_uuid.string, auth.token);
	if(!sxi_yesno("Confirm?", 1)) {
	    printf("Node creation aborted by the user\n");
	    return 1;
	}
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

static void fmt_capa(uint64_t bytes, char *buf, unsigned int buflen) {
    const char *suffix;
    double qty = bytes;

    if(buflen <= 0)
	return;
    if(qty >= 1024) {
	qty /= 1024;
	if(qty >= 1024) {
	    qty /= 1024;
	    if(qty >= 1024) {
		qty /= 1024;
		if(qty >= 1024) {
		    qty /= 1024;
		    suffix = "TB";
		} else
		    suffix = "GB";
	    } else
		suffix = "MB";
	} else
	    suffix = "KB";
    } else
	suffix = "bytes";
    snprintf(buf, buflen, "%.2f %s", qty, suffix);
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
		if(!sxi_yesno("Do you wish to proceed?", 1)) {
		    printf("Cluster creation aborted by the user\n");
		    goto create_cluster_err;
		}
	    } else
		WARN("DNS resolution of %s returns no record containing the address specified for the node (%s)", uri->host, sx_node_addr(node));
	}
    } else {
	if(!args->batch_mode_given) {
	    printf("The SX cluster you are creating appears to be DNS-less: i.e. the cluster name (%s) cannot be resolved.\nWhile this may be perfectly fine in certain local or specific environemnts, a DNS-less SX cluster is generally harder to reach.\n", uri->host);
	    if(!sxi_yesno("Do you confirm you are ok with a DNS-less SX cluster?", 1)) {
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
	    if(!sxi_yesno("Do you wish to continue?", 1)) {
		printf("Cluster creation aborted by the user\n");
		goto create_cluster_err;
	    }
	}
	sxc_cluster_free(clust);
	clust = NULL;
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
    if(!args->ssl_ca_file_given) {
	/* NON-SSL cluster */
	if(!args->batch_mode_given) {
	    printf("The SX cluster you are creating will not support SSL encryption.\nThis is generally a bad idea because all the communication will be in clear text and it's strongly discouraged.\nIf you intend to create a secure cluster, please rerun this tool with the \"--ssl-ca-file\" parameter.\n");
	    if(!sxi_yesno("Do you wish to create an INSECURE cluster?", 1)) {
		printf("Cluster creation aborted by the user\n");
		goto create_cluster_err;
	    }
	}
	/* if(sxc_cluster_set_cafile(clust, NULL)) { */
	/*     CRIT("Failed to configure cluster security"); */
	/*     goto create_cluster_err; */
	/* } */
    } else {
	/* SSL cluster with certificate check */
	FILE *f = fopen(args->ssl_ca_file_arg, "r");
	unsigned char fpts[EVP_MAX_MD_SIZE];
	char hexfpts[sizeof(fpts) * 2 + 1];
	X509_NAME *subject, *issuer;
	unsigned int nfpts, len;
	X509 *crt = NULL;

	if(f) {
	    crt = PEM_read_X509(f, NULL, NULL, NULL);
	    fclose(f);
	}
	if(!crt) {
	    CRIT("Bad certificate file %s", args->ssl_ca_file_arg);
	    goto create_cluster_err;
	}

	subject = X509_get_subject_name(crt);
	issuer = X509_get_issuer_name(crt);
	if(!subject || !issuer || !X509_digest(crt, EVP_sha1(), fpts, &nfpts)) {
	    CRIT("Invalid certificate file %s", args->ssl_ca_file_arg);
	    X509_free(crt);
	    goto create_cluster_err;
	}

	if(!args->batch_mode_given) {
	    sxi_bin2hex(fpts, nfpts, hexfpts);
	    printf("Details for the provided certificate file are:\n  - Issuer: ");
	    X509_NAME_print_ex_fp(stdout, issuer, 0, XN_FLAG_ONELINE);
	    printf("\n  - Subject: ");
	    X509_NAME_print_ex_fp(stdout, subject, 0, XN_FLAG_ONELINE);
	    printf("\n  - Fingerprints: %s\n", hexfpts);
	    if(!sxi_yesno("Is the certificate correct?", 1)) {
		printf("Cluster creation aborted by the user\n");
		X509_free(crt);
		goto create_cluster_err;
	    }
	}

	X509_free(crt);
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

    if(read_or_gen_key(args->key_arg, ROLE_ADMIN, &auth))
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
	char capastr[64];
	printf("\nPlease review the summary of your new SX cluster below and make sure all the information reported are correct.\n  - Cluster name: %s\n  - Cluster UUID: %s\n  - Cluster is %s\n  - Cluster security is: ", sxc_cluster_get_sslname(clust), sxc_cluster_get_uuid(clust), sxc_cluster_get_dnsname(clust) ? "reachable via DNS name resolution" : "DNS-less");
	if(args->ssl_ca_file_arg)
	    printf("secure (SSL is enabled and certificate validation is enforced)");
	else
	    printf("insecure (SSL is disabled)");
	printf("\n  - Cluster authentication token: %s\n  - Admin key: %s\n\nThe initial node of your new SX cluster is:\n  - Node UUID: %s\n  - Node address: %s\n", clust_token, auth.token, sx_node_uuid_str(node), sx_node_addr(node));
	if(strcmp(sx_node_addr(node), sx_node_internal_addr(node)))
	    printf("  - Node internal address: %s\n", sx_node_internal_addr(node));
	fmt_capa(sx_node_capacity(node), capastr, sizeof(capastr));
	printf("  - Node capacity: %s\n\nThe access configuration for the cluster will be saved under \"%s\" with the name \"%s\"\n\n", capastr, args->config_dir_given ? args->config_dir_arg : "~/.sx", sxc_cluster_get_sslname(clust));
	if(!sxi_yesno("Confirm cluster creation?", 1)) {
	    printf("Cluster creation aborted by the user\n");
	    goto create_cluster_err;
	}
    }

    if(sxc_cluster_save(clust, args->config_dir_arg, sxc_cluster_get_sslname(clust))) {
	CRIT("Failed to save the access configuration: %s", sxc_geterrmsg(sx));
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
	fclose(wf);
    }

    rc_ty rs = sx_storage_activate(stor, sxc_cluster_get_sslname(clust), sx_node_uuid(node), auth.uid, AUTH_UID_LEN, auth.key, AUTH_KEY_LEN, copy_cafile ? "ca.pem" : NULL, single_node);
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



static sxc_cluster_t *cluster_load(sxc_client_t *sx, struct cluster_args_info *args) {
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
	    printf("Please make sure the --config-dir points to the correct location.");
	else
	    printf("Please run sxinit first to generate it.");
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

    return clust;
}

static int change_cluster(sxc_client_t *sx, struct cluster_args_info *args) {
    unsigned int i, query_sz, query_at;
    sxc_cluster_t *clust = cluster_load(sx, args);
    char *query = NULL;
    int ret = 1;

    if(!clust)
	return 1;

    query = malloc(4096);
    query_sz = 4096;
    strcpy(query, "{\"nodeList\":[");
    query_at = strlen(query);

    for(i=0; i<args->inputs_num-1; i++) {
	sx_node_t *node = parse_nodef(args->inputs[i]);
	unsigned int need;
	const char *uuid, *addr, *int_addr;
	if(!node)
	    goto change_cluster_err;

	uuid = sx_node_uuid_str(node);
	addr = sx_node_addr(node);
	int_addr = sx_node_internal_addr(node);
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
		sx_node_delete(node);
		goto change_cluster_err;
	    }
	    query = newquery;
	}
	if(int_addr)
	    sprintf(query + query_at, "{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",\"nodeInternalAddress\":\"%s\",\"nodeCapacity\":%lld}", uuid, addr, int_addr, (long long)sx_node_capacity(node));
	else
	    sprintf(query + query_at, "{\"nodeUUID\":\"%s\",\"nodeAddress\":\"%s\",\"nodeCapacity\":%lld}", uuid, addr, (long long)sx_node_capacity(node));
	query_at = strlen(query);

	if(i != args->inputs_num-2) {
	    query[query_at++] = ',';
	    query[query_at] = '\0';
	}

	sx_node_delete(node);
    }

    strcat(query, "]}"); /* Always fits due to need above */

    if(sxi_job_submit_and_poll(sxi_cluster_get_conns(clust), NULL, ".nodes", query, strlen(query))) {
	CRIT("The update request failed: %s", sxc_geterrmsg(sx));
	goto change_cluster_err;
    }

    ret = 0;

 change_cluster_err:
    free(query);
    sxc_cluster_free(clust);
    return ret;
}


static int info_node(sxc_client_t *sx, const char *path)
{
    int ret = 0;
    const sx_nodelist_t *nodes;
    sx_hashfs_t *h;
    char *hpath = malloc(strlen(path) + 1 + sizeof("hashfs.db")), *admin;
    int64_t dsk_alloc, dsk_used;

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
    printf("Cluster authentication: %s\n", sx_hashfs_authtoken(h));
    admin = sxi_hashfs_admintoken(h);
    if(admin) {
	printf("Admin key: %s\n", sxi_hashfs_admintoken(h));
	free(admin);
    }
    printf("Internal cluster protocol: %s\n", sx_hashfs_uses_secure_proto(h) ? "SECURE" : "INSECURE");
    sx_storage_usage(h, &dsk_alloc, &dsk_used);
    printf("Used disk space: %lld\nActual data size: %lld\n", (long long)dsk_alloc, (long long)dsk_used);

    nodes = sx_hashfs_nodelist(h, NL_NEXT);
    if(nodes && sx_nodelist_count(nodes)) {
	unsigned int i, nnodes = sx_nodelist_count(nodes);
	const sx_node_t *self= sx_hashfs_self(h);
	printf("List of nodes:\n");
	for(i=0; i<nnodes; i++) {
	    const sx_node_t *n = sx_nodelist_get(nodes, i);
	    if(!n) {
		printf("Error while retrieving the node list\n");
		break;
	    }
	    printf("\t %c %s %s (%s) %lld\n", (n == self) ? '*' : '-', sx_node_uuid(n)->string, sx_node_addr(n), sx_node_internal_addr(n), (long long int)sx_node_capacity(n));
	}
    } else
	printf("No node was set yet\n");

    sx_hashfs_close(h);
    return ret;
}

static int force_gc_cluster(sxc_client_t *sx, struct cluster_args_info *args)
{
    sxc_cluster_t *clust = cluster_load(sx, args);
    if(!clust)
	return 1;
    return sxc_cluster_trigger_gc(clust);
}

struct cb_cstatus_ctx {
    sx_nodelist_t *one;
    sx_nodelist_t *two;
    yajl_handle yh;
    char *addr, *auth;
    char *int_addr;
    sx_uuid_t uuid, distid;
    uint64_t checksum;
    int64_t capa;
    int which, have_uuid, have_distid;
    unsigned int version;

    enum cstatus_state { CS_BEGIN, CS_BASEKEY, CS_CSTATUS, CS_SKEY, CS_DISTS, CS_DIST, CS_NODES, CS_NODEKEY, CS_UUID, CS_ADDR, CS_INT_ADDR, CS_CAPA, CS_DISTID, CS_DISTVER, CS_DISTCHK, CS_AUTH, CS_COMPLETE } state;
};

static int cb_cstatus_start_map(void *ctx) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;

    if(c->state == CS_BEGIN)
	c->state = CS_BASEKEY;
    else if(c->state == CS_CSTATUS)
	c->state = CS_SKEY;
    else if(c->state == CS_NODES) {
	c->state = CS_NODEKEY;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_map_key(void *ctx, const unsigned char *s, size_t l) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;

    if(c->state == CS_BASEKEY) {
	if(l == lenof("clusterStatus") && !strncmp("clusterStatus", s, lenof("clusterStatus")))
	    c->state = CS_CSTATUS;
	else
	    return 0;
    } else if(c->state == CS_SKEY) {
	if(l == lenof("distributionModels") && !strncmp("distributionModels", s, lenof("distributionModels")))
	    c->state = CS_DISTS;
	else if(l == lenof("distributionUUID") && !strncmp("distributionUUID", s, lenof("distributionUUID")))
	    c->state = CS_DISTID;
	else if(l == lenof("distributionVersion") && !strncmp("distributionVersion", s, lenof("distributionVersion")))
	    c->state = CS_DISTVER;
	else if(l == lenof("distributionChecksum") && !strncmp("distributionChecksum", s, lenof("distributionChecksum")))
	    c->state = CS_DISTCHK;
	else if(l == lenof("clusterAuth") && !strncmp("clusterAuth", s, lenof("clusterAuth")))
	    c->state = CS_AUTH;
	else
	    return 0;
    } else if(c->state == CS_NODEKEY) {
	if(l == lenof("nodeUUID") && !strncmp("nodeUUID", s, lenof("nodeUUID")))
	    c->state = CS_UUID;
	else if(l == lenof("nodeAddress") && !strncmp("nodeAddress", s, lenof("nodeAddress")))
	    c->state = CS_ADDR;
	else if(l == lenof("nodeInternalAddress") && !strncmp("nodeInternalAddress", s, lenof("nodeInternalAddress")))
	    c->state = CS_INT_ADDR;
	else if(l == lenof("nodeCapacity") && !strncmp("nodeCapacity", s, lenof("nodeCapacity")))
	    c->state = CS_CAPA;
	else
	    return 0;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_end_map(void *ctx) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;

    if(c->state == CS_NODEKEY) {
	sx_node_t *node;
	if(!c->have_uuid || !c->addr || c->capa <= 0 || c->which < 0 || c->which > 1)
	    return 0;
	node = sx_node_new(&c->uuid, c->addr, c->int_addr, c->capa);
	if(sx_nodelist_add(c->which ? c->two : c->one, node))
	    return 0;
	free(c->addr);
	free(c->int_addr);
	c->addr = NULL;
	c->int_addr = NULL;
	c->capa = 0;
	c->have_uuid = 0;
	c->state = CS_NODES;
    } else if(c->state == CS_SKEY)
	c->state = CS_BASEKEY;
    else if(c->state == CS_BASEKEY)
	c->state = CS_COMPLETE;
    else
	return 0;

    return 1;
}

static int cb_cstatus_start_array(void *ctx) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;

    if(c->state == CS_DISTS)
	c->state = CS_DIST;
    else if(c->state == CS_DIST) {
	if(c->which < 0 || c->which > 1)
	    return 0;
	if(c->which < 0 || c->which > 1)
	    return 0;
	c->state = CS_NODES;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_end_array(void *ctx) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;

    if(c->state == CS_NODES) {
	c->which++;
	c->state = CS_DIST;
    } else if(c->state == CS_DIST)
	c->state = CS_SKEY;
    else
	return 0;

    return 1;
}


static int cb_cstatus_string(void *ctx, const unsigned char *s, size_t l) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;
    char uuid[UUID_STRING_SIZE + 1];

    if(c->state == CS_UUID) {
	if(c->have_uuid || l != UUID_STRING_SIZE)
	    return 0;
	memcpy(uuid, s, UUID_STRING_SIZE);
	uuid[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&c->uuid, uuid))
	    return 0;
	c->have_uuid = 1;
	c->state = CS_NODEKEY;
    } else if(c->state == CS_DISTID) {
	if(c->have_distid || l != UUID_STRING_SIZE)
	    return 0;
	memcpy(uuid, s, UUID_STRING_SIZE);
	uuid[UUID_STRING_SIZE] = '\0';
	if(uuid_from_string(&c->distid, uuid))
	    return 0;
	c->have_distid = 1;
	c->state = CS_SKEY;
    } else if(c->state == CS_ADDR) {
	if(c->addr)
	    return 0;
	c->addr = malloc(l+1);
	if(!c->addr)
	    return 0;
	memcpy(c->addr, s, l);
	c->addr[l] = '\0';
	c->state = CS_NODEKEY;
    } else if(c->state == CS_AUTH) {
	if(c->auth)
	    return 0;
	c->auth = malloc(l+1);
	if(!c->auth)
	    return 0;
	memcpy(c->auth, s, l);
	c->auth[l] = '\0';
	c->state = CS_SKEY;
    } else
	return 0;

    return 1;
}

static int cb_cstatus_number(void *ctx, const char *s, size_t l) {
    struct cb_cstatus_ctx *c = (struct cb_cstatus_ctx *)ctx;
    char number[24], *eon;
    int64_t lld;

    if(c->state != CS_CAPA && c->state != CS_DISTVER && c->state != CS_DISTCHK)
	return 0;

    if(c->capa || l<1 || l>20)
	return 0;

    memcpy(number, s, l);
    number[l] = '\0';
    lld = strtoll(number, &eon, 10);
    if(*eon)
	return 0;

    if(c->state == CS_CAPA) {
	if(lld < 0)
	    return 0;
	c->capa = lld;
	c->state = CS_NODEKEY;
    } else if(c->state == CS_DISTVER) {
	if(lld < 0 || lld >0xffffffff)
	    return 0;
	c->version = (unsigned int)(lld & 0xffffffff);
	c->state = CS_SKEY;
    } else {
	c->checksum = (uint64_t)lld;
	c->state = CS_SKEY;
    }

    return 1;
}

static const yajl_callbacks cstatus_parser = {
    cb_fail_null,
    cb_fail_boolean,
    NULL,
    NULL,
    cb_cstatus_number,
    cb_cstatus_string,
    cb_cstatus_start_map,
    cb_cstatus_map_key,
    cb_cstatus_end_map,
    cb_cstatus_start_array,
    cb_cstatus_end_array
};

static int cstatus_setup_cb(sxi_conns_t *conns, void *ctx, const char *host) {
    struct cb_cstatus_ctx *yactx = (struct cb_cstatus_ctx *)ctx;

    if(yactx->yh)
	yajl_free(yactx->yh);

    if(!(yactx->yh  = yajl_alloc(&cstatus_parser, NULL, yactx))) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    if(yactx->one)
	sx_nodelist_empty(yactx->one);
    else if(!(yactx->one = sx_nodelist_new())) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    if(yactx->two)
	sx_nodelist_empty(yactx->two);
    else if(!(yactx->two = sx_nodelist_new())) {
	CRIT("Cannot get cluster status: out of memory");
	return 1;
    }

    free(yactx->auth);
    free(yactx->addr);
    free(yactx->int_addr);
    yactx->auth = NULL;
    yactx->addr = NULL;
    yactx->int_addr = NULL;
    yactx->have_uuid = 0;
    yactx->have_distid = 0;
    yactx->which = 0;
    yactx->version = 0;
    yactx->checksum = 0;
    yactx->capa = 0;
    yactx->state = CS_BEGIN;

    return 0;
}

static int cstatus_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_cstatus_ctx *yactx = (struct cb_cstatus_ctx *)ctx;
    if(yajl_parse(yactx->yh, data, size) != yajl_status_ok)
	return 1;
    return 0;
}

void print_dist(const sx_nodelist_t *nodes) {
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
}

static int info_cluster(sxc_client_t *sx, struct cluster_args_info *args) {
    sxc_cluster_t *clust = cluster_load(sx, args);
    struct cb_cstatus_ctx yctx;
    int ret = 1;

    if(!clust)
	return 1;

    memset(&yctx, 0, sizeof(yctx));

    /* MODHDIST add more query params and print them out */
    if(sxi_cluster_query(sxi_cluster_get_conns(clust), NULL, REQ_GET, "?clusterStatus", NULL, 0, cstatus_setup_cb, cstatus_cb, &yctx) != 200) {
	CRIT("Failed to query cluster");
	goto info_cluster_err;
    }

    if(yajl_complete_parse(yctx.yh) != yajl_status_ok || yctx.state != CS_COMPLETE || yctx.which < 0 || yctx.which > 2) {
	CRIT("Invalid cluster reply");
	goto info_cluster_err;
    }

    switch(yctx.which) {
    case 0:
	printf("Node is not part of a cluster\n");
	break;
    case 2:
	printf("Target distribution: ");
	print_dist(yctx.two);
    case 1:
	printf("Current distribution: ");
	print_dist(yctx.one);
	if(yctx.have_distid)
	    printf("Distribution: %s(v.%u) - checksum: %llu\n", yctx.distid.string, yctx.version, (unsigned long long)yctx.checksum);
	if(yctx.auth)
	    printf("Cluster authentication token: %s\n", yctx.auth);
    }
    ret = 0;

 info_cluster_err:
    free(yctx.auth);
    free(yctx.addr);
    free(yctx.int_addr);
    if(yctx.yh)
	yajl_free(yctx.yh);

    sxc_cluster_free(clust);
    return ret;
}

int main(int argc, char **argv) {
    struct main_args_info main_args;
    struct node_args_info node_args;
    struct cluster_args_info cluster_args;
    struct rlimit rlim;
    sxc_logger_t log;
    int have_command=(argc >= 2), ret = 1;
    sxc_client_t *sx = server_init(sxc_default_logger(&log, argv[0]), NULL, NULL, 0, argc, argv);

    if(!getrlimit(RLIMIT_NOFILE, &rlim) && (rlim.rlim_cur < MAX_FDS || rlim.rlim_max < MAX_FDS)) {
	unsigned int l_soft = rlim.rlim_cur, l_hard = rlim.rlim_max;
	rlim.rlim_cur = rlim.rlim_max = MAX_FDS;
	if(setrlimit(RLIMIT_NOFILE, &rlim))
	    WARN("Can't increase the limit for maximum number of open files (current: %u/%u)", l_soft, l_hard);
    }

    if(have_command && !strcmp(argv[1], "node")) {
	if(node_cmdline_parser(argc-1, argv+1, &node_args)) {
	    printf("See 'sxadm node --help' for usage information.\n");
            server_done(&sx);
	    return 1;
        }
	sxc_set_debug(sx, node_args.debug_flag);
	if(node_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
	    ret = 0;
	    goto node_out;
	}
	if(node_args.inputs_num != 1) {
	    node_cmdline_parser_print_help();
	    goto node_out;
	}
	if(node_args.run_as_given && runas(node_args.run_as_arg) == -1)
	    goto node_out;
	if(node_args.new_given)
	    ret = create_node(&node_args);
	else if(node_args.info_given)
	    ret = info_node(sx, node_args.inputs[0]);
    node_out:
	node_cmdline_parser_free(&node_args);
        server_done(&sx);
	return ret;

    } else if(have_command && !strcmp(argv[1], "cluster")) {
	if(cluster_cmdline_parser(argc-1, argv+1, &cluster_args)) {
	    printf("See 'sxadm cluster --help' for usage information.\n");
            server_done(&sx);
	    return 1;
        }
	sxc_set_debug(sx, cluster_args.debug_flag);
	if(cluster_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
	    ret = 0;
	    goto cluster_out;
	}
	if(cluster_args.run_as_given && runas(cluster_args.run_as_arg) == -1)
	    goto cluster_out;
	if(cluster_args.new_given && cluster_args.inputs_num == 2)
	    ret = create_cluster(sx, &cluster_args);
	else if(cluster_args.info_given && cluster_args.inputs_num == 1)
	    ret = info_cluster(sx, &cluster_args);
	else if(cluster_args.mod_given && cluster_args.inputs_num >= 2)
	    ret = change_cluster(sx, &cluster_args);
	else if(cluster_args.force_gc_given && cluster_args.inputs_num == 1)
	    ret = force_gc_cluster(sx, &cluster_args);
	else
	    cluster_cmdline_parser_print_help();
    cluster_out:
	cluster_cmdline_parser_free(&cluster_args);
        server_done(&sx);
	return ret;
    } else {
	if(main_cmdline_parser(argc, argv, &main_args)) {
            server_done(&sx);
	    return 1;
        }
	if(main_args.version_given)
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, src_version());
	else
	    main_cmdline_parser_print_help();
	main_cmdline_parser_free(&main_args);
    }

    server_done(&sx);
    return 0;

}
