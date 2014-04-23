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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <dirent.h>
#include <unistd.h>

#include "sx.h"
#include "cmdline.h"
#include "version.h"
#include "libsx/src/misc.h"

static sxc_client_t *sx = NULL;

static void sighandler(int signal) {
    if(sx)
	sxc_shutdown(sx, signal);
    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

/* List all clusters with profile names that are configured in configuration directory */
static int list_clusters(sxc_client_t *sx, const char *config_dir) {
    const char *confdir = NULL;
    DIR *clusters_dir = NULL, *profiles_dir = NULL;
    struct dirent *cluster_dirent = NULL, *profile_dirent;

    confdir = sxc_get_confdir(sx);
    if(!confdir){
        fprintf(stderr, "Could not locate configuration directory\n");
        return 1;
    }

    clusters_dir = opendir(confdir);
    if(!clusters_dir) {
        fprintf(stderr, "Could not open %s directory\n", confdir);
        return 1;
    }

    while((cluster_dirent = readdir(clusters_dir)) != NULL) {
        char *auth_dir_name = NULL;
        int auth_dir_len = 0;

        if(cluster_dirent->d_name[0] == '.' || cluster_dirent->d_type != DT_DIR) continue; /* Omit files and directories starting with . */

        auth_dir_len = strlen(confdir) + strlen(cluster_dirent->d_name) + strlen("/auth") + 2;
        auth_dir_name = malloc(auth_dir_len);
        if(!auth_dir_name) {
            fprintf(stderr, "Could not allocate memory for auth directory\n");
            break;
        }
        snprintf(auth_dir_name, auth_dir_len, "%s/%s/auth", confdir, cluster_dirent->d_name);

        profiles_dir = opendir(auth_dir_name);
        if(profiles_dir) {
            while((profile_dirent = readdir(profiles_dir)) != NULL) {
                if(profile_dirent->d_name[0] != '.') {
                    const char *alias = sxc_get_alias(sx, profile_dirent->d_name, cluster_dirent->d_name);
                    int left_len = strlen("sx://") + strlen(profile_dirent->d_name) + strlen(cluster_dirent->d_name) + 2;
                    /* Left is prepared separately because we want to justify ouptut */
                    char *left = malloc(left_len);
                    if(!left) {
                        fprintf(stderr, "Could not allocate memory\n");
                        break;
                    }
                    snprintf(left, left_len, "sx://%s@%s", profile_dirent->d_name, cluster_dirent->d_name);
                    if(alias) 
                        fprintf(stderr, "%-40s %s\n", left, alias);
                    else
                        fprintf(stderr, "%-40s %s\n", left, "-");
                    free(left);
                }
            }

            closedir(profiles_dir);
        }
        free(auth_dir_name);
    }

    closedir(clusters_dir);
    return 0;
}

int main(int argc, char **argv) {
    char tok_buf[AUTHTOK_ASCII_LEN+1], *token;
    struct gengetopt_args_info args;
    sxc_cluster_t *cluster = NULL;
    sxc_logger_t log;
    sxc_uri_t *u = NULL;
    int ret = 1, toklen;
    const char *alias = NULL;

    if(cmdline_parser(argc, argv, &args))
	return 1;

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	cmdline_parser_free(&args);
	return 0;
    }

    /* Check if sx://profile@cluster/ or --list option is given but bot both */
    if((args.inputs_num != 1 && !args.list_given)
        || (args.inputs_num == 1 && args.list_given)) {
	fprintf(stderr, "Wrong number of arguments (see --help)\n");
	goto init_err;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxi_yesno))) {
        fprintf(stderr, "Failed to initialize SX\n");
	goto init_err;
    }

    if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
        fprintf(stderr, "Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
        goto init_err;
    }
    sxc_set_debug(sx, args.debug_flag);

    if(args.list_given)
    {
        ret = list_clusters(sx, args.config_dir_arg);
        goto init_err;
    }

    u = sxc_parse_uri(sx, args.inputs[0]);
    if(!u) {
	fprintf(stderr, "Invalid SX URI %s\n", args.inputs[0]);
	goto init_err;
    }

    /* If --alias=... has been given, check if it was not used before and save it to .aliases file */
    if(args.alias_given) {
        alias = args.alias_arg;

        if(strncmp(alias, SXC_ALIAS_PREFIX, 1)) {
             fprintf(stderr, "Bad alias name: it must start with %s\n", SXC_ALIAS_PREFIX);
             goto init_err;
        }

        if(strlen(alias) <= 1) {
             fprintf(stderr, "Bad alias name: Alias name is too short\n");
             goto init_err;
        }
    }

    if(!args.force_reinit_flag)
	cluster = sxc_cluster_load(sx, args.config_dir_arg, u->host);

    if(!cluster) /* Either force-reinit or load failed */
	cluster = sxc_cluster_new(sx);

    if(!cluster) {
	fprintf(stderr, "Cannot initialize new cluster: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(sxc_cluster_set_sslname(cluster, u->host)) {
        fprintf(stderr, "Cannot initialize new cluster: %s\n", sxc_geterrmsg(sx));
        goto init_err;
    }

    if(args.host_list_given) {
	/* DNS-less cluster */
	char *this_host = args.host_list_arg, *next_host;

	if(sxc_cluster_set_dnsname(cluster, NULL)) {
	    fprintf(stderr, "Cannot set cluster DNS-less flag: %s\n", sxc_geterrmsg(sx));
	    goto init_err;
	}

	do {
	    next_host = strchr(this_host, ',');
	    if(next_host) {
		*next_host = '\0';
		next_host++;
	    }
	    if(sxc_cluster_add_host(cluster, this_host)) {
		fprintf(stderr, "Cannot add %s to cluster nodes: %s\n", this_host, sxc_geterrmsg(sx));
		goto init_err;
	    }
	    this_host = next_host;
	} while(this_host);
    } else {
	/* DNS based cluster */
	if(sxc_cluster_set_dnsname(cluster, u->host)) {
	    fprintf(stderr, "Cannot set cluster DNS name to %s: %s\n", u->host, sxc_geterrmsg(sx));
	    goto init_err;
	}
    }

    if(args.no_ssl_flag) {
	/* NON-SSL cluster */
	if(sxc_cluster_set_cafile(cluster, NULL)) {
	    fprintf(stderr, "Failed to configure cluster security\n");
	    goto init_err;
	}
    } else {
	/* SSL cluster */
	if(sxc_cluster_fetch_ca(cluster, args.batch_mode_flag)) {
            fprintf(stderr, "Failed to fetch cluster CA: %s\n", sxc_geterrmsg(sx));
	    goto init_err;
        }
    }

    if(args.auth_file_given && strcmp(args.auth_file_arg, "-")) {
	FILE *f = fopen(args.auth_file_arg, "r");
	if(!f) {
	    fprintf(stderr, "Failed to open key file %s\n", args.auth_file_arg);
	    goto init_err;
	}
	token = fgets(tok_buf, sizeof(tok_buf), f);
	fclose(f);
    } else {
	printf("Please enter the user key: ");
	token = fgets(tok_buf, sizeof(tok_buf), stdin);
    }

    if(!token) {
	fprintf(stderr, "Failed to read user key\n");
	goto init_err;
    }

    toklen = strlen(token);
    if(toklen && token[toklen - 1] == '\n')
	token[toklen] = '\0';

    if(!strncmp("CLUSTER/ALLNODE/ROOT/USER", token, lenof("CLUSTER/ALLNODE/ROOT/USER"))) {
	fprintf(stderr, "The token provided is a cluster identificator and cannot be used for user authentication\n");
	goto init_err;
    }

    if(sxc_cluster_add_access(cluster, u->profile, token) ||
       sxc_cluster_set_access(cluster, u->profile)) {
	fprintf(stderr, "Failed to set profile authentication: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(sxc_cluster_fetchnodes(cluster)) {
	fprintf(stderr, "Failed to retrieve cluster members: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(args.force_reinit_flag) {
	if(sxc_cluster_remove(cluster, args.config_dir_arg)) {
	    fprintf(stderr, "Failed to remove the existing access configuration: %s\n", sxc_geterrmsg(sx));
	    goto init_err;
	}
    }

    if(sxc_cluster_save(cluster, args.config_dir_arg)) {
	fprintf(stderr, "Failed to save the access configuration: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(args.alias_given) {
        if(!u->profile || !u->profile[0]) u->profile = "default";

        /* Save alias into .aliases file. Alias variable was set before. */
        if(sxc_set_alias(sx, alias, u->profile, u->host)) {
            fprintf(stderr, "Failed to set alias %s: %s\n", alias, sxc_geterrmsg(sx));
            goto init_err;
        }
    }

    ret = 0;
 init_err:
    sxc_free_uri(u);
    sxc_cluster_free(cluster);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);
    cmdline_parser_free(&args);
    return ret;
}
