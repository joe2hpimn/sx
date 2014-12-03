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
#include <errno.h>

#include "sx.h"
#include "cmdline.h"
#include "version.h"
#include "libsx/src/misc.h"
#include "libsx/src/clustcfg.h"
#include "libsx/src/cluster.h"
#include "bcrumbs.h"

static sxc_client_t *sx = NULL;

static void sighandler(int signal) {
    if(sx)
	sxc_shutdown(sx, signal);
    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

/* List all clusters with profile names that are configured in configuration directory */
static int list_clusters(void) {
    const char *confdir = NULL;
    DIR *clusters_dir = NULL, *profiles_dir = NULL;
    struct dirent *cluster_dirent = NULL, *profile_dirent;

    confdir = sxc_get_confdir(sx);
    if(!confdir){
        fprintf(stderr, "ERROR: Could not locate configuration directory\n");
        return 1;
    }

    clusters_dir = opendir(confdir);
    if(!clusters_dir) {
	if(errno == ENOENT)
	    fprintf(stderr, "No profiles configured\n");
	else
	    fprintf(stderr, "ERROR: Could not open %s directory: %s\n", confdir, strerror(errno));
        return 1;
    }

    while((cluster_dirent = readdir(clusters_dir)) != NULL) {
        char *auth_dir_name = NULL;
        int auth_dir_len = 0;

        if(cluster_dirent->d_name[0] == '.') continue; /* Omit files and directories starting with . */

        auth_dir_len = strlen(confdir) + strlen(cluster_dirent->d_name) + strlen("/auth") + 2;
        auth_dir_name = malloc(auth_dir_len);
        if(!auth_dir_name) {
            fprintf(stderr, "ERROR: Could not allocate memory for auth directory\n");
            break;
        }
        snprintf(auth_dir_name, auth_dir_len, "%s/%s/auth", confdir, cluster_dirent->d_name);

        if(access(auth_dir_name, F_OK)) {
            free(auth_dir_name);
            continue;
        }

        profiles_dir = opendir(auth_dir_name);
        if(profiles_dir) {
            while((profile_dirent = readdir(profiles_dir)) != NULL) {
                if(profile_dirent->d_name[0] != '.') {
                    char *aliases = NULL;
                    int left_len = strlen("sx://") + strlen(profile_dirent->d_name) + strlen(cluster_dirent->d_name) + 2;
                    /* Left is prepared separately because we want to justify ouptut */
                    char *left = malloc(left_len);
                    if(!left) {
                        fprintf(stderr, "ERROR: Could not allocate memory\n");
                        break;
                    }
		    if(!strcmp(profile_dirent->d_name, "default"))
			snprintf(left, left_len, "sx://%s", cluster_dirent->d_name);
		    else
			snprintf(left, left_len, "sx://%s@%s", profile_dirent->d_name, cluster_dirent->d_name);
                    if(sxc_get_aliases(sx, profile_dirent->d_name, cluster_dirent->d_name, &aliases)) {
                        free(left);
                        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx)); /* Error message should already be set */
                        break;
                    }
                    if(aliases)
                        printf("%-40s %s\n", left, aliases);
                    else
                        printf("%-40s %s\n", left, "-");
                    free(left);
                    free(aliases);
                }
            }

            closedir(profiles_dir);
        }
        free(auth_dir_name);
    }

    closedir(clusters_dir);
    return 0;
}

static int del_profile(sxc_uri_t *u) {
    int ret = -1;
    const char *config_dir = sxc_get_confdir(sx);
    unsigned int profdir_len, confdir_len, fname_len;
    const char *home_dir = NULL;
    char *fname;
    const char *profile;

    if(!u || !u->host) {
        sxi_seterr(sx, SXE_EARG, "Cannot locate config directory: Invalid argument");
        return ret;
    }

    confdir_len = strlen(u->host);
    if(memchr(u->host, '/', confdir_len)) {
        sxi_seterr(sx, SXE_EARG, "Cannot locate config directory: Invalid argument");
        return ret;
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
            return ret;
        }
        confdir_len += strlen(home_dir) + 2 + lenof(".sx");
    } else
        confdir_len += strlen(config_dir) + 1;

    if(!u->profile || !u->profile[0])
        profile = "default";
    else
        profile = u->profile;

    profdir_len = confdir_len + strlen("/auth/");
    fname_len = strlen(profile) + profdir_len + 1;
    fname = malloc(fname_len);
    if(!fname) {
        sxi_seterr(sx, SXE_EMEM, "Cannot locate config directory: Out of memory");
        goto rm_profile_err;
    }

    if(config_dir)
        snprintf(fname, fname_len, "%s/%s/auth/%s", config_dir, u->host, profile);
    else
        snprintf(fname, fname_len, "%s/.sx/%s/auth/%s", home_dir, u->host, profile);

    if(access(fname, F_OK)) {
        sxi_seterr(sx, SXE_ECFG, "Cannot locate profile 'sx://%s@%s/'", profile, u->host);
        goto rm_profile_err;
    }

    /* Remove profile key file */
    if(unlink(fname)) {
        sxi_seterr(sx, SXE_ECFG, "Cannot remove profile '%s': %s", profile, strerror(errno));
        goto rm_profile_err;
    }

    /* Clean all aliases combined with given profile */
    if(sxc_del_aliases(sx, profile, u->host)) {
        SXDEBUG("Failed to delete aliases for profile '%s': %s", profile, sxc_geterrmsg(sx));
        goto rm_profile_err;
    }

    fname[profdir_len] = '\0';
    /* Try to remove directory with all profiles, if succeeded remove whole cluster configuration since no profile is configured then */
    if(!rmdir(fname)) {
        /* Remove all subdirectories */
        fname[confdir_len] = '\0';
        if(sxi_rmdirs(fname)) {
            sxi_seterr(sx, SXE_ECFG, "Cannot remove cluster configuration directory: %s", fname);
            goto rm_profile_err;
        }
    }

    ret = 0;
rm_profile_err:
    free(fname);
    return ret;
}

/* Check if alias exists and if so, compare its uri with given by user */
static int check_alias(const char *alias, const sxc_uri_t *u) {
    sxc_uri_t *tmp = NULL;

    if(!alias || !u) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    if(strncmp(alias, SXC_ALIAS_PREFIX, lenof(SXC_ALIAS_PREFIX))) {
        fprintf(stderr, "ERROR: Bad alias name: it must start with %s\n", SXC_ALIAS_PREFIX);
        return 1;
    }

    if(strlen(alias) <= lenof(SXC_ALIAS_PREFIX)) {
        fprintf(stderr, "ERROR: Bad alias name: Alias name is too short\n");
        return 1;
    }

    if(!(tmp = sxc_parse_uri(sx, alias))) {
        if(sxc_geterrnum(sx) != SXE_ECFG) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            return 1;
        }
        sxc_clearerr(sx);
        return 0;
    }

    /* Check host part of uri */
    if(strcmp(tmp->host, u->host)) {
        fprintf(stderr, "ERROR: Alias '%s' is already used\n", alias);
        sxc_free_uri(tmp);
        return 1;
    }

    if(!u->profile && !tmp->profile) { /* No profile defined, same uri */
        sxc_free_uri(tmp);
        return 0;
    }

    if(u->profile && tmp->profile) { /* Both uris have profile defined, compare them */
        if(strcmp(u->profile, tmp->profile)) {
            fprintf(stderr, "ERROR: Alias '%s' is already used\n", alias);
            sxc_free_uri(tmp);
            return 1;
        }
    } else { /* Different profiles for same host */
        fprintf(stderr, "ERROR: Alias '%s' is already used\n", alias);
        sxc_free_uri(tmp);
        return 1;
    }

    sxc_free_uri(tmp);
    return 0;
}

static int yesno(const char *prompt, int def)
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

    /* Check if sx://profile@cluster/ or --list option is given but not both */
    if((args.inputs_num != 1 && !args.list_given)
        || (args.inputs_num == 1 && args.list_given)) {
	cmdline_parser_print_help();
	printf("\n");
	fprintf(stderr, "ERROR: Wrong number of arguments\n");
	goto init_err;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxc_input_fn, NULL))) {
        fprintf(stderr, "ERROR: Failed to initialize SX\n");
	goto init_err;
    }

    if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
        fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
        goto init_err;
    }
    sxc_set_debug(sx, args.debug_flag);

    if(args.list_given)
    {
        ret = list_clusters();
        goto init_err;
    }

    u = sxc_parse_uri(sx, args.inputs[0]);
    if(!u) {
	fprintf(stderr, "ERROR: Invalid SX URI %s\n", args.inputs[0]);
	goto init_err;
    }

    if(args.alias_given) {
        alias = args.alias_arg;
        if(check_alias(alias, u))
            goto init_err;
    }

    if(args.delete_given) {
        ret = del_profile(u);
        if(ret)
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));

        goto init_err;
    }

    if(!args.force_reinit_flag)
	cluster = sxc_cluster_load(sx, args.config_dir_arg, u->host);

    if(!cluster) /* Either force-reinit or load failed */
	cluster = sxc_cluster_new(sx);

    if(!cluster) {
	fprintf(stderr, "ERROR: Cannot initialize new cluster: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(sxc_cluster_set_sslname(cluster, u->host)) {
        fprintf(stderr, "ERROR: Cannot initialize new cluster: %s\n", sxc_geterrmsg(sx));
        goto init_err;
    }

    if(args.host_list_given) {
	/* DNS-less cluster */
	char *this_host = args.host_list_arg, *next_host;

	if(sxc_cluster_set_dnsname(cluster, NULL)) {
	    fprintf(stderr, "ERROR: Cannot set cluster DNS-less flag: %s\n", sxc_geterrmsg(sx));
	    goto init_err;
	}

	sxc_cluster_reset_hosts(cluster);
	do {
	    next_host = strchr(this_host, ',');
	    if(next_host) {
		*next_host = '\0';
		next_host++;
	    }
	    if(sxc_cluster_add_host(cluster, this_host)) {
		fprintf(stderr, "ERROR: Cannot add %s to cluster nodes: %s\n", this_host, sxc_geterrmsg(sx));
		goto init_err;
	    }
	    this_host = next_host;
	} while(this_host);
    } else {
	/* DNS based cluster */
	if(sxc_cluster_set_dnsname(cluster, u->host)) {
	    fprintf(stderr, "ERROR: Cannot set cluster DNS name to %s: %s\n", u->host, sxc_geterrmsg(sx));
	    goto init_err;
	}
    }

    if(args.port_given && sxc_cluster_set_httpport(cluster, args.port_arg)) {
	fprintf(stderr, "ERROR: Failed to configure cluster communication port\n");
	    goto init_err;
    }

    if(args.no_ssl_flag) {
	/* NON-SSL cluster */
	if(sxc_cluster_set_cafile(cluster, NULL)) {
	    fprintf(stderr, "ERROR: Failed to configure cluster security\n");
	    goto init_err;
	}

	if(!args.batch_mode_flag) {
	    /* do a bogus query with a fake key to get the remote security flag */
	    sxi_strlcpy(tok_buf, "wFPs+e1B3wMRud8TzGw7YHjS08LWGuoIdfALMZTPLMVFKYM41rVlDwAA", sizeof(tok_buf));
	    if(sxc_cluster_add_access(cluster, u->profile, tok_buf) || sxc_cluster_set_access(cluster, u->profile)) {
		fprintf(stderr, "ERROR: Failed to set profile authentication: %s\n", sxc_geterrmsg(sx));
		goto init_err;
	    }
	    if(sxc_cluster_fetchnodes(cluster) && sxc_geterrnum(sx) != SXE_EAUTH) {
		fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
		goto init_err;
	    }

	    if(sxi_conns_internally_secure(sxi_cluster_get_conns(cluster)) == 1) {
		printf("*** WARNING ***: The cluster reports secure internal communication, however you're attempting to connect with the SSL disabled.\n");
		if(!yesno("Do you want to continue?", 0)) {
		    fprintf(stderr, "Aborted\n");
		    goto init_err;
		}
	    }
	}
    } else {
	/* SSL cluster */
	if(sxc_cluster_fetch_ca(cluster, args.batch_mode_flag)) {
            fprintf(stderr, "ERROR: Failed to fetch cluster CA: %s\n", sxc_geterrmsg(sx));
	    goto init_err;
        }
    }

    if(args.auth_file_given && strcmp(args.auth_file_arg, "-")) {
	FILE *f = fopen(args.auth_file_arg, "r");
	if(!f) {
	    fprintf(stderr, "ERROR: Failed to open key file %s\n", args.auth_file_arg);
	    goto init_err;
	}
	token = fgets(tok_buf, sizeof(tok_buf), f);
	fclose(f);
    } else {
	printf("Please enter the user key: ");
	token = fgets(tok_buf, sizeof(tok_buf), stdin);
    }

    if(!token) {
	fprintf(stderr, "ERROR: Failed to read user key\n");
	goto init_err;
    }

    toklen = strlen(token);
    if(toklen && token[toklen - 1] == '\n')
	token[toklen] = '\0';

    if(!strncmp("CLUSTER/ALLNODE/ROOT/USER", token, lenof("CLUSTER/ALLNODE/ROOT/USER"))) {
	fprintf(stderr, "ERROR: The token provided is a cluster identificator and cannot be used for user authentication\n");
	goto init_err;
    }

    if(sxc_cluster_add_access(cluster, u->profile, token) ||
       sxc_cluster_set_access(cluster, u->profile)) {
	fprintf(stderr, "ERROR: Failed to set profile authentication: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(sxc_cluster_fetchnodes(cluster)) {
	fprintf(stderr, "ERROR: Failed to retrieve cluster members: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(args.force_reinit_flag) {
	if(sxc_cluster_remove(cluster, args.config_dir_arg)) {
	    fprintf(stderr, "ERROR: Failed to remove the existing access configuration: %s\n", sxc_geterrmsg(sx));
	    goto init_err;
	}
    }

    if(sxc_cluster_save(cluster, args.config_dir_arg)) {
	fprintf(stderr, "ERROR: Failed to save the access configuration: %s\n", sxc_geterrmsg(sx));
	goto init_err;
    }

    if(args.alias_given) {
        const char *profile;
        if(!u->profile || !u->profile[0])
            profile = "default";
        else
            profile = u->profile;

        /* Save alias into .aliases file. Alias variable was set before. */
        if(sxc_set_alias(sx, alias, profile, u->host)) {
            fprintf(stderr, "ERROR: Failed to set alias %s: %s\n", alias, sxc_geterrmsg(sx));
            goto init_err;
        }
    }

    ret = 0;
 init_err:
    if(sx && ret) {
	if(u && strstr(sxc_geterrmsg(sx), SXBC_SXINIT_RESOLVE_ERR))
	    fprintf(stderr, SXBC_SXINIT_RESOLVE_MSG, u->host, u->host);
	else if(strstr(sxc_geterrmsg(sx), SXBC_SXINIT_UUID_ERR))
	    fprintf(stderr, SXBC_SXINIT_UUID_MSG);
    }
    sxc_free_uri(u);
    sxc_cluster_free(cluster);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);
    cmdline_parser_free(&args);
    return ret;
}
