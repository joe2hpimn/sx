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
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sx.h"
#include "cmd_main.h"
#include "cmd_useradd.h"
#include "cmd_userlist.h"
#include "cmd_usergetkey.h"
#include "cmd_perm.h"
#include "cmd_list.h"
#include "libsx/src/misc.h"
#include "libsx/src/clustcfg.h"
#include "version.h"

static sxc_client_t *gsx = NULL;

static void sighandler(int signal)
{
    if(gsx)
	sxc_shutdown(gsx, signal);
    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

static int volume_acl(sxc_client_t *sx, const struct perm_args_info *args)
{
    /* TODO: share code with volume_add */
    sxc_uri_t *uri;
    sxc_cluster_t *cluster;
    const char *user = args->inputs[0];
    const char *volname = args->inputs[1];
    uri = sxc_parse_uri(sx, volname);
    if(!uri) {
	fprintf(stderr, "ERROR: Bad uri %s: %s\n", volname, sxc_geterrmsg(sx));
	return 1;
    }
    if(!uri->volume) {
	fprintf(stderr, "ERROR: Bad path %s\n", volname);
	sxc_free_uri(uri);
	return 1;
    }
    if(uri->path) {
	fprintf(stderr, "ERROR: Bad path %s\n", volname);
	sxc_free_uri(uri);
	return 1;
    }
    cluster = sxc_cluster_load_and_update(sx, args->config_dir_arg, uri->host, uri->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));
	sxc_free_uri(uri);
	return 1;
    }
    int ret = sxc_volume_acl(cluster, uri->volume, user,
                            args->grant_arg, args->revoke_arg);
    sxc_free_uri(uri);
    sxc_cluster_free(cluster);
    if(ret)
	fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    return ret;
}

static int add_user(sxc_client_t *sx, const char *username, const char *uri, const char *clusterdir, enum enum_role type, const char *authfile)
{
    sxc_uri_t *u;
    sxc_cluster_t *cluster;
    char *key;

/*    sxc_set_debug(sx, 1);*/
    u = sxc_parse_uri(sx, uri);
    if(!u) {
	fprintf(stderr, "ERROR: Can't parse URI %s: %s\n", uri, sxc_geterrmsg(sx));
	return 1;
    }
    if(u->volume || u->path) {
	fprintf(stderr, "ERROR: Bad URI %s. Please omit volume and path\n", uri);
	sxc_free_uri(u);
	return 1;
    }
    cluster = sxc_cluster_load_and_update(sx, clusterdir, u->host, u->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", u->host, sxc_geterrmsg(sx));
	sxc_free_uri(u);
	return 1;
    }

    key = sxc_user_add(cluster, username, type == role_arg_admin);
    if(!key) {
        fprintf(stderr, "ERROR: Can't create user %s: %s\n", username, sxc_geterrmsg(sx));
	sxc_free_uri(u);
	return 1;
    }

    printf("User successfully created!\n");
    printf("Name: %s\n", username);
    printf("Key : %s\n", key);
    printf("Type: %s\n\n", type == role_arg_admin ? "admin" : "normal");
    printf("Run 'sxinit sx://%s@%s' to start using the cluster as user '%s'.\n", username, u->host, username);

    if (authfile) {
	FILE *f;
	f = fopen(authfile, "w");
	if (!f) {
	    fprintf(stderr, "ERROR: Cannot open '%s' for writing: %s\n", authfile, strerror(errno));
	    sxc_free_uri(u);
	    sxc_cluster_free(cluster);
	    free(key);
	    return 1;
	}
	if(fprintf(f, "%s\n", key) != strlen(key) + 1) {
	    fprintf(stderr, "ERROR: Cannot write key to '%s': %s\n", authfile, strerror(errno));
	    sxc_free_uri(u);
	    sxc_cluster_free(cluster);
	    free(key);
	    fclose(f);
	    return 1;
	}
	fclose(f);
    }

    sxc_free_uri(u);
    sxc_cluster_free(cluster);
    free(key);
    return 0;
}

static int getkey_user(sxc_client_t *sx, const char *username, const char *uri, const char *clusterdir, const char *authfile)
{
    int rc = 0;
    sxc_uri_t *u;
    sxc_cluster_t *cluster;

    u = sxc_parse_uri(sx, uri);
    if(!u) {
	fprintf(stderr, "ERROR: Can't parse URI %s: %s\n", uri, sxc_geterrmsg(sx));
	return 1;
    }
    if(u->volume || u->path) {
	fprintf(stderr, "ERROR: Bad URI %s. Please omit volume and path\n", uri);
	sxc_free_uri(u);
	return 1;
    }
    cluster = sxc_cluster_load_and_update(sx, clusterdir, u->host, u->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", u->host, sxc_geterrmsg(sx));
	sxc_free_uri(u);
	return 1;
    }

    FILE *f = stdout;
    if (authfile) {
        f = fopen(authfile, "w");
        if (!f) {
            fprintf(stderr, "ERROR: Cannot open '%s' for writing: %s\n", authfile, strerror(errno));
            sxc_free_uri(u);
            sxc_cluster_free(cluster);
            return 1;
        }
    }
    rc = sxc_user_getkey(cluster, username, f);
    if (authfile)
        fclose(f);
    if (rc)
        fprintf(stderr, "ERROR: Can't retrieve key for user %s: %s\n", username, sxc_geterrmsg(sx));
    sxc_free_uri(u);
    sxc_cluster_free(cluster);
    return rc;
}

static int list_users(sxc_client_t *sx, const char *uri, const char *clusterdir, int debug)
{
    int rc = 0;
    sxc_uri_t *u;
    sxc_cluster_t *cluster;

    /* TODO: share code with join_cluster */
    sxc_set_debug(sx, debug);
    u = sxc_parse_uri(sx, uri);
    if(!u) {
	fprintf(stderr, "ERROR: Can't parse URI %s: %s\n", uri, sxc_geterrmsg(sx));
	return 1;
    }
    if(u->volume || u->path) {
	fprintf(stderr, "ERROR: Bad URI %s. Please omit volume and path\n", uri);
	sxc_free_uri(u);
	return 1;
    }
    cluster = sxc_cluster_load_and_update(sx, clusterdir, u->host, u->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", u->host, sxc_geterrmsg(sx));
	sxc_free_uri(u);
	return 1;
    }

    sxc_cluster_lu_t *lst;
    char *user = NULL;
    int is_admin;
    for (lst = sxc_cluster_listusers(cluster); lst && sxc_cluster_listusers_next(lst, &user, &is_admin);) {
        printf("%s (%s)\n", user, is_admin ? "admin" : "normal");
        free(user);
    }
    sxc_cluster_listusers_free(lst);
    if (!lst) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        rc = 1;
    }
    sxc_free_uri(u);
    sxc_cluster_free(cluster);
    return rc;
}

static int list_perms(sxc_client_t *sx, const char *uri, const char *clusterdir, int debug)
{
    int rc = 0;
    sxc_uri_t *u;
    sxc_cluster_t *cluster;

    /* TODO: share code with join_cluster */
    sxc_set_debug(sx, debug);
    u = sxc_parse_uri(sx, uri);
    if(!u) {
	fprintf(stderr, "ERROR: Can't parse URI %s: %s\n", uri, sxc_geterrmsg(sx));
	return 1;
    }
    if(u->path) {
	fprintf(stderr, "ERROR: Bad URI %s. Please omit path\n", uri);
	sxc_free_uri(u);
	return 1;
    }
    cluster = sxc_cluster_load_and_update(sx, clusterdir, u->host, u->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", u->host, sxc_geterrmsg(sx));
	sxc_free_uri(u);
	return 1;
    }

    sxc_cluster_la_t *lst;
    char *user = NULL;
    int can_read, can_write, is_owner, is_admin;
    for (lst = sxc_cluster_listaclusers(cluster, u->volume);
         lst && sxc_cluster_listaclusers_next(lst, &user, &can_read, &can_write, &is_owner, &is_admin);) {
        printf("%s:", user);
        if (can_read)
            printf(" read");
        if (can_write)
            printf(" write");
        if (is_owner)
            printf(" owner");
        if (is_admin)
            printf(" admin");
        printf("\n");
        free(user);
    }
    sxc_cluster_listaclusers_free(lst);
    if (!lst) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        rc = 1;
    }
    sxc_free_uri(u);
    sxc_cluster_free(cluster);
    return rc;
}

int main(int argc, char **argv) {
    int ret = 0;
    sxc_client_t *sx;
    sxc_logger_t log;

    struct main_args_info main_args;

    if (argc < 2) {
	main_cmdline_parser_print_help();
        fprintf(stderr, "ERROR: No command specified\n");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = gsx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxi_yesno))) {
        if(!strcmp(SRC_VERSION, sxc_get_version()))
            fprintf(stderr, "ERROR: Version mismatch: our version '%s' - library version '%s'\n", SRC_VERSION, sxc_get_version());
        else
            fprintf(stderr, "ERROR: Failed to init libsx\n");
        return 1;
    }

    do {
        if (!strcmp(argv[1], "useradd")) {
            struct useradd_args_info args;
            if (useradd_cmdline_parser(argc - 1, &argv[1], &args)) {
                ret = 1;
                break;
            }
            if(args.version_given) {
                printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
		break;
	    }
            if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
                fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
                ret = 1;
                break;
            }
            sxc_set_debug(sx, args.debug_flag);
            if (args.inputs_num != 2) {
                useradd_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
            ret = add_user(sx, args.inputs[0], args.inputs[1], args.config_dir_arg, args.role_arg, args.auth_file_arg);
            useradd_cmdline_parser_free(&args);

        } else if (!strcmp(argv[1], "userlist")) {
            struct userlist_args_info args;
            if (userlist_cmdline_parser(argc - 1, &argv[1], &args)) {
                ret = 1;
                break;
            }
            if(args.version_given) {
                printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
		break;
	    }
            if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
                fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
                ret = 1;
                break;
            }
            sxc_set_debug(sx, args.debug_flag);
            if (args.inputs_num != 1) {
                userlist_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
            ret = list_users(sx, args.inputs[0], args.config_dir_arg, args.debug_flag);
            userlist_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "usergetkey")) {
            struct usergetkey_args_info args;
            if (usergetkey_cmdline_parser(argc - 1, &argv[1], &args)) {
                ret = 1;
                break;
            }
            if(args.version_given) {
                printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
		break;
	    }
            if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
                fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
                ret = 1;
                break;
            }
            sxc_set_debug(sx, args.debug_flag);
            if (args.inputs_num != 2) {
                usergetkey_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
            ret = getkey_user(sx, args.inputs[0], args.inputs[1], args.config_dir_arg, args.auth_file_arg);
            usergetkey_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "perm")) {
            struct perm_args_info args;
            if (perm_cmdline_parser(argc - 1, &argv[1], &args)) {
                ret = 1;
                break;
            }
            if(args.version_given) {
                printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
		break;
	    }
            if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
                fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
                ret = 1;
                break;
            }
            sxc_set_debug(sx, args.debug_flag);
            if (args.inputs_num != 2) {
                perm_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
            ret = volume_acl(sx, &args);
            perm_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "list")) {
            struct list_args_info args;
            if (list_cmdline_parser(argc - 1, &argv[1], &args)) {
                ret = 1;
                break;
            }
            if(args.version_given) {
                printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
		break;
	    }
            if(args.config_dir_given && sxc_set_confdir(sx, args.config_dir_arg)) {
                fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", args.config_dir_arg, sxc_geterrmsg(sx));
                ret = 1;
                break;
            }
            sxc_set_debug(sx, args.debug_flag);
            if (args.inputs_num != 1) {
                list_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
            ret = list_perms(sx, args.inputs[0], args.config_dir_arg, args.debug_flag);
            list_cmdline_parser_free(&args);
        } else {
            if (main_cmdline_parser(argc, argv, &main_args)) {
                ret = 1;
                break;
            }
            if(main_args.version_given) {
                printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
            } else if(main_args.help_given) {
                main_cmdline_parser_print_help();
            } else {
                main_cmdline_parser_print_help();
                fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
                ret = 1;
            }
            main_cmdline_parser_free(&main_args);
        }
    } while(0);

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);
    return ret;
}
