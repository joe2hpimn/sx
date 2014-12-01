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
#include "cmd_userdel.h"
#include "cmd_userlist.h"
#include "cmd_usergetkey.h"
#include "cmd_usernewkey.h"
#include "cmd_volperm.h"
#include "cmd_volshow.h"
#include "cmd_whoami.h"
#include "libsx/src/misc.h"
#include "libsx/src/clustcfg.h"
#include "version.h"
#include "bcrumbs.h"

static sxc_client_t *gsx = NULL;

static void sighandler(int signal)
{
    if(gsx)
	sxc_shutdown(gsx, signal);
    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

sxc_cluster_t *load_config(sxc_client_t *sx, const char *uri, sxc_uri_t **sxuri)
{
    sxc_uri_t *u;
    sxc_cluster_t *cluster;

    u = sxc_parse_uri(sx, uri);
    if(!u) {
	fprintf(stderr, "ERROR: Can't parse URI %s: %s\n", uri, sxc_geterrmsg(sx));
	return NULL;
    }
    if(u->path) {
	fprintf(stderr, "ERROR: Bad URI %s. Please omit path\n", uri);
	sxc_free_uri(u);
	return NULL;
    }
    cluster = sxc_cluster_load_and_update(sx, u->host, u->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", u->host, sxc_geterrmsg(sx));
	if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CFG_ERR))
	    fprintf(stderr, SXBC_TOOLS_CFG_MSG, u->host, u->host);
        else if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CONN_ERR))
            fprintf(stderr, SXBC_TOOLS_CONN_MSG);
	sxc_free_uri(u);
	return NULL;
    }

    *sxuri = u;
    return cluster;
}

static int add_user(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *username,  enum enum_role type, const char *authfile, int batch_mode, const char *oldtoken) {
    char *key;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume\n");
	return 1;
    }

    key = sxc_user_add(cluster, username, type == role_arg_admin, oldtoken);
    if(!key) {
        fprintf(stderr, "ERROR: Can't create user %s: %s\n", username, sxc_geterrmsg(sx));
	return 1;
    }

    if(batch_mode) {
	printf("%s\n", key);
    } else {
	printf("User successfully created!\n");
	printf("Name: %s\n", username);
	printf("Key : %s\n", key);
	printf("Type: %s\n\n", type == role_arg_admin ? "admin" : "normal");
	printf("Run 'sxinit sx://%s@%s' to start using the cluster as user '%s'.\n", username, u->host, username);
    }

    if (authfile) {
	FILE *f;
	f = fopen(authfile, "w");
	if (!f) {
	    fprintf(stderr, "ERROR: Cannot open '%s' for writing: %s\n", authfile, strerror(errno));
	    free(key);
	    return 1;
	}
	if(fprintf(f, "%s\n", key) != strlen(key) + 1) {
	    fprintf(stderr, "ERROR: Cannot write key to '%s': %s\n", authfile, strerror(errno));
	    free(key);
	    fclose(f);
	    return 1;
	}
	if(fclose(f)) {
	    fprintf(stderr, "ERROR: Cannot close file '%s': %s\n", authfile, strerror(errno));
	    free(key);
	    return 1;
	}
    }

    free(key);
    return 0;
}

static int newkey_user(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *username,  const char *authfile, int batch_mode, const char *oldtoken) {
    char *key;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume\n");
	return 1;
    }

    key = sxc_user_newkey(cluster, username, oldtoken);
    if(!key) {
        fprintf(stderr, "ERROR: Can't change the key for %s: %s\n", username, sxc_geterrmsg(sx));
	return 1;
    }
    if(batch_mode) {
	printf("%s\n", key);
    } else {
	printf("Key successfully changed!\n");
	printf("Name   : %s\n", username);
	printf("New key: %s\n", key);
	printf("Run 'sxinit sx://%s@%s' and provide the new key for user '%s'.\n", username, u->host, username);
    }

    if (authfile) {
	FILE *f;
	f = fopen(authfile, "w");
	if (!f) {
	    fprintf(stderr, "ERROR: Cannot open '%s' for writing: %s\n", authfile, strerror(errno));
	    free(key);
	    return 1;
	}
	if(fprintf(f, "%s\n", key) != strlen(key) + 1) {
	    fprintf(stderr, "ERROR: Cannot write key to '%s': %s\n", authfile, strerror(errno));
	    free(key);
	    fclose(f);
	    return 1;
	}
	if(fclose(f)) {
	    fprintf(stderr, "ERROR: Cannot close file '%s': %s\n", authfile, strerror(errno));
	    free(key);
	    return 1;
	}
    }

    free(key);
    return 0;
}

static int getkey_user(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *username, const char *authfile)
{
    int rc = 0;
    FILE *f = stdout;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume\n");
	return 1;
    }

    if (authfile) {
        f = fopen(authfile, "w");
        if (!f) {
            fprintf(stderr, "ERROR: Cannot open '%s' for writing: %s\n", authfile, strerror(errno));
            return 1;
        }
    }
    rc = sxc_user_getkey(cluster, username, f);
    if (authfile && fclose(f)) {
        fprintf(stderr, "ERROR: Can't close file %s: %s\n", authfile, strerror(errno));
	return 1;
    }

    if (rc)
        fprintf(stderr, "ERROR: Can't retrieve key for user %s: %s\n", username, sxc_geterrmsg(sx));
    return rc;
}

static int list_users(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u)
{
    int rc = 0, lstrc = 0;
    sxc_cluster_lu_t *lst;
    char *user = NULL;
    int is_admin;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume.\n");
	return 1;
    }
    for (lst = sxc_cluster_listusers(cluster); lst && (lstrc = sxc_cluster_listusers_next(lst, &user, &is_admin)) > 0;) {
        printf("%s (%s)\n", user, is_admin ? "admin" : "normal");
        free(user);
    }
    sxc_cluster_listusers_free(lst);
    if (!lst || lstrc == -1) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        rc = 1;
    }
    return rc;
}

static int whoami(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u)
{
    char *user = NULL;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume.\n");
	return 1;
    }
    user = sxc_cluster_whoami(cluster);
    if (!user) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return 1;
    }
    printf("%s\n", user);
    free(user);
    return 0;
}

static int show_acls(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u)
{
    int rc = 0;
    sxc_cluster_la_t *lst;
    char *user = NULL;
    int can_read, can_write, is_owner;

    for (lst = sxc_cluster_listaclusers(cluster, u->volume);
         lst && sxc_cluster_listaclusers_next(lst, &user, &can_read, &can_write, &is_owner);) {
        printf("%s:", user);
        if (can_read)
            printf(" read");
        if (can_write)
            printf(" write");
        if (is_owner)
            printf(" owner");
        printf("\n");
        free(user);
    }
    sxc_cluster_listaclusers_free(lst);
    if (!lst) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
	if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_VOL_ERR))
	    fprintf(stderr, SXBC_TOOLS_VOL_MSG, u->profile ? u->profile : "", u->profile ? "@" : "", u->host);
        rc = 1;
    } else {
        printf("(all admin users): read write admin\n");
    }
    return rc;
}

static int volume_acl(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *uri, const char *user, const char *grant, const char *revoke)
{
    int ret;

    if(!uri->volume) {
	fprintf(stderr, "ERROR: Bad URI: No volume\n");
	return 1;
    }
    if(!grant && !revoke) {
	printf("Current volume ACL:\n");
	ret = show_acls(sx, cluster, uri);
	if(!ret)
	    printf("\nUse '--grant' or '--revoke' options to modify the permissions. See 'sxacl volperm -h' for more info.\n");
	return ret;
    }
    ret = sxc_volume_acl(cluster, uri->volume, user, grant, revoke);
    if(ret) {
	fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    } else {
	printf("New volume ACL:\n");
	ret = show_acls(sx, cluster, uri);
    }

    return ret;
}

int main(int argc, char **argv) {
    int ret = 0;
    sxc_client_t *sx;
    sxc_cluster_t *cluster = NULL;
    sxc_uri_t *uri = NULL;
    sxc_logger_t log;
    struct main_args_info main_args;

    if (argc < 2) {
	main_cmdline_parser_print_help();
        fprintf(stderr, "ERROR: No command specified\n");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = gsx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxc_input_fn, NULL))) {
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
	    cluster = load_config(sx, args.inputs[1], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = add_user(sx, cluster, uri, args.inputs[0], args.role_arg, args.auth_file_arg, args.batch_mode_flag, args.force_key_arg);
            useradd_cmdline_parser_free(&args);

	} else if(!strcmp(argv[1], "userdel")) {
            struct userdel_args_info args;
            if(userdel_cmdline_parser(argc - 1, &argv[1], &args)) {
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
            if(args.inputs_num != 2) {
                userdel_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
	    cluster = load_config(sx, args.inputs[1], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    if(sxc_user_remove(cluster, args.inputs[0])) {
		fprintf(stderr, "ERROR: Can't remove user %s: %s\n", args.inputs[0], sxc_geterrmsg(sx));
		ret = 1;
	    } else {
		printf("User '%s' successfully removed.\n", args.inputs[0]);
	    }
            userdel_cmdline_parser_free(&args);

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
	    cluster = load_config(sx, args.inputs[0], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = list_users(sx, cluster, uri);
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
	    cluster = load_config(sx, args.inputs[1], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = getkey_user(sx, cluster, uri, args.inputs[0], args.auth_file_arg);
            usergetkey_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "usernewkey")) {
            struct usernewkey_args_info args;
            if (usernewkey_cmdline_parser(argc - 1, &argv[1], &args)) {
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
                usernewkey_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
	    cluster = load_config(sx, args.inputs[1], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = newkey_user(sx, cluster, uri, args.inputs[0], args.auth_file_arg, args.batch_mode_flag, args.force_key_arg);
            usernewkey_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "volperm")) {
            struct volperm_args_info args;
            if (volperm_cmdline_parser(argc - 1, &argv[1], &args)) {
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
                volperm_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
	    cluster = load_config(sx, args.inputs[1], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = volume_acl(sx, cluster, uri, args.inputs[0], args.grant_arg, args.revoke_arg);
            volperm_cmdline_parser_free(&args);

        } else if (!strcmp(argv[1], "volshow")) {
            struct volshow_args_info args;
            if (volshow_cmdline_parser(argc - 1, &argv[1], &args)) {
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
                volshow_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
	    cluster = load_config(sx, args.inputs[0], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = show_acls(sx, cluster, uri);
            volshow_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "whoami")) {
            struct whoami_args_info args;
            if (whoami_cmdline_parser(argc - 1, &argv[1], &args)) {
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
                whoami_cmdline_parser_print_help();
		printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
	    cluster = load_config(sx, args.inputs[0], &uri);
	    if(!cluster) {
                ret = 1;
                break;
            }
	    ret = whoami(sx, cluster, uri);
            whoami_cmdline_parser_free(&args);
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
    sxc_free_uri(uri);
    sxc_cluster_free(cluster);
    sxc_shutdown(sx, 0);
    return ret;
}
