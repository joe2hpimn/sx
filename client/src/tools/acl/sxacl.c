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
#include <termios.h>
#include <sys/mman.h>

#include "sx.h"
#include "cmd_main.h"
#include "cmd_useradd.h"
#include "cmd_userdel.h"
#include "cmd_userlist.h"
#include "cmd_usergetkey.h"
#include "cmd_usernewkey.h"
#include "cmd_usermod.h"
#include "cmd_volperm.h"
#include "cmd_volshow.h"
#include "cmd_whoami.h"
#include "cmd_userclone.h"
#include "libsxclient/src/misc.h"
#include "libsxclient/src/clustcfg.h"
#include "version.h"
#include "bcrumbs.h"

static sxc_client_t *gsx = NULL;

static void sighandler(int signal)
{
    struct termios tcur;
    if(gsx)
	sxc_shutdown(gsx, signal);
    /* work around for ctrl+c during pass2token() in sxc_user_add() or sxc_user_newkey() */
    tcgetattr(0, &tcur);
    tcur.c_lflag |= ECHO;
    tcsetattr(0, TCSANOW, &tcur);

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

static int add_user(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *username, const char* pass_file, enum enum_role type, const char *authfile, int batch_mode, const char *oldtoken, const char *existing, const char *desc, int generate_key, int64_t quota) {
    char *key;
    int created_role = (type == role_arg_admin ? 1 : 0);
    char pass[1024];

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume\n");
	return 1;
    }

    if(pass_file && strcmp(pass_file, "-")) {
        if(oldtoken) {
            fprintf(stderr, "ERROR: Can't use pass file and old key\n");
            return 1;
        } else if(existing) {
            fprintf(stderr, "ERROR: Can't use pass file to clone users\n");
            return 1;
        }

        mlock(pass, sizeof(pass));
        if(sxc_read_pass_file(sx, pass_file, pass, sizeof(pass))) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            munlock(pass, sizeof(pass));
            return 1;
        }
    }

    if(batch_mode && !oldtoken && !pass_file)
        generate_key = 1;
    if(existing) /* Cloning user */
        key = sxc_user_clone(cluster, existing, username, oldtoken, &created_role, desc);
    else {
	if(!generate_key && !pass_file && !batch_mode) {
	    printf("Enter password for user '%s'\n", username);
	    fflush(stdout);
	}
	/* Creating new user */
        key = sxc_user_add(cluster, username, pass_file ? pass : NULL, type == role_arg_admin, oldtoken, desc, generate_key, quota);
    }

    if(pass_file && strcmp(pass_file, "-")) {
        memset(pass, 0, sizeof(pass));
        munlock(pass, sizeof(pass));
    }

    if(!key) {
        fprintf(stderr, "ERROR: Can't create user %s: %s\n", username, sxc_geterrmsg(sx));
	return 1;
    }

    if(batch_mode) {
	printf("%s\n", key);
    } else {
        char *conflink;

        conflink = sxc_cluster_configuration_link(cluster, username, key);
        if(!conflink) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            free(key);
            return 1;
        }
	printf("User successfully created!\n");
	printf("Name: %s\n", username);
	printf("Key : %s\n", key);
        printf("Type: %s\n", created_role ? "admin" : "normal");
        printf("Configuration link: %s", conflink);
	if(existing)
            printf("\nDescription: %s (clone of user '%s')", desc, existing);
	printf("\n\nRun 'sxinit sx://%s@%s' or 'sxinit --config-link <link>' to start using the cluster as user '%s'.\n", username, u->host, username);
        free(conflink);
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

static int newkey_user(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *username, const char* pass_file, const char *authfile, int batch_mode, const char *oldtoken, int generate_key) {
    char *key;
    char pass[1024];

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume\n");
	return 1;
    }

    if(pass_file) {
        if(oldtoken) {
            fprintf(stderr, "ERROR: Can't use pass file and old key\n");
            return 1;
        }

        mlock(pass, sizeof(pass));
        if(sxc_read_pass_file(sx, pass_file, pass, sizeof(pass))) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            munlock(pass, sizeof(pass));
            return 1;
        }
    }

    if(batch_mode && !oldtoken && !pass_file)
        generate_key = 1;

    if(!generate_key && !pass_file && !batch_mode) {
	printf("Enter new password for user '%s'\n", username);
	fflush(stdout);
    }

    key = sxc_user_newkey(cluster, username, pass_file ? pass : NULL, oldtoken, generate_key);
    if(pass_file) {
        memset(pass, 0, sizeof(pass));
        munlock(pass, sizeof(pass));
    }
    if(!key) {
        fprintf(stderr, "ERROR: Can't change the key for %s: %s\n", username, sxc_geterrmsg(sx));
	return 1;
    }
    if(batch_mode) {
	printf("%s\n", key);
    } else {
        char *conflink;

        conflink = sxc_cluster_configuration_link(cluster, username, key);
        if(!conflink) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            free(key);
            return 1;
        }
	printf("Key successfully changed!\n");
	printf("Name   : %s\n", username);
	printf("New key: %s\n", key);
        printf("Configuration link: %s\n", conflink);
	printf("\nRun 'sxinit sx://%s@%s' and provide the new key or run 'sxinit --config-link <link>' to reconfigure automatically with the new key for user '%s'.\n", username, u->host, username);
        free(conflink);
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

static int getkey_user(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *username, const char *authfile, int get_config_link)
{
    int rc = 0;
    FILE *f = stdout;
    char *user = NULL;

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

    rc = sxc_cluster_whoami(cluster, &user, NULL, NULL, NULL, NULL);
    if(rc) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        goto getkey_user_err;
    }

    if(!strcmp(username, user)) {
        const char *token;

        token = sxc_cluster_get_access(cluster, u->profile);
        if(!token) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            goto getkey_user_err;
        }

        /* Got a valid authorization token, output it to file */
        if(get_config_link) {
            char *link = sxc_cluster_configuration_link(cluster, username, token);

            if(!link) {
                fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                goto getkey_user_err;
            }

            fprintf(f, "%s\n", link);
            free(link);
        } else
            fprintf(f, "%s\n", token);
    } else {
        /* Requested user name is different, call usergetkey query */
        rc = sxc_user_getinfo(cluster, username, f, NULL, get_config_link);
        if(rc)
            fprintf(stderr, "ERROR: Can't retrieve key for user %s: %s\n", username, sxc_geterrmsg(sx));
    }

getkey_user_err:
    if (authfile && fclose(f)) {
        fprintf(stderr, "ERROR: Can't close file %s: %s\n", authfile, strerror(errno));
        rc = 1;
    }
    free(user);
    return rc;
}

static char *process_size(long long size){
    double dsize = (double)size;
    unsigned int i = 0;
    const char *units[] = { "", "K", "M", "G", "T", "P" };
    char buffer[20];
    while( dsize >= 1024 ) {
        dsize /= 1024;
        i++;
    }

    if(i >= sizeof(units)/sizeof(const char*))
        return NULL;
    if(i)
        snprintf(buffer, sizeof(buffer), "%.2f%s", dsize, units[i]);
    else
        snprintf(buffer, sizeof(buffer), "%u", (unsigned int) size);

    return strdup(buffer);
}

static int list_users(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, const char *list_clones, int verbose, int human_readable)
{
    int rc = 0, lstrc = 0;
    sxc_cluster_lu_t *lst;
    char *user = NULL, *desc = NULL;
    int64_t quota, quota_used;
    int is_admin;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume.\n");
	return 1;
    }
    for (lst = (list_clones ? sxc_cluster_listclones(cluster, list_clones) : sxc_cluster_listusers(cluster)); lst && (lstrc = sxc_cluster_listusers_next(lst, &user, &is_admin, &desc, &quota, &quota_used)) > 0;) {
        const char *is_adm = is_admin ? "admin" : "normal";
        char *human_quota = NULL, *human_quota_used = NULL;

        if (verbose) {
            char buff[128];
            if(human_readable) {
                human_quota = process_size(quota);
                human_quota_used = process_size(quota_used);
            }
            if(quota) {
                if(human_quota && human_quota_used)
                    snprintf(buff, sizeof(buff), "%s/%s/%lld%%", human_quota_used, human_quota, (long long)(quota_used * 100 / quota));
                else
                    snprintf(buff, sizeof(buff), "%lld/%lld/%lld%%", (long long)quota_used, (long long)quota, (long long)(quota_used * 100 / quota));
            } else
                snprintf(buff, sizeof(buff), "unlimited");
            printf("%-24s role:%-6s quota:%*s desc:%s\n", user, is_adm, human_readable ? -25 : -35, buff, desc);
            free(human_quota);
            free(human_quota_used);
        } else
            printf("%s (%s)\n", user, is_adm);
        free(user);
        free(desc);
    }
    sxc_cluster_listusers_free(lst);
    if (!lst || lstrc == -1) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        rc = 1;
    }
    return rc;
}

static int whoami(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u, int human_readable)
{
    char *user = NULL;
    char *role = NULL;
    char *desc = NULL;
    int64_t quota, quota_used;
    int verbose = sxc_is_verbose(sx);
    char *human_quota = NULL, *human_quota_used = NULL;
    int rc;

    if(u->volume) {
	fprintf(stderr, "ERROR: Bad URI: Please omit volume.\n");
	return 1;
    }

    if(verbose)
        rc = sxc_cluster_whoami(cluster, &user, &role, &desc, &quota, &quota_used);
    else
        rc = sxc_cluster_whoami(cluster, &user, NULL, NULL, NULL, NULL);
    if(rc) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return 1;
    }
    if (verbose) {
        char buff[128];
        if(human_readable) {
            human_quota = process_size(quota);
            human_quota_used = process_size(quota_used);
        }
        if(quota) {
            if(human_quota && human_quota_used)
                snprintf(buff, sizeof(buff), "%s/%s/%lld%%", human_quota_used, human_quota, (long long)(quota_used * 100 / quota));
            else
                snprintf(buff, sizeof(buff), "%lld/%lld/%lld%%", (long long)quota_used, (long long)quota, (long long)(quota_used * 100 / quota));
        } else
            snprintf(buff, sizeof(buff), "unlimited");
        printf("%-24s role:%-6s quota:%*s desc:%s\n", user, role, human_readable ? -25 : -35, buff, desc);
        free(human_quota);
        free(human_quota_used);
    } else
        printf("%s\n", user);
    free(user);
    free(role);
    free(desc);
    return 0;
}

static int show_acls(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *u)
{
    int rc = 0;
    sxc_cluster_la_t *lst;
    char *user = NULL;
    int acl;

    for (lst = sxc_cluster_listaclusers(cluster, u->volume);
         lst && sxc_cluster_listaclusers_next(lst, &user, &acl);) {
        printf("%s:", user);
        if (acl & SX_ACL_READ)
            printf(" read");
        if (acl & SX_ACL_WRITE)
            printf(" write");
        if (acl & SX_ACL_MANAGER)
            printf(" manager");
        if (acl & SX_ACL_OWNER)
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

static int privs_to_bits(const char *action, const char *str)
{
    int privs = 0;
    while (str && *str) {
        unsigned len = strcspn(str, ",");
        if (!strncmp(str, "read",len))
            privs |= SX_ACL_READ;
        else if (!strncmp(str, "write",len))
            privs |= SX_ACL_WRITE;
        else if (!strncmp(str, "manager",len))
            privs |= SX_ACL_MANAGER;
        else
            return -1;
        str = str + len;
        if (*str == ',') str++;
    }
    if (privs & SX_ACL_MANAGER) {
        int newprivs = privs | SX_ACL_RW;
        if (privs != newprivs) {
            fprintf(stderr, "%s read/write automatically due to change of 'manager' privilege\n", action);
            privs = newprivs;
        }
    }
    return privs;
}

static int volume_acl(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_uri_t *uri, const char *user, const char *grant, const char *revoke)
{
    int ret, grant_acls, revoke_acls;

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
    grant_acls = privs_to_bits("Granting", grant);
    revoke_acls = privs_to_bits("Revoking", revoke);
    if (grant_acls < 0) {
        fprintf(stderr, "ERROR: cannot parse grant privileges: %s\n", grant);
        return 1;
    }
    if (revoke_acls < 0) {
        fprintf(stderr, "ERROR: cannot parse revoke privileges: %s\n", grant);
        return 1;
    }
    ret = sxc_volume_acl(cluster, uri->volume, user, grant_acls, revoke_acls);
    if(ret) {
	fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    } else {
	printf("New volume ACL:\n");
	ret = show_acls(sx, cluster, uri);
    }

    return ret;
}

static int modify_user(sxc_client_t *sx, sxc_cluster_t *cluster, const char *user, int64_t quota, const char *desc) {
    int ret;

    if(!user || (quota == -1 && !desc) || quota < -1) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return 1;
    }

    ret = sxc_user_modify(cluster, user, quota, desc);
    if(ret) {
        fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
        return ret;
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
            fprintf(stderr, "ERROR: Failed to init libsxclient\n");
        return 1;
    }

    do {
        if (!strcmp(argv[1], "useradd")) {
            struct useradd_args_info args;
            int64_t quota = 0;

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

            if(args.quota_given) {
                quota = sxi_parse_size(sx, args.quota_arg, 1);
                if(quota < 0) {
                    fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                    ret = 1;
                    break;
                }
            }

	    ret = add_user(sx, cluster, uri, args.inputs[0], args.pass_file_arg, args.role_arg, args.auth_file_arg, args.batch_mode_flag, args.force_key_arg, NULL, args.description_arg, args.generate_key_given, quota);
            useradd_cmdline_parser_free(&args);

        } else if(!strcmp(argv[1], "userclone")) {
            struct userclone_args_info args;
            if (userclone_cmdline_parser(argc - 1, &argv[1], &args)) {
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
            if (args.inputs_num != 3) {
                userclone_cmdline_parser_print_help();
                printf("\n");
                fprintf(stderr, "ERROR: Wrong number of arguments\n");
                ret = 1;
                break;
            }
            cluster = load_config(sx, args.inputs[2], &uri);
            if(!cluster) {
                ret = 1;
                break;
            }
            ret = add_user(sx, cluster, uri, args.inputs[1], NULL, 0, args.auth_file_arg, args.batch_mode_flag, args.force_key_arg, args.inputs[0], args.description_arg, 0, 0);
            userclone_cmdline_parser_free(&args);

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
	    if(sxc_user_remove(cluster, args.inputs[0], args.all_given)) {
		fprintf(stderr, "ERROR: Can't remove user %s: %s\n", args.inputs[0], sxc_geterrmsg(sx));
		ret = 1;
	    } else {
		printf("User '%s'%s successfully removed.\n", args.inputs[0], args.all_given ? " and its clones" : "");
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
	    ret = list_users(sx, cluster, uri, args.clones_arg, !!args.clones_arg || args.verbose_given, args.human_readable_given);
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
	    ret = getkey_user(sx, cluster, uri, args.inputs[0], args.auth_file_arg, args.config_link_given);
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
	    ret = newkey_user(sx, cluster, uri, args.inputs[0], args.pass_file_arg, args.auth_file_arg, args.batch_mode_flag, args.force_key_arg, args.generate_key_given);
            usernewkey_cmdline_parser_free(&args);
        } else if (!strcmp(argv[1], "usermod")) {
            struct usermod_args_info args;
            int64_t quota = -1;

            if (usermod_cmdline_parser(argc - 1, &argv[1], &args)) {
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
                usermod_cmdline_parser_print_help();
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

            if(args.quota_given) {
                quota = sxi_parse_size(sx, args.quota_arg, 1);
                if(quota < 0) {
                    fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                    ret = 1;
                    break;
                }

            }

            ret = modify_user(sx, cluster, args.inputs[0], quota, args.description_given ? args.description_arg : NULL);
            if(ret)
                break;
            usermod_cmdline_parser_free(&args);
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
            sxc_set_verbose(sx, args.verbose_flag);
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
	    ret = whoami(sx, cluster, uri, args.human_readable_given);
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
