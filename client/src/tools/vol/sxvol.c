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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

#include "cmd_main.h"
#include "cmd_create.h"
#include "cmd_remove.h"
#include "cmd_filter.h"
#include "cmd_modify.h"

#include "sx.h"
#include "libsx/src/misc.h"
#include "libsx/src/volops.h"
#include "libsx/src/clustcfg.h"
#include "version.h"
#include "bcrumbs.h"

struct main_args_info main_args;
struct create_args_info create_args;
struct filter_args_info filter_args;

static sxc_client_t *gsx = NULL;

static void sighandler(int signal)
{
    struct termios tcur;
    if(gsx)
	sxc_shutdown(gsx, signal);

    /* work around for ctrl+c during getpassword() in the aes filter */
    tcgetattr(0, &tcur);
    tcur.c_lflag |= ECHO;
    tcsetattr(0, TCSANOW, &tcur);

    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

static int filter_list(sxc_client_t *sx)
{
	const sxf_handle_t *filters;
	int count, i;

    filters = sxc_filter_list(sx, &count);
    if(!filters) {
	printf("No filters available\n");
	return 1;
    }
    printf("Name\t\tVer\tType\t\tShort description\n");
    printf("----\t\t---\t----\t\t-----------------\n");
    for(i = 0; i < count; i++) {
         const sxc_filter_t *f = sxc_get_filter(&filters[i]);
	printf("%-12s\t%d.%d\t%s\t%s%s\n", f->shortname, f->version[0], f->version[1], f->tname, strlen(f->tname) >= 8 ? "" : "\t", f->shortdesc);
    }

    return 0;
}

static int filter_info(sxc_client_t *sx, const char *name)
{
	const sxf_handle_t *filters;
	int count, i, found = 0;

    filters = sxc_filter_list(sx, &count);
    if(!filters) {
	printf("No filters available\n");
	return 1;
    }
    for(i = 0; i < count; i++) {
         const sxc_filter_t *f = sxc_get_filter(&filters[i]);
	if(!strcmp(f->shortname, name)) {
	    printf("'%s' filter details:\n", f->shortname);
	    printf("Short description: %s\n", f->shortdesc);
	    printf("Summary: %s\n", f->summary);
	    printf("Options: %s\n", f->options ? f->options : "No options");
	    printf("UUID: %s\n", f->uuid);
	    printf("Type: %s\n", f->tname);
	    printf("Version: %d.%d\n", f->version[0], f->version[1]);
	    found = 1;
	}
    }

    if(!found) {
	printf("Filter '%s' not found\n", name);
	return 1;
    }

    return 0;
}

static int reject_dots(const char *str)
{
    const char *lastslash;
    if(*str == '.' || strstr(str, "/../") || strstr(str, "/./"))
        return 1;
    lastslash = strrchr(str, '/');
    if(lastslash)
        lastslash++;
    else
        lastslash = str;
    if(!strcmp(lastslash, "..") || !strcmp(lastslash, "."))
        return 1;
    return 0;
}


static sxc_cluster_t *getcluster_common(sxc_client_t *sx, const char *sxurl, const char *confdir, sxc_uri_t **clusturi) {
    sxc_cluster_t *cluster;
    sxc_uri_t *uri;

    *clusturi = NULL;
    if(confdir && sxc_set_confdir(sx, confdir)) {
	fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", confdir, sxc_geterrmsg(sx));
	return NULL;
    }

    uri = sxc_parse_uri(sx, sxurl);
    if(!uri) {
	fprintf(stderr, "ERROR: Bad uri %s: %s\n", sxurl, sxc_geterrmsg(sx));
	return NULL;
    }
    if(!uri->volume || uri->path) {
	fprintf(stderr, "ERROR: Bad path %s\n", sxurl);
	sxc_free_uri(uri);
	return NULL;
    }

    cluster = sxc_cluster_load_and_update(sx, uri->host, uri->profile);
    if(!cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));
	if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CFG_ERR))
	    fprintf(stderr, SXBC_TOOLS_CFG_MSG, uri->host, uri->host);
        else if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CONN_ERR))
            fprintf(stderr, SXBC_TOOLS_CONN_MSG);;
	sxc_free_uri(uri);
    } else
	*clusturi = uri;

    return cluster;
}

static int setup_filters(sxc_client_t *sx, const char *fdir)
{
	char *filter_dir;

    if(fdir) {
	filter_dir = strdup(fdir);
    } else {
	const char *pt = sxi_getenv("SX_FILTER_DIR");
	if(pt)
	    filter_dir = strdup(pt);
	else
	    filter_dir = strdup(SX_FILTER_DIR);
    }
    if(!filter_dir) {
	fprintf(stderr, "ERROR: Failed to set filter dir\n");
	return 1;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);
    return 0;
}

static int volume_create(sxc_client_t *sx, const char *owner)
{
	sxc_cluster_t *cluster;
	sxc_uri_t *uri;
	const char *confdir;
	char *voldir = NULL, *voldir_old = NULL;
	int ret = 1;
	int64_t size;
	sxc_meta_t *vmeta = NULL;
        const sxc_filter_t *filter = NULL;
	void *cfgdata = NULL;
	unsigned int cfgdata_len = 0;

    size = sxi_parse_size(create_args.size_arg);
    if(size <= 0) /* Bad size, message is printed already */
        return 1;

    cluster = getcluster_common(sx, create_args.inputs[0], create_args.config_dir_arg, &uri);
    if(!cluster)
	return 1;

    if(setup_filters(sx, create_args.filter_dir_arg))
	goto create_err;

    confdir = sxi_cluster_get_confdir(cluster);
    if(!confdir) {
	fprintf(stderr, "ERROR: Unable to locate SX configuration directory\n");
	goto create_err;
    }
    voldir = malloc(strlen(confdir) + strlen(uri->volume) + 10);
    voldir_old = malloc(strlen(confdir) + strlen(uri->volume) + 14);
    if(!voldir || !voldir_old) {
	fprintf(stderr, "ERROR: Out of memory\n");
	goto create_err;
    }
    sprintf(voldir, "%s/volumes/%s", confdir, uri->volume);
    sprintf(voldir_old, "%s/volumes/%s.old", confdir, uri->volume);

    /* rename existing local config */
    if(!reject_dots(uri->volume)) {
	if(!access(voldir_old, F_OK))
	    sxi_rmdirs(voldir_old);
	if(!access(voldir, F_OK) && rename(voldir, voldir_old)) {
	    fprintf(stderr, "ERROR: Can't rename old volume configuration directory %s\n", voldir);
	    goto create_err;
	}
    }

    if(create_args.filter_given) {
	    const sxf_handle_t *filters;
	    int fcount, i, filter_idx;
	    char *farg;
	    char uuidcfg[41];
	    uint8_t uuid[16];

	filters = sxc_filter_list(sx, &fcount);
	if(!filters) {
	    fprintf(stderr, "ERROR: Can't use filter '%s' - no filters available\n", create_args.filter_arg);
	    goto create_err;
	}
	farg = strchr(create_args.filter_arg, '=');
	if(farg)
	    *farg++ = 0;

	vmeta = sxc_meta_new(sx);
	if(!vmeta) {
	    fprintf(stderr, "ERROR: Out of memory\n");
	    goto create_err;
	}

	for(i = 0; i < fcount; i++) {
            const sxc_filter_t *f = sxc_get_filter(&filters[i]);
	    if(!strcmp(f->shortname, create_args.filter_arg))
		if(!filter || f->version[0] > filter->version[0] || (f->version[0] == filter->version[0] && f->version[1] > filter->version[1])) {
		    filter = f;
		    filter_idx = i;
		}
	}

	if(!filter) {
	    fprintf(stderr, "ERROR: Filter '%s' not found\n", create_args.filter_arg);
	    sxc_meta_free(vmeta);
	    goto create_err;
	}

	sxi_uuid_parse(filter->uuid, uuid);
	if(sxc_meta_setval(vmeta, "filterActive", uuid, 16)) {
	    fprintf(stderr, "ERROR: Can't use filter '%s' - metadata error\n", create_args.filter_arg);
	    sxc_meta_free(vmeta);
	    goto create_err;
	}
	snprintf(uuidcfg, sizeof(uuidcfg), "%s-cfg", filter->uuid);
	if(filter->configure) {
	    char *fdir = NULL;

	    fdir = malloc(strlen(confdir) + strlen(filter->uuid) + strlen(uri->volume) + 11);
	    if(!fdir) {
		fprintf(stderr, "ERROR: Out of memory\n");
		sxc_meta_free(vmeta);
		goto create_err;
	    }
	    sprintf(fdir, "%s/volumes/%s", confdir, uri->volume);
	    if(access(fdir, F_OK))
		mkdir(fdir, 0700);
	    sprintf(fdir, "%s/volumes/%s/%s", confdir, uri->volume, filter->uuid);
	    if(access(fdir, F_OK)) {
		if(mkdir(fdir, 0700) == -1) {
		    fprintf(stderr, "ERROR: Can't create filter configuration directory %s\n", fdir);
		    sxc_meta_free(vmeta);
		    free(fdir);
		    goto create_err;
		}
	    }
	    if(filter->configure(&filters[filter_idx], farg, fdir, &cfgdata, &cfgdata_len)) {
		fprintf(stderr, "ERROR: Can't configure filter '%s'\n", create_args.filter_arg);
		sxc_meta_free(vmeta);
		free(fdir);
		goto create_err;
	    }
	    free(fdir);
	    if(cfgdata) {
		if(sxc_meta_setval(vmeta, uuidcfg, cfgdata, cfgdata_len)) {
		    fprintf(stderr, "ERROR: Can't store configuration for filter '%s' - metadata error\n", create_args.filter_arg);
		    sxc_meta_free(vmeta);
		    free(cfgdata);
		    goto create_err;
		}
	    }
	}
    }

    ret = sxc_volume_add(cluster, uri->volume, size, create_args.replica_arg, create_args.max_revisions_arg, vmeta, owner);
    sxc_meta_free(vmeta);

    if(!ret)
	ret = sxi_volume_cfg_store(sx, cluster, uri->volume, filter ? filter->uuid : NULL, cfgdata, cfgdata_len);
    free(cfgdata);
    if(ret)
	fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    else
	printf("Volume '%s' (replica: %d, size: %s, max-revisions: %d) created.\n", uri->volume, create_args.replica_arg, create_args.size_arg, create_args.max_revisions_arg);

create_err:
    if(ret && voldir && !access(voldir, F_OK) && !reject_dots(uri->volume))
	sxi_rmdirs(voldir);

    if(voldir_old && !access(voldir_old, F_OK)) {
	if(ret)
	    rename(voldir_old, voldir);
	else
	    sxi_rmdirs(voldir_old);
    }
    free(voldir);
    free(voldir_old);
    sxc_free_uri(uri);
    sxc_cluster_free(cluster);
    return ret;
}

int main(int argc, char **argv) {
    int ret = 0;
    sxc_client_t *sx;
    sxc_logger_t log;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = gsx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxc_input_fn, NULL))) {
	if(!strcmp(SRC_VERSION, sxc_get_version()))
	    fprintf(stderr, "ERROR: Version mismatch: our version '%s' - library version '%s'\n", SRC_VERSION, sxc_get_version());
	else
	    fprintf(stderr, "ERROR: Failed to init libsx\n");
	return 1;
    }

    if(argc < 2) {
	main_cmdline_parser_print_help();
	fprintf(stderr, "ERROR: No command specified\n");
	return 1;
    }

    if(!strcmp(argv[1], "create")) {
	if(create_cmdline_parser(argc - 1, &argv[1], &create_args)) {
	    printf("\n");
	    create_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid syntax or usage\n");
	    ret = 1;
	    goto main_err;
	}

	if(create_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    goto main_err;
	}

	if(create_args.inputs_num != 1) {
	    create_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid number of arguments\n");
	    create_cmdline_parser_free(&create_args);
	    ret = 1;
	    goto main_err;
	}

        if(create_args.config_dir_given && sxc_set_confdir(sx, create_args.config_dir_arg)) {
            fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", create_args.config_dir_arg, sxc_geterrmsg(sx));
            create_cmdline_parser_free(&create_args);
            ret = 1;
            goto main_err;
        }
	sxc_set_debug(sx, create_args.debug_flag);

	ret = volume_create(sx, create_args.owner_arg);
	create_cmdline_parser_free(&create_args);

    } else if(!strcmp(argv[1], "remove")) {
	struct remove_args_info remove_args;
	sxc_cluster_t *cluster;
	sxc_uri_t *uri;

	ret = 1;
	if(remove_cmdline_parser(argc - 1, &argv[1], &remove_args)) {
	    remove_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid syntax or usage\n");
	    goto main_err;
	}

	if(remove_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    ret = 0;
	    goto main_err;
	}

	if(remove_args.inputs_num != 1) {
	    remove_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid number of arguments\n");
	    remove_cmdline_parser_free(&remove_args);
	    goto main_err;
	}
	sxc_set_debug(sx, remove_args.debug_flag);

	cluster = getcluster_common(sx, remove_args.inputs[0], remove_args.config_dir_arg, &uri);
	if(!cluster) {
	    remove_cmdline_parser_free(&remove_args);
	    goto main_err;
	}

	ret = sxc_volume_remove(cluster, uri->volume);
	if(ret) {
	    fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
	    if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_VOL_ERR))
		fprintf(stderr, SXBC_TOOLS_VOL_MSG, uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host);
	    else if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_VOLDEL_ERR))
		fprintf(stderr, SXBC_TOOLS_VOLDEL_MSG, uri->profile ? uri->profile : "", uri->profile ? "@" : "", uri->host, uri->volume);
	} else {
	    const char *confdir = sxi_cluster_get_confdir(cluster);
	    char *voldir;
	    printf("Volume '%s' removed.\n", uri->volume);

	    voldir = malloc(strlen(confdir) + strlen(uri->volume) + 10);
	    if(!voldir) {
		ret = 1;
		fprintf(stderr, "ERROR: Out of memory\n");
		remove_cmdline_parser_free(&remove_args);
		sxc_free_uri(uri);
		sxc_cluster_free(cluster);
		goto main_err;
	    }
	    sprintf(voldir, "%s/volumes/%s", confdir, uri->volume);
	    /* wipe existing local config */
	    if(!reject_dots(uri->volume)) {
		if(!access(voldir, F_OK) && sxi_rmdirs(voldir)) {
		    ret = 1;
		    fprintf(stderr, "ERROR: Can't wipe volume configuration directory %s\n", voldir);
		    free(voldir);
		    sxc_free_uri(uri);
		    sxc_cluster_free(cluster);
		    goto main_err;
		}
	    }
	    free(voldir);
	}
	sxc_free_uri(uri);
	sxc_cluster_free(cluster);
	remove_cmdline_parser_free(&remove_args);

    } else if(!strcmp(argv[1], "modify")) {
        struct modify_args_info modify_args;
        sxc_cluster_t *cluster;
        sxc_uri_t *uri;
        int64_t size = -1;
        int revs = -1;

        ret = 1;
        if(modify_cmdline_parser(argc - 1, &argv[1], &modify_args)) {
            modify_cmdline_parser_print_help();
            printf("\n");
            fprintf(stderr, "ERROR: Invalid syntax or usage\n");
            goto main_err;
        }

        if(modify_args.version_given) {
            printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
            ret = 0;
            goto main_err;
        }

        if(modify_args.inputs_num != 1) {
            modify_cmdline_parser_print_help();
            printf("\n");
            fprintf(stderr, "ERROR: Invalid number of arguments\n");
            modify_cmdline_parser_free(&modify_args);
            goto main_err;
        }

        if(!modify_args.owner_given && !modify_args.size_given && !modify_args.max_revisions_given) {
            modify_cmdline_parser_print_help();
            printf("\n");
            fprintf(stderr, "ERROR: Invalid arguments\n");
            modify_cmdline_parser_free(&modify_args);
            goto main_err;
        }
        sxc_set_debug(sx, modify_args.debug_flag);

        cluster = getcluster_common(sx, modify_args.inputs[0], modify_args.config_dir_arg, &uri);
        if(!cluster) {
            modify_cmdline_parser_free(&modify_args);
            goto main_err;
        }

        if(modify_args.size_given) {
            size = sxi_parse_size(modify_args.size_arg);
            if(size <= 0)
                goto modify_err;
        }

        if(modify_args.max_revisions_given) {
            if(modify_args.max_revisions_arg <= 0) {
                fprintf(stderr, "ERROR: Bad revisions limit: %d\n", modify_args.max_revisions_arg);
                goto modify_err;
            }
            revs = modify_args.max_revisions_arg;
        }

        ret = sxc_volume_modify(cluster, uri->volume, modify_args.owner_arg, size, revs);
        if(ret) {
            fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
            goto modify_err;
        } else {
	    if(modify_args.owner_given)
		printf("Volume owner changed to '%s'\n", modify_args.owner_arg);
	    if(modify_args.size_given)
		printf("Volume size changed to %s\n", modify_args.size_arg);
            if(modify_args.max_revisions_given)
                printf("Volume revisions limit changed to %d\n", modify_args.max_revisions_arg);
	}

    modify_err:
        sxc_free_uri(uri);
        sxc_cluster_free(cluster);
        modify_cmdline_parser_free(&modify_args);

    } else if(!strcmp(argv[1], "filter")) {
	if(filter_cmdline_parser(argc - 1, &argv[1], &filter_args)) {
	    ret = 1;
	    filter_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid syntax or usage\n");
	    goto main_err;
	}

	if(filter_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    filter_cmdline_parser_free(&filter_args);
	    goto main_err;
	}

        if(filter_args.config_dir_given && sxc_set_confdir(sx, filter_args.config_dir_arg)) {
            fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", filter_args.config_dir_arg, sxc_geterrmsg(sx));
            filter_cmdline_parser_free(&filter_args);
            ret = 1;
            goto main_err;
        }
	sxc_set_debug(sx, filter_args.debug_flag);

	if(setup_filters(sx, filter_args.filter_dir_arg)) {
	    filter_cmdline_parser_free(&filter_args);
	    ret = 1;
	    goto main_err;
	}

	if(filter_args.list_given || argc == 2) {
	    ret = filter_list(sx);
	    if(!ret && argc == 2)
		fprintf(stderr, "\nRun sxvol filter --info=<filtername> to get usage help for a specific filter.\n");
	} else if(filter_args.info_given)
	    ret = filter_info(sx, filter_args.info_arg);
	else {
	    filter_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid arguments\n");
	    ret = 1;
	    filter_cmdline_parser_free(&filter_args);
	    goto main_err;
	}

	filter_cmdline_parser_free(&filter_args);

    } else {
	if(argc > 2) {
	    fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
	    ret = 1;
	    goto main_err;
	}

	if(main_cmdline_parser(argc, argv, &main_args)) {
	    ret = 1;
	    goto main_err;
	}

	if(main_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	} else {
	    fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
	    ret = 1;
	}
	main_cmdline_parser_free(&main_args);
    }

main_err:

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);

    return ret;
}
