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
#include <unistd.h>
#include <signal.h>
#include <termios.h>

#include "sx.h"
#include "cmd_main.h"
#include "cmd_list.h"
#include "cmd_copy.h"
#include "cmd_delete.h"
#include "version.h"
#include "libsx/src/misc.h"
#include "bcrumbs.h"

static sxc_client_t *sx = NULL;

static int is_sx(const char *p) {
    return strncmp(p, "sx://", 5) == 0 || strncmp(p, SXC_ALIAS_PREFIX, strlen(SXC_ALIAS_PREFIX)) == 0;
}

static void sighandler(int signal)
{
    struct termios tcur;
    if(sx)
	sxc_shutdown(sx, signal);

    /* work around for ctrl+c during getpassword() in the aes filter */
    tcgetattr(0, &tcur);
    tcur.c_lflag |= ECHO;
    tcsetattr(0, TCSANOW, &tcur);

    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

static sxc_file_t *make_sxfile(sxc_cluster_t **cluster, const char *host, const char *profile, const char *volume, const char *path, const char *rev) {
    sxc_file_t *file;

    if(!volume || !path) {
	fprintf(stderr, "ERROR: Bad file path\n");
	return NULL;
    }

    if(!*cluster)
	*cluster = sxc_cluster_load_and_update(sx, host, profile);

    if(!*cluster) {
	fprintf(stderr, "ERROR: Failed to load config for %s: %s\n", host, sxc_geterrmsg(sx));
	if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CFG_ERR))
	    fprintf(stderr, SXBC_TOOLS_CFG_MSG, host, host);
	else if(strstr(sxc_geterrmsg(sx), SXBC_TOOLS_CONN_ERR))
	    fprintf(stderr, SXBC_TOOLS_CONN_MSG);
	return NULL;
    }

    file = sxc_file_remote(*cluster, volume, path, rev);
    if(!file)
	fprintf(stderr, "ERROR: Failed to create file object: %s\n", sxc_geterrmsg(sx));

    return file;
}


int main(int argc, char **argv) {
    sxc_file_t *file = NULL, *destfile = NULL;
    char *config_dir = NULL, *filter_dir = NULL, *selected_rev = NULL;
    const char *src;
    sxc_logger_t log;
    sxc_cluster_t *cluster = NULL, *destcluster = NULL;
    sxc_revlist_t *revs = NULL;
    sxc_uri_t *uri = NULL;
    unsigned int i, match = 0, debug = 0;
    enum { OPNONE, OPMAIN, OPLIST, OPCOPY, OPDELETE } op = OPNONE;
    struct main_args_info main_args;
    struct list_args_info list_args;
    struct copy_args_info copy_args;
    struct delete_args_info delete_args;
    int ret = 1;

    if(argc < 2) {
	main_cmdline_parser_print_help();
	fprintf(stderr, "ERROR: No command specified\n");
	return 1;
    }

    if(!strcmp(argv[1], "list")) {
	if(list_cmdline_parser(argc - 1, &argv[1], &list_args)) {
	    printf("\n");
	    list_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid syntax or usage\n");
	    goto err;
	}

	op = OPLIST;

	if(list_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    ret = 0;
	    goto err;
	}

	if(list_args.inputs_num != 1) {
	    list_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid number of arguments\n");
	    goto err;
	}

	debug = list_args.debug_flag;
	if(list_args.filter_dir_given)
	    filter_dir = list_args.filter_dir_arg;
	if(list_args.config_dir_given)
	    config_dir = list_args.config_dir_arg;
	src = list_args.inputs[0];
	if(!is_sx(src)) {
	    list_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Bad SX file\n");
	}
    } else if(!strcmp(argv[1], "copy")) {
	if(copy_cmdline_parser(argc - 1, &argv[1], &copy_args)) {
	    printf("\n");
	    copy_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid syntax or usage\n");
	    goto err;
	}

	op = OPCOPY;

	if(copy_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    ret = 0;
	    goto err;
	}

	if(copy_args.inputs_num != 2) {
	    copy_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid number of arguments\n");
	    goto err;
	}

	debug = copy_args.debug_flag;
	if(copy_args.filter_dir_given)
	    filter_dir = copy_args.filter_dir_arg;
	if(copy_args.config_dir_given)
	    config_dir = copy_args.config_dir_arg;
	src = copy_args.inputs[0];
	if(!is_sx(src)) {
	    copy_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Bad SX file\n");
	}
	if(copy_args.rev_given)
	    selected_rev = copy_args.rev_arg;
    } else if(!strcmp(argv[1], "delete")) {
	if(delete_cmdline_parser(argc - 1, &argv[1], &delete_args)) {
	    printf("\n");
	    delete_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid syntax or usage\n");
	    goto err;
	}

	op = OPDELETE;

	if(delete_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    ret = 0;
	    goto err;
	}

	if(delete_args.inputs_num != 1) {
	    delete_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Invalid number of arguments\n");
	    goto err;
	}

	debug = delete_args.debug_flag;
	if(delete_args.filter_dir_given)
	    filter_dir = delete_args.filter_dir_arg;
	if(delete_args.config_dir_given)
	    config_dir = delete_args.config_dir_arg;
	src = delete_args.inputs[0];
	if(!is_sx(src)) {
	    delete_cmdline_parser_print_help();
	    printf("\n");
	    fprintf(stderr, "ERROR: Bad SX file\n");
	}
	if(delete_args.rev_given)
	    selected_rev = delete_args.rev_arg;
    } else {
	if(argc > 2) {
	    fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
	    goto err;
	}

	if(main_cmdline_parser(argc, argv, &main_args))
	    goto err;

	if(main_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    op = OPMAIN;
	    ret = 0;
	} else
	    fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
	goto err;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxc_input_fn, NULL)))
	goto err;

    sxc_set_debug(sx, debug);
    if(config_dir && sxc_set_confdir(sx, config_dir)) {
        fprintf(stderr, "ERROR: Could not set configuration directory %s: %s\n", config_dir, sxc_geterrmsg(sx));
	goto err;
    }

    /* At this time there is no use for filters here but they are loaded anyway for consistency */
    if(filter_dir) {
	filter_dir = strdup(filter_dir);
    } else {
	const char *pt = sxi_getenv("SX_FILTER_DIR");
	if(pt)
	    filter_dir = strdup(pt);
	else
	    filter_dir = strdup(SX_FILTER_DIR);
    }
    if(!filter_dir) {
	fprintf(stderr, "ERROR: Failed to set filter dir\n");
	goto err;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);

    if(op == OPCOPY) {
	const char *dst = copy_args.inputs[1];
	if(is_sx(dst)) {
	    sxc_uri_t *desturi = sxc_parse_uri(sx, dst);
	    if(!desturi) {
		fprintf(stderr, "ERROR: Bad uri %s: %s\n", dst, sxc_geterrmsg(sx));
		goto err;
	    }
	    destfile = make_sxfile(&destcluster, desturi->host, desturi->profile, desturi->volume, desturi->path, NULL);
	    sxc_free_uri(desturi);
	    if(!destfile)
		goto err;
	} else {
	    if(!strcmp(dst, "-"))
		dst = "/dev/stdout";
	    destfile = sxc_file_local(sx, dst);
	    if(!destfile) {
		fprintf(stderr, "ERROR: Failed to create destination file object: %s\n", sxc_geterrmsg(sx));
		goto err;
	    }
	}
    }

    if(!(uri = sxc_parse_uri(sx, src))) {
	fprintf(stderr, "ERROR: Bad uri %s: %s\n", src, sxc_geterrmsg(sx));
	goto err;
    }

    if(!(file = make_sxfile(&cluster, uri->host, uri->profile, uri->volume, uri->path, NULL)))
	goto err;
    revs = sxc_revisions(file);
    sxc_file_free(file);

    if(!revs) {
	fprintf(stderr, "ERROR: Failed to retrieve file revisions: %s\n", sxc_geterrmsg(sx));
	goto err;
    }

    if(!selected_rev)
	printf("Revisions for file %s (most recent first):\n", src);
    for(i=0; i<revs->count; i++) {
	const sxc_revision_t *rev = revs->revisions[i];
	struct tm *gt = gmtime(&rev->created_at);
	if(selected_rev) {
	    if(!strcmp(rev->revision, selected_rev)) {
		match = 1;
		break;
	    }
	} else
	    printf("%u.\t%04d-%02d-%02d %02d:%02d size:%llu rev:\"%s\"\n",
		   i+1,
		   gt->tm_year + 1900,
		   gt->tm_mon + 1,
		   gt->tm_mday,
		   gt->tm_hour,
		   gt->tm_min,
		   (long long)rev->file_size,
		   rev->revision);
    }

    if(op == OPLIST) {
	ret = 0;
	goto err;
    }

    if(!selected_rev) {
	char choice[32];
	printf("Choose revision to %s: ", op == OPCOPY ? "copy" : "delete");
	if(fgets(choice, sizeof(choice), stdin)) {
	    i = atoi(choice) - 1;
	    if(i<revs->count) {
		selected_rev = revs->revisions[i]->revision;
		match = 1;
	    }
	}
    }

    if(!match) {
	fprintf(stderr, "The specified revision does not exist\n");
	ret = 2;
	goto err;
    }


    file = make_sxfile(&cluster, uri->host, uri->profile, uri->volume, uri->path, selected_rev);
    if(!file)
	goto err;

    if(op == OPCOPY && !sxc_copy_sxfile(file, destfile, 0))
	ret = 0;

    if(op == OPDELETE && !sxc_remove_sxfile(file))
	ret = 0;

    if(ret)
	fprintf(stderr, "%s operation failed: %s\n", op == OPCOPY ? "Copy" : "Delete", sxc_geterrmsg(sx));
    else 
	fprintf(stderr, "%s operation completed successfully\n", op == OPCOPY ? "Copy" : "Delete");

    sxc_file_free(file);

 err:
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    sxc_file_free(destfile);
    sxc_revisions_free(revs);
    sxc_free_uri(uri);
    sxc_cluster_free(destcluster);
    sxc_cluster_free(cluster);
    sxc_shutdown(sx, 0);
    if(op == OPMAIN)
	main_cmdline_parser_free(&main_args);
    else if(op == OPLIST)
	list_cmdline_parser_free(&list_args);
    else if(op == OPCOPY)
	copy_cmdline_parser_free(&copy_args);
    else if(op == OPDELETE)
	delete_cmdline_parser_free(&delete_args);

    return ret;
}
