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
#include "cmdline.h"
#include "version.h"
#include "libsx/src/misc.h"

struct gengetopt_args_info args;
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

static sxc_file_t *sxfile_from_arg(sxc_cluster_t **cluster, const char *arg) {
    sxc_file_t *file;

    if(is_sx(arg)) {
	sxc_uri_t *uri = sxc_parse_uri(sx, arg);

	if(!uri) {
	    fprintf(stderr, "Bad uri %s: %s\n", arg, sxc_geterrmsg(sx));
	    return NULL;
	}
	if(!uri->volume) {
	    fprintf(stderr, "Bad path %s\n", arg);
	    sxc_free_uri(uri);
	    return NULL;
	}

	*cluster = sxc_cluster_load_and_update(sx, args.config_dir_arg, uri->host, uri->profile);
	if(!*cluster) {
	    fprintf(stderr, "Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));
	    sxc_free_uri(uri);
	    return NULL;
	}

	file = sxc_file_remote(*cluster, uri->volume, uri->path);
	sxc_free_uri(uri);
	if(!file) {
	    sxc_cluster_free(*cluster);
            *cluster = NULL;
        }
    } else
	file = sxc_file_local(sx, arg);

    if(!file) {
	fprintf(stderr, "Failed to create file object: %s\n", sxc_geterrmsg(sx));
	return NULL;
    }

    return file;
}


int main(int argc, char **argv) {
    int ret = 0;
    unsigned int i;
    sxc_file_t *src_file = NULL;
    char *filter_dir;
    sxc_logger_t log;
    sxc_cluster_t *cluster = NULL;

    if(cmdline_parser(argc, argv, &args))
	exit(1);

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	cmdline_parser_free(&args);
	exit(0);
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxi_yesno))) {
	cmdline_parser_free(&args);
	return 1;
    }

    sxc_set_debug(sx, args.debug_flag);

    if(args.filter_dir_given) {
	filter_dir = strdup(args.filter_dir_arg);
    } else {
	const char *pt = getenv("SX_FILTER_DIR");
	if(pt)
	    filter_dir = strdup(pt);
	else
	    filter_dir = strdup(SX_FILTER_DIR);
    }
    if(!filter_dir) {
	fprintf(stderr, "Failed to set filter dir\n");
	cmdline_parser_free(&args);
	return 1;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);

    for(i = 0; i < args.inputs_num; i++) {
	if(!(src_file = sxfile_from_arg(&cluster, args.inputs[i]))) {
	    ret = 1;
	    break;
	}

	if(sxc_cat(src_file, STDOUT_FILENO)) {
	    fprintf(stderr, "Failed to stream %s: %s\n", args.inputs[i], sxc_geterrmsg(sx));
	    ret = 1;
	}
	sxc_file_free(src_file);
        sxc_cluster_free(cluster);
    }

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);
    cmdline_parser_free(&args);

    return ret;
}
