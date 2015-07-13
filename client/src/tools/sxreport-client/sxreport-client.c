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
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cmdline.h"

#include "sx.h"
#include "../../../../libsxclient/src/sxreport.h"
#include "../../../../libsxclient/src/misc.h"
#include "version.h"

static int filter_list(sxc_client_t *sx)
{
    const sxf_handle_t *filters;
    int count, i;

    filters = sxc_filter_list(sx, &count);
    if(!filters) {
	sxi_notice(sx, "No filters available\n");
	return 1;
    }
    for(i = 0; i < count; i++) {
        const sxc_filter_t *f = sxc_get_filter(&filters[i]);
        sxi_info(sx, "'%s' filter details:", f->shortname);
        sxi_info(sx,"\tShort description: %s", f->shortdesc);
        sxi_info(sx,"\tSummary: %s", f->summary);
        sxi_info(sx,"\tOptions: %s", f->options ? f->options : "No options");
        sxi_info(sx,"\tUUID: %s", f->uuid);
        sxi_info(sx,"\tType: %s", f->tname);
        sxi_info(sx,"\tVersion: %d.%d", f->version[0], f->version[1]);
    }

    return 0;
}

static const char *get_filter_dir(sxc_client_t *sx, const char *fdir)
{
    const char *pt;
    if(fdir)
        return fdir;
    pt = sxi_getenv("SX_FILTER_DIR");
    if(pt)
        return pt;
    return SX_FILTER_DIR;
}

int main(int argc, char **argv) {
    sxc_client_t *sx;
    sxc_logger_t log;
    struct gengetopt_args_info args;
    char file[1024];
    const char *filter_dir;

    if(cmdline_parser(argc, argv, &args))
	return 1;

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	cmdline_parser_free(&args);
	return 0;
    }

    if(args.output_given)
        snprintf(file, sizeof(file), "%s", args.output_arg);
    else
	snprintf(file, sizeof(file), "sxreport-client-%ld.log", (long)time(NULL));

    umask(077);
    if(!(sx = sxc_init(SRC_VERSION, sxc_file_logger(&log, argv[0], file, 1), NULL, NULL))) {
	cmdline_parser_free(&args);
	return 1;
    }
    sxc_set_confdir(sx, args.config_dir_arg);
    sxc_set_verbose(sx, 1);

    filter_dir = get_filter_dir(sx, args.filter_dir_arg);
    sxc_filter_loadall(sx, filter_dir);
    sxi_report_build_info(sx);
#define INFO_PKGCONFIG ""
#define INFO_PKGCONFIG_LIBDIR ""
#define INFO_PKGCONFIG_PATH ""
    sxi_report_build_flags(sx);
    sxi_report_library_versions(sx, SRC_VERSION);
    sxi_report_system_info(sx);
    sxi_report_limits(sx);
    sxi_report_section(sx, "Filters");
    sxi_info(sx,"Default filter directory: %s\n", SX_FILTER_DIR);
    sxi_info(sx,"Current filter directory: %s\n", filter_dir);
    filter_list(sx);
    sxi_report_configuration(sx, args.config_dir_arg);
    printf("Report stored in %s\n", file);
    printf("You can attach it to a bugreport at %s\n", PACKAGE_BUGREPORT);
    cmdline_parser_free(&args);
    sxc_shutdown(sx, 0);
    return 0;
}
