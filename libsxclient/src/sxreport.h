/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef SXREPORT_H
#define SXREPORT_H
#include "sx.h"
#include "default.h"
#include "libsxclient-int.h"
/* build info */
/* need to expand this in libsxclient / server respectively
 * as they might have different flags */
#define sxi_report_build_flags(sx) do {\
    sxi_info(sx,"CPPFLAGS: %s", INFO_CPPFLAGS);\
    sxi_info(sx,"CFLAGS: %s", INFO_CFLAGS);\
    sxi_info(sx,"LDFLAGS: %s", INFO_LDFLAGS);\
    sxi_info(sx,"PKG_CONFIG: %s", INFO_PKGCONFIG);\
    sxi_info(sx,"PKG_CONFIG_LIBDIR: %s", INFO_PKGCONFIG_LIBDIR);\
    sxi_info(sx,"PKG_CONFIG_PATH: %s", INFO_PKGCONFIG_PATH);\
    sxi_info(sx,"bindir: %s", INFO_BINDIR);\
    sxi_info(sx,"sysconfdir: %s", INFO_SYSCONFDIR);\
    sxi_info(sx,"localstatedir: %s", INFO_LOCALSTATEDIR);\
} while(0)

void sxi_report_build_info(sxc_client_t *sx);
void sxi_report_library_int(sxc_client_t *sx, const char *name, long compile_ver, long runtime_ver,
                            long major_div, long minor_div, long patch_div);
void sxi_report_library_versions(sxc_client_t *sx, const char *srcver);
void sxi_report_system_info(sxc_client_t *sx);
void sxi_report_limits(sxc_client_t *sx);
void sxi_report_section(sxc_client_t *sx, const char *section);
void sxi_report_configuration(sxc_client_t *sx, const char *configdir);
int sxi_list(sxc_client_t *sx, const char *dir, const char *entry, int depth);
int sxi_report_os(sxc_client_t *sx, char *name, size_t name_len, char *arch, size_t arch_len, char *release, size_t rel_len, char *version, size_t ver_len);
int sxi_report_fs(sxc_client_t *sx, const char *path, int64_t *block_size, int64_t *total_blocks, int64_t *available_blocks);
int sxi_report_cpu(sxc_client_t *sx, int *ncpus, char *endianness, size_t endianness_len);
#include "cluster.h"
/* NOTE: Linux specific, should return 0 immediately on other architectures and should not modify output */
int sxi_report_system_stat(sxc_client_t *sx, int ncpus, cpu_stat_t **cpu_stat, time_t *btime, int *processes, int *processes_running, int *processes_blocked);
int sxi_network_traffic_status(sxc_client_t *sx, sxi_conns_t *conns, const char *host, char **traffic_json, size_t *traffic_json_size);
int sxi_report_mem(sxc_client_t *sx, int64_t *total_mem, int64_t *available_mem, int64_t *swap_total, int64_t *swap_free);
#endif
