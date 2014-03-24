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
#include "libsx-int.h"
/* build info */
/* need to expand this in libsx / server respectively
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
#endif
