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

#ifndef __VOLOPS_H
#define __VOLOPS_H

#include "sx.h"

int sxi_volume_cfg_store(sxc_client_t *sx, sxc_cluster_t *cluster, const char *vname, const char *filter_uuid, const unsigned char *filter_cfg, unsigned int filter_cfglen);

int sxi_volume_cfg_check(sxc_client_t *sx, sxc_cluster_t *cluster, sxc_meta_t *vmeta, const char *vname);

#endif
