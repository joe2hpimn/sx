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

#ifndef __FILTER_H
#define __FILTER_H

#include <stdio.h>
#include "sx.h"
#include "libsxclient-int.h"

void sxi_filter_unloadall(sxc_client_t *sx);

static const struct {
    sxf_type_t type;
    const char *tname;
} sxi_filter_tname[] = {
    { SXF_TYPE_COMPRESS,   "compress"	    },
    { SXF_TYPE_CRYPT,	    "crypt"	    },
    { SXF_TYPE_GENERIC,    "generic"	    },
    { SXF_TYPE_NONE,	    NULL	    }
};

struct filter_handle *sxi_filter_gethandle(sxc_client_t *sx, const uint8_t *uuid);
int sxi_filter_add_cfg(struct filter_handle *fh, const char *volname, const void *cfg, unsigned int cfg_len);
const void *sxi_filter_get_cfg(struct filter_handle *fh, const char *volname);
unsigned int sxi_filter_get_cfg_len(struct filter_handle *fh, const char *volname);

#endif
