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

#include "version.h"
#include "sx.h"
#include "libsx-int.h"

const char *sxc_get_version(void) {
    return SRC_VERSION;
}

const char *sxi_get_useragent(void) {
    return "libSX/"SRC_VERSION;
}

int sxc_compatible_with(sxc_client_t *sx, const char *server_version)
{
    unsigned smaj, smin;
    if (sscanf(server_version, "%u.%u", &smaj, &smin) != 2) {
        SXDEBUG("Cannot parse server version: %s", server_version);
        return 0;
    }
    if (smaj != SRC_MAJOR_VERSION) {
        SXDEBUG("Server not compatible with client: major version is different: %d != %d",
                smaj, SRC_MAJOR_VERSION);
        return 0;
    }
    if (smin >= SRC_MINOR_VERSION)
        return 1;/* major.minor versions match exactly */
    if (smin > SRC_MINOR_VERSION) {
        /* minor revisions of the server MUST be backward compatible with same
         * major version */
        SXDEBUG("Server is newer than the client, compatible: %d > %d", smin, SRC_MINOR_VERSION);
        return 1;
    }
    SXDEBUG("Client version is newer than the server: %d.%d > %d.%d", SRC_MAJOR_VERSION, SRC_MINOR_VERSION, smaj, smin);
    /* pretend it is compatible */
    return 1;
}
