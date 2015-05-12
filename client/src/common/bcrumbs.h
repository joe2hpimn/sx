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

#ifndef __BCRUMBS_H
#define __BCRUMBS_H

/* WARNING: When editing msgs make sure the order and number of conversion specifiers (%'s) stays the same! */

#define SXBC_SXINIT_RESOLVE_ERR "No node found"
#define SXBC_SXINIT_RESOLVE_MSG "Failed to resolve '%s'. Try specifying the IP address manually with: sxinit -l IPaddr sx://%s\n"

#define SXBC_SXINIT_UUID_ERR "UUID mismatch"
#define SXBC_SXINIT_UUID_MSG "See http://www.skylable.com/docs/faq#Server_UUID_mismatch for more information.\n"

#define SXBC_TOOLS_CFG_ERR "Cannot stat configuration directory"
#define SXBC_TOOLS_CFG_MSG "Make sure you didn't typo cluster name '%s' or forgot to run 'sxinit sx://%s'\n"

#define SXBC_TOOLS_VOL_ERR "No such volume"
#define SXBC_TOOLS_VOL_MSG "Use 'sxls sx://%s%s%s' to list the existing volumes.\n"

#define SXBC_TOOLS_VOLDEL_ERR "Cannot delete non-empty volume"
#define SXBC_TOOLS_VOLDEL_MSG "Use 'sxrm -r sx://%s%s%s/%s' to remove all data from the volume.\n"

#define SXBC_TOOLS_RMVOL_ERR "Cannot operate on volume root in non-recursive mode"
#define SXBC_TOOLS_RMVOL_MSG "Use 'sxvol remove sx://%s%s%s/%s' to remove the empty volume.\n"

#define SXBC_TOOLS_CONN_ERR "Failed to connect"
#define SXBC_TOOLS_CONN_MSG "Please check your network connection or run sxinit again.\n"

#define SXBC_TOOLS_NOTFOUND_ERR "Not Found"
#define SXBC_TOOLS_NOTFOUND_MSG "Use -r to recursively process all files from %s\n"

#endif
