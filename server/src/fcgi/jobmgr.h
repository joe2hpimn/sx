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

#ifndef JOBMGR_H
#define JOBMGR_H

enum replace_state { RPL_HDRSIZE = 0, RPL_HDRDATA, RPL_DATA, RPL_END };
struct rplfiles {
    sx_hashfs_t *hashfs;
    sx_blob_t *b;
    sx_hash_t hash;
    uint8_t hdr[1024 +
                SXLIMIT_MAX_FILENAME_LEN +
                REV_LEN +
                ( 128 + SXLIMIT_META_MAX_KEY_LEN + SXLIMIT_META_MAX_VALUE_LEN ) * SXLIMIT_META_MAX_ITEMS];
    char volume[SXLIMIT_MAX_VOLNAME_LEN+1],
	file[SXLIMIT_MAX_FILENAME_LEN+1],
	rev[REV_LEN+1];
    unsigned int ngood, itemsz, pos, needend, files_and_volumes;
    enum replace_state state;
};

int jobmgr(sxc_client_t *sx, const char *dir, int pipe);
int rplfiles_cb(curlev_context_t *cbdata, void *ctx, const void *data, size_t size);

#endif
