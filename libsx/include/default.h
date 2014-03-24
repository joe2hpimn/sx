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

#ifndef DEFAULT_H
#define DEFAULT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* common includes that everything should have */
#include "types.h"
#include "gnuc.h"

#define SX_BS_SMALL (4*1024)
#define SX_BS_MEDIUM (16*1024)
#define SX_BS_LARGE (1*1024*1024)

#define UPLOAD_CHUNK_SIZE (4*SX_BS_LARGE)
#define DOWNLOAD_MAX_BLOCKS 30

#define AUTH_UID_LEN 20
#define AUTH_KEY_LEN 20
#define AUTHTOK_ASCII_LEN 56
#define AUTHTOK_BIN_LEN (AUTHTOK_ASCII_LEN / 4 * 3)

#ifdef HMAC_UPDATE_RETURNS_INT
#define sxi_hmac_init_ex HMAC_Init_ex
#define sxi_hmac_update HMAC_Update
#define sxi_hmac_final HMAC_Final
#else
#define sxi_hmac_init_ex(a, b, c, d, e) (HMAC_Init_ex((a), (b), (c), (d), (e)), 1)
#define sxi_hmac_update(a, b, c) (HMAC_Update((a), (b), (c)), 1)
#define sxi_hmac_final(a, b, c) (HMAC_Final((a), (b), (c)), 1)
#endif

#define HASH_BIN_LEN 20
#define HASH_TEXT_LEN (HASH_BIN_LEN * 2)

#endif
