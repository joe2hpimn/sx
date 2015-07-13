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

#define AUTH_CID_LEN 18 /* Less than AUTH_UID_LEN, its a prefix that can be shared between users */
#define AUTH_UID_LEN 20
#define AUTH_KEY_LEN 20
#define AUTHTOK_ASCII_LEN 56
#define AUTHTOK_BIN_LEN (AUTHTOK_ASCII_LEN / 4 * 3)

#define SXI_SHA1_BIN_LEN 20
#define SXI_SHA1_TEXT_LEN (SXI_SHA1_BIN_LEN * 2)

#endif
