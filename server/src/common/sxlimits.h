/*
 *  Copyright (C) 2012-2015 Skylable Ltd. <info-copyright@skylable.com>
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

#ifndef __SXLIMITS_H
#define __SXLIMITS_H

#define SXLIMIT_MIN_NODE_SIZE (1*1024*1024)

#define SXLIMIT_MIN_VOLNAME_LEN 2
#define SXLIMIT_MAX_VOLNAME_LEN 255
#define SXLIMIT_MIN_VOLUME_SIZE (1*1024*1024)
#define SXLIMIT_MAX_VOLUME_SIZE (1LL*1024LL*1024LL*1024LL*1024LL*1024LL)

#define SXLIMIT_MIN_FILENAME_LEN 1
#define SXLIMIT_MAX_FILENAME_LEN 1024
#define SXLIMIT_MIN_FILE_SIZE 0LL
#define SXLIMIT_MAX_FILE_SIZE (10LL*1024LL*1024LL*1024LL*1024LL)

#define SXLIMIT_META_MIN_KEY_LEN 1
#define SXLIMIT_META_MAX_KEY_LEN 256
#define SXLIMIT_META_MIN_VALUE_LEN 0
#define SXLIMIT_META_MAX_VALUE_LEN 65536
#define SXLIMIT_META_MAX_ITEMS 128

/* Limits used for cluster settings */
#define SXLIMIT_SETTINGS_MIN_KEY_LEN 1
#define SXLIMIT_SETTINGS_MAX_KEY_LEN 256
#define SXLIMIT_SETTINGS_MIN_VALUE_LEN 0
#define SXLIMIT_SETTINGS_MAX_VALUE_LEN 65536
#define SXLIMIT_SETTINGS_MAX_ITEMS 8

#define SXLIMIT_MIN_USERNAME_LEN 2
#define SXLIMIT_MAX_USERNAME_LEN 64
#define SXLIMIT_MIN_USERDESC_LEN 0
#define SXLIMIT_MAX_USERDESC_LEN 1024

#define SXLIMIT_MIN_REVISIONS 1
#define SXLIMIT_MAX_REVISIONS 64

#endif
