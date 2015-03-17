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

#ifndef BLOB_H
#define BLOB_H
#include "default.h"

typedef struct _sx_blob_t sx_blob_t;

sx_blob_t *sx_blob_new(void);
int sx_blob_add_int32(sx_blob_t *s, int32_t d);
int sx_blob_add_int64(sx_blob_t *s, int64_t d);
int sx_blob_add_string(sx_blob_t *s, const char *d);
int sx_blob_add_blob(sx_blob_t *s, const void *d, unsigned int len);
int sx_blob_cat(sx_blob_t *dest, sx_blob_t *src);
void sx_blob_to_data(const sx_blob_t *s, const void **d, unsigned int *len);
sx_blob_t *sx_blob_from_data(const void *d, unsigned int l);
int sx_blob_get_int32(sx_blob_t *s, int32_t *d);
int sx_blob_get_int64(sx_blob_t *s, int64_t *d);
int sx_blob_get_string(sx_blob_t *s, const char **d);
int sx_blob_get_blob(sx_blob_t *s, const void **d, unsigned int *len);
void sx_blob_free(sx_blob_t *s);
void sx_blob_savepos(sx_blob_t *s);
void sx_blob_loadpos(sx_blob_t *s);
void sx_blob_reset(sx_blob_t *s);

#endif
