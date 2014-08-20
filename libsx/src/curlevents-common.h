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

#ifndef CURLEVENTS_COMMON_H
#define CURLEVENTS_COMMON_H

typedef struct curlev curlev_t;
typedef struct curl_events curl_events_t;
typedef struct curlev_context curlev_context_t;
typedef int (*body_cb_t)(curlev_context_t *cbdata, const unsigned char *data, size_t size);
typedef int (*ctx_setup_cb_t)(curlev_context_t *cbdata, const char *host);

#endif
