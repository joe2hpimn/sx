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

#ifndef _HOSTLIST_H
#define _HOSTLIST_H

#include "libsxclient-int.h"

typedef struct _sxi_hostlist_t {
    char **hosts;
    unsigned int nhosts;
} sxi_hostlist_t;

void sxi_hostlist_init(sxi_hostlist_t *list);
void sxi_hostlist_empty(sxi_hostlist_t *list);
int sxi_hostlist_contains(const sxi_hostlist_t *list, const char *host);
int sxi_hostlist_add_host(sxc_client_t *sx, sxi_hostlist_t *list, const char *host);
int sxi_hostlist_add_list(sxc_client_t *sx, sxi_hostlist_t *list, const sxi_hostlist_t *other);
unsigned int sxi_hostlist_get_count(const sxi_hostlist_t *list);
const char *sxi_hostlist_get_host(const sxi_hostlist_t *list, unsigned int pos);
void sxi_hostlist_shuffle(sxi_hostlist_t *list);
struct addrinfo *sxi_gethostai(const char *host);
int sxi_is_valid_host(const char *host);

#endif
