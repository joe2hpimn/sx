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

#include "default.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "hostlist.h"
#include "libsxclient-int.h"
#include "misc.h"

void sxi_hostlist_init(sxi_hostlist_t *list) {
    if(list)
	memset(list, 0, sizeof(*list));
}

void sxi_hostlist_empty(sxi_hostlist_t *list) {
    if(!list)
	return;

    while(list->nhosts) {
	list->nhosts--;
	free(list->hosts[list->nhosts]);
    }
    free(list->hosts);
    sxi_hostlist_init(list);
}

struct addrinfo *sxi_gethostai(const char *host) {
    struct addrinfo hint, *res;
    if(!host)
	return NULL;

    memset(&hint, 0, sizeof(hint));
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;

    if(getaddrinfo(host, NULL, &hint, &res))
	return NULL;

    return res;
}

int sxi_is_valid_host(const char *host) {
    struct addrinfo *res = sxi_gethostai(host);
    if(!res)
	return 0;

    freeaddrinfo(res);
    return 1;
}

int sxi_hostlist_contains(const sxi_hostlist_t *list, const char *host) {
    unsigned int i;

    if(!list || !host)
	return 0;

    for(i=0; i<list->nhosts; i++)
	if(!strcmp(list->hosts[i], host))
	    return 1;

    return 0;
}

/* FIXME: not for large lists as complexity is terrible */
int sxi_hostlist_add_host(sxc_client_t *sx, sxi_hostlist_t *list, const char *host) {
    char **newarr;

    if(!list || !sxi_is_valid_host(host)) {
	SXDEBUG("called with %s", list ? "invalid host" : "NULL list");
	sxi_seterr(sx, SXE_EARG, "Cannot add host '%s' to list: Invalid %s argument", host, list ? "host" : "hostlistlist");
	return 1;
    }

    if(sxi_hostlist_contains(list, host))
	return 0;

    newarr = realloc(list->hosts, (list->nhosts+1) * sizeof(char *));
    if(!newarr) {
	SXDEBUG("OOM reallocating list");
	sxi_seterr(sx, SXE_EMEM, "Cannot add host to list: Out of memory");
	return 1;
    }
    list->hosts = newarr;
    if(!(list->hosts[list->nhosts] = strdup(host))) {
	SXDEBUG("OOM duplicating host");
	sxi_seterr(sx, SXE_EMEM, "Cannot add host to list: Out of memory");
	return 1;
    }
    list->nhosts++;

    return 0;
}

int sxi_hostlist_add_list(sxc_client_t *sx, sxi_hostlist_t *list, const sxi_hostlist_t *other) {
    unsigned int i;

    if(!list) {
	SXDEBUG("called NULL list");
	sxi_seterr(sx, SXE_EARG, "Cannot add host list to list: Invalid list argument");
	return 1;
    }
    if(!other)
	return 0;

    for(i=0; i<other->nhosts; i++)
	if(sxi_hostlist_add_host(sx, list, other->hosts[i]))
	    return 1;
    return 0;
}


unsigned int sxi_hostlist_get_count(const sxi_hostlist_t *list) {
    return list ? list->nhosts : 0;
}

const char *sxi_hostlist_get_host(const sxi_hostlist_t *list, unsigned int pos) {
    if(!list || pos >= list->nhosts)
	return NULL;
    return list->hosts[pos];
}

void sxi_hostlist_shuffle(sxi_hostlist_t *list) {
    unsigned int i;
    if(!list || list->nhosts<2)
	return;
    for(i=list->nhosts-1; i>=1; i--) {
	unsigned int r = sxi_rand() % (i+1);
	char *t;

	if(i == r)
	    continue;
	t = list->hosts[i];
	list->hosts[i] = list->hosts[r];
	list->hosts[r] = t;
    }
}

