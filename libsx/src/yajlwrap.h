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

#ifndef _YAJLWRAP_H
#define _YAJLWRAP_H

#include <yajl/yajl_parse.h>
#include "sx.h"

#define CB_ERROR_STRSZ 256
struct cb_error_ctx {
  sxc_client_t *sx;
  char node[CB_ERROR_STRSZ];
  char id[CB_ERROR_STRSZ];
  char msg[CB_ERROR_STRSZ];
  char details[CB_ERROR_STRSZ];
  int nmaps;
  int narrays;
  int status;
  enum error_state { ER_OTHER = 0, ER_NODE, ER_ID, ER_MSG, ER_DETAILS } state;
};

void ya_init(yajl_callbacks *c);
void ya_error_parser(yajl_callbacks *c);

int yacb_error_string(void *ctx, const unsigned char *s, size_t l);
int yacb_error_map_key(void *ctx, const unsigned char *s, size_t l);
int yacb_error_end_map(void *ctx);

/* Check whether the key is ErrorMessage, and initialize the error parser if so.
 * You should start calling yacb_error_* functions after this.
 */
int ya_check_error(sxc_client_t *sx, struct cb_error_ctx *ctx, const unsigned char *s, size_t l);
int sxi_parse_error_message(const unsigned char *s, size_t l, yajl_callbacks *yacb, sxc_client_t *sx);

#endif
