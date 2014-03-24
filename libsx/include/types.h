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

#ifndef TYPES_H
#define TYPES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define _STRIFY(number) #number
#define STRIFY(number) _STRIFY(number)
#define MIN(a,b) ((a<=b)?(a):(b))
#define MAX(a,b) ((a>=b)?(a):(b))
#define lenof(x) (sizeof(x)-1)

#ifndef HAVE_U_CHAR
typedef uint8_t u_char;
#endif
#ifndef HAVE_U_INT
typedef uint32_t u_int;
#endif
#ifndef HAVE_U_SHORT
typedef uint16_t u_short;
#endif
#ifndef HAVE_U_LONG
typedef unsigned long u_long;
#endif

#endif
