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

#ifndef RGEN_H
#define RGEN_H
#include "types.h"

#define rotl(x,n) (((x)<<(n)) | ((x)>>((8*sizeof(x))-(n))))

typedef struct {
  uint64_t xx;
  uint64_t yy;
} rnd_state_t;

uint64_t rand_2cmres(rnd_state_t *state);
uint64_t make_seed(void);
void rnd_seed(rnd_state_t *state, uint64_t seed);
void rnd_generate(rnd_state_t *state, uint64_t *buf, uint64_t size);
uint64_t rnd_range(rnd_state_t *state, uint64_t lo, uint64_t hi);
#endif
