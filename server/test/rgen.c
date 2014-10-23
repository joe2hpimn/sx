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

#include "default.h"
#include "rgen.h"
#include <sys/time.h>
#include <unistd.h>

uint64_t rand_2cmres(rnd_state_t *state)
{
    uint64_t t;
    t = state->xx;  state->xx *=  3188803096312630803ULL;  state->xx = rotl(state->xx,33) - t;
    t = state->yy;  state->yy *= 14882990517504201107ULL;  state->yy = rotl(state->yy,30) - t;
    return state->xx + state->yy;
}

void rnd_seed(rnd_state_t *state, uint64_t seed)
{
    seed = seed & 0xFFFFFFFFFFFFULL;

    /* Mark Overton's CMRES generator */
    uint32_t n;
    uint64_t xx = 138563767ULL, yy = 2400589211ULL, t;
    for (n = (seed & 0x00ffffu) + 10; n>0; n--) {
        t = xx;  xx *=  3188803096312630803ULL;  xx = rotl(xx,33) - t;
    }
    for (n = ((seed>>16)&0xFFFF) + 10; n>0; n--) {
        t = yy;  yy *= 14882990517504201107ULL;  yy = rotl(yy,30) - t;
    }
    state->xx = xx;
    state->yy = yy;

    /* allow for 48-bit seed */
    for (n = (seed >> 32) & 0xFFFF; n>0;n--)
        (void)rand_2cmres(state);
}

void rnd_generate(rnd_state_t *state, uint64_t *buf, uint64_t size)
{
    for(uint64_t i=0;i<size;i++)
        buf[i] = rand_2cmres(state);
}

uint64_t rnd_range(rnd_state_t *state, uint64_t lo, uint64_t hi)
{
    return lo + rand_2cmres(state) % (1 + hi - lo);
}

uint64_t make_seed(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t seed = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    seed = (seed << 16) | getpid();
    return seed;
}
