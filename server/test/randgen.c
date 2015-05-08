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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "rgen.h"

static uint64_t buf[ 128*1024 / 8];

static int gen(rnd_state_t *state, uint64_t size)
{
    uint64_t amount = size;
    while (amount > 0) {
        rnd_generate(state, buf, sizeof(buf)/sizeof(buf[0]));
        unsigned n = amount > sizeof(buf) ? sizeof(buf) : amount;
        if (fwrite(buf, n, 1, stdout) != 1)
            return -1;
        amount -= n;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    rnd_state_t state;
    uint64_t size_min, size_max, size;
    struct timeval tv0, tv1;
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <amount-min> <amount-max> [seed]\n", argv[0]);
        return 1;
    }
    size_min = atoll(argv[1]);
    size_max = atoll(argv[2]);

    uint64_t seed;
    if (argv[3]) {
        seed = strtoll(argv[3], NULL, 16);
    } else {
        seed = make_seed();
    }
    fprintf(stderr,"Seed: %012lx\n", seed);
    rnd_seed(&state, seed);

    size = rnd_range(&state, size_min, size_max);
    gettimeofday(&tv0, NULL);
    if (gen(&state, size) < 0) {
        perror("fwrite failed");
        return 2;
    }
    gettimeofday(&tv1, NULL);
    double t = (tv1.tv_sec - tv0.tv_sec) + (tv1.tv_usec - tv0.tv_usec)/1000000.0;
    double speed = size / 1048576.0 / t;
    fprintf(stderr,"Speed: %.0fMB/s, Filesize: %llu\n", speed, (long long)size);
    return 0;
}
