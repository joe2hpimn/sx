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
#include "types.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int64_t buf[1024*1024 / 8];
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <sizeMB>\n", argv[0]);
        return 1;
    }

    int64_t n = atoll(argv[1]);
    int64_t off = 0;
    for (unsigned i=0;i<n;i++) {
        for (unsigned j=0;j < sizeof(buf)/sizeof(buf[0]); j++) {
            buf[j] = off + j * sizeof(buf[0]);
        }
        if (fwrite(buf, sizeof(buf), 1, stdout) != 1) {
            fprintf(stderr, "Write failed\n");
            return 2;
        }
        off += sizeof(buf);
    }
    return 0;
}
