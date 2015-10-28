/*
 *  Copyright (C) 2015 Skylable Ltd. <info-copyright@skylable.com>
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
#include <string.h>
#include <math.h>
#include <sys/time.h>

#include "blob.h"
#include "init.h"
#include "log.h"

#define GTFO(...) do { CRIT(__VA_ARGS__); goto out; } while(0)

#define I32VAL 0x1337acab
#define I64VAL -123456789012345678
#define U64VAL 0xfedcba9876543210
#define STRVAL "Test string"
#define BLOBVAL "Test\0Blob"
#define FLOATVAL sqrt(3)

static int lame_timercmp(const struct timeval *tv1, const struct timeval *tv2) {
    /* Because OSX */
    return (tv1->tv_sec != tv2->tv_sec) || (tv1->tv_usec != tv2->tv_usec);
}

int main(int argc, char **argv) {
    sxc_client_t *sx = sx_init(NULL, NULL, NULL, 0, argc, argv);
    sx_blob_t *b = NULL, *b2;
    struct timeval tv1, tv2;
    blob_object_t t;
    uint64_t u64;
    int64_t i64;
    int32_t i32;
    double flt;
    const char *string;
    const void *bdata;
    unsigned int blen;
    int bool, ret = 1;

    if(!sx)
	GTFO("Failed ot init library");

    if(argc == 2 && !strcmp(argv[1], "--debug"))
	log_setminlevel(sx, SX_LOG_DEBUG);

    b = sx_blob_new();
    if(!b)
	GTFO("Failed to create blob");

    if(sx_blob_add_int32(b, I32VAL))
	GTFO("Failed to add int32");

    sx_blob_savepos(b);

    if(sx_blob_add_int64(b, I64VAL))
	GTFO("Failed to add int64");

    sx_blob_reset(b);

    if(!sx_blob_get_int64(b, &i64))
	GTFO("Got int of different size");

    if(sx_blob_get_int32(b, &i32))
	GTFO("Failed to get int32 (precheck)");
    if(i32 != I32VAL)
	GTFO("Value of mismatch on int32 (precheck)");

    if(sx_blob_get_int64(b, &i64))
	GTFO("Failed to get int64 (precheck)");
    if(i64 != I64VAL)
	GTFO("Value of mismatch on int64 (precheck)");

    sx_blob_loadpos(b);

    if(sx_blob_peek_objtype(b, &t) || t != BLOB_INT64)
	GTFO("Peek failed");

    if(sx_blob_get_int64(b, &i64))
	GTFO("Failed to get int64 (re-get)");
    if(i64 != I64VAL)
	GTFO("Value of mismatch on int64 (re-get)");

    if(sx_blob_add_uint64(b, U64VAL))
	GTFO("Failed to add uint64");

    if(sx_blob_add_string(b, STRVAL))
	GTFO("Failed to add string");

    if(sx_blob_add_blob(b, BLOBVAL, sizeof(BLOBVAL)))
	GTFO("Failed to add blob");

    if(sx_blob_add_bool(b, 1))
	GTFO("Failed to add bool (true)");
    if(sx_blob_add_bool(b, 0))
	GTFO("Failed to add bool (false)");

    if(sx_blob_add_float(b, FLOATVAL))
	GTFO("Failed to add float (val)");
    if(sx_blob_add_float(b, NAN))
	GTFO("Failed to add float (NaN)");
    if(sx_blob_add_float(b, INFINITY))
	GTFO("Failed to add float (+inf)");
    if(sx_blob_add_float(b, -INFINITY))
	GTFO("Failed to add float (+inf)");

    if(gettimeofday(&tv1, NULL))
	GTFO("Failed to get current time");
    if(sx_blob_add_datetime(b, &tv1))
	GTFO("Failed to add datetime");

    sx_blob_to_data(b, &bdata, &blen);
    if(!(b2 = sx_blob_from_data(bdata, blen)))
	GTFO("Failed to load blob from data");
    sx_blob_free(b);
    b = b2;

    if(sx_blob_get_int32(b, &i32))
	GTFO("Failed to get int32");
    if(i32 != I32VAL)
	GTFO("Value of mismatch on int32");

    if(sx_blob_get_int64(b, &i64))
	GTFO("Failed to get int64");
    if(i64 != I64VAL)
	GTFO("Value of mismatch on int64");

    if(sx_blob_get_uint64(b, &u64))
	GTFO("Failed to get uint64");
    if(u64 != U64VAL)
	GTFO("Value of mismatch on uint64");

    if(sx_blob_get_string(b, &string))
	GTFO("Failed to get string");
    if(strcmp(string, STRVAL))
	GTFO("Value of mismatch on string");

    if(sx_blob_get_blob(b, &bdata, &blen))
	GTFO("Failed to get blob");
    if(blen != sizeof(BLOBVAL) || memcmp(bdata, BLOBVAL, blen))
	GTFO("Value of mismatch on blob");

    if(sx_blob_get_bool(b, &bool))
	GTFO("Failed to get bool (true)");
    if(bool != 1)
	GTFO("Value of mismatch on bool (true)");
    if(sx_blob_get_bool(b, &bool))
	GTFO("Failed to get bool (false)");
    if(bool != 0)
	GTFO("Value of mismatch on bool (false)");

    if(sx_blob_get_float(b, &flt))
	GTFO("Failed to get float (val)");
    if(flt != FLOATVAL)
	GTFO("Value of mismatch on float (val)");
    if(sx_blob_get_float(b, &flt))
	GTFO("Failed to get float (NaN)");
    if(!isnan(flt))
	GTFO("Value of mismatch on float (NaN)");
    if(sx_blob_get_float(b, &flt))
	GTFO("Failed to get float (+inf)");
    if(flt <= 0 || !isinf(flt))
	GTFO("Value of mismatch on float (+inf)");
    if(sx_blob_get_float(b, &flt))
	GTFO("Failed to get float (-inf)");
    if(flt >= 0 || !isinf(flt))
	GTFO("Value of mismatch on float (-inf)");

    if(sx_blob_get_datetime(b, &tv2))
	GTFO("Failed to get datetime");
    if(lame_timercmp(&tv1, &tv2))
	GTFO("Value of mismatch on datetime");

    if(!sx_blob_peek_objtype(b, &t))
	GTFO("Found extra object at end of blob");
    
    ret = 0;
 out:
    sx_blob_free(b);
    sx_done(&sx);
    return ret;
}
