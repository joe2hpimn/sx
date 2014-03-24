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
#include "utils.h"
#include "errors.h"

#include <check.h>
#include "check_main.h"
#include <errno.h>
#include <stdlib.h>

START_TEST(test_malloc)
{
    void *p = wrap_malloc(0);
    fail_unless(p == NULL, "wrap_malloc 0");
    free(p);

    p = wrap_malloc(1);
    fail_unless(!!p, "wrap_malloc 1");
    free(p);

    if (sizeof(size_t) < sizeof(uint64_t)) {
        p = wrap_malloc(~0ULL);
        fail_unless(p == NULL && errno == EOVERFLOW, "wrap_malloc EOVERFLOW");
        free(p);
    }
}
END_TEST

START_TEST(test_calloc)
{
    void *p = wrap_calloc(1, 0);
    fail_unless(p == NULL, "wrap_calloc 1,0");
    free(p);

    p = wrap_calloc(0, 1);
    fail_unless(p == NULL, "wrap_calloc 0, 1");
    free(p);

    p = wrap_calloc(1, 1);
    fail_unless(!!p, "wrap_calloc 1");
    free(p);

    if (sizeof(size_t) < sizeof(uint64_t)) {
        p = wrap_calloc(1, ~0ULL);
        fail_unless(p == NULL && errno == EOVERFLOW, "wrap_calloc EOVERFLOW");
        free(p);
    }
}
END_TEST

START_TEST(test_realloc)
{
    void *p = wrap_realloc(NULL, 0);
    fail_unless(p == NULL, "wrap_realloc NULL,0");
    free(p);

    p = wrap_realloc(NULL, 1);
    fail_unless(!!p, "wrap_realloc 1");
    fail_unless(!wrap_realloc_or_free(p, 0), "wrap_realloc_or_free 0");

    if (sizeof(size_t) < sizeof(uint64_t)) {
        p = wrap_realloc(NULL, ~0ULL);
        fail_unless(p == NULL && errno == EOVERFLOW, "wrap_realloc EOVERFLOW");
        free(p);
    }
}
END_TEST

START_TEST(test_hex)
{
    char dst[5];
    uint8_t bin[2];
    bin2hex((const uint8_t*)"\x5a\x5b", 2, dst, sizeof(dst));
    fail_unless(!strcmp(dst, "5a5b"), "bad hex: %s", dst);

    hex2bin(dst, sizeof(dst)-1, bin, sizeof(bin));
    fail_unless(!memcmp(bin, "\x5a\x5b", 2), "bad hex2bin");
}
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("Misc");
    TCase *tc = tcase_create("alloc");
    suite_add_tcase(s, tc);

    tcase_add_test(tc, test_malloc);
    tcase_add_test(tc, test_realloc);
    tcase_add_test(tc, test_calloc);

    tc = tcase_create("hex");
    suite_add_tcase(s, tc);
    tcase_add_test(tc, test_hex);

    return s;
}
