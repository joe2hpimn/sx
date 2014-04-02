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
#include <check.h>
#include <stdlib.h>
#include "check_main.h"
#include "log.h"
#include "init.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
SRunner *sr;
int skip_dietests=0;
int main(int argc, char *argv[])
{
    int failed;
    sxc_client_t *sx = server_init(NULL, NULL, NULL, 0, argc, argv);
#ifdef ABS_BUILDDIR
    /* chdir so that tests that use execve() can find
     * the executables */
    if (chdir(ABS_BUILDDIR) == -1) {
        fprintf(stderr,"chdir failed on %s: %s",
                ABS_BUILDDIR, strerror(errno));
        return 2;
    }
#endif

    sr = srunner_create(NULL);
    if (srunner_fork_status(sr))
        skip_dietests = 1;

    srunner_add_suite(sr, test_suite());

    srunner_run_all(sr, CK_NORMAL);

    failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    server_done(&sx);
    return !failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
