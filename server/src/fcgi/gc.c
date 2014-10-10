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

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "gc.h"
#include "log.h"
#include "hashfs.h"

static int terminate = 0;

static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}


int gc(sxc_client_t *sx, const char *self, const char *dir, int pipe, int pipe_expire) {
    struct sigaction act;
    sx_hashfs_t *hashfs;
    rc_ty rc;
    struct timeval tv0, tv1, tv2;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    hashfs = sx_hashfs_open(dir, sx);
    if (!hashfs) {
        CRIT("Failed to initialize the hash server interface");
        return EXIT_FAILURE;
    }

    memset(&tv0, 0, sizeof(tv0));
    while(!terminate) {
        int forced_awake = 0, force_expire = 0;
        /* this MUST run periodically even if we don't want to
         * GC any hashes right now */
        if (wait_trigger(pipe, gc_interval, &forced_awake))
            break;
        if (forced_awake)
            INFO("GC triggered by user");
        if (wait_trigger(pipe_expire, 0, &force_expire))
            break;
        if (force_expire)
            INFO("GC force expire is set");
        if (terminate)
            break;

	gettimeofday(&tv1, NULL);
	sx_hashfs_distcheck(hashfs);
        rc = sx_hashfs_gc_periodic(hashfs, &terminate, force_expire ? -1 : GC_GRACE_PERIOD);
        sx_hashfs_checkpoint_gc(hashfs);
        sx_hashfs_checkpoint_passive(hashfs);
	gettimeofday(&tv2, NULL);
	INFO("GC periodic completed in %.1f sec", timediff(&tv1, &tv2));
        if (rc) {
            WARN("GC error: %s", rc2str(rc));
        } else {
            if (terminate)
                break;
            if (!forced_awake)
                sleep(1);
            gettimeofday(&tv1, NULL);
            if (timediff(&tv0, &tv1) > gc_interval || forced_awake) {
                sx_hashfs_gc_run(hashfs, &terminate);
                gettimeofday(&tv2, NULL);
                INFO("GC run completed in %.1f sec", timediff(&tv1, &tv2));
                sx_hashfs_gc_info(hashfs, &terminate);
                memcpy(&tv0, &tv1, sizeof(tv0));
            }
        }
        if (terminate)
            break;
        sx_hashfs_checkpoint_gc(hashfs);
        sx_hashfs_checkpoint_passive(hashfs);
    }
    sx_hashfs_close(hashfs);

    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}
