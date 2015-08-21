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

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "hashfs.h"
#include "utils.h"
#include "log.h"

static int terminate = 0;

static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}


#define HBEAT_INTERVAL 5.0f

int hbeatmgr(sxc_client_t *sx, const char *dir, int pipe) {
    struct sigaction act;
    sx_hashfs_t *hashfs = NULL;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    act.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);

    hashfs = sx_hashfs_open(dir, sx);
    if(!hashfs) {
	CRIT("Failed to initialize the hash server interface");
	goto hbeat_err;
    }

    DEBUG("Heartbeat manager started");

    while(!terminate) {
	int dc;
        if(wait_trigger(pipe, HBEAT_INTERVAL, NULL))
            break;

	dc = sx_hashfs_distcheck(hashfs);
	if(dc < 0) {
	    CRIT("Failed to reload distribution");
	    goto hbeat_err;
	} else if(dc > 0)
	    INFO("Distribution reloaded");

	DEBUG("Beat!");
	/*********************
	  Do HBEAT stuff here
	**********************/
    }

 hbeat_err:
    /*****************
      DO CLEANUP HERE
    ******************/
    sx_hashfs_close(hashfs);
    
    DEBUG("Heartbeat manager terminated");

    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}

