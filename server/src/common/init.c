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

#include "init.h"
#include "log.h"
#include "sxproc.h"
#include "utils.h"

sxc_client_t* sx_init(const sxc_logger_t *custom_logger, const char *application, const char *logfile, int log_foreground, int argc, char *argv[])
{
    sxc_client_t *sx;
    log_init(&custom_logger, application ? application : argv[0], logfile, log_foreground);
    sx = sxc_init(src_version(), custom_logger, NULL, NULL);
    if (!sx) {
        CRIT("Cannot initialize SX");
        return NULL;
    }
    sxc_set_verbose(sx, 1);
    if (application) {
        sxprocinit(argc, argv);
        sxsetproctitle(application);
    }
    return sx;
}

void sx_done(sxc_client_t **sx)
{
    sxc_shutdown(*sx, 0);
    *sx = NULL;
    log_done();
    sxprocdone();
}
