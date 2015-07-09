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
#include <stdlib.h>
#include <string.h>

#include "fcgi-actions-job.h"
#include "fcgi-utils.h"

#include "job_common.h"

void fcgi_job_result(void) {
    char *eon;
    job_t job;;
    job_status_t status;
    const char *message;

    if(strlen(path) >= UUID_STRING_SIZE + 2) {
	/* New request id format */
	sx_uuid_t emitter;
	char uuidstr[sizeof(emitter.string)];
	rc_ty s;

	if(path[UUID_STRING_SIZE] != ':')
	    quit_errmsg(404, "Invalid request id");

	memcpy(uuidstr, path, UUID_STRING_SIZE);
	uuidstr[UUID_STRING_SIZE] = '\0';

	if(uuid_from_string(&emitter, uuidstr))
	    quit_errmsg(404, "Invalid request id");

	if((s = sx_hashfs_self_uuid(hashfs, &emitter)))
	    quit_errmsg(404, "Invalid request id");

	if(strcmp(uuidstr, emitter.string))
	    quit_errmsg(404, "Invalid request id");

	job = strtoll(path + UUID_STRING_SIZE + 1, &eon, 10);
    } else /* Legacy request id format */
	job = strtoll(path, &eon, 10);
    if(*eon || job == JOB_FAILURE)
	quit_errmsg(404, "Invalid request id");

    switch(sx_hashfs_job_result(hashfs, job, has_priv(PRIV_ADMIN) ? 0 : uid, &status, &message)) {
    case OK:
	break;
    case ENOENT:
	quit_errmsg(404, "Request not found");
    default:
	quit_errmsg(500, msg_get_reason());
    }

    CGI_PUTS("Content-type: application/json\r\n\r\n{\"requestId\":");
    json_send_qstring(path);
    CGI_PRINTF(",\"requestStatus\":\"%s\",\"requestMessage\":", (status != JOB_OK ? (status == JOB_ERROR ? "ERROR" : "PENDING") : "OK"));
    json_send_qstring(message);
    CGI_PUTS("}");
}
