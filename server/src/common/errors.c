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
#include "errors.h"
#include <string.h>

const char *rc2str(rc_ty rc)
{
    if (rc > 0)
	return strerror(rc);
    enum sx_error_t e = rc;
    switch (e) {
	case ITER_NO_MORE:
	    return "Iteration ended";
	case OK:
	    return "OK";
	case FAIL_BADBLOCKSIZE:
	    return "Bad blocksize";
	case FAIL_BADREPLICA:
	    return "Bad replica count";
	case FAIL_LOCKED:
	    return "Resource is temporarily locked";
	case FAIL_EINTERNAL:
	    return "Internal error";
	case FAIL_EINIT:
	    return "Initialization failed";
	case FAIL_ETOOMANY:
	    return "Too Many Requests";
    }
    return "Unknown error";
}


int rc2http(rc_ty rc) {
    switch(rc) {

	/* 4xx */
    case EINVAL:
    case FAIL_BADBLOCKSIZE:
    case FAIL_BADREPLICA:
	return 400;

    case EPERM:
	return 403;

    case ENOENT:
	return 404;

    case EEXIST:
    case ENOTEMPTY:
    case FAIL_LOCKED:
	return 409;

    case EOVERFLOW:
    case EMSGSIZE:
	return 413;

    case ENAMETOOLONG:
	return 414;

    case FAIL_ETOOMANY:
	return 429;

	/* 5xx */
    case EFAULT:
    case FAIL_EINIT:
	return 500;

    case ENOMEM:
    case FAIL_EINTERNAL:
	return 503;

    case ENOSPC:
	return 507;

    default:
	return 503;
    }
}
