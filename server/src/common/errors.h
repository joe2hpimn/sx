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

#ifndef ERRORS_H
#define ERRORS_H
#include "log.h"

enum sx_error_t {
  /* not an actual error code, used to signal the end of an iteration */
  ITER_NO_MORE = -3000,
  /* Resource is temporary locked */
  FAIL_LOCKED,
  /* Blocksize is not one of the supported ones */
  FAIL_BADBLOCKSIZE,
  /* Replica less than 1 or greater than the number of nodes in the cluster */
  FAIL_BADREPLICA,
  FAIL_EINTERNAL,/* generic error */
  FAIL_EINIT,/* some initialization failed */
  FAIL_ETOOMANY, /* Used by rate limiting code */
  OK = 0
};

typedef int rc_ty;
/* 0 = SUCCESS
 * >0: errno values
 * <0: our own error codes from the enum above
 */

const char *rc2str(rc_ty rc);
int rc2http(rc_ty rc);

#endif
