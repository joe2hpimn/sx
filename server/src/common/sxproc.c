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

#if !HAVE_SETPROCTITLE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "sxproc.h"

extern char **environ;

static int proc_extra_len = 0;
char *self, *argv0, **argv1ptr, **oldenv = NULL;
int self_len;

void sxprocinit(int argc, char **argv) {
    char *last;
    int i, j;

    if(argc <= 0 || proc_extra_len)
	return;

    self = strrchr(argv[0], '/');
    if(!self)
	self = argv[0];
    else
	self++;
    self_len = strlen(self);

    argv0 = last = argv[0];
    argv1ptr = &argv[1];
    for(i=0; i<argc; i++) {
	if(argv[i] != last)
	    break;
	last += strlen(argv[i]) + 1;
    }

    if(last-argv0 < 128 + self_len && environ) {
	for(i=0; environ[i]; i++) {
	    if(environ[i] != last) {
		i = 0;
		break;
	    }
	    last += strlen(environ[i]) + 1;
	}
	if(i) {
	    char **newenv = malloc((i+1) * sizeof(environ[0]) + (last - environ[0]));
	    if(newenv) {
		char *env_data = (char *)&newenv[i+1];
		memcpy(env_data, environ[0], last - environ[0]);
		for(j=0; j<i; j++)
		    newenv[j] = env_data + (environ[j] - environ[0]);
		newenv[j] = NULL;
		oldenv = environ;
		environ = newenv;
	    } else
		last = environ[0];
	}
    }

    last--;
    if(last <= argv0 || last - argv0 <= self_len + 16)
	return;

    proc_extra_len = last - argv0 - self_len;
}

void sxsetproctitle(const char *fmt, ...) {
    va_list ap;

    if(!proc_extra_len)
	return;

    *argv1ptr = NULL;
    if(self != argv0) {
	memmove(argv0, self, self_len);
	self = argv0;
	memset(&argv0[self_len], 0, proc_extra_len);
    }

    argv0[self_len] = ':';
    argv0[self_len + 1] = ' ';

    va_start(ap, fmt);
    vsnprintf(&argv0[self_len + 2], proc_extra_len - 2, fmt, ap);
    va_end(ap);
}

void sxprocdone(void) {
    if(proc_extra_len && oldenv) {
	free(environ);
	environ = oldenv;
	oldenv = NULL;
    }
}

#endif

