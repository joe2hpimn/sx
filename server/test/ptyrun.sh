#!/usr/bin/env python
import pty, os, sys
(sysname,nodename,release,version,machine)=os.uname()
if sysname == "OpenBSD":
	# pty.spawn broken
	os.execlp(sys.argv[1],*sys.argv[1:])
else:
	pty.spawn(sys.argv[1:])
