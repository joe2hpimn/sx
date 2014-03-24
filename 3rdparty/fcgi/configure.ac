dnl     $Id: configure.in,v 1.26 2003/01/19 17:19:41 robs Exp $
dnl
dnl     This file is an input file used by the GNU "autoconf" program to
dnl     generate the file "configure", which is run during the build
dnl     to configure the system for the local environment.

AC_INIT(fcgi, 2.4.0)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE
LT_INIT

AM_CONFIG_HEADER(fcgi_config.h)

AC_PROG_CC
AC_PROG_CPP 
AC_PROG_INSTALL 
AC_PROG_LIBTOOL

AC_LANG([C])

AC_CHECK_LIB([nsl],       [gethostbyname])
AC_CHECK_LIB([socket],    [socket]) 

ACX_PTHREAD([THREADED=threaded${EXEEXT}])
AC_SUBST([THREADED])

FCGI_COMMON_CHECKS

AC_REPLACE_FUNCS([strerror])

AC_C_INLINE

#--------------------------------------------------------------------
#  This is a little hokie in that it avoids including config.guess
#  and config.sub in the distribution, but its been working so far.
#  Windows builds don't run configure so we should be safe fixing
#  this to 'unix' (at least for now).
#--------------------------------------------------------------------
AC_PROG_CC_WARNINGS

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libfcgi/Makefile
                ])

AC_OUTPUT
