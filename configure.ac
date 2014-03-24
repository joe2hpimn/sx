
AC_INIT([sx], [0.2])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

ac_configure_args="$ac_configure_args --enable-shared=libsx,sxclient,sx"
# Check
PKG_CHECK_MODULES([check], [check >= 0.9.4], [has_sys_check=yes],
                  [has_sys_check=no])
ac_configure_args="$ac_configure_args --disable-timeout-tests --disable-agrep"
if test "$has_sys_check" = "no"; then
    AC_CONFIG_SUBDIRS([3rdparty/check])
fi
AM_CONDITIONAL([BUILD_CHECK],[test "$has_sys_check" = "no"])

# Libfcgi
has_sys_fcgi=no
# sys fcgi is buggy on EINTR handling
#AC_CHECK_LIB([fcgi], [FCGX_Accept], [FCGI_LIBS=-lfcgi; has_sys_fcgi="yes"],
#             [has_sys_fcgi="no"])
if test "$has_sys_fcgi" = "no"; then
    AC_CONFIG_SUBDIRS([3rdparty/fcgi])
fi
AM_CONDITIONAL([BUILD_LIBFCGI], [test "$has_sys_fcgi" = "no"])

# Yajl
AC_CHECK_LIB([yajl], [yajl_complete_parse], [YAJL_LIBS=-lyajl; has_sys_yajl="yes"], 
             [has_sys_yajl="no"])
LIBS=$ac_save_LIBS
if test "$has_sys_yajl" = "no"; then
    AC_CONFIG_SUBDIRS([3rdparty/yajl_build])
fi
AM_CONDITIONAL([BUILD_YAJL], [test "$has_sys_yajl" = "no"])

# sxhttpd (nginx)
AC_ARG_ENABLE([sxhttpd],
[  --disable-sxhttpd	  do not build sxhttpd ],
build_sxhttpd=$enableval, build_sxhttpd="yes")
if test "$build_sxhttpd" = "yes"; then
    AC_CONFIG_SUBDIRS([3rdparty/sxhttpd])
fi
AM_CONDITIONAL([BUILD_SXHTTPD], [test "$build_sxhttpd" = "yes"])

AC_CONFIG_SUBDIRS([libsx])
AC_CONFIG_SUBDIRS([client])
AC_CONFIG_SUBDIRS([server])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
