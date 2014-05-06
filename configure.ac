
AC_INIT([sx], [0.1])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

ac_configure_args="$ac_configure_args --enable-shared=libsx,sxclient,sx"

# Libfcgi
AC_CHECK_LIB([fcgi], [FCGX_Accept], [FCGI_LIBS=-lfcgi; build_libfcgi="no"],
             [build_libfcgi="yes"])

# sxhttpd (nginx)
AC_ARG_ENABLE([sxhttpd],
[  --disable-sxhttpd	  do not build sxhttpd ],
build_sxhttpd=$enableval, build_sxhttpd="yes")

# server (sx.fcgi)
AC_ARG_ENABLE([server],
[  --disable-server	  do not build server ],
build_server=$enableval, build_server="yes")

if test "$build_server" = "no"; then
    build_libfcgi=no
    build_sxhttpd=no
fi

if test "$build_libfcgi" = "yes"; then
    AC_CONFIG_SUBDIRS([3rdparty/fcgi])
fi
AM_CONDITIONAL([BUILD_LIBFCGI], [test "$build_libfcgi" = "yes"])

if test "$build_sxhttpd" = "yes"; then
    AC_CONFIG_SUBDIRS([3rdparty/sxhttpd])
fi
AM_CONDITIONAL([BUILD_SXHTTPD], [test "$build_sxhttpd" = "yes"])

# Yajl
AC_CHECK_LIB([yajl], [yajl_complete_parse], [YAJL_LIBS=-lyajl; has_sys_yajl="yes"], 
             [has_sys_yajl="no"])
LIBS=$ac_save_LIBS
if test "$has_sys_yajl" = "no"; then
    AC_CONFIG_SUBDIRS([3rdparty/yajl_build])
fi
AM_CONDITIONAL([BUILD_YAJL], [test "$has_sys_yajl" = "no"])

AC_CONFIG_SUBDIRS([libsx])
AC_CONFIG_SUBDIRS([client])

if test "$build_server" = "yes"; then
    AC_CONFIG_SUBDIRS([server])
fi
AM_CONDITIONAL([BUILD_SERVER], [test "$build_server" = "yes"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
