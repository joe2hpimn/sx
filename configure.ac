
AC_INIT([sx], [0.9])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

ac_configure_args="$ac_configure_args --enable-shared=libsx,sxclient,sx"


AC_ARG_WITH([system_libs],AC_HELP_STRING([--with-system-libs],
            [Use system libraries for everything]))

if test "x$with_system_libs" = "xyes"; then
    ac_configure_args="$ac_configure_args --without-included-libltdl --with-system-sqlite3"
    with_system_sqlite3="yes"
fi

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
    if test "x$with_system_libs" = "xyes"; then
        AC_MSG_ERROR([Cannot use system libfcgi])
    fi
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
    if test "x$with_system_libs" = "xyes"; then
        AC_MSG_ERROR([Cannot use system libyajl])
    fi
    AC_CONFIG_SUBDIRS([3rdparty/yajl_build])
fi
AM_CONDITIONAL([BUILD_YAJL], [test "$has_sys_yajl" = "no"])

AC_ARG_WITH(system_sqlite3, AC_HELP_STRING([--with-system-sqlite3],
            [Use system SQLite3]))

build_sqlite3="yes"
if test "x$with_system_sqlite3" = "xyes"; then
    build_sqlite3="no"
else
    AC_CONFIG_SUBDIRS([3rdparty/libsqlite3])
fi

AM_CONDITIONAL([BUILD_SQLITE3], [test "$build_sqlite3" = "yes"])

AC_SUBST(SQLITE3_LIBS)
AC_SUBST(SQLITE3_CFLAGS)

AC_CONFIG_SUBDIRS([libsx])
AC_CONFIG_SUBDIRS([client])

if test "$build_server" = "yes"; then
    AC_CONFIG_SUBDIRS([server])
fi
AM_CONDITIONAL([BUILD_SERVER], [test "$build_server" = "yes"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
