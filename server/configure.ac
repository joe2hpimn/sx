#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([sx], [1.1], [https://bugzilla.skylable.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
dnl for cmdline.c
AH_BOTTOM([#include <unistd.h>])
AM_INIT_AUTOMAKE([foreign -Wall -Werror color-tests parallel-tests subdir-objects])
dnl std-options: TODO: implement --help and --version for all installed programs
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE
AM_PROG_AR
LT_INIT()

AC_CONFIG_SRCDIR([src/common/utils.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.

AC_DEFINE([_XOPEN_SOURCE], [600], [Expose C99, and POSIX.1-2001 + XSI extension])

# We need some BSD extensions (setgroups, struct winsize) that might be hidden by POSIX
AC_DEFINE([_BSD_SOURCE], [1], [BSD extensions])
AC_DEFINE([_DEFAULT_SOURCE], [1], [Keep glibc 2.20+ quiet])

case "$host_os" in
    solaris*)
        # According to AC_USE_SYSTEM_EXTENSIONS this is not safe define on all platforms
        AC_DEFINE([__EXTENSIONS__], [1], [Solaris BSD (and other) extensions])
        ;;
esac

AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
    AC_MSG_ERROR([A C99 compiler is required, for example GCC.])
fi

AM_PROG_CC_C_O
AC_CHECK_PROG([HASMAKE],[${am_make}],[yes],[no])
if test "$HASMAKE" = "no" && test ! -x ${am_make}; then
    AC_MSG_ERROR([Please install 'make'])
fi

do_coverage="no"
if test "x$GCC" = "xyes"; then
    AM_CPPFLAGS=-D_FORTIFY_SOURCE=2

    AX_APPEND_COMPILE_FLAGS([-Wall -Wformat-security -fstack-protector], [AM_CFLAGS])

    dnl Has to be in separate check because it depends on Wformat-security
    AX_APPEND_COMPILE_FLAGS([-Werror=format-security], [AM_CFLAGS],
                            [${AM_CFLAGS}])
    AX_APPEND_COMPILE_FLAGS([-Wno-pointer-sign],[WNPS_CFLAG])
    AX_APPEND_COMPILE_FLAGS([-fno-strict-aliasing],[NOSA_CFLAG])
    AX_APPEND_LINK_FLAGS([-Wl,-z,now -Wl,-z,relro -fstack-protector],
                         [AM_LDFLAGS])

    AX_APPEND_COMPILE_FLAGS([-pedantic], [AM_CFLAGS])
    AC_ARG_ENABLE(coverage, AS_HELP_STRING([--enable-converage],
              [Enable code coverage  testing]),[
               AX_APPEND_COMPILE_FLAGS([--coverage],[AM_CFLAGS])
               AX_APPEND_LINK_FLAGS([--coverage], [AM_LDFLAGS])
               do_coverage="yes"])
fi
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([WNPS_CFLAG])
AC_SUBST([NOSA_CFLAG])
AM_CONDITIONAL([USING_GCC], test "x$GCC" = "xyes")
AM_CONDITIONAL([COVERAGE], test "$do_coverage" = "yes")
# Checks for libraries.

# System libraries that should be available everywhere
AC_SEARCH_LIBS([logf],[m])
ac_save_LIBS=$LIBS
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 0.9], [], [
    AC_CHECK_LIB([crypto], [EVP_DigestInit_ex], [CRYPTO_LIBS=-lcrypto],[
              AC_MSG_ERROR([Please install libssl-dev or openssl-devel])])])
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(CRYPTO_CFLAGS)
LIBS=$ac_save_LIBS

# Libfcgi
FCGI_CPPFLAGS=
AC_CHECK_LIB([fcgi], [FCGX_Accept], [FCGI_LIBS=-lfcgi; has_sys_fcgi="yes"],
             [has_sys_fcgi="no"])
LIBS=$ac_save_LIBS
if test "$has_sys_fcgi" = "no"; then
    FCGI_LIBS=../3rdparty/fcgi/libfcgi/libfcgi.la
    FCGI_CPPFLAGS="-I $srcdir/../3rdparty/fcgi/include -I ../3rdparty/fcgi/include"
fi
AC_SUBST([FCGI_LIBS])
AC_SUBST([FCGI_CPPFLAGS])

# Yajl
YAJL_CPPFLAGS=
AC_CHECK_LIB([yajl], [yajl_complete_parse], [YAJL_LIBS=-lyajl; has_sys_yajl="yes"], 
             [has_sys_yajl="no"])
LIBS=$ac_save_LIBS
if test "$has_sys_yajl" = "no"; then
    YAJL_LIBS="../3rdparty/yajl_build/build/libyajl.la"
    YAJL_CPPFLAGS="-I $srcdir/../3rdparty/yajl_build/build -I ../3rdparty/yajl_build/build"
fi
AC_SUBST([YAJL_CPPFLAGS])
AC_SUBST([YAJL_LIBS])

# hdist reqs
AC_CHECK_LIB([z], [deflateEnd], [HDIST_LIBS=-lz], AC_MSG_ERROR([Please install zlib]))
AC_SUBST([HDIST_LIBS])

dnl resolv.h types (may not included in strict ansi, posix or xopen modes)
AC_CHECK_TYPES([u_char, u_short, u_int, u_long])

dnl check resolver symbols and linkage
AC_DEFUN([AC_CHECK_RESOLVER], [
orig_LIBS="$LIBS"
if test "x$1" != "x"; then
   resolv_LIBS="-l$1"
   LIBS="$resolv_LIBS $orig_LIBS"
   checkingin="$1"
else
   resolv_LIBS=""
   checkingin="c"
fi
AC_MSG_CHECKING([for working resolver in lib$checkingin])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include "$srcdir/../libsx/include/default.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
], [return (int)res_query + (int)dn_skipname;])], [AC_MSG_RESULT([found!]); RESOLV_LIBS="$resolv_LIBS"], [LIBS="$orig_LIBS"; AC_MSG_RESULT([failed]); $2])
LIBS="$orig_LIBS"
])

AC_CHECK_RESOLVER([],[
	AC_CHECK_RESOLVER([resolv],[
		AC_CHECK_RESOLVER([bind],[AC_MSG_ERROR([No suitable resolver API found])])
	])
])
AC_SUBST([RESOLV_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h string.h sys/types.h])
AC_HEADER_ASSERT

# Checks for typedefs, structures, and compiler characteristics.
AC_SYS_LARGEFILE

AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF([off_t])
if test "$ac_cv_sizeof_off_t" != "8"; then
    AC_MSG_WARN([off_t should be 64-bits])
fi
AC_C_BIGENDIAN()

# Checks for library functions.
AC_CHECK_FUNCS([setproctitle memset fdatasync setgroups])

AC_ARG_WITH(system_sqlite3,AC_HELP_STRING([--with-system-sqlite3],
            [Use system SQLite3]))

if test "x$with_system_sqlite3" == "xyes"; then
    PKG_CHECK_MODULES([SQLITE3], [sqlite3 >= 3.8.4.3], [], [
                         AC_MSG_ERROR([System SQLite3 version not found or too old])
                       ])
else
    SQLITE3_CFLAGS="-I $srcdir/../3rdparty/libsqlite3/"
    SQLITE3_LIBS="../3rdparty/libsqlite3/libsqlite3.la"
fi

# sxhttpd (nginx)
AC_ARG_ENABLE([sxhttpd],
[  --disable-sxhttpd	  do not build sxhttpd ],
build_sxhttpd=$enableval, build_sxhttpd="yes")


if test "x$build_sxhttpd" = "xno"; then
    AC_PATH_TOOL(SXHTTPD,nginx, [false],
                 [/usr/sbin:/usr/local/sbin:$PATH])
    if test "$SXHTTPD" = "false"; then
        AC_MSG_ERROR([nginx is required when --disable-sxhttpd is used])
    fi
    GZIP="off"
else
    SXHTTPD="$sbindir/sxhttpd"
    GZIP="on"
fi

AC_SUBST(GZIP)
AC_SUBST(SXHTTPD)

if test "x$prefix" = xNONE; then
    sxfcgi_conf=$ac_default_prefix/etc/sxserver/sxfcgi.conf
else
    sxfcgi_conf=$prefix/etc/sxserver/sxfcgi.conf
fi
AC_SUBST([SXFCGI_CONF], [$sxfcgi_conf])

AC_CONFIG_FILES([Makefile sxscripts/Makefile])
AC_CONFIG_FILES([man/sxadm.8 man/sxadm-node.8 man/sxadm-cluster.8 man/sx.fcgi.8 man/sxfcgi.conf.5 man/sxsim.1 man/sxreport-server.8 man/sxsetup.8 man/sxsetup.conf.5 man/sxdump.8 man/sxserver.8])
AC_OUTPUT

AC_MSG_NOTICE([Summary])
echo "    crypto library: $CRYPTO_LIBS"
MY_STATUS([libfcgi], [$has_sys_fcgi],[$FCGI_CPPFLAGS], [$FCGI_LIBS])
MY_STATUS([yajl], [$has_sys_yajl], [$YAJL_CPPFLAGS], [$YAJL_LIBS])

use_sys_sqlite3="no"
if test "x$with_system_sqlite3" = "xyes"; then
    use_sys_sqlite3="yes"
fi
MY_STATUS([sqlite3],[$use_sys_sqlite3], [$SQLITE3_CFLAGS],[$SQLITE3_LIBS])
cat <<EOF
    Compiler is GCC: $GCC
    Additional CPPFLAGS: $AM_CPPFLAGS
    Additional CFLAGS: $AM_CFLAGS
    Additional LDFLAGS: $AM_LDFLAGS
    Coverage testing: $do_coverage
EOF
if test "$buggy_build" = "1"; then
	AC_MSG_WARN([Your system lacks crucial library functions. The code may compile but the build will not work properly.])
fi

