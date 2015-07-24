#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([sxclient], [1.2], [https://bugzilla.skylable.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
dnl for cmdline.c
AH_BOTTOM([#include <unistd.h>])
AM_INIT_AUTOMAKE([foreign -Wall -Werror color-tests parallel-tests std-options subdir-objects])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE
AC_DISABLE_STATIC
AM_PROG_AR

LT_INIT([disable-static])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_DEFINE([_XOPEN_SOURCE], [600], [Expose C99, and POSIX.1-2001 + XSI extension])

AC_PROG_CC_C99
#if test "$ac_cv_prog_cc_c89" = "no"; then
#    AC_MSG_ERROR([A C89 compiler is required, for example GCC.])
#fi

AC_CHECK_PROG([HASMAKE],[${am_make}],[yes],[no])
if test "$HASMAKE" = "no" && test ! -x ${am_make}; then
    AC_MSG_ERROR([Please install 'make'])
fi

# zlib
AC_CHECK_LIB([z], [deflateEnd], [ZCOMP_LIBS="-lz"; have_zlib="yes"])
AC_SUBST([ZCOMP_LIBS])
AM_CONDITIONAL([BUILD_ZCOMP], [test "$have_zlib" = "yes"])

# libcrypto
ac_save_LIBS=$LIBS
PKG_CHECK_MODULES([OPENSSL], [libssl], [have_crypto="yes"], [
    AC_CHECK_LIB([crypto], [HMAC_Update], [OPENSSL_LIBS="-lcrypto -lssl"; have_crypto="yes"])])
LIBS=$ac_save_LIBS
AM_CONDITIONAL([BUILD_AES256], [test "$have_crypto" = "yes"])
AC_CACHE_CHECK([whether HMAC_Update returns int], ac_cv_type_HMAC_update,
[AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([#include <openssl/hmac.h>
    ],[return HMAC_Update(NULL, NULL, 0) == 1;])],
    [ac_cv_type_HMAC_update=yes],
    [ac_cv_type_HMAC_update=no])
])
if test "$ac_cv_type_HMAC_update" = "yes"; then
    AC_DEFINE([HMAC_UPDATE_RETURNS_INT], 1, [Defined if HMAC_Update returns int])
fi
VCRYPTO_LIBS="$OPENSSL_LIBS"
VCRYPTO_CFLAGS="$OPENSSL_CFLAGS"
AC_SUBST(VCRYPTO_LIBS)
AC_SUBST(VCRYPTO_CFLAGS)

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h string.h sys/types.h])
AC_HEADER_ASSERT

# Checks for typedefs, structures, and compiler characteristics.
AC_SYS_LARGEFILE

AC_C_INLINE

AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_C_BIGENDIAN()

do_coverage="no"
AC_ARG_ENABLE(coverage, AS_HELP_STRING([--enable-converage],
              [Enable code coverage  testing]),
              [CFLAGS="$CFLAGS --coverage"; LDFLAGS="$LDFLAGS --coverage";
               do_coverage="yes"])
AM_CONDITIONAL([COVERAGE], test "$do_coverage" = "yes")

# Checks for library functions.
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([isatty])

if test "x$GCC" = "xyes"; then
    AX_APPEND_COMPILE_FLAGS([-pedantic -Wall -Wformat-security -fstack-protector], [AM_CFLAGS])
    dnl Has to be in separate check because it depends on Wformat-security
    AX_APPEND_COMPILE_FLAGS([-Werror=format-security], [AM_CFLAGS],
                            [${AM_CFLAGS}])
    AX_APPEND_COMPILE_FLAGS([-Wno-pointer-sign],[WNPS_CFLAG])
    AX_APPEND_LINK_FLAGS([-Wl,-z,now -Wl,-z,relro -fstack-protector],
                         [AM_LDFLAGS])
fi
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

if test "x$prefix" = xNONE; then
  filter_dir=$ac_default_prefix/lib/$PACKAGE
else
  filter_dir=$prefix/lib/$PACKAGE
fi
AC_SUBST([SX_FILTER_DIR], [$filter_dir])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([man/sxacl.1 man/sxacl-useradd.1 man/sxacl-userclone.1 man/sxacl-userdel.1 man/sxacl-userlist.1 man/sxacl-usermod.1 man/sxacl-usergetkey.1 man/sxacl-usernewkey.1 man/sxacl-volperm.1 man/sxacl-volshow.1 man/sxacl-whoami.1 man/sxcat.1 man/sxrm.1 man/sxls.1 man/sxmv.1 man/sxcp.1 man/sxinit.1 man/sxreport-client.1 man/sxvol.1 man/sxvol-create.1 man/sxvol-modify.1 man/sxvol-remove.1 man/sxvol-filter.1 man/sxrev.1 man/sxrev-list.1 man/sxrev-copy.1 man/sxrev-delete.1])
AC_CONFIG_FILES([src/filters/attribs/Makefile])
AC_CONFIG_FILES([src/filters/zcomp/Makefile])
AC_CONFIG_FILES([src/filters/aes256/Makefile])
AC_CONFIG_FILES([src/filters/undelete/Makefile])
AC_OUTPUT
