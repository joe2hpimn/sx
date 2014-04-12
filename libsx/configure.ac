AC_PREREQ([2.68])
AC_INIT([libsx], [0.1], [https://bugzilla.skylable.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror color-tests parallel-tests std-options subdir-objects])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE
AC_DISABLE_STATIC
AM_PROG_AR

AC_CONFIG_SRCDIR([src/libsx.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# libtool/ltdl
LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([disable-static dlopen])
LTDL_INIT([recursive])
AC_CONFIG_FILES([libltdl/Makefile])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_DEFINE([_XOPEN_SOURCE], [600], [Expose C99, and POSIX.1-2001 + XSI extension])

AC_DEFINE([_BSD_SOURCE], [], [OpenBSD won''t expose some POSIX.1 definitions unless this is used])

AC_PROG_CC_C99
#if test "$ac_cv_prog_cc_c89" = "no"; then
#    AC_MSG_ERROR([A C89 compiler is required, for example GCC.])
#fi

AC_CHECK_PROG([HASMAKE],[${am_make}],[yes],[no])
if test "$HASMAKE" = "no" && test ! -x ${am_make}; then
    AC_MSG_ERROR([Please install 'make'])
fi

ac_save_LIBS=$LIBS
YAJL_CPPFLAGS=
AC_CHECK_LIB([yajl], [yajl_complete_parse], [YAJL_LIBS=-lyajl; has_sys_yajl="yes"], 
             [has_sys_yajl="no"])
LIBS=$ac_save_LIBS
if test "$has_sys_yajl" = "no"; then
    YAJL_LIBS="../3rdparty/yajl_build/build/libyajl.la -lm"
    YAJL_CPPFLAGS="-I ../3rdparty/yajl_build/build"
fi
AC_SUBST([YAJL_CPPFLAGS])
AC_SUBST([YAJL_LIBS])


ac_save_LIBS=$LIBS
PKG_CHECK_MODULES([CRYPTO], [libcrypto], [], [
    AC_CHECK_LIB([crypto], [HMAC_Update], [CRYPTO_LIBS=-lcrypto],[
              AC_MSG_ERROR([Please install libssl-dev or openssl-devel])])])
LIBS=$ac_save_LIBS
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

AC_CACHE_CHECK([for nftw], ac_cv_have_nftw,
[AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([
#define _XOPEN_SOURCE 600
#include <ftw.h>
],[void *ptr = (void *)nftw;])],
	[ac_cv_have_nftw=yes],
	[ac_cv_have_nftw=no])
])
if test "$ac_cv_have_nftw" = "yes"; then
    AC_DEFINE(HAVE_NFTW)
fi
AM_CONDITIONAL([BUILD_NFTW], [test "$ac_cv_have_nftw" = "no"])

LIBCURL_CHECK_CONFIG([], [], [], [build_curl=yes])
AC_MSG_CHECKING([whether curl is built with OpenSSL support])
ac_save_CPPFLAGS="$CPPFLAGS"
LIBS="$LIBCURL $ac_save_LIBS"
CPPFLAGS="$LIBCURL_CPPFLAGS $ac_save_CPPFLAGS"
AC_RUN_IFELSE([AC_LANG_PROGRAM([
    #include <curl/curl.h>
    #include <stdio.h>
    static CURLcode sslctxfun(CURL *curl, void *sslctx, void *parm) { return CURLE_OK; }
], [
        CURL *curl;
        curl_version_info_data *data;
        CURLcode rc = curl_global_init(CURL_GLOBAL_ALL);
        if (rc != CURLE_OK) {
            fprintf(stderr,"Cannot initialize curl: %d\n", rc);
            return 1;
        }
        data = curl_version_info(CURLVERSION_NOW);
        if (data) {
            printf("Curl SSL version: %s\n", data->ssl_version);
        }
        curl = curl_easy_init();
        if (!curl) {
            fprintf(stderr,"Cannot create curl handle\n");
            return 1;
        }
        rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
        if (rc != CURLE_OK) {
            fprintf(stderr,"Cannot set SSL context function: %s\nIs curl built with OpenSSL?\n", curl_easy_strerror(rc));
            return 1;
        }
        curl_easy_cleanup(curl);
        return 0;
])],[build_curl=no],[build_curl=yes],[build_curl=yes])
CPPFLAGS="$ac_save_CPPFLAGS"
LIBS="$ac_save_LIBS"
AC_CHECK_LIB([idn],[idn_free],[config_idn='--with-idn';link_idn='-lidn'],[config_idn='';link_idn=''])
ac_configure_args="$ac_configure_args --with-zlib $with_idn --with-pic --disable-shared --with-ssl --without-libssh2 --without-librtmp --without-nghttp2 --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smtp --disable-gopher"
if test "$build_curl" = "yes"; then
    LIBCURL="../3rdparty/curl/lib/libcurl.la $link_idn -lz"
    LIBCURL_CPPFLAGS="-I../3rdparty/curl/include"
    AC_CONFIG_SUBDIRS([../3rdparty/curl])
fi
AM_CONDITIONAL([BUILD_CURL], [test "$build_curl" = "yes"])

AC_SUBST(CURL_LIBS)
AC_SUBST(YAJL_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(CRYPTO_CFLAGS)

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
