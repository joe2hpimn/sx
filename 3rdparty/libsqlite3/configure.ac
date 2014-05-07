AC_PREREQ([2.68])
AC_INIT([YAJL-build],[2.0.4],[])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE

LIBYAJL_VERSION="$YAJL_MAJOR":"$YAJL_MICRO":"$YAJL_MINOR"

AM_PROG_AR
LT_INIT([disable-shared])
AC_PROG_CC_C99
# Checks for sqlite3 flags.
AC_CHECK_FUNCS([posix_fallocate usleep], [SQLITE3_FLAGS="$SQLITE3_FLAGS [-DHAVE_]AS_TR_CPP($ac_func)[=1]]", [buggy_build=1])
AC_SUBST(SQLITE3_FLAGS)

if test "$buggy_build" = "1"; then
	AC_MSG_WARN([Your system lacks crucial library functions. The code may compile but the build may not work properly.])
fi
AC_OUTPUT([Makefile])
