if BUILD_ZCOMP

AM_CPPFLAGS = -I $(top_srcdir)/../libsxclient/include
pkglib_LTLIBRARIES = libsxf_zcomp.la
libsxf_zcomp_la_SOURCES = zcomp.c
libsxf_zcomp_la_LDFLAGS = -module -release 11
libsxf_zcomp_la_LIBADD = @ZCOMP_LIBS@ ../../../../libsxclient/src/libsxclient.la

endif
