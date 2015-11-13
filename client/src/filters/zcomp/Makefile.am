if BUILD_ZCOMP

AM_CPPFLAGS = -I $(top_srcdir)/../libsxclient/include -I $(top_srcdir)/../
pkglib_LTLIBRARIES = libsxf_zcomp.la
libsxf_zcomp_la_SOURCES = zcomp.c
libsxf_zcomp_la_LDFLAGS = -module -release 12
libsxf_zcomp_la_LIBADD = @ZCOMP_LIBS@ ../../../../libsxclient/src/libsxclient.la

endif
