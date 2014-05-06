if BUILD_ZCOMP

AM_CPPFLAGS = -I $(top_srcdir)/../libsx/include
pkglib_LTLIBRARIES = sxf_zcomp.la
sxf_zcomp_la_SOURCES = zcomp.c
sxf_zcomp_la_LDFLAGS = -module
sxf_zcomp_la_LIBADD = @ZCOMP_LIBS@ $(top_srcdir)/../libsx/src/libsx.la

endif
