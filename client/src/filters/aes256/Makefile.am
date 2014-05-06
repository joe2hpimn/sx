if BUILD_AES256

AM_CPPFLAGS = -I $(top_srcdir)/../libsx/include -I $(top_srcdir)/../
pkglib_LTLIBRARIES = sxf_aes256.la
sxf_aes256_la_SOURCES = aes256.c
sxf_aes256_la_LDFLAGS = -module -release 12
sxf_aes256_la_LIBADD = @AES256_LIBS@ $(top_srcdir)/../libsx/src/libsx.la

endif
