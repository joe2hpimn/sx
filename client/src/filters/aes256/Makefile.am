if BUILD_AES256

AM_CPPFLAGS = -I $(top_srcdir)/../libsxclient/include -I $(top_srcdir)/../ @VCRYPTO_CFLAGS@
pkglib_LTLIBRARIES = libsxf_aes256.la
libsxf_aes256_la_SOURCES = aes256.c
libsxf_aes256_la_LDFLAGS = -module -release 15
libsxf_aes256_la_LIBADD = ../../../../libsxclient/src/libsxclient.la @VCRYPTO_LIBS@


endif
