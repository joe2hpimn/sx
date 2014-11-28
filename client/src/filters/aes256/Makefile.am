if BUILD_AES256

AM_CPPFLAGS = -I $(top_srcdir)/../libsx/include -I $(top_srcdir)/../
pkglib_LTLIBRARIES = libsxf_aes256.la
libsxf_aes256_la_SOURCES = aes256.c crypt_blowfish.c crypt_blowfish.h
libsxf_aes256_la_LDFLAGS = -module -release 13
libsxf_aes256_la_LIBADD = @AES256_LIBS@ $(top_srcdir)/../libsx/src/libsx.la

endif
