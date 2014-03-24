if BUILD_AES256

AM_CPPFLAGS = -I $(top_srcdir)/../libsx/include
pkglib_LTLIBRARIES = sxf_aes256.la
sxf_aes256_la_SOURCES = aes256.c
sxf_aes256_la_LDFLAGS = -module
sxf_aes256_la_LIBADD = @AES256_LIBS@

endif
