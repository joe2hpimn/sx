AM_CPPFLAGS = -I$(top_srcdir)/../yajl/src -Iinclude

libyajl_la_LDFLAGS = -version-info @LIBYAJL_VERSION@ -no-undefined
libyajl_la_CFLAGS=  -fPIC -DPIC

libyajl_la_SOURCES = \
	yajl_version.h \
	$(top_srcdir)/../yajl/src/api/yajl_common.h \
	$(top_srcdir)/../yajl/src/api/yajl_gen.h \
	$(top_srcdir)/../yajl/src/api/yajl_parse.h \
	$(top_srcdir)/../yajl/src/api/yajl_tree.h \
	$(top_srcdir)/../yajl/src/yajl_alloc.c \
	$(top_srcdir)/../yajl/src/yajl_alloc.h \
	$(top_srcdir)/../yajl/src/yajl_buf.c \
	$(top_srcdir)/../yajl/src/yajl_buf.h \
	$(top_srcdir)/../yajl/src/yajl_bytestack.h \
	$(top_srcdir)/../yajl/src/yajl.c \
	$(top_srcdir)/../yajl/src/yajl_encode.c \
	$(top_srcdir)/../yajl/src/yajl_encode.h \
	$(top_srcdir)/../yajl/src/yajl_gen.c \
	$(top_srcdir)/../yajl/src/yajl_lex.c \
	$(top_srcdir)/../yajl/src/yajl_lex.h \
	$(top_srcdir)/../yajl/src/yajl_parser.c \
	$(top_srcdir)/../yajl/src/yajl_parser.h \
	$(top_srcdir)/../yajl/src/yajl_tree.c \
	$(top_srcdir)/../yajl/src/yajl_version.c

noinst_LTLIBRARIES = libyajl.la
