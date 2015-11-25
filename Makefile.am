SUBDIRS=
if BUILD_LIBFCGI
SUBDIRS += 3rdparty/fcgi
endif
if BUILD_SXHTTPD
SUBDIRS += 3rdparty/sxhttpd
endif
if BUILD_YAJL
SUBDIRS += 3rdparty/yajl_build
endif
if BUILD_SQLITE3
SUBDIRS += 3rdparty/libsqlite3
endif
#if BUILD_NGINX_MODULE_VTS
#SUBDIRS += 3rdparty/nginx-module-vts
#endif
EXTRA_DIST=3rdparty/yajl 3rdparty/curl 3rdparty/nginx 3rdparty/fcgi 3rdparty/sxhttpd 3rdparty/yajl_build 3rdparty/nginx-module-vts

SUBDIRS += libsxclient client

if BUILD_SERVER
SUBDIRS += server
endif

DIST_SUBDIRS = $(SUBDIRS)

clean-local:
	rm -f test-suite.log

doc_DATA=README NEWS QUICKSTART UPGRADE
pdf_DATA=doc/manual/manual.pdf
