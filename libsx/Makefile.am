ACLOCAL_AMFLAGS = -I m4

SUBDIRS = libltdl
if BUILD_CURL
SUBDIRS += ../3rdparty/curl
endif
DIST_SUBDIRS=$(SUBDIRS)

AM_CPPFLAGS = -I $(top_srcdir)/include -I $(top_srcdir)/src $(LTDLINCL)
lib_LTLIBRARIES = src/libsx.la
src_libsx_la_SOURCES = \
	include/sx.h \
	include/default.h \
	include/gnuc.h \
	include/types.h \
	src/cert.c \
	src/cert.h \
	src/curlevents.c \
	src/curlevents.h \
	src/cluster.c \
	src/cluster.h \
	src/hostlist.c \
	src/hostlist.h \
	src/clustcfg.c \
	src/clustcfg.h \
	src/yajlwrap.c \
	src/yajlwrap.h \
	src/misc.c \
	src/misc.h \
	src/fileops.c \
	src/volops.c \
	src/volops.h \
	src/jobpoll.c \
	src/jobpoll.h \
	src/libsx.c \
	src/libsx-int.h \
	src/filter.c \
	src/filter.h \
	src/sxlog.h \
	src/sxlog.c \
	src/sxproto.h \
	src/sxproto.c \
	src/sxreport.h \
	src/sxreport.c \
	src/version.c

src_libsx_la_LIBADD = @YAJL_LIBS@ @LIBCURL@ @CRYPTO_LIBS@ @LIBLTDL@ -lssl
# TODO: only sx_ should be exported not sxi_
src_libsx_la_LDFLAGS = -no-undefined -export-symbols-regex sx.*
src_libsx_la_CPPFLAGS = $(AM_CPPFLAGS) @YAJL_CPPFLAGS@ @LIBCURL_CPPFLAGS@ @CRYPTO_CFLAGS@ \
			-DINFO_CPPFLAGS="\"$(AM_CPPFLAGS) $(CPPFLAGS) @FCGI_CPPFLAGS@ @CRYPTO_CFLAGS@ @YAJL_CPPFLAGS@\""\
			-DINFO_CFLAGS="\"$(AM_CFLAGS) $(CFLAGS)\""\
			-DINFO_LDFLAGS="\"$(AM_LDFLAGS) $(LDFLAGS) @YAJL_LIBS@ @FCGI_LIBS@ @CRYPTO_LIBS@\""\
			-DINFO_SYSCONFDIR="\"$(sysconfdir)\""\
			-DINFO_BINDIR="\"$(bindir)\""\
			-DINFO_LOCALSTATEDIR="\"$(localstatedir)\""\
			-DINFO_PKGCONFIG="\"@PKG_CONFIG@\""\
			-DINFO_PKGCONFIG_LIBDIR="\"@PKG_CONFIG_LIBDIR@\""\
			-DINFO_PKGCONFIG_PATH="\"@PKG_CONFIG_PATH@\""

BUILT_SOURCES = include/extraversion.h
include/extraversion.h: include/extraversion.h.tmp
	$(AM_V_at) (test -f $@ && cmp -s include/extraversion.h.tmp $@) || mv include/extraversion.h.tmp $@

#if exported via git archvie the COMMITVER is a commit hash otherwise it is a meaningless 'ormat:%h'
include/extraversion.h.tmp:
	$(AM_V_GEN) LANG=C \
	    VER="$$(cd $(top_srcdir) && git describe --always --dirty=+ 2>/dev/null)" &&\
	    echo "#define SRC_EXTRA_VERSION \".$$VER\"" >$@ ||\
	    (COMMITVER=$Format:%h$ && test "$$COMMITVER" != "ormat:%h" && \
	    echo "#define SRC_EXTRA_VERSION \".$$COMMITVER\"" >$@) ||\
	    echo "#define SRC_EXTRA_VERSION \"\"" >$@

.PHONY: include/extraversion.h.tmp
CLEANFILES = include/extraversion.h include/extraversion.h.tmp

install-exec-hook:
	test -n "$$DESTDIR" || PATH="$$PATH:/sbin" ldconfig $(libdir) || true;
