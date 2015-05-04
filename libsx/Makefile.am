ACLOCAL_AMFLAGS = -I m4
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
LIBSX_VERSION=2:0:0

SUBDIRS=
if BUILD_LTDL
SUBDIRS += libltdl
endif
if BUILD_CURL
SUBDIRS += curl-src
endif

EXTRA_DIST=libltdl curl-src
DIST_SUBDIRS=$(SUBDIRS)

include_HEADERS = include/sx.h

AM_CPPFLAGS = -I $(top_srcdir)/include -I $(top_srcdir)/src -I include $(LTDLINCL)
lib_LTLIBRARIES = src/libsx.la
src_libsx_la_SOURCES = \
	include/sx.h \
	include/default.h \
	include/gnuc.h \
	include/types.h \
	include/version.h \
	src/curlevents.c \
	src/curlevents.h \
	src/curlevents-common.h \
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
	src/fileops.h \
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
	src/version.c \
	src/vcrypto.h \
	src/vcryptocurl.h \
	src/crypt_blowfish.c \
	src/crypt_blowfish.h
if BUILD_NFTW
src_libsx_la_SOURCES += \
	src/nftw.c \
	src/sxftw.h
endif
if BUILD_NSS
src_libsx_la_SOURCES += src/nss.c
endif
if BUILD_OPENSSL
src_libsx_la_SOURCES += \
	src/openssl.c\
	src/cert.c \
	src/cert.h
endif

src_libsx_la_LIBADD = @YAJL_LIBS@ @LIBCURL@ @LIBLTDL@ @VCRYPTO_LIBS@
# TODO: only sx_ should be exported not sxi_
src_libsx_la_LDFLAGS = -no-undefined -export-symbols-regex sx.* -version-info $(LIBSX_VERSION)
src_libsx_la_CPPFLAGS = $(AM_CPPFLAGS) @YAJL_CPPFLAGS@ @LIBCURL_CPPFLAGS@ @VCRYPTO_CFLAGS@ \
			-DINFO_CPPFLAGS="\"$(AM_CPPFLAGS) $(CPPFLAGS) @YAJL_CPPFLAGS@ @LIBCURL_CPPFLAGS@ @OPENSSL_CFLAGS@ @NSS_CFLAGS@\""\
			-DINFO_CFLAGS="\"$(AM_CFLAGS) $(CFLAGS)\""\
			-DINFO_LDFLAGS="\"$(AM_LDFLAGS) $(LDFLAGS) @YAJL_LIBS@ @LIBCURL@ @LIBLTDL@ @VCRYPTO_LIBS@\""\
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
	$(AM_V_GEN) \
	    mkdir -p include &&\
	    (VER="$$(cd $(top_srcdir) && LANG=C git describe --exact-match 2>/dev/null)" &&\
	    echo "#define SRC_VERSION \"$$VER\"" >$@) ||\
	    (VER="$$(cd $(top_srcdir) && LANG=C git describe --always --dirty=+ 2>/dev/null)" &&\
	    echo "#define SRC_VERSION \"$$VER\"" >$@) ||\
	    (COMMITVER=$Format:%h$ && test "$$COMMITVER" != "ormat:%h" && \
	    echo "#define SRC_VERSION SRC_DEFAULT_VERSION\".$$COMMITVER\"" >$@) ||\
	    echo "#define SRC_VERSION SRC_DEFAULT_VERSION" >$@

.PHONY: include/extraversion.h.tmp
CLEANFILES = include/extraversion.h include/extraversion.h.tmp

if RUN_LDCONFIG
install-exec-hook:
	test -n "$$DESTDIR" || PATH="$$PATH:/sbin" ldconfig $(libdir) || true;
endif
