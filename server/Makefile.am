ACLOCAL_AMFLAGS = -I m4 -I /usr/share/aclocal
SUBDIRS = sxscripts
AM_CPPFLAGS += -I $(top_srcdir)/../libsx/include -I $(top_srcdir)/src/common -I $(top_srcdir)/../
SX_CPPFLAGS=-DDEFAULT_FCGI_CFGFILE=\"$(sysconfdir)/sxserver/sxfcgi.conf\"

noinst_LTLIBRARIES = src/common/libcommon.la

noinst_PROGRAMS = test/testfile test/hdist-test test/client-test test/randgen

bin_PROGRAMS = src/tools/sxsim/sxsim
sbin_PROGRAMS = src/fcgi/sx.fcgi src/tools/sxreport-server/sxreport-server src/tools/sxadm/sxadm

src_common_libcommon_la_SOURCES = \
		    src/common/blob.h\
		    src/common/errors.h\
		    src/common/hashfs.h\
		    src/common/hdist.h\
		    src/common/isaac.h\
		    src/common/job_common.h\
		    src/common/log.h\
		    src/common/nodes.h\
		    src/common/sxdbi.h\
		    src/common/utils.h\
		    src/common/clstqry.h\
		    src/common/clstqry.c\
		    src/common/qsort.h \
		    src/common/errors.c\
		    src/common/log.c\
		    src/common/utils.c\
		    src/common/blob.c\
		    src/common/nodes.c\
		    src/common/hdist.c \
		    src/common/hashfs.c \
		    src/common/hashop.h \
		    src/common/hashop.c \
		    src/common/sxdbi.c\
		    src/common/qsort.c \
		    src/common/isaac.c \
		    src/common/sxproc.c \
		    src/common/sxproc.h \
		    src/common/init.c \
		    src/common/init.h

src_common_libcommon_la_LIBADD = @CRYPTO_LIBS@ @HDIST_LIBS@ @SQLITE3_LIBS@ $(top_builddir)/../libsx/src/libsx.la
src_common_libcommon_la_CPPFLAGS = $(AM_CPPFLAGS) @CRYPTO_CFLAGS@ @YAJL_CPPFLAGS@
src_common_libcommon_la_CFLAGS = $(AM_CFLAGS) @SQLITE3_CFLAGS@
src_common_libcommon_la_LIBTOOLFLAGS = $(AM_LIBTOOLFLAGS) --tag=disable-shared

src_fcgi_sx_fcgi_SOURCES = \
		    src/fcgi/fcgi-actions.c \
		    src/fcgi/fcgi-actions.h \
		    src/fcgi/fcgi-actions-cluster.c \
		    src/fcgi/fcgi-actions-cluster.h \
		    src/fcgi/fcgi-actions-volume.c \
		    src/fcgi/fcgi-actions-volume.h \
		    src/fcgi/fcgi-actions-node.c \
		    src/fcgi/fcgi-actions-node.h \
		    src/fcgi/fcgi-actions-block.c \
		    src/fcgi/fcgi-actions-block.h \
		    src/fcgi/fcgi-actions-file.c \
		    src/fcgi/fcgi-actions-file.h \
		    src/fcgi/fcgi-actions-job.c \
		    src/fcgi/fcgi-actions-job.h \
		    src/fcgi/fcgi-actions-user.c \
		    src/fcgi/fcgi-actions-user.h \
		    src/fcgi/fcgi-utils.c \
		    src/fcgi/fcgi-utils.h \
		    src/fcgi/jobmgr.c \
		    src/fcgi/jobmgr.h \
		    src/fcgi/blockmgr.c \
		    src/fcgi/blockmgr.h \
		    src/fcgi/gc.c \
		    src/fcgi/gc.h \
		    src/fcgi/fcgi-server.c \
		    src/fcgi/fcgi-server.h \
		    src/fcgi/cfgfile.c \
		    src/fcgi/cfgfile.h \
		    src/fcgi/cmdline.c \
		    src/fcgi/cmdline.h

src_fcgi_sx_fcgi_CFLAGS = $(AM_CFLAGS) @WNPS_CFLAG@ @SQLITE3_CFLAGS@
src_fcgi_sx_fcgi_LDADD = src/common/libcommon.la @FCGI_LIBS@ @YAJL_LIBS@ @HDIST_LIBS@ @RESOLV_LIBS@
src_fcgi_sx_fcgi_CPPFLAGS = $(AM_CPPFLAGS) @FCGI_CPPFLAGS@ @YAJL_CPPFLAGS@ @CRYPTO_CFLAGS@ $(SX_CPPFLAGS)

src_tools_sxadm_sxadm_SOURCES = \
		    src/tools/sxadm/sxadm.c\
		    src/tools/sxadm/cmd_cluster.c\
		    src/tools/sxadm/cmd_cluster.h\
		    src/tools/sxadm/cmd_node.c\
		    src/tools/sxadm/cmd_node.h\
		    src/tools/sxadm/cmd_main.c\
		    src/tools/sxadm/cmd_main.h
src_tools_sxadm_sxadm_CFLAGS = $(AM_CFLAGS) @WNPS_CFLAG@ @SQLITE3_CFLAGS@
src_tools_sxadm_sxadm_LDADD = src/common/libcommon.la @YAJL_LIBS@
src_tools_sxadm_sxadm_CPPFLAGS = $(AM_CPPFLAGS) @YAJL_CPPFLAGS@

src_tools_sxreport_server_sxreport_server_SOURCES = \
		    src/tools/sxreport-server/sxreport-server.c\
		    src/tools/sxreport-server/anonymize.c\
		    src/fcgi/cfgfile.c\
		    src/fcgi/cfgfile.h\
		    src/tools/sxreport-server/cmd_main.c\
		    src/tools/sxreport-server/cmd_main.h
src_tools_sxreport_server_sxreport_server_CFLAGS = $(AM_CFLAGS) @WNPS_CFLAG@ @SQLITE3_CFLAGS@
src_tools_sxreport_server_sxreport_server_LDADD = src/common/libcommon.la @YAJL_LIBS@ @FCGI_LIBS@ @HDIST_LIBS@
src_tools_sxreport_server_sxreport_server_CPPFLAGS = $(AM_CPPFLAGS) @FCGI_CPPFLAGS@ @CRYPTO_CFLAGS@ @YAJL_CPPFLAGS@ $(SX_CPPFLAGS)\
				       -DINFO_CPPFLAGS="\"$(AM_CPPFLAGS) $(CPPFLAGS) @FCGI_CPPFLAGS@ @CRYPTO_CFLAGS@ @YAJL_CPPFLAGS@\""\
				       -DINFO_CFLAGS="\"$(AM_CFLAGS) $(CFLAGS)\""\
				       -DINFO_LDFLAGS="\"$(AM_LDFLAGS) $(LDFLAGS) @YAJL_LIBS@ @FCGI_LIBS@ @HDIST_LIBS@ @CRYPTO_LIBS@\""\
				       -DINFO_SYSCONFDIR="\"$(sysconfdir)\""\
				       -DINFO_BINDIR="\"$(bindir)\""\
				       -DINFO_LOCALSTATEDIR="\"$(localstatedir)\""\
				       -DINFO_PKGCONFIG="\"@PKG_CONFIG@\""\
				       -DINFO_PKGCONFIG_LIBDIR="\"@PKG_CONFIG_LIBDIR@\""\
				       -DINFO_PKGCONFIG_PATH="\"@PKG_CONFIG_PATH@\""

src_tools_sxsim_sxsim_SOURCES = \
		    src/common/hdist.c \
		    src/common/isaac.c \
		    src/tools/sxsim/sxsim.c\
		    src/tools/sxsim/linenoise.c \
		    src/tools/sxsim/linenoise.h \
		    src/tools/sxsim/cmdline.c\
		    src/tools/sxsim/cmdline.h

src_tools_sxsim_sxsim_CFLAGS = $(AM_CFLAGS) @WNPS_CFLAG@
src_tools_sxsim_sxsim_LDADD = src/common/libcommon.la @CRYPTO_LIBS@ @HDIST_LIBS@
src_tools_sxsim_sxsim_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/common @CRYPTO_CFLAGS@

test_randgen_SOURCES = test/randgen.c test/rgen.h test/rgen.c

test_hdist_test_SOURCES = test/hdist-test.c
test_hdist_test_LDADD = src/common/libcommon.la @HDIST_LIBS@
test_hdist_test_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/common

test_testfile_SOURCES = test/testfile.c

test_client_test_SOURCES = test/client-test.c test/rgen.h test/rgen.c test/client-test-cmdline.h test/client-test-cmdline.c
test_client_test_LDADD = src/common/libcommon.la @HDIST_LIBS@
test_client_test_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/common

check_PROGRAMS = test/printerrno

check_SCRIPTS = test/runvg.sh test/run-nginx-test.sh test/fcgi-test.pl
EXTRA_DIST = $(check_SCRIPTS)
TESTS = test/hdist-test test/run-nginx-test.sh

test_printerrno_SOURCES = test/printerrno.c

check-local:
	if test -f test-suite.log; then ln -sf `pwd`/test-suite.log ../test-suite.log; else :; fi

CLEANFILES = valgrind-test-suite.log valgrind.log test/test-nginx.conf
if COVERAGE
.PHONY: zcov coverage/output.zcov

coverage/output.zcov:
	$(AM_V_at) mkdir -p coverage
	rm -f $@
	$(AM_V_at) find . -name *.gcda -exec rm {} \;
	$(MAKE) check-am
	$(AM_V_GEN) zcov-scan $@  --look-up-dirs=3

coverage/index.html: coverage/output.zcov
	$(AM_V_at) rm -rf coverage/*.html
	$(AM_V_GEN) zcov-genhtml --root=$(PWD) $< coverage/

zcov:	coverage/index.html
	$(AM_V_at) zcov-summarize --root=$(PWD) coverage/output.zcov

clean-local:
	find . \( -name *.gcda -o -name *.gcno \) -exec rm {} \;
	rm -rf coverage
	rm -rf testdb
else
clean-local:
	rm -rf testdb

endif
