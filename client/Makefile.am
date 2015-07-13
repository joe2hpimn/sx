ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/filters/zcomp src/filters/attribs src/filters/aes256 src/filters/undelete

AM_CPPFLAGS = -I $(top_srcdir)/../libsxclient/include -I ../libsxclient/include -I $(top_srcdir)/../ -I $(top_srcdir)/src/common -DSX_FILTER_DIR=\"$(pkglibdir)\"

EXTRA_DIST = man/*.in
man_MANS = man/sxacl.1 man/sxacl-useradd.1 man/sxacl-userclone.1 man/sxacl-userdel.1 man/sxacl-userlist.1 man/sxacl-usermod.1 man/sxacl-usergetkey.1 man/sxacl-usernewkey.1 man/sxacl-volperm.1 man/sxacl-volshow.1 man/sxacl-whoami.1 man/sxcat.1 man/sxrm.1 man/sxls.1 man/sxmv.1 man/sxcp.1 man/sxinit.1 man/sxreport-client.1 man/sxvol.1 man/sxvol-create.1 man/sxvol-modify.1 man/sxvol-remove.1 man/sxvol-filter.1 man/sxrev.1 man/sxrev-list.1 man/sxrev-copy.1 man/sxrev-delete.1

bin_PROGRAMS = src/tools/init/sxinit src/tools/ls/sxls src/tools/mv/sxmv src/tools/cp/sxcp src/tools/cat/sxcat src/tools/vol/sxvol src/tools/acl/sxacl src/tools/sxreport-client/sxreport-client src/tools/rm/sxrm src/tools/rev/sxrev

src_tools_init_sxinit_SOURCES = \
	src/tools/init/sxinit.c \
	src/tools/init/cmdline.c \
	src/tools/init/cmdline.h
src_tools_init_sxinit_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_sxreport_client_sxreport_client_SOURCES = \
	src/tools/sxreport-client/sxreport-client.c \
	src/tools/sxreport-client/cmdline.c \
	src/tools/sxreport-client/cmdline.h
src_tools_sxreport_client_sxreport_client_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la
src_tools_sxreport_client_sxreport_client_CPPFLAGS = $(AM_CPPFLAGS)\
			-DINFO_CPPFLAGS="\"$(CPPFLAGS)\""\
			-DINFO_CFLAGS="\"$(AM_CFLAGS) $(CFLAGS)\""\
			-DINFO_LDFLAGS="\"$(AM_LDFLAGS) $(LDFLAGS)\""\
			-DINFO_SYSCONFDIR="\"$(sysconfdir)\""\
			-DINFO_BINDIR="\"$(bindir)\""\
			-DINFO_LOCALSTATEDIR="\"$(localstatedir)\""


src_tools_ls_sxls_SOURCES = \
	src/tools/ls/sxls.c \
	src/tools/ls/cmdline.c \
	src/tools/ls/cmdline.h
src_tools_ls_sxls_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_mv_sxmv_SOURCES = \
	src/tools/mv/sxmv.c \
	src/tools/mv/cmdline.c \
	src/tools/mv/cmdline.h
src_tools_mv_sxmv_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_cp_sxcp_SOURCES = \
	src/tools/cp/sxcp.c \
	src/tools/cp/cmdline.c \
	src/tools/cp/cmdline.h
src_tools_cp_sxcp_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_cat_sxcat_SOURCES = \
	src/tools/cat/sxcat.c \
	src/tools/cat/cmdline.c \
	src/tools/cat/cmdline.h
src_tools_cat_sxcat_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_vol_sxvol_SOURCES = \
	src/tools/vol/sxvol.c \
	src/tools/vol/cmd_main.c \
	src/tools/vol/cmd_main.h \
	src/tools/vol/cmd_create.c \
	src/tools/vol/cmd_create.h \
	src/tools/vol/cmd_remove.c \
	src/tools/vol/cmd_remove.h \
	src/tools/vol/cmd_filter.c \
	src/tools/vol/cmd_filter.h \
	src/tools/vol/cmd_modify.c \
	src/tools/vol/cmd_modify.h

src_tools_vol_sxvol_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_acl_sxacl_SOURCES = \
	src/tools/acl/sxacl.c \
	src/tools/acl/cmd_main.c \
	src/tools/acl/cmd_whoami.c \
	src/tools/acl/cmd_volperm.c \
	src/tools/acl/cmd_volshow.c \
	src/tools/acl/cmd_useradd.c \
	src/tools/acl/cmd_userclone.c \
	src/tools/acl/cmd_userdel.c \
	src/tools/acl/cmd_userlist.c \
	src/tools/acl/cmd_usergetkey.c \
	src/tools/acl/cmd_usernewkey.c \
	src/tools/acl/cmd_usermod.c \
	src/tools/acl/cmd_main.h \
	src/tools/acl/cmd_whoami.h \
	src/tools/acl/cmd_volperm.h \
	src/tools/acl/cmd_volshow.h \
	src/tools/acl/cmd_useradd.h \
	src/tools/acl/cmd_userclone.h \
	src/tools/acl/cmd_userdel.h \
	src/tools/acl/cmd_userlist.h \
	src/tools/acl/cmd_usergetkey.h \
	src/tools/acl/cmd_usernewkey.h \
	src/tools/acl/cmd_usermod.h
src_tools_acl_sxacl_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_rm_sxrm_SOURCES = \
	src/tools/rm/sxrm.c \
	src/tools/rm/cmdline.c \
	src/tools/rm/cmdline.h

src_tools_rm_sxrm_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la

src_tools_rev_sxrev_SOURCES = \
        src/common/bcrumbs.h \
	src/tools/rev/sxrev.c \
	src/tools/rev/cmd_main.c \
	src/tools/rev/cmd_main.h \
	src/tools/rev/cmd_list.c \
	src/tools/rev/cmd_list.h \
	src/tools/rev/cmd_copy.c \
	src/tools/rev/cmd_copy.h \
	src/tools/rev/cmd_delete.c \
	src/tools/rev/cmd_delete.h

src_tools_rev_sxrev_LDADD = $(top_builddir)/../libsxclient/src/libsxclient.la
