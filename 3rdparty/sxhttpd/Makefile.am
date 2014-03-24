all:
	@olddir=`pwd`; \
	cd $(top_srcdir)/../nginx; \
	$(MAKE) $(AM_MAKEFLAGS); \
	test "x$$?" != "x0" && exit 1; \
	cd $(olddir)

install-exec-local:
	@olddir=`pwd`; \
	cd $(top_srcdir)/../nginx; \
	$(MAKE) $(AM_MAKEFLAGS) install; \
	test "x$$?" != "x0" && exit 1; \
	cd $(olddir)

clean-local:
	@olddir=`pwd`; \
	cd $(top_srcdir)/../nginx; \
	test ! -f Makefile && exit 0; \
	$(MAKE) $(AM_MAKEFLAGS) clean; \
	test "x$$?" != "x0" && exit 1; \
	cd $(olddir)

distclean-local:
	@rm -f $(srcdir)/bin/sxserver; \
	rm -f $(srcdir)/bin/sxsetup; \
	rm -f $(srcdir)/logrotate.d/sxserver; \
	rm -f $(srcdir)/sxserver/sxhttpd.conf.default; \
	olddir=`pwd`; \
	cd $(top_srcdir)/../nginx; \
	test ! -f Makefile && exit 0; \
	$(MAKE) $(AM_MAKEFLAGS) distclean; \
	test "x$$?" != "x0" && exit 1; \
	cd $(olddir)

# see Installation-Directory-Variables in the autoconf manual
edit= sed \
      -e 's|@bindir[@]|$(bindir)|g' \
      -e 's|@sbindir[@]|$(sbindir)|g' \
      -e 's|@localstatedir[@]|$(localstatedir)|g' \
      -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
      -e 's|@prefix[@]|$(prefix)|g'

nobase_sysconf_DATA = sxserver/sxhttpd.conf.default sxserver/fastcgi_params sxserver/errors/414.json sxserver/errors/50x.json
nobase_doc_DATA = logrotate.d/sxserver
sbin_SCRIPTS = bin/sxserver bin/sxsetup
sxserver/sxhttpd.conf.default: $(srcdir)/sxserver/sxhttpd.conf.default.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/sxserver/sxhttpd.conf.default.in >$@.tmp
	mv $@.tmp $@
bin/sxserver: $(srcdir)/bin/sxserver.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/bin/sxserver.in >$@.tmp
	mv $@.tmp $@
bin/sxsetup: $(srcdir)/bin/sxsetup.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/bin/sxsetup.in >$@.tmp
	mv $@.tmp $@
logrotate.d/sxserver: $(srcdir)/logrotate.d/sxserver.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/logrotate.d/sxserver.in >$@.tmp
	mv $@.tmp $@

.PHONY:$(sbin_SCRIPTS) sxserver/sxhttpd.conf.default

install-data-local:
	$(MKDIR_P) $(DESTDIR)/$(localstatedir)/lib/sxserver $(DESTDIR)/$(localstatedir)/log/sxserver $(DESTDIR)/$(localstatedir)/run/sxserver

