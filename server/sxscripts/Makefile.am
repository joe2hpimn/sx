# see Installation-Directory-Variables in the autoconf manual
edit= sed \
      -e 's|@bindir[@]|$(bindir)|g' \
      -e 's|@sbindir[@]|$(sbindir)|g' \
      -e 's|@localstatedir[@]|$(localstatedir)|g' \
      -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
      -e 's|@prefix[@]|$(prefix)|g' \
      -e 's|@SXHTTPD[@]|$(SXHTTPD)|g'

nobase_sysconf_DATA = sxserver/sxhttpd.conf.default sxserver/fastcgi_params sxserver/errors/414.json sxserver/errors/50x.json
nobase_doc_DATA = logrotate.d/sxserver
sbin_SCRIPTS = sbin/sxserver sbin/sxsetup
CLEANFILES=$(sbin_SCRIPTS) $(nobase_doc_DATA) sxserver/sxhttpd.conf.default
EXTRA_DIST=sbin/sxserver.in sbin/sxsetup.in logrotate.d/sxserver.in sxserver/sxhttpd.conf.default.in sxserver/fastcgi_params sxserver/errors/414.json sxserver/errors/50x.json
sxserver/sxhttpd.conf.default: $(srcdir)/sxserver/sxhttpd.conf.default.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/sxserver/sxhttpd.conf.default.in >$@.tmp
	mv $@.tmp $@
sbin/sxserver: $(srcdir)/sbin/sxserver.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/sbin/sxserver.in >$@.tmp
	mv $@.tmp $@
sbin/sxsetup: $(srcdir)/sbin/sxsetup.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/sbin/sxsetup.in >$@.tmp
	mv $@.tmp $@
logrotate.d/sxserver: $(srcdir)/logrotate.d/sxserver.in Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/logrotate.d/sxserver.in >$@.tmp
	mv $@.tmp $@
install-data-local:
	$(MKDIR_P) $(DESTDIR)/$(localstatedir)/lib/sxserver $(DESTDIR)/$(localstatedir)/log/sxserver $(DESTDIR)/$(localstatedir)/run/sxserver
