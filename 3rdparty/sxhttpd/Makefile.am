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
	@olddir=`pwd`; \
	cd $(top_srcdir)/../nginx; \
	test ! -f Makefile && exit 0; \
	$(MAKE) $(AM_MAKEFLAGS) distclean; \
	test "x$$?" != "x0" && exit 1; \
	cd $(olddir)

uninstall-local:
	@rm -f $(sbindir)/sxhttpd
