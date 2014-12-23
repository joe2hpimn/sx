all:
	@cd build-nginx; \
	$(MAKE) $(AM_MAKEFLAGS); \
	test "x$$?" != "x0" && exit 1; \
	cd ..

install-exec-local:
	@cd build-nginx; \
	$(MAKE) $(AM_MAKEFLAGS) install; \
	test "x$$?" != "x0" && exit 1; \
	cd ..

clean-local:
	@cd build-nginx; \
	test ! -f Makefile && exit 0; \
	$(MAKE) $(AM_MAKEFLAGS) clean; \
	test "x$$?" != "x0" && exit 1; \
	cd ..

distclean-local:
	@cd build-nginx; \
	test ! -f Makefile && exit 0; \
	$(MAKE) $(AM_MAKEFLAGS) distclean; \
	test "x$$?" != "x0" && exit 1; \
	cd ..; \
	rm -rf build-nginx

uninstall-local:
	@rm -f $(sbindir)/sxhttpd
