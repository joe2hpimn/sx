AC_PREREQ([2.68])
AC_INIT([sxhttpd], [1.4.1])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE

if test "x$prefix" = xNONE; then
  prefix=$ac_default_prefix
fi

olddir=$ac_pwd
cd $ac_pwd/../nginx
./configure --without-http_proxy_module --without-http_scgi_module --without-http_uwsgi_module --without-http_rewrite_module --with-http_ssl_module --prefix=$prefix --sbin-path=`echo $sbindir`/sxhttpd --error-log-path=stderr --http-log-path=`echo $localstatedir`/sxserver/sxhttpd-access.log --pid-path=`echo $localstatedir`/run/sxserver/sxhttpd.pid --lock-path=`echo $localstatedir`/lock/sxserver/sxhttpd.lock --conf-path=`echo $sysconfdir`/sxhttpd.conf --with-ld-opt="$LDFLAGS"
test "x$?" != "x0" && echo "ERROR: Can't configure nginx" && exit 1
cd $olddir

AC_OUTPUT(Makefile)
