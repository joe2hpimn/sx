AC_PREREQ([2.68])
AC_INIT([sxhttpd], [1.0])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE

if test "x$prefix" = xNONE; then
  prefix=$ac_default_prefix
fi

dirname=`dirname $0`
absdir=`cd $dirname && pwd`
unset dirname
mkdir -p build-nginx
cd build-nginx
$absdir/../nginx/configure --without-http_proxy_module --without-http_scgi_module --without-http_rewrite_module --with-http_ssl_module --prefix=$prefix --sbin-path=`echo $sbindir`/sxhttpd --error-log-path=stderr --http-log-path=`echo $localstatedir`/log/sxserver/sxhttpd-access.log --pid-path=`echo $localstatedir`/run/sxserver/sxhttpd.pid --lock-path=`echo $localstatedir`/lock/sxserver/sxhttpd.lock --conf-path=`echo $sysconfdir`/sxhttpd.conf --with-ld-opt="$LDFLAGS"
test "x$?" != "x0" && echo "ERROR: Can't configure nginx" && exit 1
cd ..

AC_OUTPUT(Makefile)
