AC_PREREQ([2.68])
AC_INIT([sxhttpd], [1.1])
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
if test "x$nginx_module_vts" = xNONE; then
$absdir/../nginx/configure --without-http_rewrite_module --with-http_ssl_module --prefix=$prefix --sbin-path=`echo $sbindir`/sxhttpd --error-log-path=stderr --http-log-path=`echo $localstatedir`/log/sxserver/sxhttpd-access.log --pid-path=`echo $localstatedir`/run/sxserver/sxhttpd.pid --lock-path=`echo $localstatedir`/lock/sxserver/sxhttpd.lock --conf-path=`echo $sysconfdir`/sxhttpd.conf --with-ld-opt="$LDFLAGS" --with-ipv6
else
$absdir/../nginx/configure --without-http_rewrite_module --with-http_ssl_module --prefix=$prefix --sbin-path=`echo $sbindir`/sxhttpd --error-log-path=stderr --http-log-path=`echo $localstatedir`/log/sxserver/sxhttpd-access.log --pid-path=`echo $localstatedir`/run/sxserver/sxhttpd.pid --lock-path=`echo $localstatedir`/lock/sxserver/sxhttpd.lock --conf-path=`echo $sysconfdir`/sxhttpd.conf --with-ld-opt="$LDFLAGS" --with-ipv6 --add-module=$absdir/../nginx-module-vts
fi
test "x$?" != "x0" && echo "ERROR: Can't configure nginx" && exit 1
cd ..

AC_OUTPUT(Makefile)
