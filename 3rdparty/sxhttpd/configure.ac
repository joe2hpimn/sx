AC_PREREQ([2.68])
AC_INIT([sxhttpd], [1.4.1])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE

if test "x$prefix" != xNONE; then
  sx_prefix=$prefix
else
  sx_prefix=$ac_default_prefix
fi

olddir=$ac_pwd
cd $ac_pwd/../nginx
./configure --without-http_proxy_module --without-http_scgi_module --without-http_uwsgi_module --without-http_rewrite_module --with-http_ssl_module --prefix=$sx_prefix --sbin-path=$sx_prefix/sbin/sxhttpd --error-log-path=stderr --http-log-path=$sx_prefix/var/log/sxserver/sxhttpd-access.log --pid-path=$sx_prefix/var/run/sxserver/sxhttpd.pid --lock-path=$sx_prefix/var/lock/sxserver/sxhttpd.lock --conf-path=$sx_prefix/etc/sxhttpd.conf --with-ld-opt="$LDFLAGS"
test "x$?" != "x0" && echo "ERROR: Can't configure nginx" && exit 1
cd $olddir

AC_OUTPUT(Makefile)
