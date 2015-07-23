#!/bin/sh
set -e
set -x

# update PATH to standard utilities, otherwise if the user changed PATH
# we might miss essential utilities like chown
PATH="`getconf PATH`:$PATH"

# Disable proxies
unset HTTP_PROXY
unset http_proxy
unset HTTPS_PROXY
unset https_proxy

prefix_rel=`mktemp -d sx-test-XXXXXXXX`
prefix="$PWD/$prefix_rel"
cleanup () {
    (cd sxscripts && make clean)
    rm -rf $prefix
}
trap cleanup EXIT INT

# sxadm creates things in $HOME/.sx, make sure its created in a place we can
# clean it up
export HOME=$prefix/home
mkdir $HOME
mkdir -p "$prefix/bin" "$prefix/sbin" "$prefix/etc/sxserver"
mkdir -p "$prefix/var/lib/sxserver" "$prefix/var/log/sxserver" "$prefix/var/run/sxserver"

if [ `uname` = 'SunOS' ]; then
  # doesn't work with GNU make <4.0 but required for non-GNU make
  FLAG=-e
else
  FLAG=
fi
(cd sxscripts && make -s clean && make -s $FLAG prefix="$prefix" sbindir="$prefix/sbin" bindir="$prefix/bin" sysconfdir="$prefix/etc" localstatedir="$prefix/var" install)
(cd sxscripts && make -s clean && make -s)

ln -s `pwd`/../client/src/tools/init/sxinit "$prefix/bin/sxinit"
ln -s `pwd`/src/tools/sxadm/sxadm "$prefix/sbin/sxadm"
ln -s `pwd`/src/fcgi/sx.fcgi "$prefix/sbin/sx.fcgi"
ln -s `pwd`/test/client-test "$prefix/bin/client-test"

built_nginx=`pwd`/../3rdparty/sxhttpd/build-nginx/objs/nginx
rm -f "$prefix/sbin/sxhttpd"
# SXHTTPD has to be overriden when using built-in, but not when using external
# nginx, so just sed
test -x "$built_nginx" && ln -s "$built_nginx" "$prefix/sbin/sxhttpd" && \
    sed -i -e "s|if !.*[$]|if ! $prefix/sbin/sxhttpd $|" "$prefix/sbin/sxserver"

cp "$prefix/etc/sxserver/sxhttpd.conf.default" "$prefix/etc/sxserver/sxhttpd.conf"

SXRUNDIR="$prefix_rel/var/run/sxserver"
SXSTOREDIR="$prefix/var/lib/sxserver"
SXLOGFILE="$prefix/var/log/sxserver/sxfcgi.log"
cat >"$prefix/etc/sxserver/sxfcgi.conf" <<EOF
pidfile="$SXRUNDIR/sxfcgi.pid"
logfile="$SXLOGFILE"
socket="$SXRUNDIR/sxfcgi.socket"
socket-mode=0660
data-dir="$SXSTOREDIR/data"
children=2
EOF
if [ "x$VERBOSE" = "x1" ]; then
    echo debug >>"$prefix/etc/sxserver/sxfcgi.conf"
fi

cat >"$prefix/etc/sxserver/sxsetup.conf" <<EOF
SX_NO_ROOT=1
SX_RUN_DIR="$SXRUNDIR"
SX_LOG_FILE="$SXLOGFILE"
SX_LIB_DIR="$prefix/var/lib/sxserver"
EOF

sed -e "s|^user.*|user `whoami`;|" -e "s|listen .*443|listen 127.0.0.1:8443|g" \
    -e "s|listen .*80|listen 127.0.0.1:8013|g" \
    -e "s|unix:.*|unix:$SXRUNDIR/sxfcgi.socket;|" \
    $prefix/etc/sxserver/sxhttpd.conf >$prefix/etc/sxserver/sxhttpd.conf.1
mv "$prefix/etc/sxserver/sxhttpd.conf.1" "$prefix/etc/sxserver/sxhttpd.conf"

"$prefix/sbin/sxadm" node --new --batch-mode "$SXSTOREDIR/data"
"$prefix/sbin/sxadm" cluster --new --batch-mode --node-dir="$SXSTOREDIR/data" "6G/127.0.0.1" "sx://localhost"

# TODO: sxadm should be more easily scriptable
"$prefix/sbin/sxadm" node --info "$SXSTOREDIR/data" | grep 'Admin key: ' | cut -d\  -f3 >"$SXSTOREDIR/data/admin.key"
chmod 600 "$SXSTOREDIR/data/admin.key"

cleanup () {
    echo "cleaning up"
    "$prefix/sbin/sxserver" stop
    cat "$SXLOGFILE"
    rm -rf $prefix
}
export SX_FCGI_OPTS="--config-file=$prefix/etc/sxserver/sxfcgi.conf"
export SX_HTTPD_OPTS="-c $prefix/etc/sxserver/sxhttpd.conf"
"$prefix/sbin/sxserver" start

trap cleanup EXIT INT

"$prefix/bin/sxinit" --batch-mode --port=8013 --no-ssl --auth-file="$SXSTOREDIR/data/admin.key" --config-dir="$prefix/.sx" sx://localhost
"$prefix/bin/client-test" --config-dir="$prefix/.sx" --filter-dir="`pwd`/../client/src/filters" sx://localhost || {
    cat $prefix/var/log/sxserver/sxhttpd-error.log;
    exit 1
}

perl `dirname $0`/fcgi-test.pl 127.0.0.1:8013 $SXSTOREDIR/data || {
    rc=$?
    cat $prefix/var/log/sxserver/sxhttpd-error.log;
    if [ "$rc" -eq 2 ]; then
        exit 77 # perl dep missing
    fi
    exit 1;
}
