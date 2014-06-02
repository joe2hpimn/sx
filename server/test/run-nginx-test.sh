#!/bin/sh
set -e
set -x

# reset PATH to standard utilities, otherwise if the user changed PATH
# we might miss essential utilities like chown
PATH=`getconf PATH`

prefix=`mktemp -d $PWD/sx-test-XXXXXXXX`
cleanup () {
    rm -rf $prefix
}
trap cleanup EXIT INT

# sxadm creates things in $HOME/.sx, make sure its created in a place we can
# clean it up
export HOME=$prefix/home
mkdir $HOME
mkdir -p "$prefix/bin" "$prefix/sbin" "$prefix/etc/sxserver"
mkdir -p "$prefix/var/lib/sxserver" "$prefix/var/log/sxserver" "$prefix/var/run/sxserver"

edit () {
    sed \
        -e "s|@bindir@|$prefix/bin|g" \
        -e "s|@sbindir@|$prefix/sbin|g" \
        -e "s|@localstatedir@|$prefix/var|g" \
        -e "s|@sysconfdir@|$prefix/etc|g" \
        -e "s|@prefix@|$prefix|g" \
    "$1" >"$2"
}

edit sxscripts/sxserver/sxhttpd.conf.default.in "$prefix/etc/sxserver/sxhttpd.conf"
edit sxscripts/bin/sxserver.in "$prefix/sbin/sxserver"
chmod +x "$prefix/sbin/sxserver"
cp sxscripts/sxserver/fastcgi_params "$prefix/etc/sxserver/fastcgi_params"

ln -s `pwd`/../client/src/tools/init/sxinit "$prefix/bin/sxinit"
ln -s `pwd`/src/tools/sxadm/sxadm "$prefix/sbin/sxadm"
ln -s `pwd`/src/fcgi/sx.fcgi "$prefix/sbin/sx.fcgi"
ln -s `pwd`/../3rdparty/nginx/objs/nginx "$prefix/sbin/sxhttpd"

SXRUNDIR="$prefix/var/run/sxserver"
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

cat >"$prefix/etc/sxserver/sxsetup.conf" <<EOF
SX_NO_ROOT=1
SX_RUN_DIR="$SXRUNDIR"
EOF

sed -e "s|listen .*443|listen 127.0.0.1:8443|g" -e "s|listen .*80|listen 127.0.0.1:8013|g" $prefix/etc/sxserver/sxhttpd.conf >$prefix/etc/sxserver/sxhttpd.conf.1
mv "$prefix/etc/sxserver/sxhttpd.conf.1" "$prefix/etc/sxserver/sxhttpd.conf"

"$prefix/sbin/sxadm" node --new --batch-mode "$SXSTOREDIR/data"
"$prefix/sbin/sxadm" cluster --new --batch-mode --node-dir="$SXSTOREDIR/data" "100M/127.0.0.1" "sx://localhost"

# TODO: sxadm should be more easily scriptable
"$prefix/sbin/sxadm" node --info "$SXSTOREDIR/data" | grep 'Admin key: ' | cut -d\  -f3 >"$SXSTOREDIR/data/admin.key"

cleanup () {
    echo "cleaning up"
    "$prefix/sbin/sxserver" stop
    rm -rf $prefix
}
"$prefix/sbin/sx.fcgi" --config-file "$prefix/etc/sxserver/sxfcgi.conf"
"$prefix/sbin/sxhttpd" -c "$prefix/etc/sxserver/sxhttpd.conf"

trap cleanup EXIT INT
perl `dirname $0`/fcgi-test.pl 127.0.0.1:8013 $SXSTOREDIR/data || {
    rc=$?
    cat "$SXLOGFILE";
    cat $prefix/var/log/sxserver/sxhttpd-error.log;
    if [ "$rc" -eq 2 ]; then
        exit 77 # perl dep missing
    fi
    exit 1;
}
