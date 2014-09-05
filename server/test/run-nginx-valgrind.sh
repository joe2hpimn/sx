#!/bin/sh
set -e
set -x

# reset PATH to standard utilities, otherwise if the user changed PATH
# we might miss essential utilities like chown
PATH=`getconf PATH`

# Disable proxies
unset HTTP_PROXY
unset http_proxy
unset HTTPS_PROXY
unset https_proxy

prefix=`mktemp -d $PWD/sx-test-valgrind-XXXXXXXX`
cleanup () {
    make -C sxscripts clean
    rm -rf $prefix
}
trap cleanup EXIT INT

make -C sxscripts clean install prefix="$prefix" -s
touch src/fcgi/fcgi-server.c && make all prefix=$prefix -s && touch src/fcgi/fcgi-server.c
mkdir -p $prefix/bin
mkdir -p $prefix/sbin
ln -s `pwd`/../client/src/tools/init/sxinit $prefix/bin/sxinit
ln -s `pwd`/src/tools/sxadm/sxadm $prefix/sbin/sxadm

ID=server
VALGRIND_OPTS="--log-file=/tmp/valgrind.$ID.%p.log --track-fds=yes --track-origins=yes --trace-children=yes --error-exitcode=123 --leak-check=full --suppressions=valgrind.supp"
rm -f /tmp/valgrind.$ID.log valgrind.$ID.*.log
cat >$prefix/sbin/sx.fcgi <<EOF
#!/bin/sh
set -e
exec `pwd`/libtool --mode=execute valgrind $VALGRIND_OPTS `pwd`/src/fcgi/sx.fcgi $*
EOF
chmod +x $prefix/sbin/sx.fcgi
ln -s `pwd`/../3rdparty/nginx/objs/nginx $prefix/sbin/sxhttpd
cp $prefix/etc/sxserver/sxhttpd.conf.default $prefix/etc/sxserver/sxhttpd.conf
mkdir -p $prefix/tmp/sx

SXWEBUSER=`id -n -u`
SXSTOREDIR=$prefix/var/lib/sxserver
SXDEFAULT=$prefix/etc/sxserver/sxsetup-default
cat >$SXDEFAULT <<EOF
SXTHISIP=127.0.0.1
SXFIRSTIP=127.0.0.1
SXCLUSTERNAME=localhost
SXINITFLAGS=--no-check-certificate
SXSTOREDIR=$SXSTOREDIR
SXNODESIZE=1G
SXWEBUSER=$SXWEBUSER
SXCONFIRM=1
SXLOGFILE=$prefix/var/log/sxserver/sxfcgi.log
EOF

sh -x $prefix/sbin/sxsetup </dev/null
sed -e "s|^user.*|user `whoami`;|" -e "s|listen .*443|listen 127.0.0.1:8443|g" -e "s|listen .*80|listen 127.0.0.1:8013|g" -e "s|/tmp/sx|$prefix/tmp/sx|g" $prefix/etc/sxserver/sxhttpd.conf >$prefix/etc/sxserver/sxhttpd.conf.1
mv $prefix/etc/sxserver/sxhttpd.conf.1 $prefix/etc/sxserver/sxhttpd.conf
cat >>$prefix/etc/sxserver/sxfcgi.conf <<EOF
children=2
EOF

cleanup () {
    echo "cleaning up"
    $prefix/sbin/sxserver stop </dev/null
    rm -rf $prefix
    cat /tmp/valgrind.$ID.*.log >/tmp/valgrind.$ID.log
    rm -f valgrind.$ID.*.log
    cat /tmp/valgrind.$ID.log
    ls -lh /tmp/valgrind.$ID.log
    make -C sxscripts clean
}
trap cleanup EXIT INT
sh $prefix/sbin/sxserver start </dev/null
perl `dirname $0`/fcgi-test.pl 127.0.0.1:8013 $SXSTOREDIR/data
