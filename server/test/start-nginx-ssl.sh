#!/bin/sh
set -e

if [ `id -u` -eq 0 ]; then
    echo "You must NOT be root"
    exit 1
fi
# for valgrind, avoid aes_ni warnings
export OPENSSL_ia32cap="~0x200000000000000"
sudo rm -f /tmp/sxfcgi.valgrind.log.*
sudo rm -f /tmp/v.log.*

MESSAGE="LAST TEST FAILED!"
print_status() {
    echo "$MESSAGE"
}
export TMPDIR=/tmp
trap print_status EXIT
N=3
if [ `uname` = "OpenBSD" ]; then
   # we hit ENOLCK otherwise
   N=1
fi
ulimit -c unlimited
export ASAN_OPTIONS=log_path=/tmp/asan.log

ROOT=`pwd`/test-sx
sudo rm -rf $ROOT
CLUSTER_NAME=localhost

# TODO: sxadm should generate these
ADMIN_KEY=0DPiKuNIrrVmD8IUCuw1hQxNqZc8kneQi3GoAPaxWgJng4mcDWfj8QAA
CLUSTER_UUID=f2d5c774-b40e-4bbf-88fc-9ccaa8a9e8af

echo "Killing old processes"
sudo pkill -f sxhttpd || true
sudo pkill -9 -f sx.fcgi || true

i=1
while [ $i -le $N ]; do
    echo
    echo "Preparing node $i"
    prefix=$ROOT/$i
    echo "Installing nginx config and scripts to $prefix"
    (cd ../3rdparty/sxhttpd && make install-sbinSCRIPTS install-nobase_sysconfDATA install-data prefix=$prefix -s)
    mkdir -p $prefix/bin $prefix/sbin $prefix/lib
    ln -s `pwd`/../client/src/tools/init/sxinit $prefix/bin/sxinit
    ln -s `pwd`/src/tools/sxadm/sxadm $prefix/sbin/sxadm
    ln -s `pwd`/src/fcgi/sx.fcgi $prefix/sbin/sx.fcgi
    cp $prefix/etc/sxserver/sxhttpd.conf.default $prefix/etc/sxserver/sxhttpd.conf

    # Run them once to have the compiler create .libs/lt-*
    $prefix/bin/sxinit --version
    $prefix/sbin/sxadm --version
    $prefix/sbin/sx.fcgi --version

    # valgrind just the fcgi not the libtool wrapper script:
    sed -i -e "s|.*/sx.fcgi|./libtool --mode=execute \0 --config-file $prefix/etc/sxserver/sxfcgi.conf|" $prefix/sbin/sxserver

    ln -s `pwd`/../3rdparty/nginx/objs/nginx $prefix/sbin/sxhttpd

    echo "Initializing node $i"
    CONF_TMP=$prefix/conf.tmp
    cat >>$CONF_TMP <<EOF
    SX_CLUSTER_NAME="$CLUSTER_NAME"
    SX_DATA_DIR="$prefix/var/lib/sxserver"
    SX_RUN_DIR="$prefix/var/run/sxserver"
    SX_LOG_FILE="$prefix/var/log/sxserver/sxfcgi.log"
    SX_NODE_SIZE="1T"
    SX_NODE_IP="127.0.1.$i"
    SX_SERVER_USER=`id -n -u`
    SX_HTTP_PORT="80"
    SX_HTTPS_PORT="443"
    SX_USE_SSL="yes"
    SX_CLUSTER_UUID="$CLUSTER_UUID"
    SX_ADMIN_KEY="$ADMIN_KEY"
    SX_SSL_KEY_FILE=`pwd`/test/keys/cluster1.key
    SX_SSL_CERT_FILE=`pwd`/test/keys/cluster1.pem
EOF
    if [ $i -gt 1 ]; then
	echo "SX_EXISTING_NODE_IP=\"127.0.1.1\"" >> $CONF_TMP
    fi
    export SX_USE_VALGRIND=yes
    sudo -E $prefix/sbin/sxsetup --config-file $CONF_TMP
    rm -f $CONF_TMP

    i=$(( i+1 ))
done

list=127.0.1.1
i=2
while [ $i -le $N ]; do
    list="$list,127.0.1.$i"
    i=$((i+1))
done
rm -rf $HOME/.sx/$CLUSTER_NAME # avoid sxinit bugs
echo "$ADMIN_KEY" | ../client/src/tools/init/sxinit --batch --host-list=$list sx://localhost
test/valgrind-tests.sh
i=1
while [ $i -le $N ]; do
    prefix=$ROOT/$i
    $prefix/sbin/sxserver stop
    i=$(( i+1 ))
done
MESSAGE="OK"
exit 0
