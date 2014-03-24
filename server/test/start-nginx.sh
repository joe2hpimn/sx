#!/bin/sh
set -e

if [ `id -u` -eq 0 ]; then
    echo "You must NOT be root"
    exit 1
fi

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
CLUSTER_NAME=sxtest

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
    SX_USE_SSL="no"
    SX_CLUSTER_UUID="$CLUSTER_UUID"
    SX_ADMIN_KEY="$ADMIN_KEY"
EOF
    if [ $i -gt 1 ]; then
	echo "SX_EXISTING_NODE_IP=\"127.0.1.1\"" >> $CONF_TMP
    fi
    sudo $prefix/sbin/sxsetup --config-file $CONF_TMP
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
echo "$ADMIN_KEY" | ../client/src/tools/init/sxinit --host-list=$list sx://localhost --no-ssl
#sudo -u $SUDO_USER ../client/src/tools/init/sxinit --no-ssl sx://`hostname` <$STOREDIR/admin.key
../client/src/tools/vol/sxvol create sx://localhost/volr2 -r 2 -o admin
../client/src/tools/acl/sxacl useradd user1 sx://localhost
../client/src/tools/acl/sxacl useradd user2 sx://localhost
../client/src/tools/acl/sxacl perm --grant=write user1,user2 sx://localhost/volr2
../client/src/tools/acl/sxacl perm --grant=read user1 sx://localhost/volr2

MESSAGE="OK"
exit 0

SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.1 ../client/src/tools/acl/sxacl list sx://localhost/volr2
echo
SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.2 ../client/src/tools/acl/sxacl list sx://localhost/volr2
echo
../client/src/tools/acl/sxacl perm --revoke=write user2 sx://localhost/volr2
SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.1 ../client/src/tools/acl/sxacl list sx://localhost/volr2
echo
SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.2 ../client/src/tools/acl/sxacl list sx://localhost/volr2
echo
test/uldl.sh
exit 1
test/check_gc.sh
test/sx-ls.sh localhost
test/check_permissions.sh $list
mkdir -p $ROOT/filters
chown $SUDO_USER $ROOT/filters
export SX_FILTER_DIR=$ROOT/filters
../client/src/tools/init/sxinit --host-list=$list sx://localhost --no-ssl <$STOREDIR/admin.key
test/sx-errors.sh localhost $STOREDIR/admin.key
../client/src/tools/init/sxinit --host-list=$list sx://localhost --no-ssl <$STOREDIR/admin.key
MESSAGE="ALL TESTS OK"
echo
