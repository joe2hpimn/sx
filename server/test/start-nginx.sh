#!/bin/sh
N=${N-4}
. $(dirname "$0")/nodecmds.sh
sx_create_whole_cluster "$N" "$N"

exit 0
rm -f mvtestx && ../client/src/tools/cp/sxcp sx://admin@localhost/vol1/mvtest mvtestx

list=127.0.1.1
i=2
while [ $i -le $N ]; do
    list="$list,127.0.1.$i"
    i=$((i+1))
done
rm -rf $HOME/.sx/$CLUSTER_NAME # avoid sxinit bugs
echo "$ADMIN_KEY" | ../client/src/tools/init/sxinit --port "$SX_PORT" --host-list=$list --key sx://admin@localhost --no-ssl
#sudo -u $SUDO_USER ../client/src/tools/init/sxinit --no-ssl sx://`hostname` <$STOREDIR/admin.key
../client/src/tools/vol/sxvol create sx://admin@localhost/volr2 -r 2 -o admin -s 100M
../client/src/tools/acl/sxacl useradd user1 sx://admin@localhost
../client/src/tools/acl/sxacl useradd user2 sx://admin@localhost
../client/src/tools/acl/sxacl volperm --grant=write user1,user2 sx://admin@localhost/volr2
../client/src/tools/acl/sxacl volperm --grant=read user1 sx://admin@localhost/volr2

MESSAGE="OK"
exit 0

SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.1 ../client/src/tools/acl/sxacl volshow sx://admin@localhost/volr2
echo
SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.2 ../client/src/tools/acl/sxacl volshow sx://admin@localhost/volr2
echo
../client/src/tools/acl/sxacl volperm --revoke=write user2 sx://admin@localhost/volr2
SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.1 ../client/src/tools/acl/sxacl volshow sx://admin@localhost/volr2
echo
SX_DEBUG_SINGLE_VOLUMEHOST=127.0.1.2 ../client/src/tools/acl/sxacl volshow sx://admin@localhost/volr2
echo
test/uldl.sh
exit 1
test/check_gc.sh
test/sx-ls.sh localhost
test/check_permissions.sh $list
mkdir -p $ROOT/filters
chown $SUDO_USER $ROOT/filters
export SX_FILTER_DIR=$ROOT/filters
../client/src/tools/init/sxinit --host-list=$list sx://admin@localhost --no-ssl <$STOREDIR/admin.key
test/sx-errors.sh localhost $STOREDIR/admin.key
../client/src/tools/init/sxinit --host-list=$list sx://admin@localhost --no-ssl <$STOREDIR/admin.key
MESSAGE="ALL TESTS OK"
echo
