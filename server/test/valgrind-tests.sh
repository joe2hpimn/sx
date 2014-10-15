#!/bin/sh
set -e
set -x
# disable AES instruction, which generates a lot of false positives from
# valgrind
export OPENSSL_ia32cap="~0x200000000000000"
export SX_FILTER_DIR=test-sx/filters

SXACL=../client/src/tools/acl/sxacl
SXCAT=../client/src/tools/cat/sxcat
SXCP=../client/src/tools/cp/sxcp
SXINIT=../client/src/tools/init/sxinit
SXLS=../client/src/tools/ls/sxls
SXRM=../client/src/tools/rm/sxrm
SXVOL=../client/src/tools/vol/sxvol

VOL=vol`date +%s.%N`
VOLr=r$VOL
USER=user`date +%s.%N`

valgrind_run() {
    ./libtool --mode=execute valgrind --num-callers=50 --log-file=/tmp/v.log.%p --error-exitcode=123 --leak-check=full $*
}

N=3
list=127.0.1.1
i=2
while [ $i -le $N ]; do
    list="$list,127.0.1.$i"
    i=$((i+1))
done
ADMIN_KEY=0DPiKuNIrrVmD8IUCuw1hQxNqZc8kneQi3GoAPaxWgJng4mcDWfj8QAA

echo "$ADMIN_KEY" | valgrind_run $SXINIT --batch --host-list=$list sx://localhost
echo
echo "$ADMIN_KEY" | valgrind_run $SXINIT --no-ssl --batch --host-list=$list sx://localhost-nossl
echo

valgrind_run $SXVOL create sx://localhost/$VOL -o admin -r 1 -s 100M
valgrind_run $SXVOL create sx://localhost/$VOLr -o admin -r $N -s 100M

valgrind_run $SXACL useradd $USER sx://localhost
valgrind_run $SXACL userlist sx://localhost
valgrind_run $SXACL usergetkey $USER sx://localhost
valgrind_run $SXACL volshow sx://localhost/$VOL
valgrind_run $SXACL volperm --grant=read $USER sx://localhost/$VOL
valgrind_run $SXACL volperm --grant=write $USER sx://localhost/$VOL
valgrind_run $SXACL volperm --revoke=write,read $USER sx://localhost/$VOL
valgrind_run $SXACL volperm --revoke=read $USER sx://localhost/$VOL
valgrind_run $SXACL volperm --revoke=write $USER sx://localhost/$VOL
valgrind_run $SXACL volperm --grant=write,read $USER sx://localhost/$VOL
valgrind_run $SXACL volperm --grant=read,write $USER sx://localhost/$VOL
valgrind_run $SXACL volshow sx://localhost/$VOL

for size in 0 4096 8192 1048575; do
    test/randgen $size $size >ftest
    # upload
    valgrind_run $SXCP ftest sx://localhost/$VOL/
    # reupload
    valgrind_run $SXCP ftest sx://localhost/$VOL/
    # replicate
    valgrind_run $SXCP ftest sx://localhost/$VOLr/
    rm -f ftestd
    # download
    valgrind_run $SXCP sx://localhost/$VOLr/ftest ftestd
    # redownload
    valgrind_run $SXCP sx://localhost/$VOLr/ftest ftestd
    # overwrite
    test/randgen $size $size >ftestd
    valgrind_run $SXCP sx://localhost/$VOLr/ftest ftestd

    test/randgen $size $size >ftest
    # upload directly to volume with replica
    valgrind_run $SXCP ftest sx://localhost/$VOLr/

    # remote2remote (fast)
    valgrind_run $SXCP sx://localhost/$VOL/ftest sx://localhost/$VOL/ftest2
    valgrind_run $SXCP sx://localhost/$VOL/ftest sx://localhost/$VOLr/ftest2

    # remote2remote (sxcp should think its different clusters)
    valgrind_run $SXCP sx://localhost/$VOL/ftest sx://localhost/$VOL/ftest2
    valgrind_run $SXCP sx://localhost/$VOL/ftest sx://localhost/$VOLr/ftest2

    # sxcat
    valgrind_run $SXCAT sx://localhost/$VOL/ftest >/dev/null
done
rm -f ftestd

# -r upload
valgrind_run $SXCP -r test/ sx://localhost/$VOLr/t/
# -r reupload
valgrind_run $SXCP -r test/ sx://localhost/$VOLr/t/
# -r download
rm -rf ftestdir
valgrind_run $SXCP -r sx://localhost/$VOLr/t/ ftestdir
# -r redownload
valgrind_run $SXCP -r sx://localhost/$VOLr/t/ ftestdir

valgrind_run $SXLS sx://localhost/$VOLr
valgrind_run $SXLS sx://localhost/$VOLr -r -l

valgrind_run $SXRM sx://localhost/$VOLr/ftest
valgrind_run $SXRM sx://localhost/$VOLr -r

valgrind_run ../client/src/tools/sxreport-client/sxreport-client
# test filters
mkdir -p $SX_FILTER_DIR
for i in ../client/src/filters/*/.libs/*.so.0.0*; do
    # can't symlink, libsx only supports real files for plugins
    cp `pwd`/$i $SX_FILTER_DIR/
done

# filters that don't require input
for filter in attribs null zcomp; do
    vol=vf$filter
    valgrind_run $SXVOL create -f $filter -o admin -r $N -s 100M sx://localhost/$vol
    valgrind_run $SXCP configure sx://localhost/$vol/
    rm -f ftest
    valgrind_run $SXCP sx://localhost/$vol/configure ftest
done
