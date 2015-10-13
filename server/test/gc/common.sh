set -e
cd "$(dirname "$0")/../../../"
stop()
{
    for i in $(seq 1 4); do
        "test-sx/$i/sbin/sxserver" stop 2>/dev/null >/dev/null || true
    done
}

trap stop EXIT

SXCP=../client/src/tools/cp/sxcp
SXCAT=../client/src/tools/cat/sxcat
SXVOL=../client/src/tools/vol/sxvol
SXADM=src/tools/sxadm/sxadm
SXRM=../client/src/tools/rm/sxrm
RANDGEN=test/randgen
SXURI=sx://admin@sxtest

nodegc()
{
    for i in $*; do
        echo "node $i" >&2
        $SXADM node --gc "test-sx/$i/var/lib/sxserver/storage" --debug
    done
}

nodegc_expire()
{
    for i in $*; do
        echo "node $i" >&2
        $SXADM node --gc-expire "test-sx/$1/var/lib/sxserver/storage" --debug
    done
}

. test/gc/test.sh
