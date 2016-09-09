set -e
cd "$(dirname "$0")/../../../"
stop()
{
    echo "Stopping nodes" >&2
    for i in $(seq 1 4); do
        "test-sx/$i/sbin/sxserver" stop 2>/dev/null >/dev/null || true
    done
    echo "Nodes stopped" >&2
    # nested EXIT handlers don't work
    echo "ok $PLAN_LAST - 0"
}

trap stop EXIT

SXCP="../client/src/tools/cp/sxcp --replica-wait"
SXCAT=../client/src/tools/cat/sxcat
SXVOL=../client/src/tools/vol/sxvol
SXADM=src/tools/sxadm/sxadm
SXRM=../client/src/tools/rm/sxrm
RANDGEN=test/randgen
SXURI=sx://admin@sxtest
export ROOT="$(pwd)/test-sx"

nodegc_wait()
{
    echo "Waiting for unbumps"
    # TODO: should loop over all nodes always!
    for i in $*; do
        echo "node $i" >&2
        $SXADM node --unbump-wait "test-sx/$i/var/lib/sxserver/storage" --debug
    done
    echo "Unbumps OK"
}

nodegc()
{
    # Have to first wait for unbumps to complete on all nodes, because unbumps
    # can make changes on remote nodes, which would require running GC again
    nodegc_wait $*
    for i in $*; do
        echo "node $i" >&2
        $SXADM node --gc "test-sx/$i/var/lib/sxserver/storage" --debug
    done
}

nodegc_expire()
{
    nodegc_wait $*
    for i in $*; do
        echo "node $i" >&2
        $SXADM node --gc-expire "test-sx/$1/var/lib/sxserver/storage" --debug
    done
}

. test/gc/test.sh
