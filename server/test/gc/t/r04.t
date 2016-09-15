#!/bin/bash
set -e
. ./common.sh
. test/nodecmds.sh

plan 4

sx_init
require_cmd sx_wipe

require_cmd sx_create_whole_cluster 4 8
set +e
(
    testcase 1 "Cluster with 4 nodes"
    require_cmd $SXVOL create -o admin -s 2M -r 1 $SXURI/vol1
    $RANDGEN 489000 489651 >x1 2>/dev/null || exit 1
    require_cmd $SXCP x1 $SXURI/vol1/

    nodegc 1 2 3 4 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    nodegc_expire 1 2 3 4 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
    testcase 2 "Multiple node removals"
    require_cmd sx_node_remove 4
    require_cmd sx_node_remove 1
    require_cmd sx_node_remove 2
    require_cmd $SXCP $SXURI/vol1/x1 x1_
    cmp x1 x1_

    nodegc 3 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    nodegc_expire 3 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
    testcase 3 "Rebalance: add 2 nodes"
    test-sx/3/sbin/sxserver stop
    echo verbose-rebalance >>test-sx/3/etc/sxserver/sxfcgi.conf
    test-sx/3/sbin/sxserver start

    require_cmd sx_node_new_join_nowait 5 --advanced
    nodegc 3 5 >$LOGFILE 2>&1
    sx_wait_rebalance_node 3
    require_cmd sx_node_new_join 6

    require_cmd $SXCP $SXURI/vol1/x1 x1__
    cmp x1 x1__

    nodegc 3 5 6 >>$LOGFILE 2>&1

    # block may be moved multiple times due to 2 rebalances
    EXPECTED=$(grep 'RBL.*New home' test-sx/{3,5,6}/var/log/sxserver/sxfcgi.log | grep -Eo 'block [^ ]+' | sort -u | wc -l | sum)

    (grep 'freeing block with hash' $LOGFILE | sort -u | wc -l) | is "$EXPECTED"

    nodegc_expire 3 5 6 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
    testcase 4 "Delete file"
    require_cmd $SXRM $SXURI/vol1/x1

    nodegc 3 5 6 >$LOGFILE 2>&1
    (grep -c 'freeing block with hash' $LOGFILE) | is 30

    nodegc_expire 3 5 6 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
)

rm -f x1 x1_ x1__
