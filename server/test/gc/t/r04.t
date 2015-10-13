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
    require_cmd sx_node_new_join 5
    require_cmd sx_node_new_join 6

    require_cmd $SXCP $SXURI/vol1/x1 x1__
    cmp x1 x1__

    nodegc 3 5 6 >$LOGFILE 2>&1
    # TODO: should be 30 if moved?
    #(! grep -c 'freeing block' $LOGFILE) | is 0

    nodegc_expire 3 5 6 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
    testcase 4 "Delete file"
    require_cmd $SXRM $SXURI/vol1/x1

    nodegc 3 5 6 >$LOGFILE 2>&1
    # TODO: should be 30?
    #(! grep -c 'freeing block' $LOGFILE) | is 30

    nodegc_expire 3 5 6 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
)

rm -f x1 x1_ x1__
