#!/bin/bash
set -e
. ./common.sh
. test/nodecmds.sh

plan 2
N=2 require_cmd sx_create_whole_cluster 2 3
require_cmd $SXVOL create -s 1M -o admin -r 1 $SXURI/vol1

set +e
(
    testcase 1 "file is GCed on 2 node cluster"
    $RANDGEN 8192 8192 >8k || exit 1
    $SXCP 8k $SXURI/vol1/
    nodegc 1 2 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    $SXRM $SXURI/vol1 -r
    nodegc 1 2 >$LOGFILE 2>&1
    grep -c 'freeing block with hash' $LOGFILE | is 2

    nodegc_expire 1 2 >$LOGFILE 2>&1
    (! grep -c 'freeing block with hash' $LOGFILE) | is 0
)

(
    testcase 2 "file is reuploaded after GC"
    $SXCP 8k $SXURI/vol1 >$LOGFILE 2>&1
    grep -c -i 'transferred' $LOGFILE | is 1
)

rm -f 8k
