#!/bin/bash
. ./common.sh

plan 4
N=1 require_cmd test/start-nginx.sh
require_cmd $SXVOL create -s 16M -o admin -r 1 $SXURI/vol1

set +e
(
    testcase 1 "1 file 1 block"
    $RANDGEN 4096 4096 >4k
    $SXCP 4k $SXURI/vol1/
    nodegc 1 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    rm 4k
)

(
    testcase 2 "deleted file is GCed"
    $SXRM sx://admin@localhost/vol1/4k
    nodegc 1 >$LOGFILE 2>&1
    grep -c 'freeing block with hash' $LOGFILE | is 1
)

(
    testcase 3 "multiple uses of same block"
    # Test that blocks are not removed when still referenced by one file
    $RANDGEN 4096 4096 >4k2
    nodegc 1 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    $SXCP 4k2 $SXURI/vol1/1
    $SXCP 4k2 $SXURI/vol1/2
    nodegc 1 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    $SXRM $SXURI/vol1/2
    nodegc_expire 1 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
    nodegc 1 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0

    # Remove last file referencing block
    $SXRM $SXURI/vol1/1
    nodegc 1 >$LOGFILE 2>&1
    grep -c 'freeing block with hash' $LOGFILE | is 1

    rm 4k2
)

(
    testcase 4 "lots of small files"
    mkdir -p smalltest
    for i in $(seq 1 64); do $RANDGEN 131071 131071 >smalltest/$i; done
    $SXCP -r smalltest $SXURI/vol1/
    rm -f smalltest/??
    # 9 files
    $SXCP -r smalltest $SXURI/vol1/smalltest2
    nodegc 1 >$LOGFILE 2>&1
    (! grep -c 'freeing block' $LOGFILE) | is 0
    # 55 file's blocks are not referenced anymore
    $SXRM -r $SXURI/vol1/smalltest/

    nodegc 1 >$LOGFILE 2>&1
    grep -c 'freeing block with hash' $LOGFILE | is 1760

    $SXRM -r $SXURI/vol1/smalltest2/
    nodegc 1 >$LOGFILE 2>&1
    grep -c 'freeing block with hash' $LOGFILE | is 288

    rm -rf smalltest/
)
