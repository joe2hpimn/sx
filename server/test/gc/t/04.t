#!/bin/bash
. ./common.sh

plan 9
N=4 require_cmd test/start-nginx.sh
require_cmd $RANDGEN 489000 489651 >x1
require_cmd $RANDGEN 489000 489651 >x2
require_cmd $RANDGEN 489000 489651 >x3
require_cmd $SXVOL create -o admin -s 2M -r 3 $SXURI/vol3
ls -l x1 x2
require_cmd $SXCP x1 $SXURI/vol3/
require_cmd $SXCP x2 $SXURI/vol3/

set +e
(
        testcase 1 "GC one file"
        $SXRM $SXURI/vol3/x1
        nodegc 1 2 3 4 >$LOGFILE 2>&1
        grep -c 'freeing block with hash' $LOGFILE | is 90

        nodegc_expire 1 2 3 4 >$LOGFILE 2>&1
        (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
        testcase 2 "file downloadable"
        $SXCP $SXURI/vol3/x2 x2_d
        cmp x2 x2_d
)

(
        testcase 3 "upload/reuse, nothing to GC"
        $SXCP x3 $SXURI/vol3/
        nodegc_expire 1 2 3 4 >$LOGFILE 2>&1
        (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
        testcase 4 "files downloadable"
        $SXCP $SXURI/vol3/x3 x3_d
        $SXCP $SXURI/vol3/x2 x2_d2
        cmp x3 x3_d
        cmp x2 x2_d2
)

(
        testcase 5 "upload to multiple volumes"
        $RANDGEN 489000 489651 >x1
        $RANDGEN 489000 489651 >x2
        for i in $(seq 1 4); do
                $SXVOL create -o admin -s 2M -r $i $SXURI/volx$i
        done

        nodegc 1 2 3 4 >$LOGFILE 2>&1
        (! grep -c 'freeing block' $LOGFILE) | is 0

        for vol in volx1 volx2 volx3 volx4; do $SXCP x1 $SXURI/$vol/; done
        for vol in volx4 volx3 volx2 volx1; do $SXCP x2 $SXURI/$vol/; done

        nodegc 1 2 3 4 >$LOGFILE 2>&1
        (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
        testcase 6 "no GC while blocks used by other files"
        $SXRM $SXURI/volx1/x1 $SXURI/volx2/x1 $SXURI/volx3/x1

        nodegc 1 2 3 4 >$LOGFILE 2>&1
        (! grep -c 'freeing block' $LOGFILE) | is 0
)

(
        testcase 7 "GC when last file removed"
        $SXRM $SXURI/volx4/x1

        nodegc 1 2 3 4 >$LOGFILE 2>&1
        grep -c 'freeing block with hash' $LOGFILE | is 120
)

(
        testcase 8 "GC from highest replica"
        for vol in volx4 volx3 volx2 volx1; do
                $SXRM $SXURI/$vol/x2

                nodegc 1 2 3 4 >$LOGFILE 2>&1
                grep -c 'freeing block with hash' $LOGFILE | is 30
        done
)

(
        testcase 9 "nothing to expire"
        nodegc_expire 1 2 3 4 >$LOGFILE 2>&1
        (! grep -c 'freeing block' $LOGFILE) | is 0
)

rm -f x1 x2 x3 x4 x2_d x2_d2 x3_d