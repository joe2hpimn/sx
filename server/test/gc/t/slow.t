#!/bin/bash
set -e
. ./common.sh
. test/nodecmds.sh

plan 1 
N=2 require_cmd sx_create_whole_cluster 2 3
require_cmd $SXVOL create -s 10M -o admin -r 1 $SXURI/vol1

set +e

(
    # bb #1964
    # requires this patch:
#        rbl_log(&blockmeta->hash, "br_use", 1, NULL);
#+        if(!strcmp("127.0.1.1", sx_node_internal_addr(self))) {
#+            WARN("PAUSE!");
#+            sleep(15);
#+            WARN("RUN!");
#+        }

    testcase 1 "Rebalance race condition"
    set -x
    require_cmd $SXVOL create -s 1400M -o admin -r 2 $SXURI/vol2
    rm xinput/ -rf
    mkdir -p xinput
    for i in $(seq 1 1); do
        $RANDGEN 133169152 133169152 >xinput/$i 2>/dev/null || exit 1
    done
    require_cmd $SXCP -r xinput/ $SXURI/vol2/
    # Join new node and start rebalance, unlock job must run on != .1 too
    export SX_DEBUG_SINGLEHOST=127.0.1.2
    test-sx/1/sbin/sxserver stop
    test-sx/2/sbin/sxserver stop
    echo verbose-rebalance >>test-sx/1/etc/sxserver/sxfcgi.conf
    echo verbose-rebalance >>test-sx/2/etc/sxserver/sxfcgi.conf
    test-sx/1/sbin/sxserver start
    test-sx/2/sbin/sxserver start

    require_cmd sx_node_new_join_nowait 3 --advanced
    # give time for rebalance to have at least one block inside the sleep
    # could grep the logs and wait for PAUSE here
    sleep 5
    (tail -f test-sx/*/var/log/sxserver/sxfcgi.log | grep 'was not found locally')&

    $SXRM $SXURI/vol2/1
    nodegc_wait 1 2 3 >/tmp/unbump1 2>&1
    nodegc 1 >/tmp/log1 2>&1
    nodegc 2 >/tmp/log2 2>&1
    nodegc 3 >/tmp/log3 2>&1
    sx_wait_rebalance
)
