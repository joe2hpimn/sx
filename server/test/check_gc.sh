#!/bin/sh -x
print_status() {
    set +x
    for i in test-sx/*/var/lib/sxserver/data/gc.db; do
        sqlite3 $i 'select hex(hash), expires_at, reserved, used, size FROM blocks'
    done
    set -x
}
set -e
../client/src/tools/vol/sxvol create -o admin -s 100M --no-ssl sx://localhost/volgc -r 1 || true
../client/src/tools/vol/sxvol create -o admin -s 100M --no-ssl sx://localhost/volgc2 -r 2 || true
for vol in volgc volgc2; do
    test/randgen 4095 4095 >ftest
    # Upload a file, used should be 1
    ../client/src/tools/cp/sxcp --no-ssl ftest sx://localhost/$vol/ftest
    print_status
    # Upload same file again, used should be 2
    ../client/src/tools/cp/sxcp --no-ssl ftest sx://localhost/$vol/ftest2
    print_status
    # Delete one, used should be 1
    ../client/src/tools/rm/sxrm --no-ssl sx://localhost/$vol/ftest
    print_status
    # Delete the other, used should be 0
    ../client/src/tools/rm/sxrm --no-ssl sx://localhost/$vol/ftest2
    print_status
    # Wait for gc
    sleep 2
    # should be gone now
    print_status
done
test/randgen 50000 50000 >file
../client/src/tools/cp/sxcp --no-ssl file sx://localhost/volgc/file0
../client/src/tools/cp/sxcp --no-ssl file sx://localhost/volgc/file1
../client/src/tools/rm/sxrm --no-ssl sx://localhost/volgc/file0
../client/src/tools/rm/sxrm --no-ssl sx://localhost/volgc/file1
sleep 5
test/randgen 50000 50000 >file
../client/src/tools/cp/sxcp --no-ssl file sx://localhost/volgc2/file0
../client/src/tools/cp/sxcp --no-ssl file sx://localhost/volgc2/file1
../client/src/tools/rm/sxrm --no-ssl sx://localhost/volgc2/file0
../client/src/tools/rm/sxrm --no-ssl sx://localhost/volgc2/file1
sleep 5
../client/src/tools/cp/sxcp --no-ssl file sx://localhost/volgc2/file0
../client/src/tools/cp/sxcp --no-ssl configure sx://localhost/volgc/file1
../client/src/tools/cp/sxcp --no-ssl configure sx://localhost/volgc/copy1
sleep 5
grep "Periodic GC" test-sx/*/var/log/sxserver/sxfcgi.log | grep -v " 0 hashes" || true
../client/src/tools/rm/sxrm --no-ssl sx://localhost/volgc/copy1
sleep 5
grep "Periodic GC" test-sx/*/var/log/sxserver/sxfcgi.log | grep -v " 0 hashes" || true
../client/src/tools/rm/sxrm --no-ssl sx://localhost/volgc/file1
sleep 5
grep "Periodic GC" test-sx/*/var/log/sxserver/sxfcgi.log | grep -v " 0 hashes" || true


