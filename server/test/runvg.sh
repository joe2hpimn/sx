#!/bin/sh
ID=$$
VALGRIND_OPTS="--log-file=valgrind.$ID.%p.log --track-fds=yes --track-origins=yes --trace-children=yes --error-exitcode=123 --leak-check=full --suppressions=valgrind.supp --show-reachable=yes"
rm -f valgrind.$ID.log valgrind.$ID.*.log
./libtool --mode=execute valgrind $VALGRIND_OPTS $*
RESULT=$?
cat valgrind.$ID.*.log >valgrind.$ID.log
rm -f valgrind.$ID.*.log
test $RESULT -eq 0 || { cat valgrind.$ID.log; exit 123; }
(grep "FILE DESCRIPTORS:" valgrind.$ID.log | grep "at exit" | grep -v " 4 open at exit"  | grep -v " 2 open at exit") && {
    cat valgrind.$ID.log;
    echo "Leaked file descriptors";
    exit 124;
} || exit 0
