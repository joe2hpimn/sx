set -o pipefail
require_cmd()
{
    $* 1>&2 || { echo "Bail out! Required command failed: $*" >&2; exit 1; }
}

plan()
{
    # +1 for stop()
    PLAN_LAST=$(expr "$1" + 1)
    echo "1..$PLAN_LAST"
}

test_result()
{
    exitcode=$?
    echo "== END $1 - $2 =="
    if [ $exitcode -eq 0 ]; then
        echo "ok $1 - $2" >&3
        rm -f $LOGFILE
    else
        echo "not ok $1 - $2: exitcode $exitcode" >&3
    fi
}

testcase()
{
    set -e
    trap "test_result $1 \"$2\"" EXIT
    # FD 3: original stdout
    # FD 2: unchanged
    # FD 1: redirected to stderr
    exec 3>&1 1>&2
    set -x
    echo "== BEGIN $1 - $2 =="
    t=$(basename "$0")
    LOGFILE="test-$t-$1.log"
}

is()
{
    read LINE
    if [ "$LINE" = "$1" ]; then
        echo "OK"
    else
        echo
        echo "***"
        echo "Expected $1, but got $LINE"
        echo "***"
        echo
        exit 1
    fi
}
