set -o pipefail
require_cmd()
{
    $* 2>&1 | sed -e 's/^/#/' || { echo "Bail out! Required command failed: $*" >&3; exit 1; }
}

plan()
{
    echo "1..$1"
}

test_result()
{
    exitcode=$?
    echo '#' >&3
    if [ $exitcode -eq 0 ]; then
        echo "ok $1 - $2" >&3
        rm -f $LOGFILE
    else
        echo "not ok $1 - $2: exitcode $exitcode" >&3
    fi
    echo -n '#' >&3
    echo "== END $1 - $2 =="
}

testcase()
{
    set -e
    trap "test_result $1 \"$2\"" EXIT
    exec 3>&1 &> >(sed -e 's/^/#/')
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
