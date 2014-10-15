#!/bin/sh
set -e
set -x
SXVOL_CREATE=`pwd`/"../client/src/tools/vol/sxvol create --no-ssl -o admin -r 1 -s 100M"
SXCP=`pwd`/"../client/src/tools/cp/sxcp --no-ssl"
SXLS=`pwd`/"../client/src/tools/ls/sxls --no-ssl"
HOSTNAME=$1

if [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 <clustername>\n"
    exit 1
fi

SXURI=sx://$HOSTNAME/lsvol
touch foo

create() {
    name=$1
    $SXCP foo $SXURI/$name
}

lsfullpath() {
    if [ $# -eq 0 ]; then
        ls -1p
    else
        for path in "$@"; do
            if test -f "$path"; then
                echo "$path"
            else
                ls -1p "$path" | awk "{ print \"$path/\"\$0 }"
            fi
        done
    fi
}

lscompare() {
    filter=$1
    rm -f ls1 ls2
    (cd ../sxls-test; lsfullpath $1) >ls1
    $SXLS $SXURI/$filter|colrm 1 31 >ls2
    echo comparing "ls $filter"
    diff -u ls1 ls2
    rm -f ls1 ls2
}

$SXVOL_CREATE $SXURI
create a/b/c
create alc
create a/e/c
create ax/b/c
create ax
create x/b/c
create xy/b/c
create z
create t
create f/x
create f0x
create d/f
create g/h/x
create g/[test]/x
create g/[hest]/x
create 'w/*'
create 'w/foo'
$SXLS -r $SXURI/
$SXLS $SXURI
$SXLS $SXURI/
$SXLS $SXURI/a
$SXLS $SXURI/a?
$SXLS $SXURI/a?/
$SXLS $SXURI/a*
$SXLS $SXURI/a*/
$SXLS $SXURI/a*c
$SXLS $SXURI/*
$SXLS $SXURI/*/b
$SXLS $SXURI/[dg]
$SXLS $SXURI/f[.-0]x
$SXLS $SXURI/w/*
$SXLS $SXURI'/w/\*'
# match exactly, as if no globbing
$SXLS $SXURI/g/[test]/
# match h/ only, i.e. globbing
$SXLS $SXURI/g/[hest]/

