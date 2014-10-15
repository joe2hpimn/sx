#!/bin/sh -x
set -e
SXVOL_CREATE="../client/src/tools/vol/sxvol create --no-ssl -o admin -r 1 -s 100M"
SXCP="../client/src/tools/cp/sxcp --no-ssl"
SXLS="../client/src/tools/ls/sxls --no-ssl"
SXRM="../client/src/tools/rm/sxrm --no-ssl"
HOSTNAME=$1
ADMINKEY=$2

if [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 <clustername>\n"
    exit 1
fi

runtest() {
    msg=$1
    shift
    echo
    echo $msg
    if $@; then
        echo "!ERROR: Expected to fail"
    fi
}

# URLline = VERB /VOL/FILE HTTP/1.1\n
# max(URL) = max(VERB) + 2 + max(VOL) + max(FILE) + 10
# 8192 = 7 + 2 + max(VOL) + max(FILE) + 10
# => max(FILE) = 8173 - max(VOL) = 7917
# if we want length limit to be in UTF8-chars then we /12:
# => 659
# => 512 limit we designed originally

VOLNAMEMAX=$(printf "%255s" " "|sed 's/ /a/g')
FILENAMEMAX=$(printf "%1024s" "%F0%80%80%80"|sed 's/ /f/g')
OVERLONGFILENAME=$(printf "%8192s" " "|sed 's/ /o/g')

echo "Checking limits (have to pass)."

$SXVOL_CREATE sx://$HOSTNAME/$VOLNAMEMAX
$SXCP /etc/passwd sx://$HOSTNAME/$VOLNAMEMAX/$FILENAMEMAX

# TODO: custom error page for nginx 414
echo
echo "Testing errors. Look at the messages and check that they are OK"

# Length exceeded by 1 char
runtest "Volume 1 char longer" $SXVOL_CREATE sx://$HOSTNAME/z$VOLNAMEMAX
runtest "Volume 1 char longer(list)" $SXLS sx://$HOSTNAME/z$VOLNAMEMAX
runtest "Filename 1 char longer" $SXCP /etc/passwd sx://$HOSTNAME/$VOLNAMEMAX/z$FILENAMEMAX

# URL length exceeded
# test 414.
# TODO: custom json errorpage for nginx's built-in 414
runtest "Volume URL too long" $SXVOL_CREATE sx://$HOSTNAME/$OVERLONGFILENAME
runtest "Volume URL too long (list)" $SXLS sx://$HOSTNAME/$OVERLONGFILENAME
runtest "URL too long" $SXCP /etc/passwd sx://$HOSTNAME/$VOLNAMEMAX/$OVERLONGFILENAME

# UTF8 tests
# neither echo -e, or printf "\x.." is portable so use this:
INVALID1=`printf "%b" "\0304\0305"`
INVALID2=`printf "%b" "\0300\0200"`
runtest "Volume with invalid UTF8" $SXVOL_CREATE sx://$HOSTNAME/$INVALID1
runtest "Volume with invalid UTF8" $SXVOL_CREATE sx://$HOSTNAME/$INVALID2
runtest "Filename with invalid UTF8" $SXCP /etc/passwd sx://$HOSTNAME/$VOLNAMEMAX/$INVALID1
runtest "Filename with invalid UTF8" $SXCP /etc/passwd sx://$HOSTNAME/$VOLNAMEMAX/$INVALID2
runtest "List volume with invalid UTF8" $SXLS sx://$HOSTNAME/$INVALID1
runtest "List volume with invalid UTF8" $SXLS sx://$HOSTNAME/$INVALID2

#Reserved volumes
runtest "Creating reserved volume" $SXVOL_CREATE sx://$HOSTNAME/.something
runtest "Listing reserved volume" $SXLS sx://$HOSTNAME/.users

#Creating same volume again
runtest "Already existing volume" $SXVOL_CREATE sx://$HOSTNAME/$VOLNAMEMAX
#Not existing volume
runtest "Upload to non-existing volume" $SXCP /etc/passwd sx://$HOSTNAME/notexist/some
runtest "List non-existent volume" $SXLS sx://$HOSTNAME/notexist

for i in ../client/src/filters/*/.libs/*.so.0.0*; do
    # can't symlink, libsx only supports real files for plugins
    cp `pwd`/$i $SX_FILTER_DIR/
done

TESTFILE=configure
for i in ../client/src/filters/*; do
    name=`basename $i`
    if [ `uname` = "OpenBSD" -a "$name" = "aes256" ]; then
        # python pty.spawn() is broken, don't test aes filter
        continue
    fi
    # aes filter needs a password, so give it one
    printf "12345678\n12345678\n" | test/ptyrun.sh $SXVOL_CREATE -f $name sx://$HOSTNAME/v$name
    $SXCP $TESTFILE sx://$HOSTNAME/v$name/f1
    $SXCP /etc/passwd sx://$HOSTNAME/v$name/f1
    $SXCP $TESTFILE sx://$HOSTNAME/v$name/f2
    $SXLS sx://$HOSTNAME/v$name
done

# wipe client config
rm -rf $HOME/.sx/filters

for i in ../client/src/filters/*; do
    name=`basename $i`
    if [ `uname` == "OpenBSD" -a "$name" == "aes256" ]; then
        # python pty.spawn() is broken, don't test aes filter
        continue
    fi
    $SXLS sx://$HOSTNAME/v$name
    $SXCP sx://$HOSTNAME/v$name/f1 f1
    cmp -s f1 /etc/passwd
    $SXCP sx://$HOSTNAME/v$name/f2 f2
    cmp -s f2 $TESTFILE
done

runtest "Init with SSL on non-SSL server" ../client/src/tools/init/sxinit --host-list=127.0.1.1 sx://localhost <$ADMINKEY

# TODO: sxinit should remove ca.pem
rm -rf ~/.sx/localhost
../client/src/tools/init/sxinit --host-list=127.0.1.1 sx://localhost --no-ssl <$ADMINKEY
runtest "SSL use after no-SSL init" ../client/src/tools/vol/sxvol create --no-ssl sx://localhost/volu -o admin -r1 -s 100M
runtest "SSL use after no-SSL init" ../client/src/tools/vol/sxvol create sx://localhost/volu -o admin -r 1 -s 100M

echo "Testing upload/deletes"
for i in x x1 x2 y y1 xfoo x/foo x3/foo 'x*foo' 'x?foo'; do
    $SXCP configure sx://$HOSTNAME/vol1/$i
done
$SXRM sx://$HOSTNAME/vol1/x* -v
$SXLS sx://$HOSTNAME/vol1 -r
$SXCP -v -r test/ sx://$HOSTNAME/vol1/testme
$SXLS sx://$HOSTNAME/vol1 -r

echo
echo "Tests finished"
