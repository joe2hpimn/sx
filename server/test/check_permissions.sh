#!/bin/sh -x
set -e
../client/src/tools/acl/sxacl useradd $SXINITFLAGS theadmin --role=admin sx://localhost --debug --auth-file=admin2.auth
# Create normal user
OWNER=user1
../client/src/tools/acl/sxacl useradd $SXINITFLAGS $OWNER --role=normal sx://localhost --auth-file normal.auth
../client/src/tools/acl/sxacl useradd $SXINITFLAGS user2 --role=normal sx://localhost --auth-file=normal2.auth

../client/src/tools/acl/sxacl userlist sx://localhost

# Volume creation (owned by admin)
../client/src/tools/vol/sxvol create sx://localhost/vol1 --owner admin -r 1 -s 100M
# Volume creation (owned by user)
../client/src/tools/vol/sxvol create sx://localhost/vol2 --owner $OWNER -r 1 -s 100M
# Volume listing
../client/src/tools/ls/sxls sx://localhost
# TODO: sxvol delete a volume

# Upload ok
../client/src/tools/cp/sxcp configure sx://localhost/vol1/x
# List ok
../client/src/tools/ls/sxls sx://localhost/vol1
# Download ok
rm -f x
../client/src/tools/cp/sxcp sx://localhost/vol1/x x

# Check permissions for normal user
../client/src/tools/init/sxinit --no-ssl --host-list=$1 sx://localhost <normal.auth
# Volume creation should fail
if ../client/src/tools/vol/sxvol create sx://localhost/vol1; then
    echo "Volume creation expected to fail"
    exit 1
fi
# Volume listing should succeed and list only our own volumes
../client/src/tools/ls/sxls sx://localhost
# TODO: check that only our own volumes are listed

# No permission to upload here
if ../client/src/tools/cp/sxcp configure sx://localhost/vol1/x; then
    echo "Upload expected to fail"
    exit 1
fi
# No permission to download either
rm -f x
if ../client/src/tools/cp/sxcp sx://localhost/vol1/x x; then
    echo "Download expected to fail"
    exit 1
fi
# No permission to resume either
cp configure x
if ../client/src/tools/cp/sxcp sx://localhost/vol1/x x; then
    echo "Download expected to fail"
    exit 1
fi
# Upload ok
../client/src/tools/cp/sxcp configure sx://localhost/vol2/x
# Download ok
../client/src/tools/cp/sxcp sx://localhost/vol2/x y
# Resume ok
../client/src/tools/cp/sxcp sx://localhost/vol2/x x

# List denied
if ../client/src/tools/ls/sxls sx://localhost/vol1; then
    echo "List expected to fail"
    exit 1
fi
# List ok
../client/src/tools/ls/sxls sx://localhost/vol2

# TODO: test delete

# Cannot grant myself permission to admin's volume
if ../client/src/tools/acl/sxacl volperm $OWNER --grant=read,write sx://localhost/vol1; then
    echo "Grant supposed to fail"
    exit 1
fi
# Grant permission to user2 on my volume
../client/src/tools/acl/sxacl volperm user2 --grant=read,write sx://localhost/vol2
../client/src/tools/acl/sxacl volshow sx://localhost/vol2

# User2
../client/src/tools/init/sxinit --no-ssl --host-list=$1 sx://localhost --auth-file normal2.auth

../client/src/tools/ls/sxls sx://localhost/vol2
../client/src/tools/cp/sxcp configure sx://localhost/vol2/z
../client/src/tools/cp/sxcp sx://localhost/vol2/z z

# Got write permission but cannot grant permissions to others!
if ../client/src/tools/acl/sxacl volperm admin --grant=read sx://localhost/vol2; then
    echo "Expected grant to fail"
    exit 1
fi
echo "All OK"
