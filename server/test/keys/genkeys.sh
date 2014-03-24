#!/bin/sh
set -e
rm -f *.pem *.key *.csr *.srl trust/*.pem
# Self-signed cert
openssl req -x509 -config cluster1.conf -new -keyout cluster1.key -out cluster1.pem -days 36500

# Self-signed CA
openssl req -x509 -config rootca.conf -new -keyout rootca.key -out trust/rootca.pem -days 36500
c_rehash trust/

CA=trust/rootca.pem
CAKEY=rootca.key
CASERIAL=root.srl
# Sign intermediate CA
openssl req -config midca.conf -new -keyout midca.key -out midca.csr
openssl x509 -extfile midca.ext -req -days 36500 \
        -in midca.csr -CAcreateserial -CAserial $CASERIAL  -CA $CA -CAkey $CAKEY\
        -out midca.pem

openssl verify -verbose -CApath trust/ midca.pem
# Sign final cert
# cert1 is signed by root CA
# cert2..N are signed by intermediate CA
for name in cert1 cert2 cert3 cert4; do
    openssl req -config cluster2$name.conf -new -keyout cluster2$name.key -out cluster2$name.csr
    openssl x509 -extfile cluster2$name.ext -req -days 36500 \
        -in cluster2$name.csr -CAcreateserial -CAserial $CASERIAL  -CA $CA -CAkey $CAKEY\
        -out cluster2$name.pem
    if [ $CA = midca.pem ]; then 
        cat $CA >>cluster2$name.pem
        if [ $name = "cert2" ]; then
            cat trust/rootca.pem >>cluster2$name.pem
        fi
    fi
    CA=midca.pem
    CAKEY=midca.key
    CASERIAL=midca.srl
done
# TODO: create some invalid certs too: intermediate CA pathlen=0 signing another
# CA, CA:false cert signing another cert, etc.
rm -f *.csr *.srl *ca.key midca.pem
openssl verify -verbose -CApath trust/ cluster2cert1.pem
openssl verify -verbose -CApath trust/ -untrusted cluster2cert2.pem cluster2cert2.pem
openssl verify -verbose -CApath trust/ -untrusted cluster2cert3.pem cluster2cert3.pem
openssl verify -verbose -CApath trust/ -untrusted cluster2cert4.pem cluster2cert4.pem
