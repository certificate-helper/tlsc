#!/bin/sh

OPENSSL_VERSION="1.1.1d"
rm -rf openssl-${OPENSSL_VERSION}
curl "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" | tar -xzf -
cd openssl-${OPENSSL_VERSION}
./config -no-shared -no-async -no-asm
make -sj`nproc`
cp libcrypto.a libssl.a ../src/
rm -rf ../src/include/openssl
mkdir -p ../src/include/
mv include/openssl ../src/include/openssl
cd ../
rm -rf openssl-${OPENSSL_VERSION}
