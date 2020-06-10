#!/bin/sh

git submodule update --init --recursive

dir=$(pwd)

cd lib/libgcrypt-1.8.5/lib/ || exit 1
./autogen.sh
cd "$dir" || exit 1

cd lib/libgpg-error-1.37/lib/ || exit 1
./autogen.sh
cd "$dir" || exit 1

cd lib/libsodium-1.0.18/lib/ || exit 1
./autogen.sh
cd "$dir" || exit 1

cd lib/wolfSSL-4.3.0/lib/ || exit 1
./autogen.sh
cd "$dir" || exit 1