#!/usr/bin/env sh

#check and clone testu01 if not exists
if [ ! -d "testu01" ]; then
  git clone git@github.com:umontreal-simul/TestU01-2009.git testu01
fi
# clean up old test
rm -f prng_test
rm -rf testu01/dist
cd testu01
chmod +x configure install-sh
./configure --prefix=$PWD/dist
make
make install
cd ..
go build -o prng_test .
chmod +x prng_test
./prng_test
