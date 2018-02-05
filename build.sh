#!/usr/bin/bash
CURRENT=$(pwd)
rm -rf ./xmss-reference
rm -rf ./cmake-build-debug
git clone --depth=1 https://github.com/veritas-shine/xmss-reference.git
mkdir -p cmake-build-debug
cd cmake-build-debug
cmake .. && make
