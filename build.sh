#!/bin/bash

declare -A MAP=(
  ['aarch64-linux-android']='arm64-v8a'
  ['armv7-linux-androideabi']='armeabi-v7a'
  ['i686-linux-android']='x86'
  ['x86_64-linux-android']='x86_64'
)

set -x
if [[ -d out ]]; then
  rm -rf out
fi

mkdir out

for abi in "${MAP[@]}"
do
  mkdir out/$abi
done

for target in "${!MAP[@]}"
do
  cross build --target $target --release
  cp target/$target/release/inject_tool out/${MAP[$target]}/libinject_tool.so
done

set +x