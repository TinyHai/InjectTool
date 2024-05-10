#!/bin/bash

cross build --target aarch64-linux-android --release
cross build --target armv7-linux-androideabi --release
cross build --target i686-linux-android --release
cross build --target x86_64-linux-android --release