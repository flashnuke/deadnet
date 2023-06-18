# Deadnet APK

An Android app that runs Deadnet. </br> 
The APK is stored inside [bin](https://github.com/flashnuke/deadnet/tree/new_apk/apk/bin) directory, but it can be built as well since all the source files are included in the repo.
</br>The parts that are supposed to open network sockets and send the spoofed packets were written in C++ and compiled into binaries that are run by the Pythonic app.

# Requirements
* Phone must be rooted


# Building
Steps to build the app manually.

### Compiling the C++ Binaries
The C++ binaries source code files (`src/arp.cpp` for the ARP poisoning and `src/nra.cpp`) should be compiled by NDK:
```bash
cd deadnet/apk

$NDK_PATH/bin/aarch64-linux-android29-clang++ -static -o assets/nra.arm64 src/nra.cpp
$NDK_PATH/bin/armv7a-linux-androideabi29-clang++ -static -o assets/nra.arm src/nra.cpp
$NDK_PATH/bin/i686-linux-android29-clang++ -static -o assets/nra.x86 src/nra.cpp
$NDK_PATH/bin/x86_64-linux-android29-clang++ -static -o assets/nra.x86_64 src/nra.cpp

$NDK_PATH/bin/aarch64-linux-android29-clang++ -static -o assets/arp.arm64 src/arp.cpp
$NDK_PATH/bin/armv7a-linux-androideabi29-clang++ -static -o assets/arp.arm src/arp.cpp
$NDK_PATH/bin/i686-linux-android29-clang++ -static -o assets/arp.x86 src/arp.cpp
$NDK_PATH/bin/x86_64-linux-android29-clang++ -static -o assets/arp.x86_64 src/arp.cpp

# NDK_PATH example: "NDK_PATH=/home/ubuntu/my-android-toolchain"
```

### Building the APK
```bash
cd deadnet/apk
buildozer android debug # build in debug mode
```
