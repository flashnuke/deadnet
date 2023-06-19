# Deadnet APK
<p align="center"><img src="https://github.com/flashnuke/deadnet/assets/59119926/fbb72f10-764c-4272-aa8c-8623f34b8ba2" width="350" ></p>
A simple GUI that runs Deadnet directoy on an Android device. </br>
The APK is stored inside [bin](https://github.com/flashnuke/deadnet/tree/new_apk/apk/bin) directory, but it can be built manually as well.
</br>The code that is supposed to open network sockets and send the spoofed packets is written in C++ and compiled into native binaries that are run explicitly by the Python app.

# Requirements
* Device must be rooted
* Most modern devices are ARM64. The native binaries are compiled for the following machine architecture types: (ARM, ARM64, x86, x86_64), see the building section in order to compile for a different architecture type and modify the code accordingly


# Building
Steps to build the app manually. </br>
The following tools are required:
* NDK tools
* Buildozer and Kivy library

### Compiling the C++ Binaries
The C++ binaries source code files (`src/arp.cpp` for the ARP poisoning and `src/nra.cpp` for the dead router attack) should be compiled by NDK:
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

# Notes
### Permissions
* Some parts were compiled into native binaries due to lack of permissions to open raw sockets by the Python interpreter on Android (even when root)
* `ACCESS_FINE_LOCATION` permission is requested in order to access the SSID (wifi network name)


# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
