Make the network unresponsive using mass ARP poisoning

# How it works
This attack continously sends spoofed ARP packets (using [scapy](https://github.com/secdev/scapy)) to every host on the network, poisoning its ARP table. </br>
What this achieves is that the gateway (and any other destination the host tried to interact with inside the network) is mapped to an incorrect MAC address and therefore the traffic never reaches its true destination, making the network unresponsive.

# Usage

## Poisoning ARP Cache (IPv4)

The network interface (can be derived from `ifconfig`) is a mandatory param and should always be passed, for example: 
```
./arpwarp.py -i eth0
```

### Setting cidr length
The default cidr length is `24` since it is the one most commonly used, but can be set by defining the `-m, --set-cidrlen` argument.

### Setting gateway (IPv4)
In case something goes wrong and the gateway ip cannot be automatically set, a custom one can be set by defining the `-g, --set-gateway` argument.

## Spoofing Router Advertisement Packets (IPv4)
It is also possible to spoof RA packets in case the network uses IPv4 which does not implement an ARP mechanism.


# Mitigation
These kinds kind of attacks where ARP packets are spoofed can be mitigated by using a static ARP table.

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
