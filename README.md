Make a network unresponsive using ARP and ND poisoning

# How it works
This attack continously sends spoofed ARP packets (using [scapy](https://github.com/secdev/scapy)) to every host on the network, poisoning its ARP table. </br>
What this achieves is that the gateway (and any other destination the host tried to interact with inside the network) is mapped to an incorrect MAC address and therefore the traffic never reaches its true destination, making the network unresponsive. </br>
Furthermore, the gateway also receives an ARP packet from each host that contains a spoofed MAC address.
</br></br>
For IPv6 networks, it is possible to send spoofed RA packets to every host on the local link, which would poison the ND cache.


# Requirements
### OS
This works on every OS. </br>
The only difference would be in the output, which in LINUX OS would refresh the same line to log updates rather than printing new lines in other operating systems.

### 3rd libraries
3rd party libraries can be installed by running the following command: `pip3 install -r requirements.txt` as they are listed inside the requirements file:
```python
scapy~=2.4.5
```
# Usage

## Poisoning ARP Cache (IPv4)

The network interface (can be derived from `ifconfig`) is a mandatory param and should always be passed, for example: 
```bash
./arpwarp.py -i eth0
```

### Setting cidr length
The default cidr length is `24` since it is the one most commonly used, but can be set by defining the `-m, --set-cidrlen` argument.

### Setting custom gateway
In case something goes wrong and the gateway ip cannot be automatically set, a custom one can be set by defining the `-g, --set-gateway` argument.

## Spoofing Router Advertisement Packets (IPv6)
It is also possible to spoof RA packets in case the network uses IPv4 which does not implement an ARP mechanism. <br/>
This can be enabled by simply passing `-6, --spoof-ipv6nd`, for example:
```bash
./arpwarp.py -i eth0 --spoof-ipv6nd
```

### Setting preflen
The default (and most commonly used) IPv6 preflen is `64`, in order to set a different one passing `-pl, --set-preflen` should do the trick.


# Mitigation
* Dynamic ARP Inspection
* Encryption
* Static ARP table

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
