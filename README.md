Make a network unresponsive using ARP and ND poisoning </br>
![image](https://user-images.githubusercontent.com/59119926/184541147-8268eed5-e375-4915-8e59-ea1388522551.png)


# How it works
This attack continously sends spoofed ARP packets (using [scapy](https://github.com/secdev/scapy)) to every host on the network, poisoning its ARP table. </br>
What this achieves is that the gateway (and any other destination the host tried to interact with inside the network) is mapped to an incorrect MAC address and therefore the traffic never reaches its true destination, making the network unresponsive. </br>
Furthermore, the gateway also receives an ARP packet from each host that contains a spoofed MAC address.
</br></br>
For IPv6 networks, it is possible to send spoofed RA packets to every host on the local link, which would poison the ND cache.</br></br>
An illustration of running the attacker from a phone with kali (nethunter): <br>
![image](https://user-images.githubusercontent.com/59119926/184541502-1f58709b-b970-4ff4-aa25-9f783fff332f.png)


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


### Setting default hosts list
It is possible to pass a default hosts list for the IPv6 ND spoof if the desires targets are not found by the ping scans by simply setting `-sh", --set-hosts` as the filepath to the list.

# Notes
* When using `IPv6 ND spoofing`, the hosts list is refreshed every once in a while by pinging the network.</br>Old hosts will remain, and new ones will be appended, so if a ping scan yields no hosts old ones will be targeted anyway.
* Passing a default IPv4 hosts is not possible (unlike IPv6) since the IPv4 subnet will be poisoned entirely.


# Mitigation
* Dynamic ARP Inspection
* Encryption
* Static ARP table

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
