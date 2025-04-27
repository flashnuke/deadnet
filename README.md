![image](https://user-images.githubusercontent.com/59119926/201936090-065e1301-6edd-4e1c-9ed7-aba5b75f5fd5.png)


</br></br>
Make a wireless network unresponsive
* Tested on Kali Nethunter
* Works for both IPv6 and IPv4

# How it works
### IPv6
In IPv6, the ARP mechanism was ditched due to several reasons, one of them being lack of security. </br>
Instead there is `Neighbor/Router Discovery Protocol`, which will be exploited in this attack. </br>
[For more info about how IPV6 router discovery mechanism works](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol#Functions)</br>

**Dead router attack** - this attack periodically sends a spoofed RA (router discovery) packet with the gateway's lladdr to the multicast address on the local link, which signals that the router is dead. This would prevent the hosts from forwarding traffic to the gateway. Furthermore, a [scapy](https://github.com/secdev/scapy) method is running on a separate thread in the background, sniffing traffic. It immediately invalidates all incoming RA packets from routers by sending spoofed ones that indicate the router is not operational (`routerlifetime=0`). </br>

### IPv4
**ARP attack** - continuously sends spoofed ARP packets (using [scapy](https://github.com/secdev/scapy)) to every host on the network, poisoning its ARP table. </br>
The gateway is mapped to an incorrect MAC address and therefore the traffic never reaches its true destination, making the network unresponsive. </br>
Furthermore, the gateway also receives an ARP packet from each host that contains a spoofed MAC address.
</br>
### Wifi-Deauth
There's another way to make a perform a DoS attack on wireless networks, WITHOUT HAVING CREDENTIALS, and that is by sending de-auth packets.</br>
I have a separate project for that [here](https://github.com/flashnuke/wifi-deauth) and it requires a network adapter that supports packet injection. </br>
If no credentials are present and you insist on using Deadnet, it's possible to run a dictionary-attack using a [wordlist](https://github.com/flashnuke/pass-generator) in combination with another tool that cracks Wifi handshakes to gain credentials first.

# Android APP
<p align="center"><img src="https://github.com/flashnuke/deadnet/assets/59119926/fbb72f10-764c-4272-aa8c-8623f34b8ba2" width="350" ></p>

An Android APP designed to run Deadnet directly on rooted devices using a simple GUI with a couple of buttons. </br>
See [the APK section](https://github.com/flashnuke/deadnet/tree/main/apk) for more.

# Requirements
### OS
Works on every OS. </br>
The only difference would be in the output, which in LINUX OS would refresh the same line to log updates rather than printing new lines in other operating systems.

### VM
Beware that if running from a VM, the network should be set to `Bridged`

### Dependencies
3rd party libraries can be installed by running the following command: `pip3 install -r requirements.txt` as they are listed inside the requirements file:
```python
scapy~=2.4.5
```
# Usage
## Installation
```bash
git clone https://github.com/flashnuke/deadnet.git
cd deadnet
pip3 install -r requirements.txt
```

## Poisoning ARP Cache (IPv4)
The network interface is a mandatory param and should always be passed, for example (`eth0` is the most commonly used in kali): 
```bash
./deadnet.py -i eth0
```

* Setting cidr length
The default cidr length is `24` since it is the one most commonly used, but can be set by defining the `-m, --set-cidrlen` argument.

* Setting custom gateway
In case something goes wrong and the gateway ip cannot be automatically set, a custom one can be set by defining the `-g, --set-gateway` argument.

## Spoofing Router Advertisement Packets (IPv6)
As mentioned before, it is possible to spoof RA packets in case the network supports IPv6. <br/>
This attack is enabled automatically, and can be disabled by passing `-6, --disable-ipv6`, for example:
```bash
./deadnet.py -i eth0 --disable-ipv6
```

* Setting preflen
The default (and most commonly used) IPv6 preflen is `64`, in order to set a different one passing `-pl, --set-preflen` should do the trick.

# Notes
* No buffer space available exception </br>
If the following exception occurs: ```Errno 105 No Buffer Space Available```
simply increase the buffer size by running this command -> `sudo ifconfig <net_interface> txqueuelen 100000` where `net_interface` is the network interface name. </br>

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
