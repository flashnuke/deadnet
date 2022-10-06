# ArpWarp
Make a local network unresponsive </br>

# How it works
For IPv4, this attack continuously sends spoofed ARP packets (using [scapy](https://github.com/secdev/scapy)) to every host on the network, poisoning its ARP table. </br>
The gateway is mapped to an incorrect MAC address and therefore the traffic never reaches its true destination, making the network unresponsive. </br>
Furthermore, the gateway also receives an ARP packet from each host that contains a spoofed MAC address.
</br></br>
For IPv6 networks, this attack periodically sends a spoofed RA packet with the gateway's lladdr to the multicast address on the local link, which would signal the router is dead. This would prevent the hosts from forwarding traffic to the gateway. Furthermore, a [scapy](https://github.com/secdev/scapy) method is running on a separate thread in the background, sniffing traffic. It immediately invalidates all incoming RA packets from routers by sending spoofed ones that indicate the router is not operational (`routerlifetime=0`). </br></br>


# Requirements
Works on every OS. </br>
The only difference would be in the output, which in LINUX OS would refresh the same line to log updates rather than printing new lines in other operating systems.

3rd party libraries can be installed by running the following command: `pip3 install -r requirements.txt` as they are listed inside the requirements file:
```python
scapy~=2.4.5
```
# Usage

## Poisoning ARP Cache (IPv4)

The network interface is a mandatory param and should always be passed, for example (`eth0` is the most commonly used in kali): 
```bash
./arpwarp.py -i eth0
```

* Setting cidr length
The default cidr length is `24` since it is the one most commonly used, but can be set by defining the `-m, --set-cidrlen` argument.

* Setting custom gateway
In case something goes wrong and the gateway ip cannot be automatically set, a custom one can be set by defining the `-g, --set-gateway` argument.

## Spoofing Router Advertisement Packets (IPv6)
As mentioned before, it is possible to spoof RA packets in case the network uses IPv6 which does not implement an ARP mechanism. <br/>
This can be enabled by simply passing `-6, --spoof-ipv6ra`, for example:
```bash
./arpwarp.py -i eth0 --spoof-ipv6nd
```

* Setting preflen
The default (and most commonly used) IPv6 preflen is `64`, in order to set a different one passing `-pl, --set-preflen` should do the trick.

# Notes
* No buffer space avilable exception
If the following exception occurs: ```Errno 105 No Buffer Space Available```
simply increase the buffer size by running this command -> `sudo ifconfig "net_interface" txqueuelen 100000`. </br>

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.

# Preview
The screenshots illustrate this attack running from a kali nethunter phone, and from a windows terminal. </br> </br> 
<img width="268" alt="image" src="https://user-images.githubusercontent.com/59119926/184556919-e8b286b4-6207-4c13-b791-5ec2744927c1.png"></br> </br> </br> </br>
<img width="301" alt="image" src="https://user-images.githubusercontent.com/59119926/184553797-ad7050a9-6455-45d1-b00f-b1ae5c90e8aa.png">


