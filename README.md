# Simple TUN/TAP Tunnel
Create a simple tun/tap tunnel on linux system to share network.

# Requirement
* [libev](http://software.schmorp.de/pkg/libev.html)
* [mbedcrypto](https://github.com/ARMmbed/mbed-crypto)

# Build
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j2
```

# Usage
1. On host 1, run this command as root:
```bash
$ ./simple_tun -l 0.0.0.0 2020
Random password: q8_MGv2Jthj9oDscbdiaSp
```

2. On host 2, run this command as root:
```bash
$ ./simple_tun -s q8_MGv2Jthj9oDscbdiaSp host1_ip 2020
```
*host1_ip* is the ip address of host 1

3. Then you will get a tap device on both host 1 and host 2.

You can config the tap device as you need.
For example, config ip address manually:
```bash
# Host 1
$ ip link set tap0 up
$ ip addr add 192.168.20.20/31 dev tap0

# Host 2
$ ip link set tap0 up
$ ip addr add 192.168.20.21/31 dev tap0
```
And you can enable iptables' NAT to share the 3rd layer network environment:
```bash
$ iptables -t nat -A POSTROUTING -o eth0 -s 192.168.20.20/31 -j MASQUERADE
```
(Don't forget to turn on ip_forward in sysctl)

Or you can add the tap device into a bridge, and share the 2nd layer network
environment.
```bash
$ ip link set tap0 master br0
```
*br0* is the network bridge.

# Troubleshooting
## Behind NAT
If both two host behind a NAT device, udp_relay can help you connect each of
them.
1. Run udp_relay on a host which can connect to internet without nat. 
```bash
$ ./udp_relay 0.0.0.0 2020
```
2. Run simple tun
```
# Host 1
$ ./simple_tun relay_ip 2020
Random password: q8_MGv2Jthj9oDscbdiaSp

# Host 2
$ ./simple_tun -s q8_MGv2Jthj9oDscbdiaSp relay_ip 2020
```
The *relay_ip* is the ip address of the host that appeared in the 1st step.

3. If no network data is transmitted for too long, the nat device may
close your UDP port.
You can run a ping utility to keep the udp port usable.
```bash
$ ping -i 10 192.168.20.20
```
*192.168.20.20* is the ip address of the other side.

## No TAP device
Some Linux system do not enable tap driver. 
You can try TUN driver on these system by adding the '-u' option on both
 side.
But please note, TUN is a 3rd layer network device. It is unable to
share 2nd layer network information on it. So you are unable to join the
tun device into a network bridge.

# License
BSD-3-Clause