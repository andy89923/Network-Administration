2022 NYCU NA HW1
===
##### 2022.03.13
###### tags: `NA` `NYCU`

#### Account & Password for nasa-router and nasa-myagent
```
nasa-router
nasa
```

#### nasa-myagent
```
nasa-myagent
nasa
```

## WireGuard
```
$ sudo pkg install WireGuard
```
put `wg0.conf` in path */usr/local/etc/wireguard/wg0.conf*

```
[Interface]
...

[Peer]
...
```

```
$ sudo wg-quick up /usr/local/etc/wireguard/wg0.conf
```
Add the service in */etc/rc.conf*
```
wireguard_enable="YES"
wireguard_interfaces="wg0"
```
Test Connection
```
$ sudo service wireguard start
$ ping -c3 10.113.0.254
```

## DHCP Server

#### Install DHCP on FreeBSD
```
$ sudo pkg install isc-dhcp44-server
```

Enable DHCP server in ```/etc/rc.conf```
- IP of NAT: 172.16.{ID}.0
```
dhcpd_enable="yes"
dhcpd_flags="-q"
dhcpd_conf="/usr/local/etc/dhcpd.conf"
dhcpd_ifaces="em1"
dhcpd_withumask="022"

ifconfig_em1="inet 172.16.28.254 netmask 255.255.255.0"

gateway_enable="yes"
```

Restart Network Interfaces
```
$ service netif restart
```

Edit ```/usr/local/etc/dhcpd.conf``` config file
```nginx=
option domain-name "nycu.cs.edu.tw";
option domain-name-servers 8.8.8.8;

default-lease-time 600;
max-lease-time 7200;

ddns-update-style none;

subnet 172.16.28.0 netmask 255.255.255.0 {

        range 172.16.28.111 172.16.28.222;

        host agent {
                hardware ethernet 08:00:27:32:F1:90;
                fixed-address 172.16.28.123;
        }

        host myagent {
                hardware ethernet 08:00:27:B3:8B:4E;
                fixed-address 172.16.28.125;
        }
        option routers 172.16.28.254;
}
```
**"option router"** is for default gateway, to indicate the host who get ip via DHCP know the defult gateway.

#### DHCP log settings
Add the following settings in ```/etc/syslog.conf```
```
local7.* /var/log/dhcpd
```
```
$ sudo touch /var/log/dhcpd
$ sudo /etc/rc.d/syslogd reload
```

#### Start DHCP server
```
$ sudo /usr/local/etc/rc.d/isc-dhcpd start 
```


#### References
- [架設 DHCP 伺服器](https://www.weithenn.org/2012/05/freebsd-dhcp-server.html)

## NAT

#### Requirement


#### Packet Filter (PF

Add following lines in ```/etc/rc.conf```:
```
pf_enable="yes"           // 啟動 PF
pflog_enable="yes"        // 啟動 pflogd 功能
gateway_enable="yes"      // 啟動 LAN Gateway
```

Network Environment:
```
$ ifconfig
em0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
        options=481009b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM,VLAN_HWFILTER,NOMAP>
        ether 08:00:27:b3:68:37
        inet6 fe80::a00:27ff:feb3:6837%em0 prefixlen 64 scopeid 0x1
        inet 192.168.0.167 netmask 0xffffff00 broadcast 192.168.0.255
        media: Ethernet autoselect (1000baseT <full-duplex>)
        status: active
        nd6 options=23<PERFORMNUD,ACCEPT_RTADV,AUTO_LINKLOCAL>
em1: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
        options=481009b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM,VLAN_HWFILTER,NOMAP>
        ether 08:00:27:20:e7:83
        inet 172.16.28.254 netmask 0xffffff00 broadcast 172.16.28.255
        media: Ethernet autoselect (1000baseT <full-duplex>)
        status: active
        nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
        options=680003<RXCSUM,TXCSUM,LINKSTATE,RXCSUM_IPV6,TXCSUM_IPV6>
        inet6 ::1 prefixlen 128
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x3
        inet 127.0.0.1 netmask 0xff000000
        groups: lo
        nd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>
pflog0: flags=100<PROMISC> metric 0 mtu 33160
        groups: pflog
wg0: flags=80c1<UP,RUNNING,NOARP,MULTICAST> metric 0 mtu 1420
        options=80000<LINKSTATE>
        inet 10.113.28.1 netmask 0xffffffff
        groups: wg
        nd6 options=109<PERFORMNUD,IFDISABLED,NO_DAD>
```

Configuration file ```/etc/pf.conf```
```nginx=
# marco
ext_if='em0'
int_if='em1'
extvpn='wg0'
intranet='172.16.28.0/24'
vpnnet='10.113.0.0/16'

icmp_types = "{ 0, 3, 4, 8, 11, 12 }"

# Drop states as fast as possible without having excessively low timeouts
set optimization aggressive

# Block policy
set block-policy return

# Don't bother to process (filter) following interfaces such as loopback:
set skip on lo0

set loginterface $extvpn

# NAT
nat on $ext_if from $int_if:network to any -> $ext_if

block log all

# ICMP conections
pass in inet proto icmp to any keep state
pass out inet proto icmp to any keep state

# Allow DHCP
pass in on $ext_if inet proto udp to $ext_if port { 67, 68 }

# All out are same
pass out on { $ext_if, $extvpn } all keep state

# SSH
pass in inet proto tcp to { $int_if:network } port ssh keep state
pass out inet proto tcp to any port ssh keep state

# block in inet proto tcp to { "172.16.28.254", "10.113.28.1" } port ssh


# VPN
pass from $int_if to $extvpn keep state


# Local ssh
pass in inet proto tcp to $ext_if port ssh keep state
```

Start PF
```
$ sudo kldload pf
$ sudo pfctl -f /etc/pf.conf

$ sudo pfctl -sn  # check the rule now
```

#### References
- [PF-利用 PF 輕鬆達成 NAT](http://wiki.weithenn.org/cgi-bin/wiki.pl?PF-%E5%88%A9%E7%94%A8_PF_%E8%BC%95%E9%AC%86%E9%81%94%E6%88%90_NAT)
- [Generic NAT firewall pf config / template](https://forums.freebsd.org/threads/generic-nat-firewall-pf-config-template.60144/)
- [章 30. 防火牆](https://docs.freebsd.org/zh-tw/books/handbook/firewalls/)