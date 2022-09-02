2022 NYCU NA HW2
===
##### 2022.03.26
###### tags: `NA` `NYCU`

### 2 Another VMs
|   VM Name    | user_name | password |
|:------------:|:---------:|:--------:|
|  dns_master  |    ns1    |   ****   |
|  dns_slave   |    ns2    |   ****   |
| dns_resolver | resolver  |   ****   |


### DNS_router 
Edit ```/usr/local/etc/dhcpd.conf``` config file
```nginx=
option domain-name-servers ns2.28.nasa;

subnet 172.16.28.0 netmask 255.255.255.0 {
    range 172.16.28.111 172.16.28.222;
    range 172.16.28.1 172.16.28.2;
    
    option routers 172.16.28.254;
}
host agent {
    hardware ethernet 08:00:27:32:F1:90;
    fixed-address 172.16.28.123;
}
host myagent {
    hardware ethernet 08:00:27:B3:8B:4E;
    fixed-address 172.16.28.125;
}
host ns1 {    
    hardware ethernet 08:00:27:1E:A2:F0;
    fixed-address 172.16.28.1;  
}
host ns2 {    
    hardware ethernet 08:00:27:A4:09:27;
    fixed-address 172.16.28.2;  
}
host resolver {
    hardware ethernet 08:00:27:5F:92:F8;
    fixed-address 172.16.28.10;
}
```
#### ReStart DHCP server
```
$ sudo /usr/local/etc/rc.d/isc-dhcpd restart 
```


Add PF rule in ```/etc/pf.conf```
```nginx=
# DNS rule
pass in on $ext_if proto { tcp, udp } from any to any port { 53, 80 } keep state
# pass in on $extvpn proto { tcp, udp } from any to any port { 53, 80 } keep state
```
Reload
```
$ sudo kldload pf
$ sudo pfctl -f /etc/pf.conf
$ sudo pfctl -sn  # check the rule now
```

## Install packages

#### ns1 & ns2
```
$ sudo pkg install bind916
$ sudo pkg install dns/bind-tools
$ sudo pkg install bind-tools
```
In ```/etc/rc.conf```:
```
named_enable="yes"
```

#### bind9 Logging
In config file ```/usr/local/etc/namedb/named.conf```
```nginx
logging {
        channel security-log {
                file "/var/named/security.log" versions 5 size 10m;
                severity info;
                print-severity yes;
                print-time yes;
        };
        channel query-log {
                file "/var/named/query.log" versions 20 size 50m;
                severity info;
                print-severity yes;
                print-time yes;
        };

        category default { query-log; };
        category general { query-log; };
        category security { security-log; };
        category client { query-log; };
        category queries { null; };
        category dnssec { security-log; };
};
```
##### Remember to give permission to log file
```
$ sudo mkdir /var/named
$ sudo touch /var/named/security.log
$ sudo touch /var/named/query.log
```

#### Start bind9
```
$ sudo service named start
$ rndc { stop | reload | flush ... }
```


## DNS Master (ns1)

Config fire```/usr/local/etc/namedb/named.conf```

#### Option
```nginx
options {
        directory       "/usr/local/etc/namedb/working";
        pid-file        "/var/run/named/pid";
        dump-file       "/var/dump/named_dump.db";
        statistics-file "/var/stats/named.stats";

        listen-on       { any; };
        allow-query     { 127.0.0.1; 10.113.0.0/16; 172.16.28.0/24; };
        allow-transfer  { };
        recursion no;
        notify yes;
        allow-notify { 172.16.28.0/24; };
        version "Name Server 1";

        provide-ixfr no;
};
```

#### View
```nginx=
view "local" {
        match-clients { 172.16.28.0/24; };
        allow-query { any; };
        zone "." {
                type hint;
                file "/usr/local/etc/namedb/named.ca";
        };

        zone "28.nasa" {
                type master;
                file "/usr/local/etc/namedb/28.nasa_local";

                also-notify { 172.16.28.2; 172.16.28.123; };
                allow-transfer { 172.16.28.2; 172.16.28.123; };
        };
        zone "28.16.172.in-addr.arpa" {
                type master;
                file "/usr/local/etc/namedb/28.16.172.in-addr.arpa";

                also-notify { 172.16.28.2; 172.16.28.123; };
                allow-transfer { 172.16.28.2; 172.16.28.123; };
        };
};

view "intra" {
        match-clients { any; };
        allow-query { any; };

        zone "." {
            type hint;
            file "/usr/local/etc/namedb/named.ca";
        };

        zone "28.nasa" {
            type master;
            file "/usr/local/etc/namedb/28.nasa_intra";

            also-notify { 172.16.28.2; 172.16.28.123; };
            allow-transfer { 172.16.28.2; 172.16.28.123; };
        };
        zone "28.16.172.in-addr.arpa" {
            type master;
            file "/usr/local/etc/namedb/28.16.172.in-addr.arpa";

            also-notify { 172.16.28.2; 172.16.28.123; };
            allow-transfer { 172.16.28.2; 172.16.28.123; };
        };
};
```

#### named.ca
file -> ```/usr/local/etc/namedb/named.ca```
```nginx
$TTL 86400
$ORIGIN .

@       IN    SOA    .    root. (
                     2019111001        ; Serial Number
                     1M                ; Slave refresh
                     2M                ; retry
                     365W              ; expire
                     86400 )

        IN    NS     nasa.
        IN    NS     ta.nasa.

ta      IN    A      172.16.254.1
```

#### 28.nasa_local
:::info
Local (172.16.{ID}.0/24) 
:::
:::danger
Serial Number 代表 zone file 版本
Slave 會根據 Serial Number 來決定要不要進行 zone transfer

啟用 Slave 之後，一旦更新 zone file，就要改變(增加) Serial Number
:::

28.nasa_local -> ```/usr/local/etc/namedb/28.nasa_local```
```nginx=
$TTL 86400
$ORIGIN 28.nasa.

@       IN    SOA    28.nasa. root.28.nasa (
                     2022032915         ; Serial Number
                     1M                 ; Slave refresh
                     2M                 ; retry
                     365W               ; expire
                     86400 )

        IN    NS     ns.28.nasa.
        IN    NS     ns1.28.nasa.
        IN    NS     ns2.28.nasa.

ns      IN     A     172.16.28.2
ns1     IN     A     172.16.28.1
ns2     IN     A     172.16.28.2
agent   IN     A     172.16.28.123
router  IN     A     172.16.28.254
resolver IN    A     172.16.28.10
nasa    IN  CNAME   nasa.cs.nctu.edu.tw.

$ORIGIN nasa.
28      IN     A     172.16.28.2
```

#### 28.16.172.in-addr.arpa
28.16.172.in-addr.arpa -> ```/usr/local/etc/namedb/28.16.172.in-addr.arpa```
```nginx
$TTL 86400
$ORIGIN 28.16.172.in-addr.arpa.
@       IN    SOA    28.nasa. root.28.nasa (
                     2022032912         ; Serial Number
                     1M                 ; Slave refresh
                     2M                 ; retry
                     365W               ; expire
                     86400 )

        IN    NS     ns.28.nasa.
        IN    NS     ns1.28.nasa.
        IN    NS     ns2.28.nasa.


$ORIGIN in-addr.arpa.
123.28.16.172  IN  PTR  agent.28.nasa.
2.28.16.172    IN  PTR  ns2.28.nasa.
1.28.16.172    IN  PTR  ns1.28.nasa.
254.28.16.172  IN  PTR  router.28.nasa.
10.28.16.172   IN  PTR  resolver.28.nasa.
10.254.16.172  IN  PTR  test.28.nasa.
```

#### 28.nasa_intra

28.nasa_intra -> ```/usr/local/etc/namedb/28.nasa_intra```
```nginx=
$TTL 86400
$ORIGIN 28.nasa.

@       IN    SOA    28.nasa. root.28.nasa (
                     2022032909         ; Serial Number
                     1D                 ; Slave refresh
                     1M                 ; retry
                     3W               ; expire
                     86400 )

        IN    NS     ns1.28.nasa.
        IN    NS     ns2.28.nasa.

ns1     IN     A     172.16.28.1
ns2     IN     A     172.16.28.2
agent   IN     A     172.16.28.123
router  IN     A     10.113.28.1
resolver IN    A     172.16.254.10
nasa    IN   CNAME   nasa.cs.nctu.edu.tw.

$ORIGIN nasa.
28      IN     A     172.16.28.1
```


## DNS Slave (ns2)
Config fire```/usr/local/etc/namedb/named.conf```

#### Option
```nginx
options {
        directory       "/usr/local/etc/namedb/working";
        pid-file        "/var/run/named/pid";
        dump-file       "/var/dump/named_dump.db";
        statistics-file "/var/stats/named.stats";

        listen-on       { any; };
        allow-query     { 172.16.28.0/24; };
        allow-transfer  { 172.16.28.123;  };

        recursion yes;
        allow-recursion { 172.16.28.0/24; };
        allow-query-cache { any;};
        forwarders {
                8.8.8.8;
        };
        dnssec-validation no;

        notify yes;
        allow-notify { 172.16.28.0/24; };

        version "Name Server 2";
        request-ixfr yes;
        provide-ixfr no;
};
```

#### Zone
```nginx
view "local" {
        match-clients { 172.16.28.0/24; };
        allow-query { any; };

        zone "." {
                type hint;
                file "/usr/local/etc/namedb/named.ca";
        };

        zone "28.nasa" {
                type slave;
                file "/usr/local/etc/namedb/28.nasa_local";

                masters { 172.16.28.1; };

                transfer-source 172.16.28.2;
        };

        zone "28.16.172.in-addr.arpa" {
                type slave;
                file "/usr/local/etc/namedb/28.16.172.in-addr.arpa";

                masters { 172.16.28.1; };

                transfer-source 172.16.28.2;
        };
};

view "intra" {
        match-clients { 10.113.0.0/16; };
        allow-query { any;  };

        zone "." {
                type hint;
                file "/usr/local/etc/namedb/named.ca";
        };
        zone "28.nasa" {
                type slave;
                file "/usr/local/etc/namedb/28.nasa_intra";

                masters { 172.16.28.1; };
                transfer-source 172.16.28.2;
        };

        zone "28.16.172.in-addr.arpa" {
                type slave;
                file "/usr/local/etc/namedb/28.16.172.in-addr.arpa_intra";

                masters { 172.16.28.1; };

                transfer-source 172.16.28.2;
        };
};
```

### Bonus: Bonus_AO_VerLimitLocal
In both ns1 and ns2
```
view "chaos" CH {
        match-clients { 10.113.0.0/16; };
        allow-query { };

        zone "bind" ch {
                type master;
                file "db.bind";
                allow-update { none; };
        };
};
```


## DNSSEC
    
#### SSHFP (SSH Finger Print)
[Reference](https://unix.stackexchange.com/questions/121880/how-do-i-generate-sshfp-records)
    
```
$ ssh-keyscan -D agent.28.nasa
; agent.28.nasa:22 SSH-2.0-OpenSSH_8.4
agent.28.nasa IN SSHFP 3 1 632ccce8a13872ada40738d98f01ff4a0985c178
agent.28.nasa IN SSHFP 3 2 d8f01205929813e84339cb2d3b5f69da1caf1090ac8ad38079ca9fdf754ed383
; agent.28.nasa:22 SSH-2.0-OpenSSH_8.4
agent.28.nasa IN SSHFP 1 1 528ac02e3debe9d93febed6426dad6fe3c11029b
agent.28.nasa IN SSHFP 1 2 e03fa9c465e00a6027e49665ee14042717d2a784f515050d5ca5c0ac197db79a
; agent.28.nasa:22 SSH-2.0-OpenSSH_8.4
agent.28.nasa IN SSHFP 4 1 325077eeb664473458a7f0d146f3be0023fc5f0a
agent.28.nasa IN SSHFP 4 2 ab5c8d6065398e3faef6ecd87142ad9db66930fc098de0a997d1edab48f0554a
```
We need:
```
agent IN SSHFP 1 2 e03fa9c465e00a6027e49665ee14042717d2a784f515050d5ca5c0ac197db79a
agent IN SSHFP 3 2 d8f01205929813e84339cb2d3b5f69da1caf1090ac8ad38079ca9fdf754ed383
agent IN SSHFP 4 2 ab5c8d6065398e3faef6ecd87142ad9db66930fc098de0a997d1edab48f0554a
```
Check
```
$ dig SSHFP agent.28.nasa
$ ssh -o "VerifyHostKeyDNS=yes" -o "FingerprintHash=sha256" agent.28.nasa
```


### ns1
[How To Setup DNSSEC on an Authoritative BIND DNS Server](https://www.digitalocean.com/community/tutorials/how-to-setup-dnssec-on-an-authoritative-bind-dns-server-2)
[DNSSEC Guide - Bind9](https://bind9.readthedocs.io/en/latest/dnssec-guide.html)
#### Generate KSK (key signing key)
```
$ sudo dnssec-keygen -3 -a RSASHA256 -b 2048 -f KSK -n ZONE 28.nasa 

K28.nasa.+008+40999
```

#### Generate ZSK (zone signing key)
```
$ sudo dnssec-keygen -3 -a RSASHA256 -b 2048 -n ZONE 28.nasa 

K28.nasa.+008+53449
```


#### Sign Zone using ZSK
```
$ sudo cp 28.nasa_local 28.nasa_local.dnssec
$ sudo cp 28.nasa_intra 28.nasa_intra.dnssec
```
Add the following lines in ```28.nasa_local.dnssec``` and ```28.nasa_intra.dnssec```
```
$INCLUDE K28.nasa.+008+40999.key ; KSK
$INCLUDE K28.nasa.+008+53449.key ; ZSK
```

dnssec-signzone -3 <salt> -A -o <zonename> -t -k <KSK> <zonefilename> <ZSK> 
```
$ sudo dnssec-signzone -3 140113 -o 28.nasa -t -k K28.nasa.+008+40999 28.nasa_local.dnssec K28.nasa.+008+53449
$ sudo dnssec-signzone -3 140113 -o 28.nasa -t -k K28.nasa.+008+40999 28.nasa_intra.dnssec K28.nasa.+008+53449
```

Change the zone file to ```*.dnssec.signed```
    
    
Test result:
```
$ dig agent.28.nasa @172.16.28.1 +dnssec
```
    
DS record in ```dsset-28.nasa.```
```
$ cat dsset-28.nasa.
28.nasa.  IN DS 40999 8 2 F03E89C63021DEFA61508D182EECBB2062C6F9FE591867BB8C29BC3A E3E5FF61
```

Script to resign the zone file: ```/usr/local/etc/namedb/reassign.sh```
```shell=
#!/bin/sh
sudo cp 28.nasa_intra 28.nasa_intra.dnssec
sudo cp 28.nasa_local 28.nasa_local.dnssec
sudo dnssec-signzone -3 140113 -o 28.nasa -t -k K28.nasa.+008+40999 28.nasa_local.dnssec K28.nasa.+008+53449
sudo dnssec-signzone -3 140113 -o 28.nasa -t -k K28.nasa.+008+40999 28.nasa_intra.dnssec K28.nasa.+008+53449
sudo rndc reload
```
    

## Local Resolver
```nginx=
options {
        directory       "/usr/local/etc/namedb/working";
        pid-file        "/var/run/named/pid";
        dump-file       "/var/dump/named_dump.db";
        statistics-file "/var/stats/named.stats";

        listen-on       { any; };
        allow-query     { 127.0.0.1; 172.16.28.0/24; 10.113.0.0/24; };
        allow-transfer  { };


        recursion yes;
        allow-query-cache { 127.0.0.1; 172.16.28.0/24; 10.113.0.0/24; };
        forwarders {
                8.8.8.8;
                172.16.254.11;
                172.16.254.1;
                172.16.28.1;
        };
        notify yes;
        allow-notify { 172.16.28.0/24; };
        listen-on-v6 {  };

        version "Resolver";
        dnssec-validation yes;

        empty-zones-enable no;
};
    
zone "nasa" {
        type forward;
        forward first;
        forwarders {
                172.16.254.1;
        };
};

zone "28.16.172.in-addr.arpa" {
        type forward;
        forward first;
        forwarders {
                172.16.28.1;
        };
};

zone "254.16.172.in-addr.arpa" {
        type forward;
        forward first;
        forwarders {
                172.16.254.11;
        };
};

zone "28.nasa" {
        type forward;
        forward first;
        forwarders {
                172.16.28.1;
        };
};

```
### LocResolv_DNSSEC-AD (Authenticated Data)
Add ZSK in ```named.conf```
```nginx
trust-anchors {
        28.nasa static-key 257 3 8 "AwEAAalz9J3rSq830uH1...";
};
```
    