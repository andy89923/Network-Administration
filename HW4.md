2022 NYCU NA HW4
===
##### 2022.05.10
###### tags: `NA` `NYCU`
#### Reference: [HackMD](https://hackmd.io/kX5Cv-0pTpq1tNrgTM2J_Q?view)


## 2 New VMs
|   VM Name   | user_name | password |       Hostname       |
|:-----------:|:---------:|:--------:|:--------------------:|
| ldap_server | ldap_sev  |   ****   |    ldap.28.nasa.     |
| workstation |  station  |   ****   | workstation.28.nasa. |


## DNS_router 
Edit ```/usr/local/etc/dhcpd.conf``` config file
```nginx=
host ldapserver {
    hardware ethernet 08:00:27:3B:D7:E2;
    fixed-address 172.16.28.15;
}
host workstation {
    hardware ethernet 08:00:27:22:32:DA;
    fixed-address 172.16.28.30;
}
```

```/etc/pf.conf```
```
pass in on $extvpn proto tcp from any to any port { 389, 3268 } keep state
```

```
ReStart DHCP server
$ sudo /usr/local/etc/rc.d/isc-dhcpd restart

Reload Packetfilter
$ sudo pfctl -f /etc/pf.conf
```

Useful file or commands:
* SSH configure file ```/etc/ssh/sshd_config```


## Install LDAP (LDAP_Server)

### Basic Settings
Reference:
* [以 LDAP 整合帳號](http://mail.lsps.tp.edu.tw/~gsyan/freebsd2001/pam_ldap.html)

```
$ cd /usr/ports
$ sudo portsnap [fetch | extract | update ]
$ sudo portsnap fetch update

$ cd /usr/ports/net/openldap24-server
$ sudo make install clean
```

Add the following in ```/etc/rc.conf```:
```
 slapd_enable="YES"
```
To generate root's password:
```
$ slappasswd
New password:
Re-enter new password:
{SSHA}QosX7Y88apCDuedbebwShWgnyZh0oGG2
```

LDAP Server configure file: ```/usr/local/etc/openldap/slapd.conf```
```nginx
include         /usr/local/etc/openldap/schema/core.schema
include         /usr/local/etc/openldap/schema/cosine.schema
include         /usr/local/etc/openldap/schema/nis.schema
pidfile         /var/run/openldap/slapd.pid
argsfile        /var/run/openldap/slapd.args

modulepath      /usr/local/libexec/openldap
moduleload      back_mdb
moduleload      back_ldap

database        mdb
maxsize         1073741824
suffix          "dc=28,dc=nasa"
rootdn          "cn=root,dc=28,dc=nasa"
rootpw          {SSHA}QosX7Y88apCDuedbebwShWgnyZh0oGG2
directory       /var/db/openldap-data

index   objectClass     eq
```

Start the service and test the result:
```
$ sudo service slapd start
$ ldapwhoami -H ldap://localhost -D 'cn=root,dc=28,dc=nasa' -W -v
dn:cn=root,dc=28,dc=nasa
Result: Success (0)
```
***<note>*** ldapwhoami need to enter the password in previous settings.


### Setup Loging
in ```/etc/syslog.conf```
```
local4.* /var/log/ldap.log
```
```shell
$ sudo touch /var/log/ldap.log
$ sudo chmod +rw /var/log/ldap.log
$ sudo /etc/rc.d/syslogd restart
```
    
    
### StartTLS
    
Reference:
* [OpenLDAP-SSL TLS 設定](http://wiki.weithenn.org/cgi-bin/wiki.pl?OpenLDAP-SSL_TLS_%E8%A8%AD%E5%AE%9A#Heading6) 
* [28.5. FreeBSD and LDAP](https://people.freebsd.org/~blackend/en_US.ISO8859-1/books/handbook/network-ldap.html) 
   

Finally this one is easier!
```
$ sudo openssl req -days 365 -nodes -new -x509 -keyout ca.key -out ca.crt
$ sudo openssl req -days 365 -nodes -new -keyout server.key -out server.csr
$ sudo openssl x509 -req -days 365 -in server.csr -out server.crt -CA ca.crt -CAkey ca.key -CAcreateserial
```

```bash
$ pwd
/root/tls_file
$ sudo openssl genrsa -des3 -out rootca.key 2048
$ sudo openssl req -new -key rootca.key -out rootca.req
$ sudo openssl x509 -req -days 7305 -sha1 \ 
    -extfile /etc/ssl/openssl.cnf         \
    -extensions v3_ca -signkey rootca.key \
    -in rootca.req -out rootca.crt

$ sudo openssl genrsa -out ldap.key 2048
$ sudo openssl req -new -key ldap.key -out ldap.csr
$ sudo openssl x509 -req -days 3650 -sha1  \
    -extfile /etc/ssl/openssl.cnf          \ 
    -extensions v3_req                     \ 
    -CA rootca.crt -CAkey rootca.key       \
    -CAserial rootca.srl -CAcreateserial -in ldap.csr -out ldap.crt
    
$ ls -l
-rw-r--r--  1 root  wheel  1229 May 11 15:17 ldap.crt
-rw-r--r--  1 root  wheel   989 May 11 15:16 ldap.csr
-rw-------  1 root  wheel  1679 May 11 15:15 ldap.key
-rw-r--r--  1 root  wheel  1306 May 11 15:15 rootca.crt
-rw-------  1 root  wheel  1751 May 11 15:12 rootca.key
-rw-r--r--  1 root  wheel   989 May 11 15:14 rootca.req
-rw-r--r--  1 root  wheel    41 May 11 15:17 rootca.srl
    
$ base64 ca.crt
...<SKIP>.....
```
Add the TLS setting in ```/usr/local/etc/openldap/slapd.conf```:
```
TLSCipherSuite          HIGH:MEDIUM:+SSLv2:+SSLv3:TLSv1
TLSCACertificateFile    /root/tls_file/rootca.crt
TLSCertificateFile      /root/tls_file/ldap.crt
TLSCertificateKeyFile   /root/tls_file/ldap.key
TLSVerifyClient         try  
```
Also, give the file permission to slapd:
```bash
$ sudo chmod +x /root
$ sudo chmod 666 /root/tls_file/*
```

LDAP Client: ```/usr/local/etc/openldap/ldap.conf```
```
TLS_REQCERT             demand
TLSCACertificateFile    /root/tls_file/rootca.crt
TLS_CIPHER_SUITE        HIGH:MEDIUM:+SSLv3
```
    
Test TLS sonnection:
```
$ openssl s_client -connect ldap.28.nasa:389 -starttls ldap
$ ldapwhoami -H ldap://localhost -D 'cn=root,dc=28,dc=nasa' -W -v -ZZ
```
* -ZZ 的意思表示會發起 TLS 連線請求且要求一定要成功
    
Enforce TLS: ```/usr/local/etc/openldap/slapd.conf```
```
security tls=1
```
```
$ ldapwhoami -H ldap://localhost -D 'cn=root,dc=28,dc=nasa' -W -v
ldap_bind: Confidentiality required (13)
    additional info: TLS confidentiality required
```
    
    
    
### DNS Server (ns1)
### Add new A records
- Remember to increase the ***Serial Number***.
- Reassign the zone file ```$sudo ./reassign.sh```

Working Directory: ```/usr/local/etc/namedb/```
In ```28.nasa_local``` and ```28.nasa_intra```
```
ldap         IN  A  172.16.28.15 
workstation  IN  A  172.16.28.30
```
    
### Add new txt records
- Add CA certificate to DNS TXT Record
```
cert         IN TXT "...<SKIP>..." "..." "..."
```
將跨行的放不同行，以空白隔開
    



## LDAP Administration
    
### Schema
/usr/local/etc/openldap/schema/sshkey.schema
```
#
# publicKeyLogin schema
#
attributetype ( 3.4.5.1
  NAME 'sshPublicKey'
  DESC 'ssh public key'
  EQUALITY octetStringMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
# objectClass definition
objectclass ( 4.7.2.7
  NAME 'publicKeyLogin'
  DESC 'publicKeyLogin objectclass'
  SUP top
  AUXILIARY
  MUST sshPublicKey )
```

Add in ```slapd.conf```
```
include   /usr/local/etc/openldap/schema/sshkey.schema
```
    
    
### Add User Group & User
    
* [FreeBSD LDAP](https://yves2005.pixnet.net/blog/post/53944282)
    
    
Working directory: ```/usr/local/etc/openldap/ldif_files```

```container.ldif```    
```
dn:ou=Group,dc=28,dc=nasa
objectclass: top
objectclass: organizationalUnit
ou: Group

dn:ou=People,dc=28,dc=nasa
objectclass: top
objectclass: organizationalUnit
ou: People
```
    
```groups_ta.ldif```
```
# Group ta
dn: cn=ta,ou=Group,dc=28,dc=nasa
cn: ta
gidNumber: 601
objectClass: top
objectClass: posixGroup
```

```group_stu.ldif```
```
# Group stu
dn: cn=stu,ou=Group,dc=28,dc=nasa
cn: stu
gidNumber: 602
objectClass: top
objectClass: posixGroup
```

```user_ta.ldif```
```
dn: uid=ta1,ou=People,dc=28,dc=nasa
changetype: add
objectClass: posixAccount
objectClass: posixGroup
objectClass: shadowAccount
cn: ta1
gidNumber: 601
homeDirectory: /home/ta1
uid: 10001
uidNumber: 10001
loginShell: /bin/sh
userPassword: hGMFsuVS22pxKm9qc6uxS5nB6ZR2RN9t
```
```user_stu.ldif```
```
dn: uid=stu28,ou=People,dc=28,dc=nasa
changetype: add
objectClass: posixAccount
objectClass: posixGroup
objectClass: shadowAccount
cn: stu28
gidNumber: 602
homeDirectory: /home/ta1
uid: 20028
uidNumber: 20028
loginShell: /bin/sh
userPassword: hGMFsuVS22pxKm9qc6uxS5nB6ZR2RN9t
```
    
Check
```
$ ldapsearch -b "uid=ta1,ou=People,dc=28,dc=nasa" -s base -x -W -ZZ -D "cn=root,dc=28,dc=nasa"
```
    
Add the ldif file:
```
$ sudo ldapadd -H ldap:/// -D "cn=root,dc=28,dc=nasa" -W -v -f <xxx.ldif> -ZZ
```
    

    
    
    
## LDAP Client

Install ```pam_ldap``` 和 ```nss_ldap```
```
$ sudo pkg install pam_ldap nss_ldap pam_mkhomedir
    
LDAP configuration:     /usr/local/etc/nss_ldap.conf
LDAP secret (optional): /usr/local/etc/nss_ldap.secret
```
    
Configure file ```/usr/local/etc/ldap.conf```: 
```
host             ldap.28.nasa
bind_policy      soft

TLS_REQCERT      allow
TLS_CRLCHECK     none

BASE             dc=28,dc=nasa
URI              ldap://ldap.28.nasa

ssl              start_tls
TLS_CIPHER_SUITE HIGH:MEDIUM:+SSLv2:+SSLv3:TLSv1
TLS_CACERT       /root/tls_file/ca.crt

binddn          cn=root,dc=28,dc=nasa
bindpw          nasa

pam_filter objectclass=posixAccount
pam_login_attribute uid

nss_base_passwd ou=People,dc=28,dc=nasa?one
nss_base_shadow ou=People,dc=28,dc=nasa?one
nss_base_group  ou=Group,dc=28,dc=nasa?one
```


nss_ldap configure file:
```
$ cd /usr/local/etc
$ sudo rm nss_ldap.conf
$ sudo ln -s ./openldap/ldap.conf nss_ldap.conf
```
    
```/etc/nsswitch.conf ```
```
group_compat: ldap nis
passwd_compat ldap nis
```

```
$ sudo vipw
+:*::::::::
    
$ sudo vim /etc/group
+:*::
```    

Add the following line in ```/etc/pam.d/login```
```
session required /usr/local/lib/pam_mkhomedir.so
``` 

# Ansible
* [Install on FreeBSD](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-ansible-on-freebsd)
```
$ sudo pkg install py37-ansible
```