2022 NYCU NA HW3
===
##### 2022.04.15
###### tags: `NA` `NYCU`

### 1 Another VMs
|   VM Name   |  user_name  | password |
|:-----------:|:-----------:|:--------:|
| mail_server | mail_server |   ****   |

Hostname: ```mail.28.nasa.```

#### Reference: [BoHao](https://hackmd.io/kprE6NSERomH-hW9sfDeVg)

### DNS_router 
Edit ```/usr/local/etc/dhcpd.conf``` config file
```nginx=
host mailserver {
    hardware ethernet 08:00:27:C5:43:CB;
    fixed-address 172.16.28.20;
}
```
#### ReStart DHCP server
```
$ sudo /usr/local/etc/rc.d/isc-dhcpd restart 
```

#### Packetfilter
```/etc/pf.conf```
```
pass in on $extvpn proto tcp from any to any port { 25, 587, 465, 110, 995, 143, 993 } keep state
```
```
$ sudo pfctl -f /etc/pf.conf
```


## Mail-server

Add two user:

| Username |             password             | AUTH                                                     |
|:--------:|:--------------------------------:| -------------------------------------------------------- |
|    ta    | ----VS22pxKm9qc6uxS5nB6ZR2RN9t | AFRBAGhHTUZzdVZTMjJweEttOXFjNnV4UzVuQjZaUjJS         |
| cool-ta  | ----VS22pxKm9qc6uxS5nB6ZR2RN9t |2wtVEEAaEdNRnN1VlMyMnB4S205cWM2dXhTNW5CNlpSMlJOOXQ= |

:::warning
Username should be 'TA' and 'cool-TA', but login Dovecot are case sensitive(wiered). 
add the ```auth_username_format = %Lu``` in Dovecot configure to translates the username to lower case before doing a lookup.
:::
[REF](https://serverfault.com/questions/534996/trouble-with-case-sensitive-ldap-user-logins-to-dovecot)

```
$ su -
$ adduser

$ perl -MMIME::Base64 -e 'print encode_base64("\000TA\000hGMFsuVS22pxKm9qc6uxS5nB6ZR2RN9t")'
AFRBAGhHTUZzdVZTMjJweEttOXFjNnV4UzVuQjZaUjJSTjl0

$ perl -MMIME::Base64 -e 'print encode_base64("\000cool-TA\000hGMFsuVS22pxKm9qc6uxS5nB6ZR2RN9t")'
AGNvb2wtVEEAaEdNRnN1VlMyMnB4S205cWM2dXhTNW5CNlpSMlJOOXQ=

$ perl -MMIME::Base64 -e 'print encode_base64("\000mail-server\000nasa")'
AG1haWwtc2VydmVyAG5hc2E=

> openssl -connect
> D1 AUTHENTICATE PLAIN
> AG1haWwtc2VydmVyAG5hc2E=
```


### Install Postfix & Dovecot

In ```/etc/rc.conf```:
```
sendmail_enable="NONE"
postfix_enable="YES"
dovecot_enable="YES"
```
In ```/etc/periodic.conf```:
```
daily_clean_hoststat_enable="NO"
daily_status_mail_rejects_enable="NO"
daily_status_include_submit_mailq="NO"
daily_submit_queuerun="NO"
```
In ```/etc/mail/mailer.conf```:
```
sendmail        /usr/local/sbin/sendmail
mailq           /usr/local/sbin/sendmail
newaliases      /usr/local/sbin/sendmail
hoststat        /usr/local/sbin/sendmail
purgestat       /usr/local/sbin/sendmail
```
Install Postfix & Dovecot packages:
```
$ sudo pkg install postfix dovecot
```
Copy configuration files
```
$ sudo cp -R /usr/local/etc/dovecot/example-config/* /usr/local/etc/dovecot
```

### Basic MTA Settings
```/usr/local/etc/postfix/main.cf```
```nginx
myhostname = mail.28.nasa
mydomain = 28.nasa
virtual_alias_domains = mail.28.nasa
myorigin = $myhostname
mydestination = $myhostname, $mydomain

compatibility_level = 3.7
alias_maps = hash:/usr/local/etc/postfix/aliases
```

Commands:
```
$ sudo newaliases
$ sudo postmap hash:/usr/local/etc/postfix/canonical
$ sudo postfix reload
$ sudo service postfix { start | stop | status }
```
Testing Postfix in localhost (no need DNS)
```
$ telnet localhost 25
mail from: root@mail.28.nasa
rcpt to: root@28.nasa
data
<text> <text>
.
quit
```

### Dovecot
Set Up **Dovecot** SASL in Postfix: ```/usr/local/etc/postfix/main.cf```
```nginx
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
broken_sasl_auth_clients = yes
smtpd_sasl_security_options = noanonymous
smtpd_recipient_restrictions = permit_mynetworks,
                permit_sasl_authenticated,
                reject_unauth_destination

smtpd_tls_auth_only = yes

smtpd_sender_login_maps = hash:/usr/local/etc/postfix/login_map
smtpd_sender_restrictions = reject_sender_login_mismatch,
                reject_authenticated_sender_login_mismatch,
                reject_unauthenticated_sender_login_mismatch,
                permit_mynetworks
```
Add authenticate configuration file: ```/etc/pam.d/dovecot```
```
auth     required   pam_unix.so
account  required   pam_unix.so
```

```10-mail.conf```
```
mail_location = mbox:~/mail:INBOX=/var/mail/%u
```

```10-mail.conf``` -> To indicate the where the mails save
```
mail_location = mbox:~/mail:INBOX=/var/mail/%u
```

```login_map```
```
TA@28.nasa           ta
TA@mail.28.nasa      ta
cool-TA@28.nasa      cool-ta
cool-TA@mail.28.nasa cool-ta
```

```
$ sudo postmap login_map
```

In Dovecot configure file:``` /usr/local/etc/dovecot/conf.d/10-master.conf```
```nginx
service auth {
    # Postfix smtp-auth
    unix_listener /var/spool/postfix/private/auth {
        mode = 0666
    }
}
```
```/usr/local/etc/dovecot/conf.d/10-auth.conf```
```nginx
auth_username_format = %Lu
auth_mechanisms = plain login
first_valid_gid = 0
```

### StartTLS
[Stack Exchange](https://serverfault.com/questions/926478/dovecot-ssl-imap-works-smtp-fails)
#### SMTP
Generate key and certificate
```
$ sudo openssl req -newkey rsa:4096 -sha512 -x509 -days 365 -nodes -keyout mail.key -out mail.pem
```
Added to configure file: ```/usr/local/etc/postfix/main.cf```
```nginx
smtpd_tls_cert_file = /usr/local/etc/postfix/tls_file/mail.csr
smtpd_tls_key_file = /usr/local/etc/postfix/tls_file/mail.pem

smtpd_tls_security_level = encrypt
```
Verify the result
```
$ openssl s_client -connect mail.28.nasa:25 -starttls smtp
```

#### IMPA
In dovecot config file: ```/usr/local/etc/dovecot/conf.d/10-ssl.conf```
```nginx
ssl = required

ssl_cert = </usr/local/etc/postfix/tls_file/mail.csr
ssl_key = </usr/local/etc/postfix/tls_file/mail.pem
```
Testing:
```
$ sudo service dovecot restart
$ telnet localhost imap
  
  .....STARTTLS ...] Dovecot ready
$ openssl s_client -connect mail.28.nasa:143 -starttls imap
a login <username> <password>
```


### No Open Relay
Added to configure file: ```/usr/local/etc/postfix/main.cf```
```nginx
mynetworks = 127.0.0.0/8, 172.16.28.0/24
```

## DNS Server (ns1)
Working Directory: ```/usr/local/etc/namedb/```

**Re-Sign Zone using ZSK & PSK:**
```
$ sudo ./reassign.sh
```

### MX record

In ```28.nasa_local``` and ```28.nasa_intra```
```
mail    IN     A  172.16.28.20
mail    IN    MX 5 mail.28.nasa.

$ORIGIN nasa.
28      IN    MX 5 mail.28.nasa.
```
- Remember to increase the ***Serial Number***.
- Reassign the zone file
- Push to DNS slave

### SPF record

Add the following record in DNS server:
```
28 IN TXT v=spf1 a ip4:172.16.28.20 -all
28 IN SPF v=spf1 a ip4:172.16.28.20 -all
```

#### SPF policy check
```
$ sudo pkg install postfix-policyd-spf-perl-2.010_1
```

```main.cf```
```
spf-policy_time_limit = 3600
smtpd_relay_restrictions = 
            permit_mynetworks,
            reject_unauth_destination,
            check_policy_service unix:private/spf-policy
```
```master.cf```
```
spf-policy unix -       n       n       -       0       spawn
        user=nobody argv=/usr/local/libexec/postfix-policyd-spf-perl
```



## Mailserver

### Alias
Add config in: ```/usr/local/etc/postfix/main.cf```

```
virtual_alias_maps = regexp:/usr/local/etc/postfix/virtual
```
```virtual```
```
/^(.*)\|(.*)/ $2
/(NASATA@mail)\.(28)\.(nasa)/ TA@mail.28.nasa
/(NASATA@28)\.(nasa)/         TA@mail.28.nasa
```
Commands:
```
$ sudo postmap /usr/local/etc/postfix/virtual
# Test query
$ sudo postmap -q NASATA@mail.28.nasa regexp:/usr/local/etc/postfix/virtual
```

### Deny Null Sender
```
smtpd_sender_restrictions = reject_sender_login_mismatch,
                reject_authenticated_sender_login_mismatch,
                reject_unauthenticated_sender_login_mismatch,
                check_recipient_access regexp:/usr/local/etc/postfix/rcp_access,
                permit_mynetworks
```
```
$ sudo postmap rcp_access
$ sudo postfix restart
```

### Greylisting

Package install:
```
$ sudo pkg install postgrey
```

```/etc/rc.conf```
```
postgrey_enable = "YES"
```
Add opts file:```/etc/default/postgrey```
```
POSTGREY_OPTS="--inet=127.0.0.1:10023 --delay=30"
```
Add postgrey in ```/usr/local/etc/postfix/main.cf```
```
smtpd_recipient_restrictions = ...,
            check_policy_service inet:127.0.0.1:10023
```


### NCTU Filter
- Reject mails whose subject contains "NCTU" or "陽交"

```main.cf```
```
header_checks = regexp:/usr/local/etc/postfix/header_checks
```

```
$ echo -n "陽交" | mmencode -q
=E9=99=BD=E4=BA=A4=
$ echo -n "陽交" | mmencode
6Zm95Lqk
```

```header_checks```
```
/^(Subject:).*(NCTU).*/                 REJECT
/^(Subject:).*(6Zm95Lqk).*/             REJECT
/^(Subject:).*(=E9=99=BD=E4=BA=A4=).*/  REJECT
```
```
$ sudo postmap header_checks
```

[Base64Encoder](https://www.base64encode.org/) - **BIG5, UTF-8, GBK(GB18030)**
[Reference](https://kafeiou.pw/2018/06/05/689/)

### Ingoing mail filter ?
Install package:
```
$ sudo pkg install clamav spamassassin amavisd-new
```
```/etc/rc.conf```
```
amavisd_enable="YES"
clamav_clamd_enable="YES"
spamd_enable="YES"
spamass_milter_enable="YES"
```
Update Spam & Virus DB:
```
$ sudo freshclam
$ suda sa-update
$ sudo sa-compile
```

```main.cf```
```
# AMAVISD
content_filter = smtp-amavis:[127.0.0.1]:10024
```


```master.cf```
```
smtp-amavis unix    -       -       n       -       10       smtp
        -o smtp_data_done_timeout=1200s
        -o smtp_never_send_ehlo=yes
        -o notify_classes=protocol,resource,software

127.0.0.1:10025 inet    n       -       n       -       -       smtpd
        -o content_filter=
        -o mynetworks=127.0.0.0/8
        -o local_recipient_maps=
        -o relay_recipient_maps=
        -o smtpd_restriction_classes=
        -o smtpd_client_restrictions=
        -o smtpd_sender_restrictions=
        -o smtpd_recipient_restrictions=
        -o smtpd_tls_security_level=
```

**Spamassassin**
```/usr/local/etc/mail/spamassassin```

**Amavisd** configure file: ```/usr/local/etc/amavisd.conf```
```
$forward_method = 'smtp:127.0.0.1:10025'
$sa_tag_level_deflt = -999;
$sa_tag2_level_deflt = 5;
$sa_kill_level_deflt = 12;

$subject_tag_maps_by_ccat{+CC_VIRUS} = [ '*** SPAM ***' ];
$sa_spam_subject_tag = '*** SPAM ***';
$sa_spam_modifies_subj = 1;

$final_virus_destiny = D_PASS;
$final_spam_destiny = D_PASS;

@bypass_virus_checks_maps = (1); 
@bypass_spam_checks_maps = (1);

@av_scanners = (

['ClamAV-clamd', 


... ],

)
```

To start the service:
```	
$ sudo service sa-spamd start
$ sudo service amavisd start
$ sudo service clamav-clamd start
```

### Sender Rewrite

Add config in: ```/usr/local/etc/postfix/main.cf```

```
sender_canonical_maps = regexp:/usr/local/etc/postfix/sender_canonical
```

New file: ```/usr/local/etc/postfix/sender_canonical```
```
/(cool-TA@mail.28.nasa)/  notcool-TA@28.nasa
/(cool-TA@28.nasa)/       notcool-TA@28.nasa
/(.*)(@mail.28.nasa)/     ${1}@28.nasa
```
```
$ sudo postmap /usr/local/etc/postfix/sender_canonical
```

### DKIM

[How to run Postfix with OpenDKIM on FreeBSD 9.0](https://www.prado.it/2012/04/26/how-to-run-postfix-with-opendkim-on-freebsd-9-0/)

Install opendkim:
```
$ sudo pkg install opendkim
$ sudo pw useradd -n opendkim -d /var/db/opendkim \
    -g mail -m -s "/usr/sbin/nologin" -w no
$ sudo mkdir -p /var/run/milteropendkim
$ touch /var/run/milteropendkim/pid
$ sudo touch /var/db/opendkim/trusted.hosts
$ sudo touch /var/db/opendkim/key.table
```

```/var/db/opendkim/trusted.hosts```
```
127.0.0.1
localhost
*.28.nasa
*.mail.28.nasa
```

```/var/db/opendkim/key.table```
```
MYDEMO._domainkey.28.nasa     28.nasa:MYDEMO:/var/db/opendkim/MYDEMO.private
```


Add in```/etc/rc.conf```:
```
milteropendkim_enable="YES"
milteropendkim_uid="opendkim"
```

Postifx ```main.cf```
```nginx
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
```

Configure file:
File: ```/usr/local/etc/mail/opendkim.conf```
```
LogWhy yes
Syslog yes
SyslogSuccess yes
Canonicalization relaxed/simple
Domain 28.nasa
AutoRestart         yes
AutoRestartRate     10/1M
Background          yes
DNSTimeout          5
SignatureAlgorithm  rsa-sha256
Selector MYDEMO
KeyFile /var/db/opendkim/MYDEMO.private
Socket inet:8891@localhost
ReportAddress root
SendReports yes
InternalHosts       /var/db/opendkim/trusted.hosts
```
Generate the keys:
```
$ sudo mkdir /var/db/opendkim
$ sudo opendkim-genkey -D /var/db/opendkim -d 28.nasa -s MYDEMO
$ ls /var/db/opendkim/
MYDEMO.private  MYDEMO.txt
```
```
$ sudo cat /var/db/opendkim/MYDEMO.txt
MYDEMO._domainkey       IN      TXT     ( "v=DKIM1; k=rsa; "
          "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXAh4FHu03hEAyYOqdGukyeTPq/e9YsBQoFrvlKbMx1uq37lvTtNV5cobT0s4rqQzUhq6r9z7aNSRPcSYhcd0n1USIVu34DrMY7IsO8Styh7IHxP0uGiXI0EL1yXN2zd/+Q+a5BeCClZm39DIpgDTivhetAfbHHjdKR8ThseiJ0QIDAQAB" )  ; ----- DKIM key MYDEMO for 28.nasa
```

Add the following records in DNS server:
```
_domainkey IN TXT "t=y\; o=~\;"
MYDEMO._domainkey       IN      TXT     ( "v=DKIM1; k=rsa; " "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXAh4FHu03hEAyYOqdGukyeTPq/e9YsBQoFrvlKbMx1uq37lvTtNV5cobT0s4rqQzUhq6r9z7aNSRPcSYhcd0n1USIVu34DrMY7IsO8Styh7IHxP0uGiXI0EL1yXN2zd/+Q+a5BeCClZm39DIpgDTivhetAfbHHjdKR8ThseiJ0QIDAQAB" )
```

```
$ sudo service milter-opendkim restart
$ sudo service postfix restart
```

### DMARC

Add the DMARC record in DNS server:
```
_dmarc IN TXT "v=DMARC1; p=reject;"
```

Install DMARC package:
```
$ sudo pkg install opendmarc
```
```/etc/rc.conf```
```
opendmarc_enable="YES"
```
Configure file: ```/usr/local/etc/mail/opendmarc.conf```
```
SOCKET inet:83682@localhost
```

Postfix Setting: ```main.cf```
```nginx=
# OpenDKIM + DMARC
smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:83682
non_smtpd_milters = $smtpd_milters
```

## Usefule Commands
### mailq
[Reference](https://fireflybug.pixnet.net/blog/post/51053736)
```
$ mailq                # check mail in queue
$ postqueue -f         # force to resend all mail
```