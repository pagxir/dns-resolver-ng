PREPARE
=============

install node (version > 18.0) and npm, for example in ubuntu/debian, you can try
```
apt install nodejs npm
```

HOW TO INSTALL
===============

```
git clone  https://github.com/pagxir/dns-resolver-ng -b simple
cd dns-resolver-ng
npm install
```

HOW TO CHANGE CONFIG
=====================

if you run from home in china, you can try follow config, modify the config.js as following
-------------------------------------------------------------------------------------------

```
const NameServers = {
    nearby: { address: "::ffff:223.5.5.5", port: 53},
    nearby6: { address: "2001:4860:4860::8888", port: 53},
    global: { address: "64:ff9b::1.1.1.1", port: 53},
    global6: { address: "64:ff9b::8.8.8.8", port: 53},
    oiling: { address: "::ffff:202.12.30.131", port: 53},
};

const Config = {};
Config.oilingMode = "China";
Config.preferNat64 = true;
```

- please replace "::ffff:223.5.5.5" with your ISP dns server for IPv4 resolv
- please replace "2001:4860:4860::8888" with your ISP dns server for IPv6 resolv
- "64:ff9b::1.1.1.1" is use for oversea domain IPv4 lookup (DNS 'A' record)
- "64:ff9b::8.8.8.8" is use for oversea domain IPv6 lookup (DNS 'AAAA' record)
- "::ffff:202.12.30.131" is use for auto detect domain is fake by GFW
- if you do not prefer Nat64 you can change Config.preferNat64 = false

plesse confirm "64:ff9b::1.1.1.1" and "64:ff9b::8.8.8.8" is not response by GFW when dns quering

if you run from VPS oversea, you can try follow config
-------------------------------------------------------------------------------------------

```
const NameServers = {
    nearby: { address: "::ffff:180.76.76.76", port: 53},
    nearby6: { address: "2001:4860:4860::8888", port: 53},
    global: { address: "::ffff:1.1.1.1", port: 53},
    global6: { address: "::ffff:8.8.8.8", port: 53},
    oiling: { address: "::ffff:202.12.30.131", port: 53},
};

const Config = {};
Config.oilingMode = "Global";
Config.preferNat64 = true; 
```

HOW TO RUN
=====================

```
node resolver-ng.js
```

HOW TO DIAGNOSTIC
=====================

First install dig and try 

```
dig @::ffff:223.5.5.5 www.163.com +short
dig @2001:4860:4860::8888 www.163.com AAAA +short

dig @64:ff9b::1.1.1.1 www.google.com +short
dig @64:ff9b::8.8.8.8 www.google.com AAAA +short

dig @::ffff:202.12.30.131 www.163.com
dig @::ffff:202.12.30.131 www.google.com
```

Here is some diagnostic run results
```
$ dig @::ffff:223.5.5.5 www.163.com +short
www.163.com.163jiasu.com.
www.163.com.w.kunluncan.com.
221.181.64.231
221.181.64.234
221.181.64.232
221.181.64.228
221.181.64.229
221.181.64.227
221.181.64.230
221.181.64.233
www.163.com.163jiasu.com.
www.163.com.w.kunluncan.com.

$ dig @2001:4860:4860::8888 www.163.com AAAA +short
2409:8c1e:68e0:403:3::3e7
2409:8c1e:68e0:403:3::3e8

$ dig @64:ff9b::1.1.1.1 www.google.com +short
142.251.42.196

$ dig @64:ff9b::8.8.8.8 www.google.com AAAA +short
2404:6800:4004:828::2004

$ dig @::ffff:202.12.30.131 www.163.com
; <<>> DiG 9.18.12-1ubuntu1-Ubuntu <<>> @202.12.30.131 www.163.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 37606
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 826e1faddbbeeb710100000066dbd79435dcba232a327b38 (good)
;; QUESTION SECTION:
;www.163.com.                   IN      A

;; Query time: 64 msec
;; SERVER: 202.12.30.131#53(202.12.30.131) (UDP)
;; WHEN: Sat Sep 07 04:33:24 UTC 2024
;; MSG SIZE  rcvd: 68


$ dig @::ffff:202.12.30.131 www.google.com
; <<>> DiG 9.18.12-1ubuntu1-Ubuntu <<>> @202.12.30.131 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41736
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com.                        IN      A

;; ANSWER SECTION:
www.google.com.         152     IN      A       31.13.94.41

;; Query time: 8 msec
;; SERVER: 202.12.30.131#53(202.12.30.131) (UDP)
;; WHEN: Sat Sep 07 04:33:24 UTC 2024
;; MSG SIZE  rcvd: 48
```

FAQ
===

- Does have a predefine GFW fake domain list
> No, fake domain is auto detect by oiling server

- How to detect a domain is china domain or oversea doamain
> apnic-table-6.js contains a network subset for china network, If a domain is not fake by GFW and the Config.NameServers.nearby
 return a A record with IPv4 address is in China, we say this domain is china domain. And this is same as Config.NameServers.nearby6

- Folling domain will take as china domain
  - dl.google.com
  - www.appp.com
  - www.microsoft.com
  - qy.163.com
  - www.163.com
  - and more

> all domain which is fake by GFW will take as oversea domain
