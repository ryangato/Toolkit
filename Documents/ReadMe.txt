### Linux Usage
* Run terminal and enter to DNSPing directory of source directory.
* Run "cmake ." to build a Makefile and run "make" to compile.
* After all processes finished, the binary is in current directory.


### Usage
       DNSPing [Options] Test_DomainName Target
  e.g. DNSPing -a -qt AAAA -n 5 -w 500 -edns0 www.google.com 8.8.4.4


### Options
   ?/-h              Description.
   -t                Pings the specified host until stopped.
                     To see statistics and continue type Control-Break.
                     To stop type Control-C.
   -a                Resolve addresses to host names.
   -n Count          Set number of echo requests to send.
                     Count must between 1 - 0xFFFF/65535.
   -f                Set the "Don't Fragment" flag in outgoing packets(IPv4).
                     No available on Linux.
   -i HopLimit/TTL   Specifie a Hop Limit or Time To Live for outgoing packets.
                     HopLimit/TTL must between 1 - 255.
   -w Timeout        Set a long wait periods (in milliseconds) for a response
                     Timeout must between 500 - 0xFFFF/65535.
   -id DNS_ID        Specifie DNS header ID.
                     DNS ID must between 0x0001 - 0xFFFF/65535.
   -qr               Set DNS header QR flag.
   -opcode OPCode    Specifie DNS header OPCode.
                     OPCode must between 0x0000 - 0x00FF/255.
   -aa               Set DNS header AA flag.
   -tc               Set DNS header TC flag.
   -rd               Set DNS header RD flag.
   -ra               Set DNS header RA flag.
   -ad               Set DNS header AD flag.
   -cd               Set DNS header CD flag.
   -rcode RCode      Specifie DNS header RCode.
                     RCode must between 0x0000 - 0x00FF/255.
   -qn Count         Specifie DNS header Question count.
                     Question count must between 0x0001 - 0xFFFF/65535.
   -ann Count        Specifie DNS header Answer count.
                     Answer count must between 0x0001 - 0xFFFF/65535.
   -aun Count        Specifie DNS header Authority count.
                     Authority count must between 0x0001 - 0xFFFF/65535.
   -adn Count        Specifie DNS header Additional count.
                     Additional count must between 0x0001 - 0xFFFF/65535.
   -ti IntervalTime  Specifie transmission interval time(in milliseconds).
   -edns0            Send with EDNS0 Label.
   -payload Length   Specifie EDNS0 Label UDP Payload length.
                     Payload length must between 512 - 0xFFFF/65535.
   -dnssec           Send with DNSSEC requesting.
                     EDNS0 Label will enable when DNSSEC is enable.
   -qt Type          Specifie Query type.
                     Query type must between 0x0001 - 0xFFFF/65535.
                     Type: A|NS|MD|MF|CNAME|SOA|MB|MG|MR|NULL|WKS|PTR|HINFO|
                           MINFO|MX|TXT|RP|AFSDB|X25|ISDN|RT|NSAP|NSAPPTR|
                           SIG|KEY|PX|GPOS|AAAA|LOC|NXT|EID|NIMLOC|SRV|ATMA|
                           NAPTR|KX|A6|CERT|DNAME|SINK|OPT|APL|DS|SSHFP|
                           IPSECKEY|RRSIG|NSEC|DNSKEY|DHCID|NSEC3|NSEC3PARAM|
                           TLSA|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|
                           SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|
                           EUI64|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY|URI|
                           CAA|TA|DLV|RESERVED
   -qc Classes       Specifie Query classes.
                     Query classes must between 0x0001 - 0xFFFF/65535.
                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY
   -p ServiceName    Specifie UDP port/protocol(Sevice names).
                     UDP port must between 0x0001 - 0xFFFF/65535.
                     Protocol: TCPMUX|ECHO|DISCARD|SYSTAT|DAYTIME|NETSTAT|
                               QOTD|MSP|CHARGEN|FTP|SSH|TELNET|SMTP|
                               TIME|RAP|RLP|NAME|WHOIS|TACACS|DNS|XNSAUTH|MTP
                               BOOTPS|BOOTPC|TFTP|RJE|FINGER|TTYLINK|SUPDUP|
                               SUNRPC|SQL|NTP|EPMAP|NETBIOSNS|NETBIOSDGM|
                               NETBIOSSSN|IMAP|BFTP|SGMP|SQLSRV|DMSP|SNMP|
                               SNMPTRAP|ATRTMP|ATHBP|QMTP|IPX|IMAP|IMAP3|
                               BGMP|TSP|IMMP|ODMR|RPC2PORTMAP|CLEARCASE|
                               HPALARMMGR|ARNS|AURP|LDAP|UPS|SLP|SNPP|
                               MICROSOFTDS|KPASSWD|TCPNETHASPSRV|RETROSPECT|
                               ISAKMP|BIFFUDP|WHOSERVER|SYSLOG|ROUTERSERVER|
                               NCP|COURIER|COMMERCE|RTSP|NNTP|HTTPRPCEPMAP|
                               IPP|LDAPS|MSDP|AODV|FTPSDATA|FTPS|NAS|TELNETS
   -rawdata RAW_Data Specifie Raw data to send.
                     RAW_Data is hex, but do not add "0x" before hex.
                     Length of RAW_Data must between 64 - 1500 bytes.
   -raw ServiceName  Specifie Raw socket type.
                     Service Name: HOPOPTS|ICMP|IGMP|GGP|IPV4|ST|TCP|CBT|EGP|
                                   IGP|BBNRCCMON|NVPII|PUP|ARGUS|EMCON|XNET|
                                   CHAOS|MUX|DCN|HMP|PRM|IDP|TRUNK_1|TRUNK_2
                                   LEAF_1|LEAF_2|RDP|IRTP|ISOTP4|MFE|MERIT|
                                   DCCP|3PC|IDPR|XTP|DDP|IDPRCMTP|TP++|IL|
                                   IPV6|SDRP|ROUTING|FRAGMENT|IDRP|RSVP|GRE|
                                   DSR|BNA|ESP|AH|NLSP|SWIPE|NARP|MOBILE|TLSP
                                   SKIP|ICMPV6|NONE|DSTOPTS|AHI|CFTP|ALN|SAT|
                                   KRYPTOLAN|RVD|IPPC|ADF|SATMON|VISA|IPCV|
                                   CPNX|CPHB|WSN|PVP|BR|ND|ICLFXBM|WBEXPAK|
                                   ISO|VMTP|SVMTP|VINES|TTP|IPTM|NSFNET|DGP|
                                   TCF|EIGRP|SPRITE|LARP|MTP|AX25|IPIP|MICP|
                                   SCC|ETHERIP|ENCAP|APES|GMTP|IFMP|PNNI|PIM|
                                   ARIS|SCPS|QNX|AN|IPCOMP|SNP|COMPAQ|IPX|PGM
                                   0HOP|L2TP|DDX|IATP|STP|SRP|UTI|SMP|SM|
                                   PTP|ISIS|FIRE|CRTP|CRUDP|SSCOPMCE|IPLT|
                                   SPS|PIPE|SCTP|FC|RSVPE2E|MOBILITY|UDPLITE|
                                   MPLS|MANET|HIP|SHIM6|WESP|ROHC|TEST-1|
                                   TEST-2|RAW
   -buf Size         Specifie receive buffer size.
                     Buffer size must between 512 - 4096 bytes.
   -dv               Disable packets validated.
   -show Response    Show result or data of responses.
                     Response: Result|Hex
   -of FileName      Output result to file.
                     FileName must less than 260 bytes.
   -6                Using IPv6.
   -4                Using IPv4.
   Test_DomainName   A domain name which will make requesting to send
                     to DNS server.
   Target            Target of DNSPing, support IPv4/IPv6 address and domain.


### TCPing
* DNSPing server which using UDP protocol.
* TCPing 53 port of server if you want to using TCP protocol.


### TraceTCP
* TCP traceroute 53 port of server if you want to using TCP protocol.
