### Build in Linux/Mac
* Run terminal and enter to Toolkit directory.
* Run "chmod 755 CMake_Build.sh" to give running privilege to script.
* Run "./CMake_Build.sh" to build binary.


### Usage and options(DNSPing)
       DNSPing [-options] domain target
  e.g. DNSPing -a -qt AAAA -n 5 -w 500 -edns0 www.google.com 8.8.4.4

   ?/-h              Description.
   -t                Pings the specified host until stopped.
                     To see statistics and continue type Control-Break.
                     To stop type Control-C.
   -a                Resolve addresses to host names.
   -n count          Set number of echo requests to send.
                     Count must between 1 - 0xFFFF/65535.
   -f                Set the "Do Not Fragment" flag in outgoing packets(IPv4).
                     No available in Mac OS X.
   -i hoplimit/ttl   Specifie a Hop Limit or Time To Live for outgoing packets.
                     HopLimit/TTL must between 1 - 255.
   -w timeout        Set a long wait periods (in milliseconds) for a response
                     Timeout must between 500 - 0xFFFF/65535.
   -id dns_id        Specifie DNS header ID.
                     DNS ID must between 0x0001 - 0xFFFF/65535.
   -qr               Set DNS header QR flag.
   -opcode opcode    Specifie DNS header OPCode.
                     OPCode must between 0x0000 - 0x00FF/255.
   -aa               Set DNS header AA flag.
   -tc               Set DNS header TC flag.
   -rd               Set DNS header RD flag.
   -ra               Set DNS header RA flag.
   -ad               Set DNS header AD flag.
   -cd               Set DNS header CD flag.
   -rcode rcode      Specifie DNS header RCode.
                     RCode must between 0x0000 - 0x00FF/255.
   -qn count         Specifie DNS header Question count.
                     Question count must between 0x0001 - 0xFFFF/65535.
   -ann count        Specifie DNS header Answer count.
                     Answer count must between 0x0001 - 0xFFFF/65535.
   -aun count        Specifie DNS header Authority count.
                     Authority count must between 0x0001 - 0xFFFF/65535.
   -adn count        Specifie DNS header Additional count.
                     Additional count must between 0x0001 - 0xFFFF/65535.
   -ti interval_time Specifie transmission interval time(in milliseconds).
   -edns0            Send with EDNS0 Label.
   -payload length   Specifie EDNS0 Label UDP Payload length.
                     Payload length must between 512 - 0xFFFF/65535.
   -dnssec           Send with DNSSEC request.
                     EDNS0 Label will enable when DNSSEC is enable.
   -qt type          Specifie Query type.
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
   -qc classes       Specifie Query classes.
                     Query classes must between 0x0001 - 0xFFFF/65535.
                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY
   -p service_name   Specifie UDP port/protocol(Sevice names).
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
   -rawdata raw_data Specifie Raw data to send.
                     RAW_Data is hex, but do not add "0x" before hex.
                     Length of RAW_Data must between 64 - 1500 bytes.
   -raw service_name Specifie Raw socket type.
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
   -socks target            Specifie target of SOCKS server.
                            Target is Server:Port, like [::1]:1080.
   -socks_username username Specifie username of SOCKS server.
                            Length of SOCKS username must between 1 - 255 bytes.
   -socks_password password Specifie password of SOCKS server.
                            Length of SOCKS password must between 1 - 255 bytes.
   -buf size                Specifie receive buffer size.
                            Buffer size must between 512 - 4096 bytes.
   -dv                      Disable packets validated.
   -show type               Show result or hex data of responses.
                            Type: Result|Hex
   -of file_name            Output result to file.
                            FileName must less than 260 bytes.
   -6                       Using IPv6.
   -4                       Using IPv4.
   domain                   A domain name which will make request to send
                            to DNS server.
   target                   Target of DNSPing, support IPv4/IPv6 address and domain.


### Usage and options(FileHash)
       FileHash -option/-algorithm [Filename]
  e.g. FileHash -SHA3 filename

Supported options:
   -v/--version:     Print current version on screen.
   -?/-h/--help      Print description.

Supported hash algorithms:
   * CRC family:     -CRC                        = -CRC32
                     -CRC8                       CRC 8 bits
                     -CRC8_ITU                   CRC 8 bits ITU
                     -CRC8_ATM                   CRC 8 bits ATM
                     -CRC8_CCITT                 CRC 8 bits CCITT
                     -CRC8_MAXIM                 CRC 8 bits Maxim
                     -CRC8_ICODE                 CRC 8 bits Icode
                     -CRC8_J1850                 CRC 8 bits J1850
                     -CRC8_WCDMA                 CRC 8 bits WCDMA
                     -CRC8_ROHC                  CRC 8 bits Rohc
                     -CRC8_DARC                  CRC 8 bits Darc
                     -CRC16                      CRC 16 bits
                     -CRC16_BUYPASS              CRC 16 bits Buypass
                     -CRC16_DDS_110              CRC 16 bits DDS 110
                     -CRC16_EN_13757             CRC 16 bits EN 13757
                     -CRC16_TELEDISK             CRC 16 bits Teledisk
                     -CRC16_MODBUS               CRC 16 bits Modbus
                     -CRC16_MAXIM                CRC 16 bits Maxim
                     -CRC16_USB                  CRC 16 bits USB
                     -CRC16_T10_DIF              CRC 16 bits T10 DIF
                     -CRC16_DECT_X               CRC 16 bits DECT X
                     -CRC16_DECT_R               CRC 16 bits DECT R
                     -CRC16_SICK                 CRC 16 bits Sick
                     -CRC16_DNP                  CRC 16 bits DNP
                     -CRC16_CCITT_XMODEM         CRC 16 bits CCITT Xmodem
                     -CRC16_CCITT_FFFF           CRC 16 bits CCITT FFFF
                     -CRC16_CCITT_1D0F           CRC 16 bits CCITT 1D0F
                     -CRC16_GENIBUS              CRC 16 bits Genibus
                     -CRC16_KERMIT               CRC 16 bits Kermit
                     -CRC16_X25                  CRC 16 bits X25
                     -CRC16_MCRF4XX              CRC 16 bits MCRF4XX
                     -CRC16_RIELLO               CRC 16 bits Riello
                     -CRC16_FLETCHER             CRC 16 bits Fletcher
                     -CRC24                      = -CRC24_R64
                     -CRC24_FLEXRAY_A            CRC 24 bits Flexray A
                     -CRC24_FLEXRAY_B            CRC 24 bits Flexray B
                     -CRC24_R64                  CRC 24 bits R64
                     -CRC32                      CRC 32 bits
                     -CRC32_JAM                  CRC 32 bits JamCRC
                     -CRC32C                     CRC 32 bits C
                     -CRC32D                     CRC 32 bits D
                     -CRC32_BZIP2                CRC 32 bits BZIP2
                     -CRC32_MPEG2                CRC 32 bits MPEG2
                     -CRC32_POSIX                CRC 32 bits POSIX
                     -CRC32K                     CRC 32 bits K
                     -CRC32Q                     CRC 32 bits Q
                     -CRC40                      CRC 40 bits
                     -CRC64                      CRC 64 bits
                     -CRC64_1B                   CRC 64 bits 1B
                     -CRC64_WE                   CRC 64 bits WE
                     -CRC64_JONES                CRC 64 bits JONES
   * Checksum:       -CHECKSUM                   Internet protocol checksum
   * MD2:            -MD2
   * MD4 family:     -MD4
                     -ED2K                       eDonkey/eMule hash algorithm
   * MD5:            -MD5
   * SHA-1:          -SHA1
   * SHA-2 family:   -SHA2                       = -SHA2_256
                     -SHA224/-SHA2_224           SHA-2 224 bits
                     -SHA256/-SHA2_256           SHA-2 256 bits
                     -SHA384/-SHA2_384           SHA-2 384 bits
                     -SHA512/-SHA2_512           SHA-2 512 bits
                     -SHA512_224/-SHA2_512_224   SHA-2 512/224 bits truncated
                     -SHA512_256/-SHA2_512_256   SHA-2 512/256 bits truncated
   * SHA-3 family:   -SHA3                       = -SHA3_256
                     -SHA3_224                   SHA-3 224 bits
                     -SHA3_256                   SHA-3 256 bits
                     -SHA3_384                   SHA-3 384 bits
                     -SHA3_512                   SHA-3 512 bits
                     -SHA3_SHAKE                 = -SHA3_SHAKE_128
                     -SHA3_SHAKE=Size            = -SHA3_SHAKE_128=Size
                     -SHA3_SHAKE_128=Size        SHA-3 SHAKE 128 bits
                                                 Size = Digest output length
                     -SHA3_SHAKE_256=Size        SHA-3 SHAKE 256 bits
                                                 Size = Digest output length


### Release Hash[SHA-3(256)]
* Windows
  * DNSPing.exe: 
  * DNSPing_x86.exe: 
  * DNSPing_XP.exe: 
  * FileHash.exe: 
  * FileHash_x86.exe: 
  * FileHash_XP.exe: 
* Mac
  * DNSPing: 
  * FileHash: 
