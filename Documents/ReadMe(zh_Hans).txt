### Linux/Mac 用法
* 打开终端，并进入 Toolkit 目录
* 运行 chmod 755 CMake_Build.sh 基于编译脚本运行权限
* 运行 ./CMake_Build.sh 生成二进制可执行文件


### DNSPing 用法和选项
       DNSPing [-options] domain target
  e.g. DNSPing -a -qt AAAA -n 5 -w 500 -edns0 www.google.com 8.8.4.4

   ?/-h              打印说明
   -t                直到按下 Control-Break 或 Control-C 才停止 Ping
                     想看从 Ping 开始到按下时的统计信息但不想停止请按 Control-Break
                     想停止 Ping 并查看统计信息请按 Control-C
   -a                反向解析地址的域名
   -n count          发送 Ping 的数量
                     Count 必须介乎于 1 - 0xFFFF/65535
   -f                设定 Ping 数据包的不分片选项（只适用于IPv4）
                     不适用于 Mac OS X 系统
   -i hoplimit/ttl   设定 Ping 数据包的跳数限制/生存时间
                     HopLimit/TTL 必须介乎于 1 - 255
   -w timeout        设定超时时间（单位：毫秒）
                     Timeout 必须介乎于 500 - 0xFFFF/65535
   -id dns_id        设定 DNS 请求包头的 ID
                     DNS ID 必须介乎于 0x0001 - 0xFFFF/65535
   -qr               设定 DNS 请求包头的 QR 标志
   -opcode opcode    设定 DNS 请求包头的 OPCode
                     OPCode 必须介乎于 0x0000 - 0x00FF/255
   -aa               设定 DNS 请求包头的 AA 标志
   -tc               设定 DNS 请求包头的 TC 标志
   -rd               设定 DNS 请求包头的 RD 标志
   -ra               设定 DNS 请求包头的 RA 标志
   -ad               设定 DNS 请求包头的 AD 标志
   -cd               设定 DNS 请求包头的 CD 标志
   -rcode rcode      设定 DNS 请求包头的 RCode
                     RCode 必须介乎于 0x0000 - 0x00FF/255
   -qn count         设定 DNS 请求包头的 Question count
                     Question count 必须介乎于 0x0001 - 0xFFFF/65535
   -ann count        设定 DNS 请求包头的 Answer count
                     Answer count 必须介乎于 0x0001 - 0xFFFF/65535
   -aun count        设定 DNS 请求包头的 Authority count
                     Authority count 必须介乎于 0x0001 - 0xFFFF/65535
   -adn count        设定 DNS 请求包头的 Additional count
                     Additional count 必须介乎于 0x0001 - 0xFFFF/65535
   -ti interval_time 设定每次请求之间的时间间隔（单位：毫秒）
   -edns0            发送时添加 EDNS0 标签
   -payload length   设定 EDNS0 标签的 UDP Payload length
                     Payload length 必须介乎于 512 - 0xFFFF/65535
   -dnssec           发送时添加可以接受 DNSSEC 的请求
                     启用添加可以接受 DNSSEC 时发送时添加 EDNS0 标签也会被启用
   -qt Type          设定请求类型 Query Type
                     Query 类型的值必须介乎于 0x0001 - 0xFFFF/65535
                     Type: A|NS|MD|MF|CNAME|SOA|MB|MG|MR|NULL|WKS|PTR|HINFO|
                           MINFO|MX|TXT|RP|AFSDB|X25|ISDN|RT|NSAP|NSAPPTR|
                           SIG|KEY|PX|GPOS|AAAA|LOC|NXT|EID|NIMLOC|SRV|ATMA|
                           NAPTR|KX|A6|CERT|DNAME|SINK|OPT|APL|DS|SSHFP|
                           IPSECKEY|RRSIG|NSEC|DNSKEY|DHCID|NSEC3|NSEC3PARAM|
                           TLSA|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|
                           SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|
                           EUI64|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY|URI|
                           CAA|TA|DLV|RESERVED
   -qc classes       设定请求类型 Query Classes
                     Classes 类型的值必须介乎于 0x0001 - 0xFFFF/65535
                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY
   -p service_name   设定 UDP 端口或服务名称
                     UDP 端口的值必须介乎于 0x0001 - 0xFFFF/65535
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
   -rawdata raw_data 设定想要发送的原始数据
                     RAW_Data 是以十六进制表示的数据，不需要在前面加 0x
                     RAW_Data 长度必须介乎于 64 - 1500 字节
   -raw service_name 设定要使用的原始套接字类型
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
   -socks target            设定 SOCKS 服务器的地址
                            地址的格式是 地址:端口，例如 [::1]:1080
   -socks_username username 设定 SOCKS 服务器的用户名
                            用户名长度必须介乎于 1 - 255 字节
   -socks_password password 设定 SOCKS 服务器的密码
                            密码长度必须介乎于 1 - 255 字节
   -buf size                设定接收缓冲区长度
                            缓冲区长度必须介乎于 512 - 4096 字节
   -dv                      关闭数据包验证
   -show type               显示收到的解析包的内容
                            Type: Result|Hex
   -of file_name            输出结果到文本文件
                            文本文件名称长度必须小于 260 字节
   -6                       强制使用 IPv6
   -4                       强制使用 IPv4
   domain                   设定发送 DNS 请求用的查询的域名
   target                   Ping 的目标，支持 IPv4/IPv6 地址和域名


### FileHash 用法和选项
       FileHash -option/-algorithm [Filename]
  e.g. FileHash -SHA3 filename

支持的选项:
   -v/--version:     输出当前程序的版本号
   -?/-h/--help      输出程序的帮助信息

支持的 Hash 算法:
   * CRC family:     -CRC                        = -CRC32
                     -CRC8                       CRC 8 位
                     -CRC8_ITU                   CRC 8 位 ITU
                     -CRC8_ATM                   CRC 8 位 ATM
                     -CRC8_CCITT                 CRC 8 位 CCITT
                     -CRC8_MAXIM                 CRC 8 位 Maxim
                     -CRC8_ICODE                 CRC 8 位 Icode
                     -CRC8_J1850                 CRC 8 位 J1850
                     -CRC8_WCDMA                 CRC 8 位 WCDMA
                     -CRC8_ROHC                  CRC 8 位 Rohc
                     -CRC8_DARC                  CRC 8 位 Darc
                     -CRC16                      CRC 16 位
                     -CRC16_BUYPASS              CRC 16 位 Buypass
                     -CRC16_DDS_110              CRC 16 位 DDS 110
                     -CRC16_EN_13757             CRC 16 位 EN 13757
                     -CRC16_TELEDISK             CRC 16 位 Teledisk
                     -CRC16_MODBUS               CRC 16 位 Modbus
                     -CRC16_MAXIM                CRC 16 位 Maxim
                     -CRC16_USB                  CRC 16 位 USB
                     -CRC16_T10_DIF              CRC 16 位 T10 DIF
                     -CRC16_DECT_X               CRC 16 位 DECT X
                     -CRC16_DECT_R               CRC 16 位 DECT R
                     -CRC16_SICK                 CRC 16 位 Sick
                     -CRC16_DNP                  CRC 16 位 DNP
                     -CRC16_CCITT_XMODEM         CRC 16 位 CCITT Xmodem
                     -CRC16_CCITT_FFFF           CRC 16 位 CCITT FFFF
                     -CRC16_CCITT_1D0F           CRC 16 位 CCITT 1D0F
                     -CRC16_GENIBUS              CRC 16 位 Genibus
                     -CRC16_KERMIT               CRC 16 位 Kermit
                     -CRC16_X25                  CRC 16 位 X25
                     -CRC16_MCRF4XX              CRC 16 位 MCRF4XX
                     -CRC16_RIELLO               CRC 16 位 Riello
                     -CRC16_FLETCHER             CRC 16 位 Fletcher
                     -CRC24                      = -CRC24_R64
                     -CRC24_FLEXRAY_A            CRC 24 位 Flexray A
                     -CRC24_FLEXRAY_B            CRC 24 位 Flexray B
                     -CRC24_R64                  CRC 24 位 R64
                     -CRC32                      CRC 32 位
                     -CRC32_JAM                  CRC 32 位 JamCRC
                     -CRC32C                     CRC 32 位 C
                     -CRC32D                     CRC 32 位 D
                     -CRC32_BZIP2                CRC 32 位 BZIP2
                     -CRC32_MPEG2                CRC 32 位 MPEG2
                     -CRC32_POSIX                CRC 32 位 POSIX
                     -CRC32K                     CRC 32 位 K
                     -CRC32Q                     CRC 32 位 Q
                     -CRC40                      CRC 40 位
                     -CRC64                      CRC 64 位
                     -CRC64_1B                   CRC 64 位 1B
                     -CRC64_WE                   CRC 64 位 WE
                     -CRC64_JONES                CRC 64 位 JONES
   * Checksum:       -CHECKSUM                   Internet 协议检验和
   * MD2:            -MD2
   * MD4 family:     -MD4
                     -ED2K                       eDonkey/eMule Hash 算法
   * MD5:            -MD5
   * SHA-1:          -SHA1
   * SHA-2 family:   -SHA2                       = -SHA2_256
                     -SHA224/-SHA2_224           SHA-2 224 位
                     -SHA256/-SHA2_256           SHA-2 256 位
                     -SHA384/-SHA2_384           SHA-2 384 位
                     -SHA512/-SHA2_512           SHA-2 512 位
                     -SHA512_224/-SHA2_512_224   SHA-2 512/224 位截断
                     -SHA512_256/-SHA2_512_256   SHA-2 512/256 位截断
   * SHA-3 family:   -SHA3                       = -SHA3_256
                     -SHA3_224                   SHA-3 224 位
                     -SHA3_256                   SHA-3 256 位
                     -SHA3_384                   SHA-3 384 位
                     -SHA3_512                   SHA-3 512 位
                     -SHA3_SHAKE                 = -SHA3_SHAKE_128
                     -SHA3_SHAKE=Size            = -SHA3_SHAKE_128=Size
                     -SHA3_SHAKE_128=Size        SHA-3 SHAKE 128 位
                                                 Size = 输出长度
                     -SHA3_SHAKE_256=Size        SHA-3 SHAKE 256 位
                                                 Size = 输出长度


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
