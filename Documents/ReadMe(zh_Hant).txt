### Linux/Mac 用法
* 打開終端，並進入 Toolkit 目錄
* 運行 chmod 755 CMake_Build.sh 基於編譯腳本運行許可權
* 運行 ./CMake_Build.sh 生成二進位可執行檔


### DNSPing 用法和選項
       DNSPing [-options] domain target
  e.g. DNSPing -a -qt AAAA -n 5 -w 500 -edns0 www.google.com 8.8.4.4

   ?/-h              列印說明
   -t                直到按下 Control-Break 或 Control-C 才停止 Ping
                     想看從 Ping 開始到按下時的統計資訊但不想停止請按 Control-Break
                     想停止 Ping 並查看統計資訊請按 Control-C
   -a                反向解析位址的功能變數名稱
   -n count          發送 Ping 的數量
                     Count 必須介乎于 1 - 0xFFFF/65535
   -f                設定 Ping 資料包的不分片選項（只適用于IPv4）
                     不適用於 Mac OS X 系統
   -i hoplimit/ttl   設定 Ping 資料包的跳數限制/存留時間
                     HopLimit/TTL 必須介乎于 1 - 255
   -w timeout        設定超時時間（單位：毫秒）
                     Timeout 必須介乎于 500 - 0xFFFF/65535
   -id dns_id        設定 DNS 請求包頭的 ID
                     DNS ID 必須介乎于 0x0001 - 0xFFFF/65535
   -qr               設定 DNS 請求包頭的 QR 標誌
   -opcode opcode    設定 DNS 請求包頭的 OPCode
                     OPCode 必須介乎于 0x0000 - 0x00FF/255
   -aa               設定 DNS 請求包頭的 AA 標誌
   -tc               設定 DNS 請求包頭的 TC 標誌
   -rd               設定 DNS 請求包頭的 RD 標誌
   -ra               設定 DNS 請求包頭的 RA 標誌
   -ad               設定 DNS 請求包頭的 AD 標誌
   -cd               設定 DNS 請求包頭的 CD 標誌
   -rcode rcode      設定 DNS 請求包頭的 RCode
                     RCode 必須介乎于 0x0000 - 0x00FF/255
   -qn count         設定 DNS 請求包頭的 Question count
                     Question count 必須介乎于 0x0001 - 0xFFFF/65535
   -ann count        設定 DNS 請求包頭的 Answer count
                     Answer count 必須介乎于 0x0001 - 0xFFFF/65535
   -aun count        設定 DNS 請求包頭的 Authority count
                     Authority count 必須介乎于 0x0001 - 0xFFFF/65535
   -adn count        設定 DNS 請求包頭的 Additional count
                     Additional count 必須介乎于 0x0001 - 0xFFFF/65535
   -ti interval_time 設定每次請求之間的時間間隔（單位：毫秒）
   -edns0            發送時添加 EDNS0 標籤
   -payload length   設定 EDNS0 標籤的 UDP Payload length
                     Payload length 必須介乎于 512 - 0xFFFF/65535
   -dnssec           發送時添加可以接受 DNSSEC 的請求
                     啟用添加可以接受 DNSSEC 時發送時添加 EDNS0 標籤也會被啟用
   -qt type          設定請求類型 Query Type
                     Query 類型的值必須介乎于 0x0001 - 0xFFFF/65535
                     Type: A|NS|MD|MF|CNAME|SOA|MB|MG|MR|NULL|WKS|PTR|HINFO|
                           MINFO|MX|TXT|RP|AFSDB|X25|ISDN|RT|NSAP|NSAPPTR|
                           SIG|KEY|PX|GPOS|AAAA|LOC|NXT|EID|NIMLOC|SRV|ATMA|
                           NAPTR|KX|A6|CERT|DNAME|SINK|OPT|APL|DS|SSHFP|
                           IPSECKEY|RRSIG|NSEC|DNSKEY|DHCID|NSEC3|NSEC3PARAM|
                           TLSA|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|
                           SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|
                           EUI64|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY|URI|
                           CAA|TA|DLV|RESERVED
   -qc classes       設定請求類型 Query Classes
                     Classes 類型的值必須介乎于 0x0001 - 0xFFFF/65535
                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY
   -p service_name   設定 UDP 埠
                     UDP 埠的值必須介乎于 0x0001 - 0xFFFF/65535
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
   -rawdata raw_data 設定發送原始資料
                     原始資料為不需要添加 0x 開頭的16進制數
                     原始資料長度必須介乎于 64 - 1500 位元組
   -raw service_name 設定 RAW 通訊端類型
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
   -socks target                   設定 SOCKS 伺服器的位址
                                   位址的格式是 位址:埠，例如 [::1]:1080
   -socks_username username        設定 SOCKS 伺服器的使用者名
                                   使用者名長度必須介乎于 1 - 255 位元組
   -socks_password password        設定 SOCKS 伺服器的密碼
                                   密碼長度必須介乎于 1 - 255 位元組
   -buf size                       設定接收緩衝區長度
                                   緩衝區長度必須介乎于 512 - 4096 位元組
   -dv                             關閉資料包驗證
   -show type                      顯示收到的解析包的內容
                                   Type: Result|Hex
   -of file_name                   輸出結果到文字檔
                                   文字檔名稱長度必須小於 260 位元組
   -6                              強制使用 IPv6
   -4                              強制使用 IPv4
   domain                          設定發送 DNS 請求用的查詢的功能變數名稱
   target                          Ping 的目標，支援 IPv4/IPv6 位址和功能變數名稱


### FileHash 用法和選項
       FileHash -option/-algorithm [Filename]
  e.g. FileHash -SHA3 filename

支援的選項:
   -v/--version: 輸出當前程式的版本號
   -?/-h/--help 輸出程式的説明資訊

支援的 Hash 演算法:
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
   * Checksum:       -CHECKSUM                   Internet 協定校驗和
   * MD2:            -MD2
   * MD4 family:     -MD4
                     -ED2K                       eDonkey/eMule Hash 演算法
   * MD5:            -MD5
   * SHA-1:          -SHA1
   * SHA-2 family:   -SHA2                       = -SHA2_256
                     -SHA224/-SHA2_224           SHA-2 224 位
                     -SHA256/-SHA2_256           SHA-2 256 位
                     -SHA384/-SHA2_384           SHA-2 384 位
                     -SHA512/-SHA2_512           SHA-2 512 位
                     -SHA512_224/-SHA2_512_224   SHA-2 512/224 位截斷
                     -SHA512_256/-SHA2_512_256   SHA-2 512/256 位截斷
   * SHA-3 family:   -SHA3                       = -SHA3_256
                     -SHA3_224                   SHA-3 224 位
                     -SHA3_256                   SHA-3 256 位
                     -SHA3_384                   SHA-3 384 位
                     -SHA3_512                   SHA-3 512 位
                     -SHA3_SHAKE                 = -SHA3_SHAKE_128
                     -SHA3_SHAKE=Size            = -SHA3_SHAKE_128=Size
                     -SHA3_SHAKE_128=Size        SHA-3 SHAKE 128 位
                                                 Size = 輸出長度
                     -SHA3_SHAKE_256=Size        SHA-3 SHAKE 256 位
                                                 Size = 輸出長度


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
