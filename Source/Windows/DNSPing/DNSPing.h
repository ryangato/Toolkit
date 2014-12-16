// This code is part of DNSPing(Windows)
// DNSPing, Ping with DNS requesting.
// Copyright (C) 2014 Chengr28
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


// Base Header
//C Standard Library Headers
#include <ctime>                   //Date&Time

//C++ Standard Template Library/STL Headers
#include <memory>                  //Manage dynamic memory support
#include <string>                  //String support

//Windows API Headers
#include <tchar.h>                 //Unicode(UTF-8/UTF-16)/Wide-Character Support
#include <winsock2.h>              //WinSock 2.0+(MUST be including before windows.h)
#include <ws2tcpip.h>              //WinSock 2.0+ Extension for TCP/IP protocols
//Minimum supported system of Windows Version Helpers is Windows Vista.
#ifdef _WIN64
	#include <windows.h>               //Master include file
	#include <VersionHelpers.h>        //Windows Version Helpers
#endif

// Static librarys
#pragma comment(lib, "ws2_32.lib")            //WinSock 2.0+
//#pragma comment(lib, "iphlpapi.lib")        //IP Stack for MIB-II and related functionality

// Base definitions
#pragma pack(1)                                      //Memory alignment: 1 bytes/8 bits
#define __LITTLE_ENDIAN           1U                 //Little Endian
#define __BIG_ENDIAN              2U                 //Big Endian
#define __BYTE_ORDER              __LITTLE_ENDIAN    //x86 and x86-64/x64

//ASCII values definitions
#define ASCII_SPACE               32                   //" "
#define ASCII_PERIOD              46                   //"."
#define ASCII_SLASH               47                   //"/"
#define ASCII_ZERO                48                   //"0"
#define ASCII_NINE                57                   //"9"
#define ASCII_COLON               58                   //":"
#define ASCII_AT                  64                   //"@"
#define ASCII_UPPERCASE_A         65                   //"A"
#define ASCII_UPPERCASE_F         70                   //"F"
#define ASCII_BRACKETS_LEAD       91                   //"["
#define ASCII_ACCENT              96                   //"`"
#define ASCII_LOWERCASE_A         97                   //"a"
#define ASCII_LOWERCASE_F         102                   //"f"
#define ASCII_BRACES_LEAD         123                  //"{"
#define ASCII_TILDE               126                  //"~"
#define ASCII_UPPER_TO_LOWER      32U                  //Uppercase to lowercase
#define ASCII_LOWER_TO_UPPER      32U                  //Lowercase to uppercase

// Protocol Header structures
//Internet Protocol Numbers
//About this list, see http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
/*
#define IPPROTO_HOPOPTS           0                    //IPv6 Hop-by-Hop Option
#define IPPROTO_ICMP              1U                   //Internet Control Message
#define IPPROTO_IGMP              2U                   //Internet Group Management
#define IPPROTO_GGP               3U                   //Gateway-to-Gateway
#define IPPROTO_IPV4              4U                   //IPv4 encapsulation
#define IPPROTO_ST                5U                   //Stream
#define IPPROTO_TCP               6U                   //Transmission Control
#define IPPROTO_CBT               7U                   //CBT
#define IPPROTO_EGP               8U                   //Exterior Gateway Protocol
#define IPPROTO_IGP               9U                   //Any private interior gateway
*/
#define IPPROTO_BBN_RCC_MON       10U                  //BBN RCC Monitoring
#define IPPROTO_NVP_II            11U                  //Network Voice Protocol
//#define IPPROTO_PUP               12U                  //PUP
#define IPPROTO_ARGUS             13U                  //ARGUS
#define IPPROTO_EMCON             14U                  //EMCON
#define IPPROTO_XNET              15U                  //Cross Net Debugger
#define IPPROTO_CHAOS             16U                  //Chaos
//#define IPPROTO_UDP               17U                  //User Datagram
#define IPPROTO_MUX               18U                  //Multiplexing
#define IPPROTO_DCN               19U                  //DCN Measurement Subsystems
#define IPPROTO_HMP               20U                  //Host Monitoring
#define IPPROTO_PRM               21U                  //Packet Radio Measurement
//#define IPPROTO_IDP               22U                  //XEROX NS IDP
#define IPPROTO_TRUNK_1           23U                  //Trunk-1
#define IPPROTO_TRUNK_2           24U                  //Trunk-2
#define IPPROTO_LEAF_1            25U                  //Leaf-1
#define IPPROTO_LEAF_2            26U                  //Leaf-2
//#define IPPROTO_RDP               27U                  //Reliable Data Protocol
#define IPPROTO_IRTP              28U                  //Internet Reliable Transaction
#define IPPROTO_ISO_TP4           29U                  //ISO Transport Protocol Class 4
#define IPPROTO_NETBLT            30U                  //Bulk Data Transfer Protocol
#define IPPROTO_MFE               31U                  //MFE Network Services Protocol
#define IPPROTO_MERIT             32U                  //MERIT Internodal Protocol
#define IPPROTO_DCCP              33U                  //Datagram Congestion Control Protocol
#define IPPROTO_3PC               34U                  //Third Party Connect Protocol
#define IPPROTO_IDPR              35U                  //Inter-Domain Policy Routing Protocol
#define IPPROTO_XTP               36U                  //XTP
#define IPPROTO_DDP               37U                  //Datagram Delivery Protocol
#define IPPROTO_IDPR_CMTP         38U                  //IDPR Control Message Transport Proto
#define IPPROTO_TPPLUS            39U                  //TP++ Transport Protocol
#define IPPROTO_IL                40U                  //IL Transport Protocol
//#define IPPROTO_IPv6              41U                  //IPv6 encapsulation
#define IPPROTO_SDRP              42U                  //Source Demand Routing Protocol
/*
#define IPPROTO_ROUTING           43U                  //Route Routing Header for IPv6
#define IPPROTO_FRAGMENT          44U                  //Frag Fragment Header for IPv6
*/
#define IPPROTO_IDRP              45U                  //Inter - Domain Routing Protocol
#define IPPROTO_RSVP              46U                  //Reservation Protocol
#define IPPROTO_GRE               47U                  //Generic Routing Encapsulation
#define IPPROTO_DSR               48U                  //Dynamic Source Routing Protocol
#define IPPROTO_BNA               49U                  //BNA
/*
#define IPPROTO_ESP               50U                  //Encap Security Payload
#define IPPROTO_AH                51U                  //Authentication Header
*/
#define IPPROTO_NLSP              52U                  //Integrated Net Layer Security TUBA
#define IPPROTO_SWIPE             53U                  //IP with Encryption
#define IPPROTO_NARP              54U                  //NBMA Address Resolution Protocol
#define IPPROTO_MOBILE            55U                  //IP Mobility
#define IPPROTO_TLSP              56U                  //Transport Layer Security Protocol using Kryptonet key management
#define IPPROTO_SKIP              57U                  //SKIP
/*
#define IPPROTO_ICMPV6            58U                  //ICMP for IPv6
#define IPPROTO_NONE              59U                  //No Next Header for IPv6
#define IPPROTO_DSTOPTS           6OU                  //Destination Options for IPv6
*/
#define IPPROTO_AHI               61U                  //Any host internal protocol
#define IPPROTO_CFTP              62U                  //CFTP
#define IPPROTO_ALN               63U                  //Any local network
#define IPPROTO_SAT               64U                  //EXPAK SATNET and Backroom EXPAK
#define IPPROTO_KRYPTOLAN         65U                  //Kryptolan
#define IPPROTO_RVD               66U                  //MIT Remote Virtual Disk Protocol
#define IPPROTO_IPPC              67U                  //Internet Pluribus Packet Core
#define IPPROTO_ADF               68U                  //Any distributed file system
#define IPPROTO_SAT_MON           69U                  //SATNET Monitoring
#define IPPROTO_VISA              70U                  //VISA Protocol
#define IPPROTO_IPCV              71U                  //Internet Packet Core Utility
#define IPPROTO_CPNX              72U                  //Computer Protocol Network Executive
#define IPPROTO_CPHB              73U                  //Computer Protocol Heart Beat
#define IPPROTO_WSN               74U                  //Wang Span Network
#define IPPROTO_PVP               75U                  //Packet Video Protocol
#define IPPROTO_BR                76U                  //SAT - MON Backroom SATNET Monitoring
/*
#define IPPROTO_ND                77U                  //SUN ND PROTOCOL - Temporary
#define IPPROTO_ICLFXBM           78U                  //WIDEBAND Monitoring
*/
#define IPPROTO_WBEXPAK           79U                  //WIDEBAND EXPAK
#define IPPROTO_ISO               80U                  //IP ISO Internet Protocol
#define IPPROTO_VMTP              81U                  //VMTP
#define IPPROTO_SVMTP             82U                  //SECURE - VMTP
#define IPPROTO_VINES             83U                  //VINES
#define IPPROTO_TTP               84U                  //Transaction Transport Protocol
#define IPPROTO_IPTM              85U                  //Internet Protocol Traffic ManageR
#define IPPROTO_NSFNET            86U                  //NSFNET - IGP
#define IPPROTO_DGP               87U                  //Dissimilar Gateway Protocol
#define IPPROTO_TCF               88U                  //TCF
#define IPPROTO_EIGRP             89U                  //EIGRP
#define IPPROTO_SPRITE            90U                  //RPC Sprite RPC Protocol
#define IPPROTO_LARP              91U                  //Locus Address Resolution Protocol
#define IPPROTO_MTP               92U                  //Multicast Transport Protocol
#define IPPROTO_AX25              93U                  //AX.25 Frames
#define IPPROTO_IPIP              94U                  //IP - within - IP Encapsulation Protocol
#define IPPROTO_MICP              95U                  //Mobile Internetworking Control Pro.
#define IPPROTO_SCC               96U                  //Semaphore Communications Sec.Pro.
#define IPPROTO_ETHERIP           97U                  //Ethernet - within - IP Encapsulation
#define IPPROTO_ENCAP             98U                  //Encapsulation Header
#define IPPROTO_APES              100U                 //Any private encryption scheme
#define IPPROTO_GMTP              101U                 //GMTP
#define IPPROTO_IFMP              102U                 //Ipsilon Flow Management Protocol
#define IPPROTO_PNNI              103U                 //PNNI over IP
//#define IPPROTO_PIM               104U                 //Protocol Independent Multicast
#define IPPROTO_ARIS              105U                 //ARIS
#define IPPROTO_SCPS              106U                 //SCPS
#define IPPROTO_QNX               107U                 //QNX
#define IPPROTO_AN                108U                 //Active Networks
#define IPPROTO_IPCOMP            109U                 //IP Payload Compression Protocol
#define IPPROTO_SNP               110U                 //Sitara Networks Protocol
#define IPPROTO_COMPAQ            111U                 //Peer Compaq Peer Protocol
#define IPPROTO_IPX               112U                 //IP IPX in IP
//#define IPPROTO_PGM               113U                 //PGM Reliable Transport Protocol
#define IPPROTO_0HOP              114U                 //Any 0-hop protocol
//#define IPPROTO_L2TP              115U                 //Layer Two Tunneling Protocol
#define IPPROTO_DDX               116U                 //D - II Data Exchange(DDX)
#define IPPROTO_IATP              117U                 //Interactive Agent Transfer Protocol
#define IPPROTO_STP               118U                 //Schedule Transfer Protocol
#define IPPROTO_SRP               119U                 //SRP SpectraLink Radio Protocol
#define IPPROTO_UTI               120U                 //UTI UTI
#define IPPROTO_SMP               121U                 //SMP Simple Message Protocol
#define IPPROTO_SM                122U                 //SM Simple Multicast Protocol
#define IPPROTO_PTP               123U                 //PTP Performance Transparency Protocol
#define IPPROTO_ISIS              124U                 //ISIS over IPv4
#define IPPROTO_FIRE              125U                 //FIRE
#define IPPROTO_CRTP              126U                 //Combat Radio Transport Protocol
#define IPPROTO_CRUDP             127U                 //Combat Radio User Datagram
#define IPPROTO_SSCOPMCE          128U                 //SSCOPMCE
#define IPPROTO_IPLT              129U                 //IPLT
#define IPPROTO_SPS               130U                 //Secure Packet Shield
#define IPPROTO_PIPE              131U                 //Private IP Encapsulation within IP
//#define IPPROTO_SCTP              132U                 //Stream Control Transmission Protocol
#define IPPROTO_FC                133U                 //Fibre Channel
#define IPPROTO_RSVP_E2E          134U                 //RSVP-E2E-IGNORE
#define IPPROTO_MOBILITY          135U                 //Mobility Header
#define IPPROTO_UDPLITE           136U                 //UDP Lite
#define IPPROTO_MPLS              137U                 //MPLS in IP
#define IPPROTO_MANET             138U                 //MANET Protocols
#define IPPROTO_HIP               139U                 //Host Identity Protocol
#define IPPROTO_SHIM6             140U                 //Shim6 Protocol
#define IPPROTO_WESP              141U                 //Wrapped Encapsulating Security Payload
#define IPPROTO_ROHC              142U                 //Robust Header Compression
#define IPPROTO_TEST_1            253U                 //Use for experimentation and testing
#define IPPROTO_TEST_2            254U                 //Use for experimentation and testing
//#define IPPROTO_RESERVED          255U                 //Reserved

//Port definitions(1 - 1024, well-known ports)
//About this list, see https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#define IPPORT_SSH                  22U
#define IPPORT_RAP                  38U
#define IPPORT_RLP                  39U
#define IPPORT_TACACS               49U
#define IPPORT_XNSAUTH              56U
#define IPPORT_BOOTPS               67U
#define IPPORT_BOOTPC               68U
#define IPPORT_HTTP                 80U
#define IPPORT_HTTPBACKUP           81U
#define IPPORT_SUNRPC               111U
#define IPPORT_SQL                  118U
#define IPPORT_BFTP                 152U
#define IPPORT_SGMP                 153U
#define IPPORT_SQLSRV               156U
#define IPPORT_DMSP                 158U
#define IPPORT_ATRTMP               201U
#define IPPORT_ATHBP                202U
#define IPPORT_QMTP                 209U
#define IPPORT_IPX                  213U
#define IPPORT_BGMP                 264U
#define IPPORT_TSP                  318U
#define IPPORT_IMMP                 323U
#define IPPORT_ODMR                 366U
#define IPPORT_RPC2PORTMAP          369U
#define IPPORT_CLEARCASE            371U
#define IPPORT_HPALARMMGR           383U
#define IPPORT_ARNS                 384U
#define IPPORT_AURP                 387U
#define IPPORT_UPS                  401U
#define IPPORT_SLP                  427U
#define IPPORT_SNPP                 444U
#define IPPORT_KPASSWD              464U
#define IPPORT_TCPNETHASPSRV        475U
#define IPPORT_RETROSPECT           497U
#define IPPORT_ISAKMP               500U
#define IPPORT_SYSLOG               514U
#define IPPORT_NCP                  524U
#define IPPORT_COURIER              530U
#define IPPORT_COMMERCE             542U
#define IPPORT_RTSP                 554U
#define IPPORT_NNTP                 563U
#define IPPORT_HTTPRPCEPMAP         593U
#define IPPORT_IPP                  631U
#define IPPORT_LDAPS                636U
#define IPPORT_MSDP                 639U
#define IPPORT_AODV                 654U
#define IPPORT_FTPSDATA             989U
#define IPPORT_FTPS                 990U
#define IPPORT_NAS                  991U
#define IPPORT_TELNETS              992U

//Domain Name System/DNS Part
/* About RFC standards
RFC 920(https://tools.ietf.org/html/rfc920), Domain Requirements – Specified original top-level domains
RFC 1032(https://tools.ietf.org/html/rfc1032), Domain Administrators Guide
RFC 1033(https://tools.ietf.org/html/rfc1033), Domain Administrators Operations Guide
RFC 1034(https://tools.ietf.org/html/rfc1034), Domain Names - Concepts and Facilities
RFC 1035(https://tools.ietf.org/html/rfc1035), Domain Names - Implementation and Specification
RFC 1101(https://tools.ietf.org/html/rfc1101), DNS Encodings of Network Names and Other Types
RFC 1123(https://tools.ietf.org/html/rfc1123), Requirements for Internet Hosts—Application and Support
RFC 1178(https://tools.ietf.org/html/rfc1178), Choosing a Name for Your Computer (FYI 5)
RFC 1183(https://tools.ietf.org/html/rfc1183), New DNS RR Definitions
RFC 1348(https://tools.ietf.org/html/rfc1348), DNS NSAP RRs
RFC 1591(https://tools.ietf.org/html/rfc1591), Domain Name System Structure and Delegation (Informational)
RFC 1664(https://tools.ietf.org/html/rfc1664), Using the Internet DNS to Distribute RFC1327 Mail Address Mapping Tables
RFC 1706(https://tools.ietf.org/html/rfc1706), DNS NSAP Resource Records
RFC 1712(https://tools.ietf.org/html/rfc1712), DNS Encoding of Geographical Location
RFC 1876(https://tools.ietf.org/html/rfc1876), A Means for Expressing Location Information in the Domain Name System
RFC 1886(https://tools.ietf.org/html/rfc1886), DNS Extensions to support IP version 6
RFC 1912(https://tools.ietf.org/html/rfc1912), Common DNS Operational and Configuration Errors
RFC 1995(https://tools.ietf.org/html/rfc1995), Incremental Zone Transfer in DNS
RFC 1996(https://tools.ietf.org/html/rfc1996), A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
RFC 2052(https://tools.ietf.org/html/rfc2052), A DNS RR for specifying the location of services (DNS SRV)
RFC 2100(https://tools.ietf.org/html/rfc2100), The Naming of Hosts (Informational)
RFC 2136(https://tools.ietf.org/html/rfc2136), Dynamic Updates in the domain name system (DNS UPDATE)
RFC 2181(https://tools.ietf.org/html/rfc2181), Clarifications to the DNS Specification
RFC 2182(https://tools.ietf.org/html/rfc2182), Selection and Operation of Secondary DNS Servers
RFC 2230(https://tools.ietf.org/html/rfc2230), Key Exchange Delegation Record for the DNS
RFC 2308(https://tools.ietf.org/html/rfc2308), Negative Caching of DNS Queries (DNS NCACHE)
RFC 2317(https://tools.ietf.org/html/rfc2317), Classless IN-ADDR.ARPA delegation (BCP 20)
RFC 2535(https://tools.ietf.org/html/rfc2535), Domain Name System Security Extensions
RFC 2536(https://tools.ietf.org/html/rfc2536), DSA KEYs and SIGs in the Domain Name System (DNS)
RFC 2537(https://tools.ietf.org/html/rfc2537), RSA/MD5 KEYs and SIGs in the Domain Name System (DNS)
RFC 2539(https://tools.ietf.org/html/rfc2539), Storage of Diffie-Hellman Keys in the Domain Name System (DNS)
RFC 2671(https://tools.ietf.org/html/rfc2671), Extension Mechanisms for DNS (EDNS0)
RFC 2672(https://tools.ietf.org/html/rfc2672), Non-Terminal DNS Name Redirection
RFC 2845(https://tools.ietf.org/html/rfc2845), Secret Key Transaction Authentication for DNS (TSIG)
RFC 2874(https://tools.ietf.org/html/rfc2874), DNS Extensions to Support IPv6 Address Aggregation and Renumbering
RFC 2930(https://tools.ietf.org/html/rfc2930), Secret Key Establishment for DNS (TKEY RR)
RFC 3110(https://tools.ietf.org/html/rfc3110), RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)
RFC 3123(https://tools.ietf.org/html/rfc3123), A DNS RR Type for Lists of Address Prefixes (APL RR)
RFC 3225(https://tools.ietf.org/html/rfc3225), Indicating Resolver Support of DNSSEC
RFC 3226(https://tools.ietf.org/html/rfc3226), DNSSEC and IPv6 A6 aware server/resolver message size requirements
RFC 3403(https://tools.ietf.org/html/rfc3403), Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database
RFC 3597(https://tools.ietf.org/html/rfc3597), Handling of Unknown DNS Resource Record (RR) Types
RFC 3696(https://tools.ietf.org/html/rfc3696), Application Techniques for Checking and Transformation of Names (Informational)
RFC 4025(https://tools.ietf.org/html/rfc4025), A Method for Storing IPsec Keying Material in DNS
RFC 4034(https://tools.ietf.org/html/rfc4034), Resource Records for the DNS Security Extensions
RFC 4255(https://tools.ietf.org/html/rfc4255), Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
RFC 4343(https://tools.ietf.org/html/rfc4343), Domain Name System (DNS) Case Insensitivity Clarification
RFC 4398(https://tools.ietf.org/html/rfc4398), Storing Certificates in the Domain Name System (DNS)
RFC 4408(https://tools.ietf.org/html/rfc4408), Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1
RFC 4431(https://tools.ietf.org/html/rfc4431), The DNSSEC Lookaside Validation (DLV) DNS Resource Record
RFC 4592(https://tools.ietf.org/html/rfc4592), The Role of Wildcards in the Domain Name System
RFC 4635(https://tools.ietf.org/html/rfc4635), HMAC SHA TSIG Algorithm Identifiers
RFC 4701(https://tools.ietf.org/html/rfc4701), A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)
RFC 4892(https://tools.ietf.org/html/rfc4892), Requirements for a Mechanism Identifying a Name Server Instance (Informational)
RFC 5001(https://tools.ietf.org/html/rfc5001), DNS Name Server Identifier (NSID) Option
RFC 5155(https://tools.ietf.org/html/rfc5155), DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
RFC 5205(https://tools.ietf.org/html/rfc5205), Host Identity Protocol (HIP) Domain Name System (DNS) Extension
RFC 5452(https://tools.ietf.org/html/rfc5452), Measures for Making DNS More Resilient against Forged Answers
RFC 5625(https://tools.ietf.org/html/rfc5625), DNS Proxy Implementation Guidelines (BCP 152)
RFC 5890(https://tools.ietf.org/html/rfc5890), Internationalized Domain Names for Applications (IDNA):Definitions and Document Framework
RFC 5891(https://tools.ietf.org/html/rfc5891), Internationalized Domain Names in Applications (IDNA): Protocol
RFC 5892(https://tools.ietf.org/html/rfc5892), The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)
RFC 5893(https://tools.ietf.org/html/rfc5893), Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)
RFC 5894(https://tools.ietf.org/html/rfc5894), Internationalized Domain Names for Applications (IDNA):Background, Explanation, and Rationale (Informational)
RFC 5895(https://tools.ietf.org/html/rfc5895), Mapping Characters for Internationalized Domain Names in Applications (IDNA) 2008 (Informational)
RFC 5936(https://tools.ietf.org/html/rfc5936), DNS Zone Transfer Protocol (AXFR)
RFC 5966(https://tools.ietf.org/html/rfc5966), DNS Transport over TCP - Implementation Requirements
RFC 6195(https://tools.ietf.org/html/rfc6195), Domain Name System (DNS) IANA Considerations (BCP 42)
RFC 6698(https://tools.ietf.org/html/rfc6698), The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
RFC 6742(https://tools.ietf.org/html/rfc6742), DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)
RFC 6844(https://tools.ietf.org/html/rfc6844), DNS Certification Authority Authorization (CAA) Resource Record
RFC 6975(https://tools.ietf.org/html/rfc6975), Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)
RFC 7043(https://tools.ietf.org/html/rfc7043), Resource Records for EUI-48 and EUI-64 Addresses in the DNS
RFC 7314(https://tools.ietf.org/html/rfc7314), Extension Mechanisms for DNS (EDNS) EXPIRE Option

//About this list, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
*/
//Port and Flags definitions
#define IPPORT_DNS              53U      //Standard DNS(TCP and UDP) Port
#define IPPORT_MDNS             5353U    //Multicast Domain Name System/mDNS  Port
#define IPPORT_LLMNR            5355U    //Link-Local Multicast Name Resolution/LLMNR Port
#define DNS_STANDARD            0x0100   //System Standard query
#define DNS_SQR_NE              0x8180   //Standard query response and no error.
#define DNS_SQR_NETC            0x8380   //Standard query response and no error, but Truncated.
#define DNS_SQR_FE              0x8181   //Standard query response, Format Error
#define DNS_SQR_SF              0x8182   //Standard query response, Server failure
#define DNS_SQR_SNH             0x8183   //Standard query response, but no such name.
#define DNS_QUERY_PTR           0xC00C   //Pointer of first query

//OPCode definitions
#define DNS_OPCODE_QUERY        0        //Query, ID is 0.
#define DNS_OPCODE_IQUERY       1U       //Inverse Query(Obsolete), ID is 1.
#define DNS_OPCODE_STATUS       2U       //Status, ID is 2.
#define DNS_OPCODE_NOTIFY       4U       //Notify, ID is 3.
#define DNS_OPCODE_UPDATE       5U       //Update, ID is 4.

//Classes definitions
#define DNS_CLASS_IN            0x0001   //DNS INTERNET, ID is 1.
#define DNS_CLASS_CSNET         0x0002   //DNS CSNET Classes, ID is 2.
#define DNS_CLASS_CHAOS         0x0003   //DNS CHAOS Classes, ID is 3.
#define DNS_CLASS_HESIOD        0x0004   //DNS HESIOD Classes, ID is 4.
#define DNS_CLASS_NONE          0x00FE   //DNS NONE Classes, ID is 254.
#define DNS_CLASS_ALL           0x00FF   //DNS ALL Classes, ID is 255.
#define DNS_CLASS_ANY           0x00FF   //DNS ANY Classes, ID is 255.

//RCode definitions
#define DNS_RCODE_NOERROR       0        //No Error, ID is 0.
#define DNS_RCODE_FORMERR       0x0001   //Format Error, ID is 1.
#define DNS_RCODE_SERVFAIL      0x0002   //Server Failure, ID is 2.
#define DNS_RCODE_NXDOMAIN      0x0003   //Non-Existent Domain, ID is 3.
#define DNS_RCODE_NOTIMP        0x0004   //Not Implemented, ID is 4.
#define DNS_RCODE_REFUSED       0x0005   //Query Refused, ID is 5.
#define DNS_RCODE_YXDOMAIN      0x0006   //Name Exists when it should not, ID is 6.
#define DNS_RCODE_YXRRSET       0x0007   //RR Set Exists when it should not, ID is 7.
#define DNS_RCODE_NXRRSET       0x0008   //RR Set that should exist does not, ID is 8.
#define DNS_RCODE_NOTAUTH       0x0009   //Server Not Authoritative for zone/Not Authorized, ID is 9.
#define DNS_RCODE_NOTZONE       0x000A   //Name not contained in zone, ID is 10.
#define DNS_RCODE_BADVERS       0x0010   //Bad OPT Version/TSIG Signature Failure, ID is 16.
#define DNS_RCODE_BADKEY        0x0011   //Key not recognized, ID is 17.
#define DNS_RCODE_BADTIME       0x0012   //Signature out of time window, ID is 18.
#define DNS_RCODE_BADMODE       0x0013   //Bad TKEY Mode, ID is 19.
#define DNS_RCODE_BADNAME       0x0014   //Duplicate key name, ID is 20.
#define DNS_RCODE_BADALG        0x0015   //Algorithm not supported, ID is 21.
#define DNS_RCODE_BADTRUNC      0x0016   //Bad Truncation, ID is 22.
#define DNS_RCODE_PRIVATE_A     0xFF00   //DNS Reserved Private use opcodes, ID is begin at 3841.
#define DNS_RCODE_PRIVATE_B     0xFFFE   //DNS Reserved Private use opcodes, ID is end at 4095.
#define DNS_OPCODE_RESERVED     0xFFFF   //DNS Reserved opcodes, ID is 65535.

//Record Types definitions
#define DNS_RECORD_A            0x0001   //DNS A Record, ID is 1.
#define DNS_RECORD_NS           0x0002   //DNS NS Record, ID is 2.
#define DNS_RECORD_MD           0x0003   //DNS MD Record, ID is 3.(Obsolete)
#define DNS_RECORD_MF           0x0004   //DNS MF Record, ID is 4.(Obsolete)
#define DNS_RECORD_CNAME        0x0005   //DNS CNAME Record, ID is 5.
#define DNS_RECORD_SOA          0x0006   //DNS SOA Record, ID is 6.
#define DNS_RECORD_MB           0x0007   //DNS MB Record, ID is 7.(Experimental)
#define DNS_RECORD_MG           0x0008   //DNS MG Record, ID is 8.(Experimental)
#define DNS_RECORD_MR           0x0009   //DNS MR Record, ID is 9.(Experimental)
#define DNS_RECORD_NULL         0x000A   //DNS NULL Record, ID is 10.(Experimental)
#define DNS_RECORD_WKS          0x000B   //DNS WKS Record, ID is 11.
#define DNS_RECORD_PTR          0x000C   //DNS PTR Record, ID is 12.
#define DNS_RECORD_HINFO        0x000D   //DNS HINFO Record, ID is 13.
#define DNS_RECORD_MINFO        0x000E   //DNS MINFO Record, ID is 14.
#define DNS_RECORD_MX           0x000F   //DNS MX Record, ID is 15.
#define DNS_RECORD_TXT          0x0010   //DNS TXT Record, ID is 16.
#define DNS_RECORD_RP           0x0011   //DNS RP Record, ID is 17.
#define DNS_RECORD_AFSDB        0x0012   //DNS AFSDB Record, ID is 18.
#define DNS_RECORD_X25          0x0013   //DNS X25 Record, ID is 19.
#define DNS_RECORD_ISDN         0x0014   //DNS ISDN Record, ID is 20.
#define DNS_RECORD_RT           0x0015   //DNS RT Record, ID is 21.
#define DNS_RECORD_NSAP         0x0016   //DNS NSAP Record, ID is 22.
#define DNS_RECORD_NSAP_PTR     0x0017   //DNS NSAP PTR Record, ID is 23.(Obsolete)
#define DNS_RECORD_SIG          0x0018   //DNS SIG Record, ID is 24.
#define DNS_RECORD_KEY          0x0019   //DNS KEY Record, ID is 25.
#define DNS_RECORD_PX           0x001A   //DNS PX Record, ID is 26.
#define DNS_RECORD_GPOS         0x001B   //DNS GPOS Record, ID is 27.
#define DNS_RECORD_AAAA         0x001C   //DNS AAAA Record, ID is 28.
#define DNS_RECORD_LOC          0x001D   //DNS LOC Record, ID is 29.
#define DNS_RECORD_NXT          0x001E   //DNS NXT Record, ID is 30.
#define DNS_RECORD_EID          0x001F   //DNS EID Record, ID is 31.
#define DNS_RECORD_NIMLOC       0x0020   //DNS NIMLOC Record, ID is 32.
#define DNS_RECORD_SRV          0x0021   //DNS SRV Record, ID is 33.
#define DNS_RECORD_ATMA         0x0022   //DNS ATMA Record, ID is 34.
#define DNS_RECORD_NAPTR        0x0023   //DNS NAPTR Record, ID is 35.
#define DNS_RECORD_KX           0x0024   //DNS KX Record, ID is 36.
#define DNS_RECORD_CERT         0x0025   //DNS CERT Record, ID is 37.
#define DNS_RECORD_A6           0x0026   //DNS A6 Record, ID is 38.(Obsolete)
#define DNS_RECORD_DNAME        0x0027   //DNS DNAME Record, ID is 39.
#define DNS_RECORD_SINK         0x0028   //DNS SINK Record, ID is 40.
#define DNS_RECORD_OPT          0x0029   //DNS OPT/EDNS0 Record, ID is 41.
#define DNS_RECORD_APL          0x002A   //DNS APL Record, ID is 42.
#define DNS_RECORD_DS           0x002B   //DNS DS Record, ID is 43.
#define DNS_RECORD_SSHFP        0x002C   //DNS SSHFP Record, ID is 44.
#define DNS_RECORD_IPSECKEY     0x002D   //DNS IPSECKEY Record, ID is 45.
#define DNS_RECORD_RRSIG        0x002E   //DNS RRSIG Record, ID is 46.
#define DNS_RECORD_NSEC         0x002F   //DNS NSEC Record, ID is 47.
#define DNS_RECORD_DNSKEY       0x0030   //DNS DNSKEY Record, ID is 48.
#define DNS_RECORD_DHCID        0x0031   //DNS DHCID Record, ID is 49.
#define DNS_RECORD_NSEC3        0x0032   //DNS NSEC3 Record, ID is 50.
#define DNS_RECORD_NSEC3PARAM   0x0033   //DNS NSEC3PARAM Record, ID is 51.
#define DNS_RECORD_TLSA         0x0034   //DNS TLSA Record, ID is 52.
#define DNS_RECORD_HIP          0x0037   //DNS HIP Record, ID is 55.
#define DNS_RECORD_NINFO        0x0038   //DNS NINFO Record, ID is 56.
#define DNS_RECORD_RKEY         0x0039   //DNS RKEY Record, ID is 57.
#define DNS_RECORD_TALINK       0x003A   //DNS TALINK Record, ID is 58.
#define DNS_RECORD_CDS          0x003B   //DNS CDS Record, ID is 59.
#define DNS_RECORD_CDNSKEY      0x003C   //DNS CDNSKEY Record, ID is 60.
#define DNS_RECORD_OPENPGPKEY   0x003D   //DNS OPENPGPKEY Record, ID is 61.
#define DNS_RECORD_SPF          0x0063   //DNS SPF Record, ID is 99.
#define DNS_RECORD_UINFO        0x0064   //DNS UINFO Record, ID is 100.
#define DNS_RECORD_UID          0x0065   //DNS UID Record, ID is 101.
#define DNS_RECORD_GID          0x0066   //DNS GID Record, ID is 102.
#define DNS_RECORD_UNSPEC       0x0067   //DNS UNSPEC Record, ID is 103.
#define DNS_RECORD_NID          0x0068   //DNS NID Record, ID is 104.
#define DNS_RECORD_L32          0x0069   //DNS L32 Record, ID is 105.
#define DNS_RECORD_L64          0x006A   //DNS L64 Record, ID is 106.
#define DNS_RECORD_LP           0x006B   //DNS LP Record, ID is 107.
#define DNS_RECORD_EUI48        0x006C   //DNS EUI48 Record, ID is 108.
#define DNS_RECORD_EUI64        0x006D   //DNS EUI64 Record, ID is 109.
#define DNS_RECORD_TKEY         0x00F9   //DNS TKEY Record, ID is 249.
#define DNS_RECORD_TSIG         0x00FA   //DNS TSIG Record, ID is 250.
#define DNS_RECORD_IXFR         0x00FB   //DNS IXFR Record, ID is 251.
#define DNS_RECORD_AXFR         0x00FC   //DNS AXFR Record, ID is 252.
#define DNS_RECORD_MAILB        0x00FD   //DNS MAILB Record, ID is 253.
#define DNS_RECORD_MAILA        0x00FE   //DNS MAILA Record, ID is 254.
#define DNS_RECORD_ANY          0x00FF   //DNS ANY Record, ID is 255.
#define DNS_RECORD_URI          0x0100   //DNS URI Record, ID is 256.
#define DNS_RECORD_CAA          0x0101   //DNS CAA Record, ID is 257.
#define DNS_RECORD_TA           0x8000   //DNS TA Record, ID is 32768.
#define DNS_RECORD_DLV          0x8001   //DNS DLVS Record, ID is 32769.
#define DNS_RECORD_PRIVATE_A    0xFF00   //DNS Reserved Private use records, ID is begin at 65280.
#define DNS_RECORD_PRIVATE_B    0xFFFE   //DNS Reserved Private use records, ID is end at 65534.
#define DNS_RECORD_RESERVED     0xFFFF   //DNS Reserved records, ID is 65535.

/* Domain Name System/DNS Header
// With User Datagram Protocol/UDP

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |Q|OPCode |A|T|R|R|Z|A|C| RCode |  QR/Query and Response, AA/Authoritative Answer, TC/Truncated, RD/Recursion Desired, RA/Recursion Available
|                               |R|       |A|C|D|A| |D|D|       |  Z/Zero, AD/Authenticated Data, CD/Checking Disabled, RCode/Return Code
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Total Questions        |       Total Answer RRs        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Total Authority RRs      |     Total Additional RRs      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define OLD_DNS_MAXSIZE 512U
typedef struct _dns_hdr_
{
	uint16_t              ID;
	union {
		uint16_t          Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       RD:1;
			uint8_t       TC:1;
			uint8_t       AA:1;
			uint8_t       OPCode_Second:1;
			uint8_t       OPCode_First:3;
			uint8_t       QR:1;
			uint8_t       RCode:4;
			uint8_t       AD:1;
			uint8_t       CD:1;
			uint8_t       Zero:1;
			uint8_t       RA:1;
		#else //BIG_ENDIAN
			uint8_t       QR:1;
			uint8_t       OPCode:4;
			uint8_t       AA:1;
			uint8_t       TC:1;
			uint8_t       RD:1;
			uint8_t       RA:1;
			uint8_t       Zero:1;
			uint8_t       AD:1;
			uint8_t       CD:1;
			uint8_t       RCode:4;
		#endif
		}FlagsBits;
	};
	uint16_t              Questions;
	uint16_t              Answer;
	uint16_t              Authority;
	uint16_t              Additional;
}dns_hdr;

/* Domain Name System/DNS Query

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Name                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |            Classes            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_qry_
{
//	PUCHAR                Name;
	uint16_t              Type;
	uint16_t              Classes;
}dns_qry;

/* Domain Name System/DNS Standard Resource Record

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Name                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |           Classes             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Time To Live          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_standard_
{
//	PUCHAR                Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	PUCHAR                Data;
}dns_standard_record;

/* Start Of a zone of Authority/SOA Resource Record

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                         Primary Name                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                         Mailbox Name                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Serial                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Refresh Interval                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Retry Interval                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Expire Limit                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Minimum TTL                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_soa_
{
//	PUCHAR                PrimaryName;
//	PUCHAR                MailboxName;
	uint32_t              Serial;
	uint32_t              RefreshInterval;
	uint32_t              RetryInterval;
	uint32_t              ExpireLimit;
	uint32_t              MinimumTTL;
}dns_soa_record;

/* Mail eXchange/MX Resource Record

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Preference           |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                      Mail Exchange Name                       /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_mx_
{
	uint16_t              Preference;
//	PUCHAR                MailExchangeName;
}dns_mx_record;

/* Text strings/TXT Resource Record

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Length     |                                               /
+-+-+-+-+-+-+-+-+                                               /
/                              TXT                              /
/                                                               /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_txt_
{
	uint8_t              Length;
//	PUCHAR               TXT;

}dns_txt_record;

/* Server Selection/SRV Resource Record

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Priority            |            Weight             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Port              |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                            Target                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_srv_
{
	uint16_t             Priority;
	uint16_t             Weight;
	uint16_t             Port;
//	PUCHAR               Target;
}dns_srv_record;

// Option/OPT Resource Record(Extension Mechanisms for Domain Name System/EDNS, EDNS0 Label)
#define EDNS0_CODE_LLQ                 0x0001   //Long-lived query
#define EDNS0_CODE_UL                  0x0002   //Update lease
#define EDNS0_CODE_NSID                0x0003   //Name Server Identifier (RFC 5001)
#define EDNS0_CODE_OWNER               0x0004   //Owner, reserved
#define EDNS0_CODE_DAU                 0x0005   //DNSSEC Algorithm Understood (RFC6975)
#define EDNS0_CODE_DHU                 0x0006   //DS Hash Understood (RFC6975)
#define EDNS0_CODE_N3U                 0x0007   //DSEC3 Hash Understood (RFC6975)
#define EDNS0_CODE_CLIENT_SUBNET       0x0008   //Client subnet as assigned by IANA
#define EDNS0_CODE_EDNS_EXPIRE         0x0009   //EDNS Expire (RFC7314)
#define EDNS0_CODE_CLIENT_SUBNET_EXP   0x50FA   //Client subnet, ID is 20730

/*
                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |       UDP Payload Size        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Extended RCode | EDNS0 Version |D|          Reserved           |  Extended RCode/Higher bits in extended Return Code, D/DO bit
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |\---------- Z Field -----------/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define EDNS0_MINSIZE 1220U
typedef struct _dns_opt_
{
	uint8_t               RootName;
	uint16_t              Type;              //Additional RRs Type
	uint16_t              UDPPayloadSize;
	uint8_t               Extended_RCode;
	uint8_t               Version;           //EDNS0 Version
	union {
		uint16_t          Z_Field;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       Reserved_First:7;
			uint8_t       DO:1;              //DO bit
		#else //BIG_ENDIAN
			uint8_t       DO:1;              //DO bit
			uint8_t       Reserved_First:7;
		#endif
			uint8_t       Reserved_Second;
		}Z_Bits;
	};
	uint16_t              DataLength;
}dns_opt_record;

/* Extension Mechanisms for Domain Name System/EDNS0 Option

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Code                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Length                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_edns0_option_
{
	uint16_t              Code;
	uint16_t              Length;
//	PUCHAR                Data;
}dns_edns0_option;

// RRSIG Record(Resource Record Digital Signature)
#define DNSSEC_AlGORITHM_RSA_MD5               1U
#define DNSSEC_AlGORITHM_DH                    2U
#define DNSSEC_AlGORITHM_DSA                   3U
#define DNSSEC_AlGORITHM_ECC                   4U
#define DNSSEC_AlGORITHM_RSA_SHA1              5U
#define DNSSEC_AlGORITHM_DSA_NSEC3_SHA1        6U
#define DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1   7U
#define DNSSEC_AlGORITHM_RSA_SHA256            8U
#define DNSSEC_AlGORITHM_RSA_SHA512            10U
#define DNSSEC_AlGORITHM_ECC_GOST              12U
#define DNSSEC_AlGORITHM_ECDSA_P256_SHA256     13U
#define DNSSEC_AlGORITHM_ECDSA_P386_SHA386     14U
#define DNSSEC_AlGORITHM_HMAC_MD5              157U
#define DNSSEC_AlGORITHM_INDIRECT              252U
#define DNSSEC_AlGORITHM_PRIVATE_DNS           253U
#define DNSSEC_AlGORITHM_PRIVATE_OID           254U

/*
                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Type Covered           |   Algorithm   |    Labels     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Original TTL                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature Expiration                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature Inception                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Key Tag            |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Signature                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_rrsig_
{
	uint16_t              TypeCovered;
	uint8_t               Algorithm;
	uint8_t               Labels;
	uint32_t              TTL;
	uint32_t              Expiration;
	uint32_t              Inception;
	uint16_t              KeyTag;
//	PUCHAR                SignerName;
//	PUCHAR                Signature;
}dns_rrsig_record;

/* Certification Authority Authorization/CAA Resource Record

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |    Length     |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                             Tag                               /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Value                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_caa_
{
	uint8_t              Flags;
	uint8_t              Length;
//	PUCHAR               Tag;
//	PUCHAR               Value;
}dns_caa_record;


//Base definitions
#define MBSTOWCS_NULLTERMINATE       -1          //MultiByteToWideChar() find null-terminate.
#define BYTES_TO_BITS                8U
#define U4_MAXNUM                    0x000F      //Maximum value of half of uint8_t/4 bits
#define U8_MAXNUM                    0x00FF      //Maximum value of uint8_t/8 bits
#define U16_MAXNUM                   0xFFFF      //Maximum value of uint16_t/16 bits
#define HIGHEST_BIT_U16              0x7FFF      //Get highest bit in uint16_t/16 bits data.
#define HIGHEST_MOVE_BIT_U16         15U         //Move 15 bits to get highest bit in uint16_t/16 bits data.
#define U16_NUM_1                    0x0001
#define NUM_HEX                      16
#define PACKET_MINSIZE               64U         //Minimum size of packets in Ethernet network.
#define PACKET_MAXSIZE               1512U       //Maximum size of packets(1500 bytes maximum payload length + 8 bytes Ethernet header + 4 bytes FCS), Standard MTU of Ethernet network
#define LARGE_PACKET_MAXSIZE         4096U       //Maximum size of packets(4KB/4096 bytes) of TCP protocol
#define ADDR_STRING_MAXSIZE          64U         //Maximum size of addresses(IPv4/IPv6) words
#define STANDARD_TIME_OUT            1000U       //Standard timeout, 1000 ms(1 second)
#define MICROSECOND_TO_MILLISECOND   1000U       //1000 microseconds(1 millisecond)
#define TIME_OUT_MIN                 500U        //Minimum timeout, 500 ms
#define DEFAULT_TIME_OUT             2000U       //Default timeout, 2000 ms(2 seconds)
#define DEFAULT_SEND_TIMES           4U          //Default send times
#define SECONDS_IN_YEAR              31536000U   //31536000 seconds in a year(30 days in a month and 12 months in a year)
#define SECONDS_IN_MONTH             2592000U    //2592000 seconds in a month(30 days in a month)
#define SECONDS_IN_DAY               86400U      //86400 seconds in a day
#define SECONDS_IN_HOUR              3600U       //3600 seconds in an hour
#define SECONDS_IN_MINUTE            60U         //60 seconds in a minute
#define DOMAIN_MAXSIZE               256U        //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).

//Protocol.cpp
//Minimum supported system of Windows Version Helpers is Windows Vista.
#ifdef _WIN64
#else //x86
bool __fastcall IsLowerThanWin8(void);
#endif
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length);
size_t __fastcall CaseConvert(bool LowerUpper, const PSTR Buffer, const size_t Length);
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *pAddr, const uint16_t Protocol, SSIZE_T &ErrorCode);
uint16_t __fastcall InternetProtocolNameToPort(const LPWSTR Buffer);
uint16_t __fastcall ServiceNameToPort(const LPWSTR Buffer);
uint16_t __fastcall DNSClassesNameToHex(const LPWSTR Buffer);
uint16_t __fastcall DNSTypeNameToHex(const LPWSTR Buffer);
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName);
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName, uint16_t &Truncated);
bool __fastcall ValidatePacket(const PSTR Buffer, const size_t Length, const uint16_t DNS_ID);
void __fastcall PrintSecondsInDateTime(const time_t Seconds);
void __fastcall PrintSecondsInDateTime(const time_t Seconds, FILE *OutputFile);
void __fastcall PrintDateTime(const time_t Time);
void __fastcall PrintDateTime(const time_t Time, FILE *OutputFile);

//Process.cpp
size_t __fastcall SendProcess(const sockaddr_storage Target);
size_t __fastcall PrintProcess(const bool PacketStatistics, const bool TimeStatistics);
void __fastcall PrintDescription(void);

//Resolver.cpp
void __fastcall PrintResponseHex(const PSTR Buffer, const size_t Length);
void __fastcall PrintResponseHex(const PSTR Buffer, const size_t Length, FILE *OutputFile);
void __fastcall PrintResponse(const PSTR Buffer, const size_t Length);
void __fastcall PrintResponse(const PSTR Buffer, const size_t Length, FILE *OutputFile);
void __fastcall PrintFlags(const uint16_t Flags);
void __fastcall PrintFlags(const uint16_t Flags, FILE *OutputFile);
void __fastcall PrintTypeClassesName(const uint16_t Type, const uint16_t Classes);
void __fastcall PrintTypeClassesName(const uint16_t Type, const uint16_t Classes, FILE *OutputFile);
size_t __fastcall PrintDomainName(const PSTR Buffer, const size_t Location);
size_t __fastcall PrintDomainName(const PSTR Buffer, const size_t Location, FILE *OutputFile);
void __fastcall PrintResourseData(const PSTR Buffer, const size_t Location, const uint16_t Length, const uint16_t Type, const uint16_t Classes);
void __fastcall PrintResourseData(const PSTR Buffer, const size_t Location, const uint16_t Length, const uint16_t Type, const uint16_t Classes, FILE *OutputFile);

//Console.cpp
BOOL __fastcall CtrlHandler(const DWORD fdwCtrlType);
