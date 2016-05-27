// This code is part of DNSPing
// Ping with DNS requesting.
// Copyright (C) 2014-2016 Chengr28
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


#include "Base.h"

extern ConfigurationTable ConfigurationParameter;

//Internet Protocol Numbers
//About this list, see http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#ifndef IPPROTO_HOPOPTS
	#define IPPROTO_HOPOPTS           0                    //IPv6 Hop-by-Hop Option
#endif
#ifndef IPPROTO_ICMP
	#define IPPROTO_ICMP              1U                   //Internet Control Message
#endif
#ifndef IPPROTO_IGMP
	#define IPPROTO_IGMP              2U                   //Internet Group Management
#endif
#ifndef IPPROTO_GGP
	#define IPPROTO_GGP               3U                   //Gateway-to-Gateway
#endif
#ifndef IPPROTO_IPV4
	#define IPPROTO_IPV4              4U                   //IPv4 encapsulation
#endif
#ifndef IPPROTO_ST
	#define IPPROTO_ST                5U                   //Stream
#endif
#ifndef IPPROTO_TCP
	#define IPPROTO_TCP               6U                   //Transmission Control
#endif
#ifndef IPPROTO_CBT
	#define IPPROTO_CBT               7U                   //Core Based Tree
#endif
#ifndef IPPROTO_EGP
	#define IPPROTO_EGP               8U                   //Exterior Gateway Protocol
#endif
#ifndef IPPROTO_IGP
	#define IPPROTO_IGP               9U                   //Any private interior gateway
#endif
#ifndef IPPROTO_BBN_RCC_MON
	#define IPPROTO_BBN_RCC_MON       10U                  //BBN RCC Monitoring
#endif
#ifndef IPPROTO_NVP_II
	#define IPPROTO_NVP_II            11U                  //Network Voice Protocol
#endif
#ifndef IPPROTO_PUP
	#define IPPROTO_PUP               12U                  //PUP
#endif
#ifndef IPPROTO_ARGUS
	#define IPPROTO_ARGUS             13U                  //ARGUS
#endif
#ifndef IPPROTO_EMCON
	#define IPPROTO_EMCON             14U                  //EMCON
#endif
#ifndef IPPROTO_XNET
	#define IPPROTO_XNET              15U                  //Cross Net Debugger
#endif
#ifndef IPPROTO_CHAOS
	#define IPPROTO_CHAOS             16U                  //Chaos
#endif
#ifndef IPPROTO_UDP
	#define IPPROTO_UDP               17U                  //User Datagram
#endif
#ifndef IPPROTO_MUX
	#define IPPROTO_MUX               18U                  //Multiplexing
#endif
#ifndef IPPROTO_DCN
	#define IPPROTO_DCN               19U                  //DCN Measurement Subsystems
#endif
#ifndef IPPROTO_HMP
	#define IPPROTO_HMP               20U                  //Host Monitoring
#endif 
#ifndef IPPROTO_PRM
	#define IPPROTO_PRM               21U                  //Packet Radio Measurement
#endif
#ifndef IPPROTO_IDP
	#define IPPROTO_IDP               22U                  //XEROX NS IDP
#endif
#ifndef IPPROTO_TRUNK_1
	#define IPPROTO_TRUNK_1           23U                  //Trunk-1
#endif
#ifndef IPPROTO_TRUNK_2
	#define IPPROTO_TRUNK_2           24U                  //Trunk-2
#endif
#ifndef IPPROTO_LEAF_1
	#define IPPROTO_LEAF_1            25U                  //Leaf-1
#endif
#ifndef IPPROTO_LEAF_2
	#define IPPROTO_LEAF_2            26U                  //Leaf-2
#endif
#ifndef IPPROTO_RDP
	#define IPPROTO_RDP               27U                  //Reliable Data Protocol
#endif
#ifndef IPPROTO_IRTP
	#define IPPROTO_IRTP              28U                  //Internet Reliable Transaction
#endif
#ifndef IPPROTO_ISO_TP4
	#define IPPROTO_ISO_TP4           29U                  //ISO Transport Protocol Class 4
#endif
#ifndef IPPROTO_NETBLT
	#define IPPROTO_NETBLT            30U                  //Bulk Data Transfer Protocol
#endif
#ifndef IPPROTO_MFE
	#define IPPROTO_MFE               31U                  //MFE Network Services Protocol
#endif
#ifndef IPPROTO_MERIT
	#define IPPROTO_MERIT             32U                  //MERIT Internodal Protocol
#endif
#ifndef IPPROTO_DCCP
	#define IPPROTO_DCCP              33U                  //Datagram Congestion Control Protocol
#endif
#ifndef IPPROTO_3PC
	#define IPPROTO_3PC               34U                  //Third Party Connect Protocol
#endif
#ifndef IPPROTO_IDPR
	#define IPPROTO_IDPR              35U                  //Inter-Domain Policy Routing Protocol
#endif
#ifndef IPPROTO_XTP
	#define IPPROTO_XTP               36U                  //XTP
#endif
#ifndef IPPROTO_DDP
	#define IPPROTO_DDP               37U                  //Datagram Delivery Protocol
#endif
#ifndef IPPROTO_IDPR_CMTP
	#define IPPROTO_IDPR_CMTP         38U                  //IDPR Control Message Transport Proto
#endif
#ifndef IPPROTO_TPPLUS
	#define IPPROTO_TPPLUS            39U                  //TP++ Transport Protocol
#endif
#ifndef IPPROTO_IL
	#define IPPROTO_IL                40U                  //IL Transport Protocol
#endif
#ifndef IPPROTO_IPV6
	#define IPPROTO_IPV6              41U                  //IPv6 encapsulation
#endif
#ifndef IPPROTO_SDRP
	#define IPPROTO_SDRP              42U                  //Source Demand Routing Protocol
#endif
#ifndef IPPROTO_ROUTING
	#define IPPROTO_ROUTING           43U                  //Route Routing Header for IPv6
#endif
#ifndef IPPROTO_FRAGMENT
	#define IPPROTO_FRAGMENT          44U                  //Frag Fragment Header for IPv6
#endif
#ifndef IPPROTO_IDRP
	#define IPPROTO_IDRP              45U                  //Inter - Domain Routing Protocol
#endif
#ifndef IPPROTO_RSVP
	#define IPPROTO_RSVP              46U                  //Reservation Protocol
#endif
#ifndef IPPROTO_GRE
	#define IPPROTO_GRE               47U                  //Generic Routing Encapsulation
#endif
#ifndef IPPROTO_DSR
	#define IPPROTO_DSR               48U                  //Dynamic Source Routing Protocol
#endif
#ifndef IPPROTO_BNA
	#define IPPROTO_BNA               49U                  //BNA
#endif
#ifndef IPPROTO_ESP
	#define IPPROTO_ESP               50U                  //Encap Security Payload
#endif
#ifndef IPPROTO_AH
	#define IPPROTO_AH                51U                  //Authentication Header
#endif
#ifndef IPPROTO_NLSP
	#define IPPROTO_NLSP              52U                  //Integrated Net Layer Security TUBA
#endif
#ifndef IPPROTO_SWIPE
	#define IPPROTO_SWIPE             53U                  //IP with Encryption
#endif
#ifndef IPPROTO_NARP
	#define IPPROTO_NARP              54U                  //NBMA Address Resolution Protocol
#endif
#ifndef IPPROTO_MOBILE
	#define IPPROTO_MOBILE            55U                  //IP Mobility
#endif
#ifndef IPPROTO_TLSP
	#define IPPROTO_TLSP              56U                  //Transport Layer Security Protocol using Kryptonet key management
#endif
#ifndef IPPROTO_SKIP
	#define IPPROTO_SKIP              57U                  //SKIP
#endif
#ifndef IPPROTO_ICMPV6
	#define IPPROTO_ICMPV6            58U                  //ICMP for IPv6
#endif
#ifndef IPPROTO_NONE
	#define IPPROTO_NONE              59U                  //No Next Header for IPv6
#endif
#ifndef IPPROTO_DSTOPTS
	#define IPPROTO_DSTOPTS           60U                  //Destination Options for IPv6
#endif
#ifndef IPPROTO_AHI
	#define IPPROTO_AHI               61U                  //Any host internal protocol
#endif
#ifndef IPPROTO_CFTP
	#define IPPROTO_CFTP              62U                  //CFTP
#endif
#ifndef IPPROTO_ALN
	#define IPPROTO_ALN               63U                  //Any local network
#endif
#ifndef IPPROTO_SAT
	#define IPPROTO_SAT               64U                  //EXPAK SATNET and Backroom EXPAK
#endif
#ifndef IPPROTO_KRYPTOLAN
	#define IPPROTO_KRYPTOLAN         65U                  //Kryptolan
#endif
#ifndef IPPROTO_RVD
	#define IPPROTO_RVD               66U                  //MIT Remote Virtual Disk Protocol
#endif
#ifndef IPPROTO_IPPC
	#define IPPROTO_IPPC              67U                  //Internet Pluribus Packet Core
#endif
#ifndef IPPROTO_ADF
	#define IPPROTO_ADF               68U                  //Any distributed file system
#endif
#ifndef IPPROTO_SAT_MON
	#define IPPROTO_SAT_MON           69U                  //SATNET Monitoring
#endif
#ifndef IPPROTO_VISA
	#define IPPROTO_VISA              70U                  //VISA Protocol
#endif
#ifndef IPPROTO_IPCV
	#define IPPROTO_IPCV              71U                  //Internet Packet Core Utility
#endif
#ifndef IPPROTO_CPNX
	#define IPPROTO_CPNX              72U                  //Computer Protocol Network Executive
#endif
#ifndef IPPROTO_CPHB
	#define IPPROTO_CPHB              73U                  //Computer Protocol Heart Beat
#endif
#ifndef IPPROTO_WSN
	#define IPPROTO_WSN               74U                  //Wang Span Network
#endif
#ifndef IPPROTO_PVP
	#define IPPROTO_PVP               75U                  //Packet Video Protocol
#endif
#ifndef IPPROTO_BR
	#define IPPROTO_BR                76U                  //SAT - MON Backroom SATNET Monitoring
#endif
#ifndef IPPROTO_ND
	#define IPPROTO_ND                77U                  //SUN ND PROTOCOL - Temporary
#endif
#ifndef IPPROTO_ICLFXBM
	#define IPPROTO_ICLFXBM           78U                  //WIDEBAND Monitoring
#endif
#ifndef IPPROTO_WBEXPAK
	#define IPPROTO_WBEXPAK           79U                  //WIDEBAND EXPAK
#endif
#ifndef IPPROTO_ISO
	#define IPPROTO_ISO               80U                  //IP ISO Internet Protocol
#endif
#ifndef IPPROTO_VMTP
	#define IPPROTO_VMTP              81U                  //VMTP
#endif
#ifndef IPPROTO_SVMTP
	#define IPPROTO_SVMTP             82U                  //SECURE - VMTP
#endif
#ifndef IPPROTO_VINES
	#define IPPROTO_VINES             83U                  //VINES
#endif
#ifndef IPPROTO_TTP
	#define IPPROTO_TTP               84U                  //Transaction Transport Protocol
#endif
#ifndef IPPROTO_IPTM
	#define IPPROTO_IPTM              85U                  //Internet Protocol Traffic ManageR
#endif
#ifndef IPPROTO_NSFNET
	#define IPPROTO_NSFNET            86U                  //NSFNET - IGP
#endif
#ifndef IPPROTO_DGP
	#define IPPROTO_DGP               87U                  //Dissimilar Gateway Protocol
#endif
#ifndef IPPROTO_TCF
	#define IPPROTO_TCF               88U                  //TCF
#endif
#ifndef IPPROTO_EIGRP
	#define IPPROTO_EIGRP             89U                  //EIGRP
#endif
#ifndef IPPROTO_SPRITE
	#define IPPROTO_SPRITE            90U                  //RPC Sprite RPC Protocol
#endif
#ifndef IPPROTO_LARP
	#define IPPROTO_LARP              91U                  //Locus Address Resolution Protocol
#endif
#ifndef IPPROTO_MTP
	#define IPPROTO_MTP               92U                  //Multicast Transport Protocol
#endif
#ifndef IPPROTO_AX25
	#define IPPROTO_AX25              93U                  //AX.25 Frames
#endif
#ifndef IPPROTO_IPIP
	#define IPPROTO_IPIP              94U                  //IP - within - IP Encapsulation Protocol
#endif
#ifndef IPPROTO_MICP
	#define IPPROTO_MICP              95U                  //Mobile Internetworking Control Pro.
#endif
#ifndef IPPROTO_SCC
	#define IPPROTO_SCC               96U                  //Semaphore Communications Sec.Pro.
#endif
#ifndef IPPROTO_ETHERIP
	#define IPPROTO_ETHERIP           97U                  //Ethernet - within - IP Encapsulation
#endif
#ifndef IPPROTO_ENCAP
	#define IPPROTO_ENCAP             98U                  //Encapsulation Header
#endif
#ifndef IPPROTO_APES
	#define IPPROTO_APES              100U                 //Any private encryption scheme
#endif
#ifndef IPPROTO_GMTP
	#define IPPROTO_GMTP              101U                 //GMTP
#endif
#ifndef IPPROTO_IFMP
	#define IPPROTO_IFMP              102U                 //Ipsilon Flow Management Protocol
#endif
#ifndef IPPROTO_PNNI
	#define IPPROTO_PNNI              103U                 //PNNI over IP
#endif
#ifndef IPPROTO_PIM
	#define IPPROTO_PIM               104U                 //Protocol Independent Multicast
#endif
#ifndef IPPROTO_ARIS
	#define IPPROTO_ARIS              105U                 //ARIS
#endif
#ifndef IPPROTO_SCPS
	#define IPPROTO_SCPS              106U                 //SCPS
#endif
#ifndef IPPROTO_QNX
	#define IPPROTO_QNX               107U                 //QNX
#endif
#ifndef IPPROTO_AN
	#define IPPROTO_AN                108U                 //Active Networks
#endif
#ifndef IPPROTO_IPCOMP
	#define IPPROTO_IPCOMP            109U                 //IP Payload Compression Protocol
#endif
#ifndef IPPROTO_SNP
	#define IPPROTO_SNP               110U                 //Sitara Networks Protocol
#endif
#ifndef IPPROTO_COMPAQ
	#define IPPROTO_COMPAQ            111U                 //Peer Compaq Peer Protocol
#endif
#ifndef IPPROTO_IPX
	#define IPPROTO_IPX               112U                 //IP IPX in IP
#endif
#ifndef IPPROTO_PGM
	#define IPPROTO_PGM               113U                 //PGM Reliable Transport Protocol
#endif
#ifndef IPPROTO_0HOP
	#define IPPROTO_0HOP              114U                 //Any 0-hop protocol
#endif
#ifndef IPPROTO_L2TP
	#define IPPROTO_L2TP              115U                 //Layer Two Tunneling Protocol
#endif
#ifndef IPPROTO_DDX
	#define IPPROTO_DDX               116U                 //D - II Data Exchange(DDX)
#endif
#ifndef IPPROTO_IATP
	#define IPPROTO_IATP              117U                 //Interactive Agent Transfer Protocol
#endif
#ifndef IPPROTO_STP
	#define IPPROTO_STP               118U                 //Schedule Transfer Protocol
#endif
#ifndef IPPROTO_SRP
	#define IPPROTO_SRP               119U                 //SRP SpectraLink Radio Protocol
#endif
#ifndef IPPROTO_UTI
	#define IPPROTO_UTI               120U                 //UTI
#endif
#ifndef IPPROTO_SMP
	#define IPPROTO_SMP               121U                 //SMP Simple Message Protocol
#endif
#ifndef IPPROTO_SM
	#define IPPROTO_SM                122U                 //SM Simple Multicast Protocol
#endif
#ifndef IPPROTO_PTP
	#define IPPROTO_PTP               123U                 //PTP Performance Transparency Protocol
#endif
#ifndef IPPROTO_ISIS
	#define IPPROTO_ISIS              124U                 //ISIS over IPv4
#endif
#ifndef IPPROTO_FIRE
	#define IPPROTO_FIRE              125U                 //FIRE
#endif
#ifndef IPPROTO_CRTP
	#define IPPROTO_CRTP              126U                 //Combat Radio Transport Protocol
#endif
#ifndef IPPROTO_CRUDP
	#define IPPROTO_CRUDP             127U                 //Combat Radio User Datagram
#endif
#ifndef IPPROTO_SSCOPMCE
	#define IPPROTO_SSCOPMCE          128U                 //SSCOPMCE
#endif
#ifndef IPPROTO_IPLT
	#define IPPROTO_IPLT              129U                 //IPLT
#endif
#ifndef IPPROTO_SPS
	#define IPPROTO_SPS               130U                 //Secure Packet Shield
#endif
#ifndef IPPROTO_PIPE
	#define IPPROTO_PIPE              131U                 //Private IP Encapsulation within IP
#endif
#ifndef IPPROTO_SCTP
	#define IPPROTO_SCTP              132U                 //Stream Control Transmission Protocol
#endif
#ifndef IPPROTO_FC
	#define IPPROTO_FC                133U                 //Fibre Channel
#endif
#ifndef IPPROTO_RSVP_E2E
	#define IPPROTO_RSVP_E2E          134U                 //RSVP-E2E-IGNORE
#endif
#ifndef IPPROTO_MOBILITY
	#define IPPROTO_MOBILITY          135U                 //Mobility Header
#endif
#ifndef IPPROTO_UDPLITE
	#define IPPROTO_UDPLITE           136U                 //UDP Lite
#endif
#ifndef IPPROTO_MPLS
	#define IPPROTO_MPLS              137U                 //MPLS in IP
#endif
#ifndef IPPROTO_MANET
	#define IPPROTO_MANET             138U                 //MANET Protocols
#endif
#ifndef IPPROTO_HIP
	#define IPPROTO_HIP               139U                 //Host Identity Protocol
#endif
#ifndef IPPROTO_SHIM6
	#define IPPROTO_SHIM6             140U                 //Shim6 Protocol
#endif
#ifndef IPPROTO_WESP
	#define IPPROTO_WESP              141U                 //Wrapped Encapsulating Security Payload
#endif
#ifndef IPPROTO_ROHC
	#define IPPROTO_ROHC              142U                 //Robust Header Compression
#endif
#ifndef IPPROTO_TEST_1
	#define IPPROTO_TEST_1            253U                 //Use for experimentation and testing
#endif
#ifndef IPPROTO_TEST_2
	#define IPPROTO_TEST_2            254U                 //Use for experimentation and testing
#endif
#ifndef IPPROTO_RESERVED
	#define IPPROTO_RESERVED          255U                 //Reserved
#endif

//Port definitions(1 - 1024, well-known ports)
//About this list, see https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#ifndef IPPORT_TCPMUX
	#define IPPORT_TCPMUX               1U
#endif
#ifndef IPPORT_ECHO
	#define IPPORT_ECHO                 7U
#endif
#ifndef IPPORT_DISCARD
	#define IPPORT_DISCARD              9U
#endif
#ifndef IPPORT_SYSTAT
	#define IPPORT_SYSTAT               11U
#endif
#ifndef IPPORT_DAYTIME
	#define IPPORT_DAYTIME              13U
#endif
#ifndef IPPORT_NETSTAT
	#define IPPORT_NETSTAT              15U
#endif
#ifndef IPPORT_QOTD
	#define IPPORT_QOTD                 17U
#endif
#ifndef IPPORT_MSP
	#define IPPORT_MSP                  18U
#endif
#ifndef IPPORT_CHARGEN
	#define IPPORT_CHARGEN              19U
#endif
#ifndef IPPORT_FTP_DATA
	#define IPPORT_FTP_DATA             20U
#endif
#ifndef IPPORT_FTP
	#define IPPORT_FTP                  21U
#endif
#ifndef IPPORT_SSH
	#define IPPORT_SSH                  22U
#endif
#ifndef IPPORT_TELNET
	#define IPPORT_TELNET               23U
#endif
#ifndef IPPORT_SMTP
	#define IPPORT_SMTP                 25U
#endif
#ifndef IPPORT_TIMESERVER
	#define IPPORT_TIMESERVER           37U
#endif
#ifndef IPPORT_RAP
	#define IPPORT_RAP                  38U
#endif
#ifndef IPPORT_RLP
	#define IPPORT_RLP                  39U
#endif
#ifndef IPPORT_NAMESERVER
	#define IPPORT_NAMESERVER           42U
#endif
#ifndef IPPORT_WHOIS
	#define IPPORT_WHOIS                43U
#endif
#ifndef IPPORT_TACACS
	#define IPPORT_TACACS               49U
#endif
#ifndef IPPORT_XNSAUTH
	#define IPPORT_XNSAUTH              56U
#endif
#ifndef IPPORT_MTP
	#define IPPORT_MTP                  57U
#endif
#ifndef IPPORT_BOOTPS
	#define IPPORT_BOOTPS               67U
#endif
#ifndef IPPORT_BOOTPC
	#define IPPORT_BOOTPC               68U
#endif
#ifndef IPPORT_TFTP
	#define IPPORT_TFTP                 69U
#endif
#ifndef IPPORT_RJE
	#define IPPORT_RJE                  77U
#endif
#ifndef IPPORT_FINGER
	#define IPPORT_FINGER               79U
#endif
#ifndef IPPORT_HTTP
	#define IPPORT_HTTP                 80U
#endif
#ifndef IPPORT_HTTPBACKUP
	#define IPPORT_HTTPBACKUP           81U
#endif
#ifndef IPPORT_TTYLINK
	#define IPPORT_TTYLINK              87U
#endif
#ifndef IPPORT_SUPDUP
	#define IPPORT_SUPDUP               95U
#endif
#ifndef IPPORT_POP3
	#define IPPORT_POP3                 110U
#endif
#ifndef IPPORT_SUNRPC
	#define IPPORT_SUNRPC               111U
#endif
#ifndef IPPORT_SQL
	#define IPPORT_SQL                  118U
#endif
#ifndef IPPORT_NTP
	#define IPPORT_NTP                  123U
#endif
#ifndef IPPORT_EPMAP
	#define IPPORT_EPMAP                135U
#endif
#ifndef IPPORT_NETBIOS_NS
	#define IPPORT_NETBIOS_NS           137U
#endif
#ifndef IPPORT_NETBIOS_DGM
	#define IPPORT_NETBIOS_DGM          138U
#endif
#ifndef IPPORT_NETBIOS_SSN
	#define IPPORT_NETBIOS_SSN          139U
#endif
#ifndef IPPORT_IMAP
	#define IPPORT_IMAP                 143U
#endif
#ifndef IPPORT_BFTP
	#define IPPORT_BFTP                 152U
#endif
#ifndef IPPORT_SGMP
	#define IPPORT_SGMP                 153U
#endif
#ifndef IPPORT_SQLSRV
	#define IPPORT_SQLSRV               156U
#endif
#ifndef IPPORT_DMSP
	#define IPPORT_DMSP                 158U
#endif
#ifndef IPPORT_SNMP
	#define IPPORT_SNMP                 161U
#endif
#ifndef IPPORT_SNMP_TRAP
	#define IPPORT_SNMP_TRAP            162U
#endif
#ifndef IPPORT_ATRTMP
	#define IPPORT_ATRTMP               201U
#endif
#ifndef IPPORT_ATHBP
	#define IPPORT_ATHBP                202U
#endif
#ifndef IPPORT_QMTP
	#define IPPORT_QMTP                 209U
#endif
#ifndef IPPORT_IPX
	#define IPPORT_IPX                  213U
#endif
#ifndef IPPORT_IMAP3
	#define IPPORT_IMAP3                220U
#endif
#ifndef IPPORT_BGMP
	#define IPPORT_BGMP                 264U
#endif
#ifndef IPPORT_TSP
	#define IPPORT_TSP                  318U
#endif
#ifndef IPPORT_IMMP
	#define IPPORT_IMMP                 323U
#endif
#ifndef IPPORT_ODMR
	#define IPPORT_ODMR                 366U
#endif
#ifndef IPPORT_RPC2PORTMAP
	#define IPPORT_RPC2PORTMAP          369U
#endif
#ifndef IPPORT_CLEARCASE
	#define IPPORT_CLEARCASE            371U
#endif
#ifndef IPPORT_HPALARMMGR
	#define IPPORT_HPALARMMGR           383U
#endif
#ifndef IPPORT_ARNS
	#define IPPORT_ARNS                 384U
#endif
#ifndef IPPORT_AURP
	#define IPPORT_AURP                 387U
#endif
#ifndef IPPORT_LDAP
	#define IPPORT_LDAP                 389U
#endif
#ifndef IPPORT_UPS
	#define IPPORT_UPS                  401U
#endif
#ifndef IPPORT_SLP
	#define IPPORT_SLP                  427U
#endif
#ifndef IPPORT_HTTPS
	#define IPPORT_HTTPS                443U
#endif
#ifndef IPPORT_SNPP
	#define IPPORT_SNPP                 444U
#endif
#ifndef IPPORT_MICROSOFT_DS
	#define IPPORT_MICROSOFT_DS         445U
#endif
#ifndef IPPORT_KPASSWD
	#define IPPORT_KPASSWD              464U
#endif
#ifndef IPPORT_TCPNETHASPSRV
	#define IPPORT_TCPNETHASPSRV        475U
#endif
#ifndef IPPORT_RETROSPECT
	#define IPPORT_RETROSPECT           497U
#endif
#ifndef IPPORT_ISAKMP
	#define IPPORT_ISAKMP               500U
#endif
#ifndef IPPORT_BIFFUDP
	#define IPPORT_BIFFUDP              512U
#endif
#ifndef IPPORT_WHOSERVER
	#define IPPORT_WHOSERVER			513U
#endif
#ifndef IPPORT_SYSLOG
	#define IPPORT_SYSLOG               514U
#endif
#ifndef IPPORT_ROUTESERVER
	#define IPPORT_ROUTESERVER          520U
#endif
#ifndef IPPORT_NCP
	#define IPPORT_NCP                  524U
#endif
#ifndef IPPORT_COURIER
	#define IPPORT_COURIER              530U
#endif
#ifndef IPPORT_COMMERCE
	#define IPPORT_COMMERCE             542U
#endif
#ifndef IPPORT_RTSP
	#define IPPORT_RTSP                 554U
#endif
#ifndef IPPORT_NNTP
	#define IPPORT_NNTP                 563U
#endif
#ifndef IPPORT_HTTPRPCEPMAP
	#define IPPORT_HTTPRPCEPMAP         593U
#endif
#ifndef IPPORT_IPP
	#define IPPORT_IPP                  631U
#endif
#ifndef IPPORT_LDAPS
	#define IPPORT_LDAPS                636U
#endif
#ifndef IPPORT_MSDP
	#define IPPORT_MSDP                 639U
#endif
#ifndef IPPORT_AODV
	#define IPPORT_AODV                 654U
#endif
#ifndef IPPORT_FTPSDATA
	#define IPPORT_FTPSDATA             989U
#endif
#ifndef IPPORT_FTPS
	#define IPPORT_FTPS                 990U
#endif
#ifndef IPPORT_NAS
	#define IPPORT_NAS                  991U
#endif
#ifndef IPPORT_TELNETS
	#define IPPORT_TELNETS              992U
#endif
