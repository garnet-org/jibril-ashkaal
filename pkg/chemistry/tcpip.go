package chemistry

import (
	"fmt"
	"strings"
)

type Service uint16

const (
	SVC_Reserved                Service = 0     // Reserved
	SVC_TCPMUX                  Service = 1     // TCPMUX
	SVC_CompressNet             Service = 2     // CompressNet
	SVC_CompressNet2            Service = 3     // CompressNet
	SVC_RJE                     Service = 5     // RJE
	SVC_Echo                    Service = 7     // Echo
	SVC_Discard                 Service = 9     // Discard
	SVC_Systat                  Service = 11    // Systat
	SVC_Daytime                 Service = 13    // Daytime
	SVC_Netstat                 Service = 15    // Netstat
	SVC_QOTD                    Service = 17    // QOTD
	SVC_MSP                     Service = 18    // MSP
	SVC_Chargen                 Service = 19    // Chargen
	SVC_FTP_Data                Service = 20    // FTP-Data
	SVC_FTP                     Service = 21    // FTP
	SVC_SSH                     Service = 22    // SSH
	SVC_Telnet                  Service = 23    // Telnet
	SVC_LMTP                    Service = 24    // LMTP
	SVC_SMTP                    Service = 25    // SMTP
	SVC_NSW_FE                  Service = 27    // NSW-FE
	SVC_MSG_ICP                 Service = 29    // MSG-ICP
	SVC_MSG_Auth                Service = 31    // MSG-Auth
	SVC_DSP                     Service = 33    // DSP
	SVC_Time                    Service = 37    // Time
	SVC_RAP                     Service = 38    // RAP
	SVC_RLP                     Service = 39    // RLP
	SVC_Graphics                Service = 41    // Graphics
	SVC_Nameserver              Service = 42    // Nameserver
	SVC_Whois                   Service = 43    // Whois
	SVC_MPM_Flags               Service = 44    // MPM-Flags
	SVC_MPM                     Service = 45    // MPM
	SVC_MPM_Snd                 Service = 46    // MPM-Snd
	SVC_Auditd                  Service = 48    // Auditd
	SVC_TACACS                  Service = 49    // TACACS
	SVC_ReMail_CK               Service = 50    // ReMail-CK
	SVC_XNS_Time                Service = 52    // XNS-Time
	SVC_DNS                     Service = 53    // DNS
	SVC_XNS_Ch                  Service = 54    // XNS-Ch
	SVC_ISI_GL                  Service = 55    // ISI-GL
	SVC_XNS_Auth                Service = 56    // XNS-Auth
	SVC_XNS_Mail                Service = 58    // XNS-Mail
	SVC_ACAS                    Service = 62    // ACAS
	SVC_WhoisPP                 Service = 63    // Whois++
	SVC_Covia                   Service = 64    // Covia
	SVC_TACACS_DS               Service = 65    // TACACS-DS
	SVC_SQLNet                  Service = 66    // SQL-Net
	SVC_BOOTPS                  Service = 67    // BOOTPS
	SVC_BOOTPC                  Service = 68    // BOOTPC
	SVC_TFTP                    Service = 69    // TFTP
	SVC_Gopher                  Service = 70    // Gopher
	SVC_Netrjs_1                Service = 71    // Netrjs-1
	SVC_Netrjs_2                Service = 72    // Netrjs-2
	SVC_Netrjs_3                Service = 73    // Netrjs-3
	SVC_Netrjs_4                Service = 74    // Netrjs-4
	SVC_Any_Dial                Service = 75    // any-dial
	SVC_DEOS                    Service = 76    // DEOS
	SVC_Any_RJE                 Service = 77    // any-rje
	SVC_Vettcp                  Service = 78    // Vettcp
	SVC_Finger                  Service = 79    // Finger
	SVC_HTTP                    Service = 80    // HTTP
	SVC_Hosts2_NS               Service = 81    // hosts2-ns
	SVC_XFER                    Service = 82    // XFER
	SVC_MIT_ML_Dev              Service = 83    // MIT-ML-Dev
	SVC_CTF                     Service = 84    // CTF
	SVC_MIT_ML_Dev_2            Service = 85    // MIT-ML-Dev
	SVC_MFCOBOL                 Service = 86    // MFCOBOL
	SVC_Link                    Service = 87    // link
	SVC_Kerberos                Service = 88    // Kerberos
	SVC_SU_MIT_Telnet           Service = 89    // SU-MIT-Telnet
	SVC_DNSIX                   Service = 90    // DNSIX
	SVC_MIT_Dov                 Service = 91    // MIT-Dov
	SVC_NPP                     Service = 92    // NPP
	SVC_DCP                     Service = 93    // DCP
	SVC_Objcall                 Service = 94    // Objcall
	SVC_SUPDUP                  Service = 95    // SUPDUP
	SVC_DIXIE                   Service = 96    // DIXIE
	SVC_Swift_RVF               Service = 97    // Swift-RVF
	SVC_TAC_News                Service = 98    // TAC-News
	SVC_Metagram                Service = 99    // Metagram
	SVC_Newacct                 Service = 100   // newacct
	SVC_NIC_Hostname            Service = 101   // NIC-Hostname
	SVC_ISO_TSAP                Service = 102   // ISO-TSAP
	SVC_Gennet                  Service = 103   // gennet
	SVC_DICOM                   Service = 104   // DICOM
	SVC_CCSO                    Service = 105   // CCSO
	SVC_Poppassd                Service = 106   // poppassd
	SVC_RTelnet                 Service = 107   // RTelnet
	SVC_SNA_Gateway             Service = 108   // SNA-Gateway
	SVC_POP2                    Service = 109   // POP2
	SVC_POP3                    Service = 110   // POP3
	SVC_SunRPC                  Service = 111   // SunRPC
	SVC_McIDAS                  Service = 112   // McIDAS
	SVC_Ident                   Service = 113   // Ident
	SVC_Audionews               Service = 114   // audionews
	SVC_SFTP                    Service = 115   // SFTP
	SVC_Ansanotify              Service = 116   // ansanotify
	SVC_UUCP_Path               Service = 117   // UUCP-Path
	SVC_SQL_Services            Service = 118   // SQL-Services
	SVC_NNTP                    Service = 119   // NNTP
	SVC_CFDPTKT                 Service = 120   // cfdptkt
	SVC_Smakynet                Service = 122   // smakynet
	SVC_NTP                     Service = 123   // NTP
	SVC_Entitlement             Service = 124   // entitlement
	SVC_NXEdit                  Service = 126   // NXEdit
	SVC_Locus_PC                Service = 127   // locus-pc
	SVC_EPMAP                   Service = 135   // EPMAP
	SVC_Profile                 Service = 136   // profile
	SVC_NetBIOS_NS              Service = 137   // NetBIOS-NS
	SVC_NetBIOS_DGM             Service = 138   // NetBIOS-DGM
	SVC_NetBIOS_SSN             Service = 139   // NetBIOS-SSN
	SVC_IMAP                    Service = 143   // IMAP
	SVC_HEMS                    Service = 151   // HEMS
	SVC_BFTP                    Service = 152   // BFTP
	SVC_SGMP                    Service = 153   // SGMP
	SVC_SQL_Service             Service = 156   // SQL-Service
	SVC_DMSP                    Service = 158   // DMSP
	SVC_SNMP                    Service = 161   // SNMP
	SVC_SNMP_Trap               Service = 162   // SNMP-Trap
	SVC_Xerox                   Service = 165   // Xerox
	SVC_SEND                    Service = 169   // SEND
	SVC_Print_Server            Service = 170   // Print-Server
	SVC_VMNET                   Service = 175   // VMNET
	SVC_XDMCP                   Service = 177   // XDMCP
	SVC_BGP                     Service = 179   // BGP
	SVC_MTP                     Service = 181   // mtp
	SVC_IRC_IANA                Service = 194   // IRC (IANA, rarely used)
	SVC_SMUX                    Service = 199   // SMUX
	SVC_AppleTalk_RTM           Service = 201   // AppleTalk-RTM
	SVC_QMTP                    Service = 209   // QMTP
	SVC_Z39_50                  Service = 210   // Z39.50
	SVC_IPX                     Service = 213   // IPX
	SVC_MPP                     Service = 218   // MPP
	SVC_IMAP3                   Service = 220   // IMAP3
	SVC_ESRO                    Service = 259   // ESRO
	SVC_Arcisdms                Service = 262   // Arcisdms
	SVC_BGMP                    Service = 264   // BGMP
	SVC_HTTP_Mgmt               Service = 280   // HTTP-Mgmt
	SVC_Novastor                Service = 308   // Novastor
	SVC_MacOS_Admin             Service = 311   // MacOS-Admin
	SVC_PKIX_TSP                Service = 318   // PKIX-TSP
	SVC_PTP_Event               Service = 319   // PTP-Event
	SVC_PTP_General             Service = 320   // PTP-General
	SVC_RPKI                    Service = 323   // RPKI
	SVC_PDAP                    Service = 344   // pdap
	SVC_MATIP_A                 Service = 350   // MATIP-A
	SVC_MATIP_B                 Service = 351   // MATIP-B
	SVC_Cloanto_Net             Service = 356   // Cloanto-Net
	SVC_ODMR                    Service = 366   // ODMR
	SVC_Rpc2portmap             Service = 369   // Rpc2portmap
	SVC_Codaauth2               Service = 370   // Codaauth2
	SVC_ClearCase               Service = 371   // ClearCase
	SVC_Amiga_Envoy             Service = 376   // Amiga-Envoy
	SVC_HP_Alarm                Service = 383   // HP-Alarm
	SVC_AURP                    Service = 387   // AURP
	SVC_Unidata_LDM             Service = 388   // Unidata-LDM
	SVC_LDAP                    Service = 389   // LDAP
	SVC_DECnet                  Service = 399   // DECnet
	SVC_UPS                     Service = 401   // UPS
	SVC_PRM_SM                  Service = 407   // prm-sm
	SVC_PRM_NM                  Service = 408   // prm-nm
	SVC_SLP                     Service = 427   // SLP
	SVC_NNTP_SSL                Service = 433   // NNTP-SSL
	SVC_Mobile_IP               Service = 434   // Mobile-IP
	SVC_HTTPS                   Service = 443   // HTTPS
	SVC_SNPP                    Service = 444   // SNPP
	SVC_Microsoft_DS            Service = 445   // Microsoft-DS
	SVC_Kpasswd                 Service = 464   // Kpasswd
	SVC_SMTPS                   Service = 465   // SMTPS (submissions)
	SVC_Tcpnethaspsrv           Service = 475   // Tcpnethaspsrv
	SVC_Retrospect              Service = 497   // Retrospect
	SVC_ISAKMP                  Service = 500   // ISAKMP
	SVC_Modbus                  Service = 502   // Modbus
	SVC_Citadel                 Service = 504   // Citadel
	SVC_FirstClass              Service = 510   // FirstClass
	SVC_Rexec                   Service = 512   // Rexec
	SVC_Rlogin                  Service = 513   // Rlogin
	SVC_Syslog                  Service = 514   // Syslog
	SVC_LPD                     Service = 515   // LPD
	SVC_Talk                    Service = 517   // Talk
	SVC_NTalk                   Service = 518   // NTalk
	SVC_RIP                     Service = 520   // RIP
	SVC_RIPng                   Service = 521   // RIPng
	SVC_NCP                     Service = 524   // NCP
	SVC_Timed                   Service = 525   // Timed
	SVC_RPC                     Service = 530   // RPC
	SVC_Netnews                 Service = 532   // Netnews
	SVC_Netwall                 Service = 533   // Netwall
	SVC_UUCP                    Service = 540   // UUCP
	SVC_Commerce                Service = 542   // Commerce
	SVC_Klogin                  Service = 543   // Klogin
	SVC_Kshell                  Service = 544   // Kshell
	SVC_DHCPv6_Client           Service = 546   // DHCPv6-Client
	SVC_DHCPv6_Server           Service = 547   // DHCPv6-Server
	SVC_AFP                     Service = 548   // AFP
	SVC_NewRwho                 Service = 550   // NewRwho
	SVC_RTSP                    Service = 554   // RTSP
	SVC_Remotefs                Service = 556   // Remotefs
	SVC_Rmonitor                Service = 560   // Rmonitor
	SVC_Monitor                 Service = 561   // Monitor
	SVC_NNTPS                   Service = 563   // NNTPS
	SVC_Submission              Service = 587   // Submission
	SVC_FileMaker               Service = 591   // FileMaker
	SVC_HTTP_RPC_EP             Service = 593   // HTTP-RPC-EP
	SVC_Reliable_Syslog         Service = 601   // Reliable-Syslog
	SVC_TUNNEL                  Service = 604   // TUNNEL
	SVC_ASF_RMCP                Service = 623   // ASF-RMCP
	SVC_IPP                     Service = 631   // IPP
	SVC_RLZ_DBase               Service = 635   // RLZ-DBase
	SVC_LDAPS                   Service = 636   // LDAPS
	SVC_MSDP                    Service = 639   // MSDP
	SVC_SupportSoft             Service = 641   // SupportSoft
	SVC_SANity                  Service = 643   // SANity
	SVC_LDP                     Service = 646   // LDP
	SVC_DHCP_Failover           Service = 647   // DHCP-Failover
	SVC_RRP                     Service = 648   // RRP
	SVC_IEEE_MMS                Service = 651   // IEEE-MMS
	SVC_Tinc                    Service = 655   // Tinc
	SVC_IBM_RMC                 Service = 657   // IBM-RMC
	SVC_MacOS_Server            Service = 660   // MacOS-Server
	SVC_NFS_Statd               Service = 662   // NFS-Statd
	SVC_Doom                    Service = 666   // Doom
	SVC_ACAP                    Service = 674   // ACAP
	SVC_CORBA_IIOP_SSL          Service = 684   // CORBA-IIOP-SSL
	SVC_MDC                     Service = 685   // MDC
	SVC_Velneo_VATP             Service = 690   // Velneo-VATP
	SVC_MS_Exchange             Service = 691   // MS-Exchange
	SVC_AFS                     Service = 700   // AFS
	SVC_Kerberos_Admin          Service = 749   // Kerberos-Admin
	SVC_DNS_Over_TLS            Service = 853   // DNS-Over-TLS
	SVC_RSYNC                   Service = 873   // rsync
	SVC_RNDC                    Service = 953   // RNDC
	SVC_FTPS_Data               Service = 989   // FTPS-Data
	SVC_FTPS                    Service = 990   // FTPS
	SVC_Telnets                 Service = 992   // Telnets
	SVC_IMAPS                   Service = 993   // IMAPS
	SVC_IRCS_IANA               Service = 994   // IRCS (IANA, rarely used)
	SVC_POP3S                   Service = 995   // POP3S
	SVC_SOCKS                   Service = 1080  // SOCKS
	SVC_OpenVPN                 Service = 1194  // OpenVPN
	SVC_MSSQL                   Service = 1433  // MSSQL
	SVC_MSSQL_Browser           Service = 1434  // MSSQL-Browser
	SVC_Oracle_TNS              Service = 1521  // Oracle-TNS
	SVC_L2TP                    Service = 1701  // L2TP
	SVC_H323                    Service = 1720  // H.323
	SVC_PPTP                    Service = 1723  // PPTP
	SVC_Radius                  Service = 1812  // Radius
	SVC_Radius_Acct             Service = 1813  // Radius-Acct
	SVC_MQTT                    Service = 1883  // MQTT
	SVC_SSDP                    Service = 1900  // SSDP (UPnP discovery)
	SVC_NFS                     Service = 2049  // NFS
	SVC_Zookeeper               Service = 2181  // Zookeeper
	SVC_Docker                  Service = 2375  // Docker
	SVC_Docker_TLS              Service = 2376  // Docker-TLS
	SVC_Docker_Swarm            Service = 2377  // Docker-Swarm
	SVC_etcd_Client             Service = 2379  // etcd-Client
	SVC_etcd_Peer               Service = 2380  // etcd-Peer
	SVC_Grafana                 Service = 3000  // Grafana
	SVC_Squid                   Service = 3128  // Squid-Proxy
	SVC_MySQL                   Service = 3306  // MySQL
	SVC_RDP                     Service = 3389  // RDP
	SVC_SVN                     Service = 3690  // SVN
	SVC_Diameter                Service = 3868  // Diameter
	SVC_NATS                    Service = 4222  // NATS
	SVC_IPsec_NAT_T             Service = 4500  // IPsec-NAT-T
	SVC_VXLAN                   Service = 4789  // VXLAN
	SVC_Commplex_Main           Service = 5000  // commplex-main
	SVC_RTP                     Service = 5004  // RTP
	SVC_RTCP                    Service = 5005  // RTCP
	SVC_SIP                     Service = 5060  // SIP
	SVC_SIPS                    Service = 5061  // SIPS
	SVC_XMPP_Client             Service = 5222  // XMPP-Client
	SVC_XMPP_Server             Service = 5269  // XMPP-Server
	SVC_MDNS                    Service = 5353  // mDNS
	SVC_LLMNR                   Service = 5355  // LLMNR
	SVC_WSDAPI                  Service = 5357  // wsdapi
	SVC_PostgreSQL              Service = 5432  // PostgreSQL
	SVC_Kibana                  Service = 5601  // Kibana
	SVC_AMQPS                   Service = 5671  // AMQPS
	SVC_AMQP                    Service = 5672  // AMQP
	SVC_VNC                     Service = 5900  // VNC
	SVC_WinRM                   Service = 5985  // WinRM
	SVC_WinRM_HTTPS             Service = 5986  // WinRM-HTTPS
	SVC_X11                     Service = 6000  // X11
	SVC_Redis                   Service = 6379  // Redis
	SVC_PgBouncer               Service = 6432  // PgBouncer
	SVC_Kubernetes_API          Service = 6443  // Kubernetes-API
	SVC_Syslog_TLS              Service = 6514  // Syslog-TLS
	SVC_IRC                     Service = 6667  // IRC (de facto standard)
	SVC_IRCS                    Service = 6697  // IRCS (IRC over TLS, de facto standard)
	SVC_Spark_Master            Service = 7077  // Spark-Master
	SVC_Spark_Worker            Service = 7078  // Spark-Worker
	SVC_Docker_Gossip           Service = 7946  // Docker-Gossip
	SVC_Hadoop_Name             Service = 8020  // Hadoop-Name
	SVC_HTTP_Proxy              Service = 8080  // HTTP-Proxy
	SVC_Nexus                   Service = 8081  // Nexus
	SVC_InfluxDB                Service = 8086  // InfluxDB
	SVC_Splunk                  Service = 8089  // Splunk
	SVC_TeamCity                Service = 8111  // TeamCity
	SVC_Vault                   Service = 8200  // Vault
	SVC_HTTPS_Alt               Service = 8443  // HTTPS-Alt
	SVC_Consul                  Service = 8500  // Consul
	SVC_Consul_GRPC             Service = 8502  // Consul-gRPC
	SVC_MQTT_TLS                Service = 8883  // MQTT-TLS
	SVC_Cassandra               Service = 9042  // Cassandra
	SVC_Prometheus              Service = 9090  // Prometheus
	SVC_Prometheus_Pushgateway  Service = 9091  // Prometheus-Pushgateway
	SVC_Kafka                   Service = 9092  // Kafka
	SVC_Prometheus_Alertmanager Service = 9093  // Prometheus-Alertmanager
	SVC_JetDirect               Service = 9100  // JetDirect
	SVC_Elasticsearch           Service = 9200  // Elasticsearch
	SVC_Elasticsearch_Transport Service = 9300  // Elasticsearch-Transport
	SVC_Git                     Service = 9418  // Git
	SVC_NDMP                    Service = 10000 // NDMP
	SVC_Kubelet                 Service = 10250 // Kubelet
	SVC_Kubelet_ReadOnly        Service = 10255 // Kubelet-ReadOnly
	SVC_DICOM_Alt               Service = 11112 // DICOM-Alt
	SVC_Memcached               Service = 11211 // memcache
	SVC_RabbitMQ_Mgmt           Service = 15672 // RabbitMQ-Mgmt
	SVC_NFS_Mount               Service = 20048 // NFS-Mount
	SVC_Minecraft               Service = 25565 // Minecraft
	SVC_Quake                   Service = 26000 // Quake
	SVC_Cockroach               Service = 26257 // CockroachDB
	SVC_Steam                   Service = 27015 // Steam
	SVC_MongoDB                 Service = 27017 // MongoDB
	SVC_Hadoop_Data             Service = 50010 // Hadoop-Data
	SVC_Grpc                    Service = 50051 // gRPC
	SVC_WireGuard               Service = 51820 // WireGuard
	SVC_ActiveMQ                Service = 61616 // ActiveMQ
)

var serviceNames = map[Service]string{
	SVC_Reserved:                "Reserved",
	SVC_TCPMUX:                  "TCPMUX",
	SVC_CompressNet:             "CompressNet",
	SVC_CompressNet2:            "CompressNet2",
	SVC_RJE:                     "RJE",
	SVC_Echo:                    "Echo",
	SVC_Discard:                 "Discard",
	SVC_Systat:                  "Systat",
	SVC_Daytime:                 "Daytime",
	SVC_Netstat:                 "Netstat",
	SVC_QOTD:                    "QOTD",
	SVC_MSP:                     "MSP",
	SVC_Chargen:                 "Chargen",
	SVC_FTP_Data:                "FTP-Data",
	SVC_FTP:                     "FTP",
	SVC_SSH:                     "SSH",
	SVC_Telnet:                  "Telnet",
	SVC_LMTP:                    "LMTP",
	SVC_SMTP:                    "SMTP",
	SVC_NSW_FE:                  "NSW-FE",
	SVC_MSG_ICP:                 "MSG-ICP",
	SVC_MSG_Auth:                "MSG-Auth",
	SVC_DSP:                     "DSP",
	SVC_Time:                    "Time",
	SVC_RAP:                     "RAP",
	SVC_RLP:                     "RLP",
	SVC_Graphics:                "Graphics",
	SVC_Nameserver:              "Nameserver",
	SVC_Whois:                   "Whois",
	SVC_MPM_Flags:               "MPM-Flags",
	SVC_MPM:                     "MPM",
	SVC_MPM_Snd:                 "MPM-Snd",
	SVC_Auditd:                  "Auditd",
	SVC_TACACS:                  "TACACS",
	SVC_ReMail_CK:               "ReMail-CK",
	SVC_XNS_Time:                "XNS-Time",
	SVC_DNS:                     "DNS",
	SVC_XNS_Ch:                  "XNS-Ch",
	SVC_ISI_GL:                  "ISI-GL",
	SVC_XNS_Auth:                "XNS-Auth",
	SVC_XNS_Mail:                "XNS-Mail",
	SVC_ACAS:                    "ACAS",
	SVC_WhoisPP:                 "Whois++",
	SVC_Covia:                   "Covia",
	SVC_TACACS_DS:               "TACACS-DS",
	SVC_SQLNet:                  "SQL-Net",
	SVC_BOOTPS:                  "BOOTPS",
	SVC_BOOTPC:                  "BOOTPC",
	SVC_TFTP:                    "TFTP",
	SVC_Gopher:                  "Gopher",
	SVC_Netrjs_1:                "Netrjs-1",
	SVC_Netrjs_2:                "Netrjs-2",
	SVC_Netrjs_3:                "Netrjs-3",
	SVC_Netrjs_4:                "Netrjs-4",
	SVC_Any_Dial:                "any-dial",
	SVC_DEOS:                    "DEOS",
	SVC_Any_RJE:                 "any-rje",
	SVC_Vettcp:                  "Vettcp",
	SVC_Finger:                  "Finger",
	SVC_HTTP:                    "HTTP",
	SVC_Hosts2_NS:               "hosts2-ns",
	SVC_XFER:                    "XFER",
	SVC_MIT_ML_Dev:              "MIT-ML-Dev",
	SVC_CTF:                     "CTF",
	SVC_MIT_ML_Dev_2:            "MIT-ML-Dev2",
	SVC_MFCOBOL:                 "MFCOBOL",
	SVC_Link:                    "link",
	SVC_Kerberos:                "Kerberos",
	SVC_SU_MIT_Telnet:           "SU-MIT-Telnet",
	SVC_DNSIX:                   "DNSIX",
	SVC_MIT_Dov:                 "MIT-Dov",
	SVC_NPP:                     "NPP",
	SVC_DCP:                     "DCP",
	SVC_Objcall:                 "Objcall",
	SVC_SUPDUP:                  "SUPDUP",
	SVC_DIXIE:                   "DIXIE",
	SVC_Swift_RVF:               "Swift-RVF",
	SVC_TAC_News:                "TAC-News",
	SVC_Metagram:                "Metagram",
	SVC_Newacct:                 "newacct",
	SVC_NIC_Hostname:            "NIC-Hostname",
	SVC_ISO_TSAP:                "ISO-TSAP",
	SVC_Gennet:                  "gennet",
	SVC_DICOM:                   "DICOM",
	SVC_CCSO:                    "CCSO",
	SVC_Poppassd:                "poppassd",
	SVC_RTelnet:                 "RTelnet",
	SVC_SNA_Gateway:             "SNA-Gateway",
	SVC_POP2:                    "POP2",
	SVC_POP3:                    "POP3",
	SVC_SunRPC:                  "SunRPC",
	SVC_McIDAS:                  "McIDAS",
	SVC_Ident:                   "Ident",
	SVC_Audionews:               "audionews",
	SVC_SFTP:                    "SFTP",
	SVC_Ansanotify:              "ansanotify",
	SVC_UUCP_Path:               "UUCP-Path",
	SVC_SQL_Services:            "SQL-Services",
	SVC_NNTP:                    "NNTP",
	SVC_CFDPTKT:                 "cfdptkt",
	SVC_Smakynet:                "smakynet",
	SVC_NTP:                     "NTP",
	SVC_Entitlement:             "entitlement",
	SVC_NXEdit:                  "NXEdit",
	SVC_Locus_PC:                "locus-pc",
	SVC_EPMAP:                   "EPMAP",
	SVC_Profile:                 "profile",
	SVC_NetBIOS_NS:              "NetBIOS-NS",
	SVC_NetBIOS_DGM:             "NetBIOS-DGM",
	SVC_NetBIOS_SSN:             "NetBIOS-SSN",
	SVC_IMAP:                    "IMAP",
	SVC_HEMS:                    "HEMS",
	SVC_BFTP:                    "BFTP",
	SVC_SGMP:                    "SGMP",
	SVC_SQL_Service:             "SQL-Service",
	SVC_DMSP:                    "DMSP",
	SVC_SNMP:                    "SNMP",
	SVC_SNMP_Trap:               "SNMP-Trap",
	SVC_Xerox:                   "Xerox",
	SVC_SEND:                    "SEND",
	SVC_Print_Server:            "Print-Server",
	SVC_VMNET:                   "VMNET",
	SVC_XDMCP:                   "XDMCP",
	SVC_BGP:                     "BGP",
	SVC_MTP:                     "mtp",
	SVC_IRC_IANA:                "IRC-IANA",
	SVC_IRC:                     "IRC",
	SVC_SMUX:                    "SMUX",
	SVC_AppleTalk_RTM:           "AppleTalk-RTM",
	SVC_QMTP:                    "QMTP",
	SVC_Z39_50:                  "Z39.50",
	SVC_IPX:                     "IPX",
	SVC_MPP:                     "MPP",
	SVC_IMAP3:                   "IMAP3",
	SVC_ESRO:                    "ESRO",
	SVC_Arcisdms:                "Arcisdms",
	SVC_BGMP:                    "BGMP",
	SVC_HTTP_Mgmt:               "HTTP-Mgmt",
	SVC_Novastor:                "Novastor",
	SVC_MacOS_Admin:             "MacOS-Admin",
	SVC_PKIX_TSP:                "PKIX-TSP",
	SVC_PTP_Event:               "PTP-Event",
	SVC_PTP_General:             "PTP-General",
	SVC_RPKI:                    "RPKI",
	SVC_PDAP:                    "pdap",
	SVC_MATIP_A:                 "MATIP-A",
	SVC_MATIP_B:                 "MATIP-B",
	SVC_Cloanto_Net:             "Cloanto-Net",
	SVC_ODMR:                    "ODMR",
	SVC_Rpc2portmap:             "Rpc2portmap",
	SVC_Codaauth2:               "Codaauth2",
	SVC_ClearCase:               "ClearCase",
	SVC_Amiga_Envoy:             "Amiga-Envoy",
	SVC_HP_Alarm:                "HP-Alarm",
	SVC_AURP:                    "AURP",
	SVC_Unidata_LDM:             "Unidata-LDM",
	SVC_LDAP:                    "LDAP",
	SVC_DECnet:                  "DECnet",
	SVC_UPS:                     "UPS",
	SVC_PRM_SM:                  "prm-sm",
	SVC_PRM_NM:                  "prm-nm",
	SVC_SLP:                     "SLP",
	SVC_NNTP_SSL:                "NNTP-SSL",
	SVC_Mobile_IP:               "Mobile-IP",
	SVC_HTTPS:                   "HTTPS",
	SVC_SNPP:                    "SNPP",
	SVC_Microsoft_DS:            "Microsoft-DS",
	SVC_Kpasswd:                 "Kpasswd",
	SVC_SMTPS:                   "SMTPS",
	SVC_Tcpnethaspsrv:           "Tcpnethaspsrv",
	SVC_Retrospect:              "Retrospect",
	SVC_ISAKMP:                  "ISAKMP",
	SVC_Modbus:                  "Modbus",
	SVC_Citadel:                 "Citadel",
	SVC_FirstClass:              "FirstClass",
	SVC_Rexec:                   "Rexec",
	SVC_Rlogin:                  "Rlogin",
	SVC_Syslog:                  "Syslog",
	SVC_LPD:                     "LPD",
	SVC_Talk:                    "Talk",
	SVC_NTalk:                   "NTalk",
	SVC_RIP:                     "RIP",
	SVC_RIPng:                   "RIPng",
	SVC_NCP:                     "NCP",
	SVC_Timed:                   "Timed",
	SVC_RPC:                     "RPC",
	SVC_Netnews:                 "Netnews",
	SVC_Netwall:                 "Netwall",
	SVC_UUCP:                    "UUCP",
	SVC_Commerce:                "Commerce",
	SVC_Klogin:                  "Klogin",
	SVC_Kshell:                  "Kshell",
	SVC_DHCPv6_Client:           "DHCPv6-Client",
	SVC_DHCPv6_Server:           "DHCPv6-Server",
	SVC_AFP:                     "AFP",
	SVC_NewRwho:                 "NewRwho",
	SVC_RTSP:                    "RTSP",
	SVC_Remotefs:                "Remotefs",
	SVC_Rmonitor:                "Rmonitor",
	SVC_Monitor:                 "Monitor",
	SVC_NNTPS:                   "NNTPS",
	SVC_Submission:              "Submission",
	SVC_FileMaker:               "FileMaker",
	SVC_HTTP_RPC_EP:             "HTTP-RPC-EP",
	SVC_Reliable_Syslog:         "Reliable-Syslog",
	SVC_TUNNEL:                  "TUNNEL",
	SVC_ASF_RMCP:                "ASF-RMCP",
	SVC_IPP:                     "IPP",
	SVC_RLZ_DBase:               "RLZ-DBase",
	SVC_LDAPS:                   "LDAPS",
	SVC_MSDP:                    "MSDP",
	SVC_SupportSoft:             "SupportSoft",
	SVC_SANity:                  "SANity",
	SVC_LDP:                     "LDP",
	SVC_DHCP_Failover:           "DHCP-Failover",
	SVC_RRP:                     "RRP",
	SVC_IEEE_MMS:                "IEEE-MMS",
	SVC_Tinc:                    "Tinc",
	SVC_IBM_RMC:                 "IBM-RMC",
	SVC_MacOS_Server:            "MacOS-Server",
	SVC_NFS_Statd:               "NFS-Statd",
	SVC_Doom:                    "Doom",
	SVC_ACAP:                    "ACAP",
	SVC_CORBA_IIOP_SSL:          "CORBA-IIOP-SSL",
	SVC_MDC:                     "MDC",
	SVC_Velneo_VATP:             "Velneo-VATP",
	SVC_MS_Exchange:             "MS-Exchange",
	SVC_AFS:                     "AFS",
	SVC_Kerberos_Admin:          "Kerberos-Admin",
	SVC_DNS_Over_TLS:            "DNS-Over-TLS",
	SVC_RSYNC:                   "rsync",
	SVC_RNDC:                    "RNDC",
	SVC_FTPS_Data:               "FTPS-Data",
	SVC_FTPS:                    "FTPS",
	SVC_Telnets:                 "Telnets",
	SVC_IMAPS:                   "IMAPS",
	SVC_IRCS_IANA:               "IRCS-IANA",
	SVC_IRCS:                    "IRCS",
	SVC_POP3S:                   "POP3S",
	SVC_SOCKS:                   "SOCKS",
	SVC_OpenVPN:                 "OpenVPN",
	SVC_MSSQL:                   "MSSQL",
	SVC_MSSQL_Browser:           "MSSQL-Browser",
	SVC_Oracle_TNS:              "Oracle-TNS",
	SVC_L2TP:                    "L2TP",
	SVC_H323:                    "H.323",
	SVC_PPTP:                    "PPTP",
	SVC_Radius:                  "Radius",
	SVC_Radius_Acct:             "Radius-Acct",
	SVC_MQTT:                    "MQTT",
	SVC_SSDP:                    "SSDP",
	SVC_NFS:                     "NFS",
	SVC_Zookeeper:               "Zookeeper",
	SVC_Docker:                  "Docker",
	SVC_Docker_TLS:              "Docker-TLS",
	SVC_Docker_Swarm:            "Docker-Swarm",
	SVC_etcd_Client:             "etcd-Client",
	SVC_etcd_Peer:               "etcd-Peer",
	SVC_Grafana:                 "Grafana",
	SVC_Squid:                   "Squid-Proxy",
	SVC_MySQL:                   "MySQL",
	SVC_RDP:                     "RDP",
	SVC_SVN:                     "SVN",
	SVC_Diameter:                "Diameter",
	SVC_NATS:                    "NATS",
	SVC_IPsec_NAT_T:             "IPsec-NAT-T",
	SVC_VXLAN:                   "VXLAN",
	SVC_Commplex_Main:           "commplex-main",
	SVC_RTP:                     "RTP",
	SVC_RTCP:                    "RTCP",
	SVC_SIP:                     "SIP",
	SVC_SIPS:                    "SIPS",
	SVC_XMPP_Client:             "XMPP-Client",
	SVC_XMPP_Server:             "XMPP-Server",
	SVC_MDNS:                    "mDNS",
	SVC_LLMNR:                   "LLMNR",
	SVC_WSDAPI:                  "wsdapi",
	SVC_PostgreSQL:              "PostgreSQL",
	SVC_Kibana:                  "Kibana",
	SVC_AMQPS:                   "AMQPS",
	SVC_AMQP:                    "AMQP",
	SVC_VNC:                     "VNC",
	SVC_WinRM:                   "WinRM",
	SVC_WinRM_HTTPS:             "WinRM-HTTPS",
	SVC_X11:                     "X11",
	SVC_Redis:                   "Redis",
	SVC_PgBouncer:               "PgBouncer",
	SVC_Kubernetes_API:          "Kubernetes-API",
	SVC_Syslog_TLS:              "Syslog-TLS",
	SVC_Spark_Master:            "Spark-Master",
	SVC_Spark_Worker:            "Spark-Worker",
	SVC_Docker_Gossip:           "Docker-Gossip",
	SVC_Hadoop_Name:             "Hadoop-Name",
	SVC_HTTP_Proxy:              "HTTP-Proxy",
	SVC_Nexus:                   "Nexus",
	SVC_InfluxDB:                "InfluxDB",
	SVC_Splunk:                  "Splunk",
	SVC_TeamCity:                "TeamCity",
	SVC_Vault:                   "Vault",
	SVC_HTTPS_Alt:               "HTTPS-Alt",
	SVC_Consul:                  "Consul",
	SVC_Consul_GRPC:             "Consul-gRPC",
	SVC_MQTT_TLS:                "MQTT-TLS",
	SVC_Cassandra:               "Cassandra",
	SVC_Prometheus:              "Prometheus",
	SVC_Prometheus_Pushgateway:  "Prometheus-Pushgateway",
	SVC_Kafka:                   "Kafka",
	SVC_Prometheus_Alertmanager: "Prometheus-Alertmanager",
	SVC_JetDirect:               "JetDirect",
	SVC_Elasticsearch:           "Elasticsearch",
	SVC_Elasticsearch_Transport: "Elasticsearch-Transport",
	SVC_Git:                     "Git",
	SVC_NDMP:                    "NDMP",
	SVC_Kubelet:                 "Kubelet",
	SVC_Kubelet_ReadOnly:        "Kubelet-ReadOnly",
	SVC_DICOM_Alt:               "DICOM-Alt",
	SVC_Memcached:               "memcache",
	SVC_RabbitMQ_Mgmt:           "RabbitMQ-Mgmt",
	SVC_NFS_Mount:               "NFS-Mount",
	SVC_Minecraft:               "Minecraft",
	SVC_Quake:                   "Quake",
	SVC_Cockroach:               "CockroachDB",
	SVC_Steam:                   "Steam",
	SVC_MongoDB:                 "MongoDB",
	SVC_Hadoop_Data:             "Hadoop-Data",
	SVC_Grpc:                    "gRPC",
	SVC_WireGuard:               "WireGuard",
	SVC_ActiveMQ:                "ActiveMQ",
}

var nameToService map[string]Service

func init() {
	nameToService = make(map[string]Service, len(serviceNames))
	for svc, name := range serviceNames {
		// Map canonical name (lowercase, no hyphens) to service.
		canon := strings.ToLower(strings.ReplaceAll(name, "-", ""))
		if _, exists := nameToService[canon]; !exists {
			nameToService[canon] = svc
		}
		// Map original name (lowercase) to service.
		orig := strings.ToLower(name)
		if _, exists := nameToService[orig]; !exists {
			nameToService[orig] = svc
		}
	}
}

func (s Service) String() string {
	if name, ok := serviceNames[s]; ok {
		return fmt.Sprintf("%d (%s)", uint16(s), strings.ToLower(name))
	}
	return fmt.Sprintf("%d", uint16(s))
}

func PortToService(port uint16) (Service, bool) {
	s := Service(port)
	_, ok := serviceNames[s]
	return s, ok
}

func ServiceToPort(s Service) (uint16, bool) {
	_, ok := serviceNames[s]
	return uint16(s), ok
}

func NameToService(name string) (Service, bool) {
	s, ok := nameToService[strings.ToLower(name)]
	return s, ok
}

func NameToPort(name string) (uint16, bool) {
	s, ok := NameToService(name)
	if !ok {
		return 0, false
	}
	return uint16(s), true
}

func LikelyServicePort(a, b uint16) uint16 {
	knownA := Service(a)
	knownB := Service(b)
	_, inA := serviceNames[knownA]
	_, inB := serviceNames[knownB]
	switch {
	case inA && !inB:
		return a
	case inB && !inA:
		return b
	case inA && inB:
		if a <= b {
			return a
		}
		return b
	default:
		return 0
	}
}
