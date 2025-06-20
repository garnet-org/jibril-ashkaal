package chemistry

import "fmt"

// revive:disable

var (
	IPv4Regex       = `[^\w|\.](\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}([^\w|\.]|$)`
	IPv6Regex       = `[^\w|\.](([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))([^\w|\.]|$)`
	IPv4OrIPv6Regex = fmt.Sprintf("(%s|%s)", IPv4Regex, IPv6Regex)
)

// revive:enable

type Family uint16

const (
	AF_UNSPEC Family = 0
	AF_INET   Family = 2
	AF_INET6  Family = 10
)

var familyStrings = map[Family]string{
	AF_UNSPEC: "unpec",
	AF_INET:   "AF_INET",
	AF_INET6:  "AF_INET6",
}

func (f Family) String() string {
	if s, ok := familyStrings[f]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%d)", f)
}

type Proto uint16

const (
	IPPROTO_IP       Proto = 0   // Dummy protocol for TCP
	IPPROTO_ICMP     Proto = 1   // Internet Control Message Protocol
	IPPROTO_IGMP     Proto = 2   // Internet Group Management Protocol
	IPPROTO_IPIP     Proto = 4   // IPIP tunnels (older KA9Q tunnels use 94)
	IPPROTO_TCP      Proto = 6   // Transmission Control Protocol
	IPPROTO_EGP      Proto = 8   // Exterior Gateway Protocol
	IPPROTO_PUP      Proto = 12  // PUP protocol
	IPPROTO_UDP      Proto = 17  // User Datagram Protocol
	IPPROTO_IDP      Proto = 22  // XNS IDP protocol
	IPPROTO_TP       Proto = 29  // SO Transport Protocol Class 4
	IPPROTO_DCCP     Proto = 33  // Datagram Congestion Control Protocol
	IPPROTO_IPV6     Proto = 41  // IPv6 header
	IPPROTO_ROUTING  Proto = 43  // IPv6 routing header
	IPPROTO_FRAGMENT Proto = 44  // IPv6 fragmentation header
	IPPROTO_RSVP     Proto = 46  // Reservation Protocol
	IPPROTO_GRE      Proto = 47  // General Routing Encapsulation
	IPPROTO_ESP      Proto = 50  // encapsulating security payload
	IPPROTO_AH       Proto = 51  // authentication header
	IPPROTO_ICMPV6   Proto = 58  // ICMPv6
	IPPROTO_NONE     Proto = 59  // IPv6 no next header
	IPPROTO_DSTOPTS  Proto = 60  // IPv6 destination options
	IPPROTO_MTP      Proto = 92  // Multicast Transport Protocol
	IPPROTO_BEETPH   Proto = 94  // IP option pseudo header for BEET
	IPPROTO_ENCAP    Proto = 98  // Encapsulation Header
	IPPROTO_PIM      Proto = 103 // Protocol Independent Multicast
	IPPROTO_COMP     Proto = 108 // Compression Header Protocol
	IPPROTO_SCTP     Proto = 132 // Stream Control Transmission Protocol
	IPPROTO_MH       Proto = 135 // IPv6 mobility header
	IPPROTO_UDPLITE  Proto = 136 // UDP-Lite protocol
	IPPROTO_MPLS     Proto = 137 // MPLS in IP
	IPPROTO_ETHERNET Proto = 143 // Ethernet-within-IPv6 Encapsulation
	IPPROTO_RAW      Proto = 255 // Raw IP packets
	IPPROTO_MPTCP    Proto = 262 // Multipath TCP connection
)

var protocolStrings = map[Proto]string{
	IPPROTO_IP:       "IP",
	IPPROTO_ICMP:     "ICMP",
	IPPROTO_IGMP:     "IGMP",
	IPPROTO_IPIP:     "IPIP",
	IPPROTO_TCP:      "TCP",
	IPPROTO_EGP:      "EGP",
	IPPROTO_PUP:      "PUP",
	IPPROTO_UDP:      "UDP",
	IPPROTO_IDP:      "IDP",
	IPPROTO_TP:       "TP",
	IPPROTO_DCCP:     "DCCP",
	IPPROTO_IPV6:     "IPV6",
	IPPROTO_ROUTING:  "ROUTING",
	IPPROTO_FRAGMENT: "FRAGMENT",
	IPPROTO_RSVP:     "RSVP",
	IPPROTO_GRE:      "GRE",
	IPPROTO_ESP:      "ESP",
	IPPROTO_AH:       "AH",
	IPPROTO_ICMPV6:   "ICMPV6",
	IPPROTO_NONE:     "NONE",
	IPPROTO_DSTOPTS:  "DSTOPTS",
	IPPROTO_MTP:      "MTP",
	IPPROTO_BEETPH:   "BEETPH",
	IPPROTO_ENCAP:    "ENCAP",
	IPPROTO_PIM:      "PIM",
	IPPROTO_COMP:     "COMP",
	IPPROTO_SCTP:     "SCTP",
	IPPROTO_MH:       "MH",
	IPPROTO_UDPLITE:  "UDPLITE",
	IPPROTO_MPLS:     "MPLS",
	IPPROTO_ETHERNET: "ETHERNET",
	IPPROTO_RAW:      "RAW",
	IPPROTO_MPTCP:    "MPTCP",
}

func (p Proto) String() string {
	if s, ok := protocolStrings[p]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%d)", p)
}

type ICMPType uint8

const (
	ICMP_ECHOREPLY         ICMPType = 0
	ICMP_UNREACH           ICMPType = 3
	ICMP_SOURCEQUENCH      ICMPType = 4
	ICMP_REDIRECT          ICMPType = 5
	ICMP_ALTHOSTADDR       ICMPType = 6
	ICMP_ECHO              ICMPType = 8
	ICMP_ROUTERADVERT      ICMPType = 9
	ICMP_ROUTERSOLICIT     ICMPType = 10
	ICMP_TIMXCEED          ICMPType = 11
	ICMP_PARAMPROB         ICMPType = 12
	ICMP_TSTAMP            ICMPType = 13
	ICMP_TSTAMPREPLY       ICMPType = 14
	ICMP_IREQ              ICMPType = 15
	ICMP_IREQREPLY         ICMPType = 16
	ICMP_MASKREQ           ICMPType = 17
	ICMP_MASKREPLY         ICMPType = 18
	ICMP_TRACEROUTE        ICMPType = 30
	ICMP_DATACONVERR       ICMPType = 31
	ICMP_MOBILE_REDIRECT   ICMPType = 32
	ICMP_IPV6_WHEREAREYOU  ICMPType = 33
	ICMP_IPV6_IAMHERE      ICMPType = 34
	ICMP_MOBILE_REGREQUEST ICMPType = 35
	ICMP_MOBILE_REGREPLY   ICMPType = 36
	ICMP_SKIP              ICMPType = 39
	ICMP_PHOTURIS          ICMPType = 40
)

var icmpTypeStrings = map[ICMPType]string{
	ICMP_ECHOREPLY:         "EchoReply",
	ICMP_UNREACH:           "Unreach",
	ICMP_SOURCEQUENCH:      "SourceQuench",
	ICMP_REDIRECT:          "Redirect",
	ICMP_ALTHOSTADDR:       "AltHostAddr",
	ICMP_ECHO:              "EchoRequest",
	ICMP_ROUTERADVERT:      "RouterAdvert",
	ICMP_ROUTERSOLICIT:     "RouterSolicit",
	ICMP_TIMXCEED:          "TimeExceeded",
	ICMP_PARAMPROB:         "ParamProblem",
	ICMP_TSTAMP:            "Timestamp",
	ICMP_TSTAMPREPLY:       "TimestampReply",
	ICMP_IREQ:              "InfoRequest",
	ICMP_IREQREPLY:         "InfoReply",
	ICMP_MASKREQ:           "MaskRequest",
	ICMP_MASKREPLY:         "MaskReply",
	ICMP_TRACEROUTE:        "Traceroute",
	ICMP_DATACONVERR:       "DataConversionError",
	ICMP_MOBILE_REDIRECT:   "MobileRedirect",
	ICMP_IPV6_WHEREAREYOU:  "IPv6WhereAreYou",
	ICMP_IPV6_IAMHERE:      "IPv6IAmHere",
	ICMP_MOBILE_REGREQUEST: "MobileRegRequest",
	ICMP_MOBILE_REGREPLY:   "MobileRegReply",
	ICMP_SKIP:              "Skip",
	ICMP_PHOTURIS:          "Photuris",
}

func (t ICMPType) String() string {
	if s, ok := icmpTypeStrings[t]; ok {
		return s
	}
	return fmt.Sprintf("%d", t)
}

type ICMPCode uint8

var icmpCodeStrings = map[ICMPType]map[ICMPCode]string{
	ICMP_UNREACH: {
		0:  "Net",
		1:  "Host",
		2:  "Protocol",
		3:  "Port",
		4:  "NeedFrag",
		5:  "SrcFail",
		6:  "NetUnknown",
		7:  "HostUnknown",
		8:  "Isolated",
		9:  "NetProhib",
		10: "HostProhib",
		11: "TOSNet",
		12: "TOSHost",
		13: "FilterProhib",
		14: "HostPrecedence",
		15: "PrecedenceCutoff",
	},
	ICMP_REDIRECT: {
		0: "Net",
		1: "Host",
		2: "TOSNet",
		3: "TOSHost",
	},
	ICMP_PARAMPROB: {
		0: "ErrAtPtr",
		1: "OptAbsent",
		2: "Length",
	},
	ICMP_PHOTURIS: {
		1: "UnknownIndex",
		2: "AuthFailed",
		3: "DecryptFailed",
	},
}

func (c ICMPCode) String(t ICMPType) string {
	if m, ok := icmpCodeStrings[t]; ok {
		if s, ok := m[c]; ok {
			return s
		}
	}
	return fmt.Sprintf("%d", c)
}
