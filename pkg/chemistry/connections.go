package chemistry

// ConnectionDirection: The direction of a connection.

type ConnectionDirection uint64

const (
	ConnectionDirectionNone    ConnectionDirection = 0               // Nothing.
	ConnectionDirectionIngress ConnectionDirection = 1 << (iota - 1) // Remote node initiated.
	ConnectionDirectionEgress                                        // Local node initiated.
	ConnectionDirectionLocal                                         // Loopback connection.
)

func (cd ConnectionDirection) String() string {
	switch cd {
	case ConnectionDirectionIngress:
		return "ingress"
	case ConnectionDirectionEgress:
		return "egress"
	case ConnectionDirectionLocal:
		return "local"
	}
	return "unknown"
}

func (cd ConnectionDirection) Uint64() uint64 {
	return uint64(cd)
}

func (cd ConnectionDirection) Int() int {
	return int(cd)
}
