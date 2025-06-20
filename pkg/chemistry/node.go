package chemistry

type NodeType int

const (
	Suffix NodeType = iota
	Prefix
	Exact
)
