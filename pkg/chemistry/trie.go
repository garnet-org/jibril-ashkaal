package chemistry

type TrieType int

const (
	TrieTypeNone TrieType = iota
	TrieTypeSuffix
	TrieTypePrefix
	TrieTypeExact
)
