package chemistry

type ReactionFormat int

const (
	ReactionFormatNone ReactionFormat = iota
	ReactionFormatYAML
	ReactionFormatShell
	ReactionFormatJS
	ReactionFormatEnd
)

func (r ReactionFormat) String() string {
	switch r {
	case ReactionFormatYAML:
		return "yaml"
	case ReactionFormatShell:
		return "shell"
	case ReactionFormatJS:
		return "js"
	default:
		return "none"
	}
}

func ReactionFormatFromString(s string) ReactionFormat {
	switch s {
	case "yaml":
		return ReactionFormatYAML
	case "shell":
		return ReactionFormatShell
	case "js":
		return ReactionFormatJS
	default:
		return ReactionFormatNone
	}
}
