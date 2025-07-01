package kind

import (
	"regexp"
	"strings"
)

//
// Kind is both:
//
// - a class of detection events (e.g. "flows", "infos", "detections", "netpolicy")
// - a detection event name (e.g. "unprivileged_bpf_config_access")
//
// The class of detection events is used to group detection events into a class.
// The detection event name is used to identify a specific detection event.
//

// The "flows" kind is duplicated with "flow" being created in detect plugin now.
// TODO: use just "flow" after listendev printer is gone.

// The regex is used to replace all special characters with underscores.
var normalizeRegexp = regexp.MustCompile(`[.\-\/\\:;,|()\[\]{}<>'"` + "`" + `~!@#$%^&*?=+\n\r\t\v ]`)

func NormalizeString(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = normalizeRegexp.ReplaceAllString(s, "_")
	return s
}

const (
	// Class of detection events.
	KindNone       Kind = "none"
	KindEmpty      Kind = "empty"
	KindFlows      Kind = "flows" // see TODO above.
	KindInfos      Kind = "infos"
	KindDetections Kind = "detections"
	KindNetPolicy  Kind = "netpolicy"
	//
	// ... (detection event names using their pkg names).
	//
)

type Kind string

func New(event string) Kind {
	return Kind(event)
}

func (k Kind) String() string {
	return string(k)
}

func (k Kind) Normalized() string {
	return NormalizeString(k.String())
}
