package kind

import (
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

func NormalizeString(s string) string {
	created := s
	created = strings.ToLower(created)
	created = strings.TrimSpace(created)
	created = strings.ReplaceAll(created, "/", "_")
	created = strings.ReplaceAll(created, ".", "_")
	created = strings.ReplaceAll(created, "\n", "")
	created = strings.ReplaceAll(created, "\r", "")
	created = strings.ReplaceAll(created, "\t", "")
	created = strings.ReplaceAll(created, "\v", "")
	created = strings.ReplaceAll(created, " ", "_")
	return created
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
