package ongoing

import "fmt"

// Canonical keys for the process and target registries.
//
// The hash is calculated by the kernel. A zero hash has
// no key (empty string), so an unresolved reference never
// becomes a registry key.

const (
	targetKindFile = "file"
	targetKindFlow = "flow"
)

func hashKey(h uint32) string {
	if h == 0 {
		return ""
	}
	return fmt.Sprintf("%08x", h)
}

func targetEventKey(eventKind string, h uint32) string {
	key := hashKey(h)
	if key == "" {
		return ""
	}
	return eventKind + ":" + key
}
