package ongoing

import (
	"strconv"
	"strings"
)

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
	hex := strconv.FormatUint(uint64(h), 16)
	return strings.Repeat("0", 8-len(hex)) + hex
}

func targetEventKey(eventKind string, h uint32) string {
	key := hashKey(h)
	if key == "" {
		return ""
	}
	return eventKind + ":" + key
}
