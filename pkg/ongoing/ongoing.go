package ongoing

import "github.com/garnet-org/jibril-ashkaal/pkg/kind"

// OnGoing is the interface for all ongoing data.

type OnGoing interface {
	UUID() string
	Kind() kind.Kind
	SetPrivate(string, any)
	GetPrivate(string) any
	Duplicate() OnGoing
	Add(map[string]any)
	Serialize() []byte
	Destroy()
}
