package ongoing

import "github.com/garnet-org/jibril-ashkaal/pkg/kind"

// OnGoingEmpty is an empty implementation of the OnGoing interface.
// It is used as a placeholder for errors.

type OnGoingEmpty struct{}

func NewOnGoingEmpty() *OnGoingEmpty { return &OnGoingEmpty{} }

func (*OnGoingEmpty) UUID() string { return "" }

func (*OnGoingEmpty) Kind() kind.Kind { return kind.KindEmpty }

func (*OnGoingEmpty) SetPrivate(string, any) {}

func (*OnGoingEmpty) GetPrivate(string) any { return nil }

func (*OnGoingEmpty) Duplicate() OnGoing { return &OnGoingEmpty{} }

func (*OnGoingEmpty) Add(map[string]any) {}

func (*OnGoingEmpty) Serialize() []byte { return []byte{} }

func (*OnGoingEmpty) Destroy() {}
